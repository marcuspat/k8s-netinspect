//! In-cluster connectivity probe.
//!
//! `can-reach` predicts a verdict from policy objects. `--probe` checks it
//! against reality by running one TCP connect **from inside the source pod's
//! network namespace**, using an ephemeral container (the mechanism behind
//! `kubectl debug`). That is the only vantage point where the source pod's
//! egress policy, its node's dataplane and the destination's ingress policy
//! all apply exactly as they do for the workload.
//!
//! The pieces that decide things — the container spec, how a result is
//! classified, how it compares with the prediction — are pure and tested.
//! [`run`] talks to the cluster: it has been exercised against a live kind
//! cluster (v1.37, 2026-10-14) — patching, polling, log reading and the
//! success path end to end. What that run surfaced is folded into
//! [`classify`]: `nc` failures are often *silent* (busybox `nc` times out
//! with no output, and its diagnostics go to stderr), so classification is
//! exit-code-first and a non-zero exit without recognisable output is a
//! [`Observation::Failed`], not an error.

use k8s_openapi::api::core::v1::{Capabilities, EphemeralContainer, Pod, SecurityContext};
use kube::api::{LogParams, Patch, PatchParams};
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

use crate::errors::{NetInspectError, NetInspectResult};

pub const DEFAULT_IMAGE: &str = "busybox:1.36";
const CONTAINER_PREFIX: &str = "netinspect-probe";
/// Extra time, beyond the connect timeout, for the image pull and start.
const STARTUP_ALLOWANCE: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct ProbeSpec {
    pub image: String,
    pub target: IpAddr,
    pub port: u16,
    /// TCP connect timeout, seconds.
    pub timeout_secs: u32,
}

/// What the probe saw on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observation {
    /// TCP handshake completed.
    Connected,
    /// The destination answered with a reset: the path is open and nothing
    /// is listening on that port.
    Refused,
    /// No answer: packets are being dropped somewhere.
    TimedOut,
    /// The connect failed but `nc` said nothing usable about how (busybox
    /// `nc` is silent on `-w` timeouts and prints its diagnostics to
    /// stderr, which the log read does not always surface). A failure with
    /// an unknown flavour: it is consistent with a blocking policy, and
    /// under an allowing one it means "nothing listening, or dropped
    /// beyond the evaluated policies".
    Failed,
    /// The probe did not produce a usable result.
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    pub observed: Observation,
    /// Does the observation match the policy prediction?
    pub agrees: bool,
    pub explanation: String,
    /// Ephemeral container that ran the probe (it stays in the pod spec).
    pub container: String,
}

/// The ephemeral container that performs the connect. Unprivileged: no added
/// capabilities, no privilege escalation; it only needs to open a socket.
pub fn container(name: &str, spec: &ProbeSpec) -> EphemeralContainer {
    EphemeralContainer {
        name: name.to_string(),
        image: Some(spec.image.clone()),
        // `nc -z` connects and closes without sending data. Arguments are
        // passed as an argv array — nothing is interpreted by a shell.
        command: Some(vec![
            "nc".to_string(),
            "-z".to_string(),
            "-w".to_string(),
            spec.timeout_secs.to_string(),
            spec.target.to_string(),
            spec.port.to_string(),
        ]),
        image_pull_policy: Some("IfNotPresent".to_string()),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            privileged: Some(false),
            capabilities: Some(Capabilities {
                add: None,
                drop: Some(vec!["ALL".to_string()]),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// `netinspect-probe-<suffix>`; the suffix makes repeated probes of the same
/// pod distinct, since ephemeral containers can never be removed or reused.
pub fn container_name(suffix: u64) -> String {
    format!("{CONTAINER_PREFIX}-{suffix}")
}

/// Interpret the probe container's exit code and output.
///
/// Exit-code first: `nc` exiting 0 means the handshake completed, and any
/// other exit means the connect failed. Log text refines *how* it failed
/// when there is any (`refused` vs a drop); busybox `nc` is silent on
/// `-w` timeouts and writes diagnostics to stderr, which the log read does
/// not always surface, so an unexplained non-zero exit is
/// [`Observation::Failed`] — a real failure, flavour unknown — not an
/// unusable result. Only exits that mean "nc never ran" (`127` command
/// not found, `126` not executable) stay [`Observation::Inconclusive`].
pub fn classify(exit_code: i32, logs: &str) -> Observation {
    if exit_code == 0 {
        return Observation::Connected;
    }
    let logs = logs.to_lowercase();
    if logs.contains("refused") {
        Observation::Refused
    } else if logs.contains("timed out") || logs.contains("timeout") {
        Observation::TimedOut
    } else if logs.contains("unreachable") || logs.contains("no route") {
        // ICMP unreachable is still "the packet did not get there".
        Observation::TimedOut
    } else if exit_code == 126 || exit_code == 127 {
        // The container ran but `nc` did not: image without `nc`.
        Observation::Inconclusive
    } else {
        // `nc` ran and the connect failed, with nothing usable about how.
        Observation::Failed
    }
}

/// Compare what policy predicted with what the probe observed.
///
/// `agrees` means "consistent with the policy verdict". The verdict is about
/// policy, never a promise the connection succeeds, so a *failed* connect
/// under an allowing verdict is not a contradiction — it is reported with
/// where else to look. Exit 8 (the caller's mismatch) is reserved for the
/// genuine contradictions: policy blocks the flow, yet the connect succeeds
/// or the destination answers. `Inconclusive` never claims agreement; the
/// caller gives it its own exit status.
pub fn compare(predicted_allowed: bool, observed: Observation, container: &str) -> ProbeReport {
    let (agrees, explanation) = match (predicted_allowed, observed) {
        (true, Observation::Connected) => (true, "Connected, as policy predicts."),
        (false, Observation::TimedOut) => (
            true,
            "No answer, consistent with the policy that blocks this flow.",
        ),
        (true, Observation::Refused) => (
            true,
            "The destination reset the connection: the network path is open, but nothing is \
             listening on that port.",
        ),
        (true, Observation::TimedOut) => (
            true,
            "Policy allows this flow, but packets are dropped — 'allowed' never meant the \
             connection would succeed. Look beyond the evaluated policies: a CNI-native \
             policy, a service mesh, a host or cloud firewall, a broken CNI on either node, \
             or the destination not listening behind a dropping firewall.",
        ),
        (true, Observation::Failed) => (
            true,
            "Policy allows this flow, but the connect failed (the probe could not tell a \
             closed port from a drop). Either nothing is listening on that port, or packets \
             are dropped beyond the evaluated policies — the same places to look as for a \
             timeout.",
        ),
        (false, Observation::Failed) => (
            true,
            "The connect failed, consistent with the policy that blocks this flow. The probe \
             could not tell a drop from a reset; a reset here would mean the policy is not \
             being enforced — if you suspect that, re-run with a longer --probe-timeout.",
        ),
        (false, Observation::Connected) => (
            false,
            "Policy blocks this flow but the connection succeeded: the policy is not being \
             enforced. The CNI may not implement NetworkPolicy (plain Flannel does not), its \
             agent may be down on a node, or one endpoint uses hostNetwork.",
        ),
        (false, Observation::Refused) => (
            false,
            "Policy blocks this flow but the destination answered with a reset, so packets \
             reached it: the policy is not being enforced.",
        ),
        (_, Observation::Inconclusive) => (
            false,
            "The probe did not produce a usable result (image without `nc`, or the container \
             failed to start); nothing can be concluded.",
        ),
    };
    ProbeReport {
        observed,
        agrees,
        explanation: explanation.to_string(),
        container: container.to_string(),
    }
}

/// Run the probe in `namespace/pod`. Adds an ephemeral container to that pod
/// — a change that cannot be undone short of deleting the pod — so callers
/// must only reach this behind an explicit opt-in.
pub async fn run(
    client: Client,
    namespace: &str,
    pod: &str,
    name: &str,
    spec: &ProbeSpec,
) -> NetInspectResult<(i32, String)> {
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    let patch = serde_json::json!({
        "spec": {"ephemeralContainers": [container(name, spec)]}
    });
    pods.patch_ephemeral_containers(pod, &PatchParams::default(), &Patch::Strategic(patch))
        .await
        .map_err(|e| match NetInspectError::from(e) {
            NetInspectError::PermissionDenied(m) => NetInspectError::PermissionDenied(format!(
                "{m}. --probe needs `patch` on pods/ephemeralcontainers in namespace \
                 '{namespace}'."
            )),
            other => other,
        })?;

    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(u64::from(spec.timeout_secs))
        + STARTUP_ALLOWANCE;
    loop {
        let current = pods.get(pod).await.map_err(NetInspectError::from)?;
        let state = current
            .status
            .as_ref()
            .and_then(|s| s.ephemeral_container_statuses.as_ref())
            .and_then(|list| list.iter().find(|c| c.name == name))
            .and_then(|c| c.state.clone());
        if let Some(state) = state {
            if let Some(terminated) = state.terminated {
                let logs = pods
                    .logs(
                        pod,
                        &LogParams {
                            container: Some(name.to_string()),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap_or_default();
                return Ok((terminated.exit_code, logs));
            }
            if let Some(waiting) = state.waiting {
                let reason = waiting.reason.unwrap_or_default();
                if reason == "ErrImagePull" || reason == "ImagePullBackOff" {
                    return Err(NetInspectError::Runtime(format!(
                        "Probe image '{}' could not be pulled ({reason}). Pass an image your \
                         cluster can reach with --probe-image.",
                        spec.image
                    )));
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(NetInspectError::Timeout(format!(
                "Probe container '{name}' did not finish in time"
            )));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ProbeSpec {
        ProbeSpec {
            image: DEFAULT_IMAGE.to_string(),
            target: "10.0.1.12".parse().unwrap(),
            port: 5432,
            timeout_secs: 5,
        }
    }

    #[test]
    fn container_is_unprivileged_and_runs_exactly_one_connect() {
        let c = container(&container_name(1727836800), &spec());
        assert_eq!(c.name, "netinspect-probe-1727836800");
        assert_eq!(c.image.as_deref(), Some("busybox:1.36"));
        assert_eq!(
            c.command.unwrap(),
            vec!["nc", "-z", "-w", "5", "10.0.1.12", "5432"]
        );
        assert!(c.args.is_none(), "no shell, no extra arguments");
        let sc = c.security_context.unwrap();
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        assert_eq!(sc.privileged, Some(false));
        let caps = sc.capabilities.unwrap();
        assert_eq!(caps.drop.unwrap(), vec!["ALL"]);
        assert!(caps.add.is_none());

        // IPv6 targets are passed verbatim as one argv element.
        let v6 = ProbeSpec {
            target: "fd00:10:244::1a".parse().unwrap(),
            ..spec()
        };
        assert_eq!(container("p", &v6).command.unwrap()[4], "fd00:10:244::1a");
    }

    #[test]
    fn classification_of_nc_results() {
        assert_eq!(classify(0, ""), Observation::Connected);
        assert_eq!(
            classify(
                1,
                "nc: can't connect to remote host (10.0.1.12): Connection refused\n"
            ),
            Observation::Refused
        );
        assert_eq!(classify(1, "nc: timed out\n"), Observation::TimedOut);
        assert_eq!(
            classify(
                1,
                "nc: can't connect to remote host (10.0.1.12): Connection timed out"
            ),
            Observation::TimedOut
        );
        assert_eq!(
            classify(1, "nc: can't connect to remote host: No route to host"),
            Observation::TimedOut
        );
        assert_eq!(
            classify(127, "exec: \"nc\": executable file not found in $PATH"),
            Observation::Inconclusive
        );
        assert_eq!(classify(126, ""), Observation::Inconclusive);
        // The live-cluster case that drove this shape: busybox nc times out
        // silently, so a failed connect often carries no log text at all.
        assert_eq!(classify(1, ""), Observation::Failed);
        assert_eq!(classify(1, "some unrecognised noise"), Observation::Failed);
    }

    #[test]
    fn comparison_flags_every_disagreement() {
        use Observation::*;
        let agrees = |predicted, observed| compare(predicted, observed, "c").agrees;
        assert!(agrees(true, Connected));
        assert!(agrees(false, TimedOut));
        assert!(
            agrees(true, Refused),
            "open path, closed port is not a policy mismatch"
        );
        // A failed connect never contradicts an allowing verdict: 'allowed'
        // never promised the connection would succeed.
        assert!(agrees(true, TimedOut));
        assert!(agrees(true, Failed));
        // ...nor a blocking one, when the failure flavour is unknown.
        assert!(agrees(false, Failed));
        // The genuine contradictions: policy blocks, yet packets get through.
        assert!(!agrees(false, Connected));
        assert!(!agrees(false, Refused));
        assert!(!agrees(true, Inconclusive));
        assert!(!agrees(false, Inconclusive));

        let leak = compare(false, Connected, "netinspect-probe-1");
        assert!(leak.explanation.contains("not being enforced"));
        assert_eq!(leak.container, "netinspect-probe-1");
        let drop = compare(true, TimedOut, "c");
        assert!(drop.explanation.contains("CNI-native policy"));
        let unknown = compare(true, Failed, "c");
        assert!(unknown.explanation.contains("nothing is listening"));
    }

    #[test]
    fn report_serializes_with_stable_names() {
        let drop = serde_json::to_value(compare(true, Observation::TimedOut, "c")).unwrap();
        assert_eq!(drop["observed"], "timed_out");
        assert_eq!(drop["agrees"], true);
        let leak = serde_json::to_value(compare(false, Observation::Connected, "c")).unwrap();
        assert_eq!(leak["observed"], "connected");
        assert_eq!(leak["agrees"], false);
        let unknown = serde_json::to_value(compare(true, Observation::Failed, "c")).unwrap();
        assert_eq!(unknown["observed"], "failed");
    }
}
