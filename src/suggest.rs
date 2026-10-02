//! Remediation: the smallest NetworkPolicy that would let a blocked flow
//! through. Suggestions are printed, never applied.
//!
//! Policies are additive, so the fix for a denied direction is always one
//! more policy selecting the isolated pod and allowing exactly this peer and
//! port. Each suggestion is re-evaluated against the snapshot before it is
//! shown; a suggestion that would not change the verdict is not offered.

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::analysis::policy::{evaluate, Decision, DirectionVerdict, Endpoint, Flow, Protocol};
use crate::snapshot::ClusterSnapshot;

/// Labels that identify a workload, in order of preference.
const IDENTITY_LABELS: &[&str] = &[
    "app.kubernetes.io/name",
    "app.kubernetes.io/instance",
    "app.kubernetes.io/component",
    "app",
    "k8s-app",
];

/// Labels that change per rollout or per replica: selecting on them would
/// make the policy stop matching after the next deploy.
const VOLATILE_LABELS: &[&str] = &[
    "pod-template-hash",
    "controller-revision-hash",
    "pod-template-generation",
    "statefulset.kubernetes.io/pod-name",
    "apps.kubernetes.io/pod-index",
    "controller-uid",
    "batch.kubernetes.io/controller-uid",
    "batch.kubernetes.io/job-completion-index",
];

#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    /// Policies to add. Empty when nothing can or needs to be suggested.
    pub policies: Vec<NetworkPolicy>,
    /// `policies` as a multi-document YAML manifest.
    pub yaml: String,
    /// True when re-evaluating with `policies` added allows the flow.
    pub verified: bool,
    /// Why something was not suggested, and what to check before applying.
    pub notes: Vec<String>,
}

/// Stable labels to select `pod` by, or `None` if it has none to offer.
fn selector_labels(pod: &Pod) -> Option<BTreeMap<String, String>> {
    let labels = pod.metadata.labels.as_ref()?;
    let identity: BTreeMap<String, String> = labels
        .iter()
        .filter(|(k, _)| IDENTITY_LABELS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if !identity.is_empty() {
        return Some(identity);
    }
    let stable: BTreeMap<String, String> = labels
        .iter()
        .filter(|(k, _)| !VOLATILE_LABELS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    (!stable.is_empty()).then_some(stable)
}

fn ns_of(pod: &Pod) -> &str {
    pod.metadata.namespace.as_deref().unwrap_or("default")
}

/// Short workload name for the policy's own name.
fn short_name(endpoint: &Endpoint<'_>) -> String {
    match endpoint {
        Endpoint::Ip(ip) => ip.to_string(),
        Endpoint::Pod(pod) => selector_labels(pod)
            .and_then(|l| {
                IDENTITY_LABELS
                    .iter()
                    .find_map(|k| l.get(*k).cloned())
                    .or_else(|| l.values().next().cloned())
            })
            .or_else(|| pod.metadata.name.clone())
            .unwrap_or_else(|| "pod".to_string()),
    }
}

/// A valid DNS-1123 label of at most 63 characters.
fn dns_label(raw: &str) -> String {
    let mut out: String = raw
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches('-');
    let out = &out[..out.len().min(63)];
    out.trim_matches('-').to_string()
}

/// The `from` / `to` peer for `actual`, as seen from a policy in `policy_ns`.
fn peer(actual: &Endpoint<'_>, policy_ns: &str) -> Result<Value, String> {
    match actual {
        Endpoint::Ip(ip) => {
            let bits = if ip.is_ipv4() { 32 } else { 128 };
            Ok(json!({"ipBlock": {"cidr": format!("{ip}/{bits}")}}))
        }
        Endpoint::Pod(pod) => {
            let labels = selector_labels(pod).ok_or_else(|| {
                format!(
                    "{}/{} has no stable labels to select it by; label the workload first.",
                    ns_of(pod),
                    pod.metadata.name.as_deref().unwrap_or("<unnamed>")
                )
            })?;
            let mut peer = json!({"podSelector": {"matchLabels": labels}});
            if ns_of(pod) != policy_ns {
                peer["namespaceSelector"] =
                    json!({"matchLabels": {"kubernetes.io/metadata.name": ns_of(pod)}});
            }
            Ok(peer)
        }
    }
}

fn build(
    subject: &Pod,
    other: &Endpoint<'_>,
    flow: &Flow<'_>,
    egress: bool,
) -> Result<NetworkPolicy, String> {
    let ns = ns_of(subject);
    let labels = selector_labels(subject).ok_or_else(|| {
        format!(
            "{}/{} has no stable labels to select it by; label the workload first.",
            ns,
            subject.metadata.name.as_deref().unwrap_or("<unnamed>")
        )
    })?;
    let ports =
        json!([{"protocol": format!("{:?}", flow.protocol).to_uppercase(), "port": flow.port}]);
    let subject_name = short_name(&Endpoint::Pod(subject));
    let (name, spec) = if egress {
        (
            format!(
                "allow-{}-to-{}-{}",
                subject_name,
                short_name(other),
                flow.port
            ),
            json!({
                "podSelector": {"matchLabels": labels},
                "policyTypes": ["Egress"],
                "egress": [{"to": [peer(other, ns)?], "ports": ports}],
            }),
        )
    } else {
        (
            format!(
                "allow-{}-from-{}-{}",
                subject_name,
                short_name(other),
                flow.port
            ),
            json!({
                "podSelector": {"matchLabels": labels},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [peer(other, ns)?], "ports": ports}],
            }),
        )
    };
    serde_json::from_value(json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": dns_label(&name), "namespace": ns},
        "spec": spec,
    }))
    .map_err(|e| format!("could not build policy: {e}"))
}

fn needs_policy(direction: &DirectionVerdict, notes: &mut Vec<String>, side: &str) -> bool {
    if direction.decision != Decision::Denied {
        return false;
    }
    if let Some(by) = &direction.decided_by {
        notes.push(format!(
            "{side} is denied by {by}. An admin-tier rule outranks NetworkPolicy, so no \
             NetworkPolicy can allow this flow; the admin policy itself must change."
        ));
        return false;
    }
    true
}

/// Suggest NetworkPolicies that would allow `flow`, given its current verdict.
pub fn suggest(snapshot: &ClusterSnapshot, flow: &Flow<'_>) -> Suggestion {
    let verdict = evaluate(snapshot, flow);
    let mut notes = Vec::new();
    let mut policies = Vec::new();

    if verdict.allowed {
        notes.push("The flow is already allowed; nothing to add.".to_string());
    }
    if flow.protocol != Protocol::Tcp {
        notes.push(format!(
            "Protocol is {:?}: remember that replies are allowed automatically, but each \
             direction of a two-way UDP/SCTP exchange initiated separately needs its own rule.",
            flow.protocol
        ));
    }

    if needs_policy(&verdict.egress, &mut notes, "Egress") {
        if let Endpoint::Pod(src) = flow.src {
            match build(src, &flow.dst, flow, true) {
                Ok(p) => policies.push(p),
                Err(e) => notes.push(e),
            }
        }
    }
    if needs_policy(&verdict.ingress, &mut notes, "Ingress") {
        if let Endpoint::Pod(dst) = flow.dst {
            match build(dst, &flow.src, flow, false) {
                Ok(p) => policies.push(p),
                Err(e) => notes.push(e),
            }
        }
    }

    // Prove the suggestion works before offering it.
    let verified = !policies.is_empty() && {
        let mut patched = snapshot.clone();
        patched.network_policies.extend(policies.iter().cloned());
        evaluate(&patched, flow).allowed
    };
    if !policies.is_empty() && !verified {
        notes.push(
            "Adding these policies would not be enough on its own (see the other notes); they \
             are shown for the part NetworkPolicy can fix."
                .to_string(),
        );
    }
    if !policies.is_empty() {
        notes.push(
            "Selectors use workload labels, so every pod carrying them is covered — check that \
             is the scope you intend."
                .to_string(),
        );
        if !verdict.complete {
            notes.push(
                "The verdict is incomplete (see caveats): policies this tool does not evaluate \
                 may still block the flow."
                    .to_string(),
            );
        }
    }

    let yaml = policies
        .iter()
        .filter_map(|p| serde_json::to_value(p).ok())
        .map(|v| to_yaml(&v))
        .collect::<Vec<_>>()
        .join("---\n");
    Suggestion {
        policies,
        yaml,
        verified,
        notes,
    }
}

/// Can `s` be written as a plain (unquoted) YAML scalar and read back as the
/// same string?
fn plain_safe(s: &str) -> bool {
    let reserved = [
        "", "~", "null", "true", "false", "yes", "no", "on", "off", "y", "n",
    ];
    !reserved.contains(&s.to_lowercase().as_str())
        && s.parse::<f64>().is_err()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-'))
        && !s.starts_with('-')
}

fn scalar(s: &str) -> String {
    if plain_safe(s) {
        s.to_string()
    } else {
        // A JSON string is a valid double-quoted YAML scalar.
        serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
    }
}

/// Minimal block-style YAML for a JSON value. Enough for Kubernetes
/// manifests: maps, lists, strings, numbers, booleans.
pub fn to_yaml(value: &Value) -> String {
    let mut out = String::new();
    write_yaml(value, 0, &mut out);
    out
}

fn write_yaml(value: &Value, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                match v {
                    Value::Object(m) if m.is_empty() => {
                        out.push_str(&format!("{pad}{}: {{}}\n", scalar(k)))
                    }
                    Value::Array(a) if a.is_empty() => {
                        out.push_str(&format!("{pad}{}: []\n", scalar(k)))
                    }
                    Value::Object(_) => {
                        out.push_str(&format!("{pad}{}:\n", scalar(k)));
                        write_yaml(v, indent + 1, out);
                    }
                    Value::Array(_) => {
                        out.push_str(&format!("{pad}{}:\n", scalar(k)));
                        write_yaml(v, indent, out);
                    }
                    _ => out.push_str(&format!("{pad}{}: {}\n", scalar(k), leaf(v))),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::Object(_) | Value::Array(_) => {
                        let mut nested = String::new();
                        write_yaml(item, indent + 1, &mut nested);
                        // Put the first key on the dash line.
                        let body = nested.trim_start_matches(' ');
                        out.push_str(&format!("{pad}- {body}"));
                    }
                    _ => out.push_str(&format!("{pad}- {}\n", leaf(item))),
                }
            }
        }
        _ => out.push_str(&format!("{pad}{}\n", leaf(value))),
    }
}

fn leaf(value: &Value) -> String {
    match value {
        Value::String(s) => scalar(s),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_emitter_handles_nesting_and_quoting() {
        let v = json!({
            "apiVersion": "networking.k8s.io/v1",
            "metadata": {"name": "allow-web", "labels": {}},
            "spec": {
                "podSelector": {"matchLabels": {"app": "web", "version": "1.0", "enabled": "true"}},
                "policyTypes": ["Egress"],
                "egress": [{"to": [{"ipBlock": {"cidr": "10.0.0.1/32"}}],
                            "ports": [{"protocol": "TCP", "port": 5432}]}],
                "empty": []
            }
        });
        let yaml = to_yaml(&v);
        let expected = "\
apiVersion: networking.k8s.io/v1
metadata:
  labels: {}
  name: allow-web
spec:
  egress:
  - ports:
    - port: 5432
      protocol: TCP
    to:
    - ipBlock:
        cidr: 10.0.0.1/32
  empty: []
  podSelector:
    matchLabels:
      app: web
      enabled: \"true\"
      version: \"1.0\"
  policyTypes:
  - Egress
";
        assert_eq!(yaml, expected);
    }

    #[test]
    fn scalars_that_yaml_would_reinterpret_are_quoted() {
        for s in [
            "true", "No", "null", "1.0", "42", "", "a: b", "x#y", "-lead", "~",
        ] {
            assert!(scalar(s).starts_with('"'), "{s:?} must be quoted");
        }
        for s in ["web", "app.kubernetes.io/name", "10.0.0.1/32", "v1.2.3-rc1"] {
            assert_eq!(scalar(s), s);
        }
    }

    #[test]
    fn dns_labels_are_valid_and_bounded() {
        assert_eq!(
            dns_label("allow-Web_App-to-10.0.0.1-5432"),
            "allow-web-app-to-10-0-0-1-5432"
        );
        assert_eq!(dns_label("allow-a-to-fd00::1-80"), "allow-a-to-fd00-1-80");
        let long = dns_label(&"x".repeat(100));
        assert_eq!(long.len(), 63);
        assert!(!dns_label("--edge--").starts_with('-'));
    }
}
