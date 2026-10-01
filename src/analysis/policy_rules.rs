//! Findings about the NetworkPolicy objects themselves: policies that do
//! nothing, rules that can never match, and the classic "default-deny egress
//! broke DNS" outage.

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use std::collections::BTreeMap;

use super::policy::{
    applies_to, evaluate, is_host_network, named_port, namespace_labels, ns_of, policy_id,
    ports_match, selector_matches, Decision, Direction, Endpoint, Flow, Protocol,
};
use crate::model::{Finding, Severity};
use crate::snapshot::ClusterSnapshot;

const DNS_NAMESPACE: &str = "kube-system";
const DNS_LABEL: (&str, &str) = ("k8s-app", "kube-dns");

pub fn analyze(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    // Without pods there is nothing to match selectors against; reporting
    // "selects no pods" would be a false positive.
    if snapshot.network_policies.is_empty() || snapshot.is_unknown("pods") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    findings.extend(dns_egress_blocked(snapshot));
    for policy in &snapshot.network_policies {
        findings.extend(check_policy(snapshot, policy));
    }
    findings
}

/// True when the snapshot holds every pod and namespace in the cluster, so
/// "nothing matches" conclusions about cross-namespace selectors are sound.
fn cluster_wide(snapshot: &ClusterSnapshot) -> bool {
    snapshot.namespace.is_none() && !snapshot.is_unknown("namespaces")
}

fn is_active(pod: &Pod) -> bool {
    !matches!(
        pod.status.as_ref().and_then(|s| s.phase.as_deref()),
        Some("Succeeded") | Some("Failed")
    )
}

/// POL-001: pods isolated for egress with no way to reach cluster DNS.
fn dns_egress_blocked(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let dns_pods: Vec<&Pod> = snapshot
        .pods
        .iter()
        .filter(|p| {
            ns_of(p) == DNS_NAMESPACE
                && p.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(DNS_LABEL.0))
                    .map(String::as_str)
                    == Some(DNS_LABEL.1)
        })
        .collect();

    // namespace -> (blocked pod names, isolating policy ids)
    let mut by_ns: BTreeMap<&str, (Vec<&str>, Vec<String>)> = BTreeMap::new();

    for pod in snapshot
        .pods
        .iter()
        .filter(|p| is_active(p) && !is_host_network(p))
    {
        let isolating = egress_policies(snapshot, pod);
        if isolating.is_empty() {
            continue;
        }
        let blocked = if dns_pods.is_empty() {
            // DNS pods are not in the snapshot (namespace-scoped, or a
            // non-standard DNS): fall back to "does any rule open UDP 53".
            !isolating
                .iter()
                .any(|p| opens_port(p, 53, Protocol::Udp, pod))
        } else {
            dns_pods.iter().all(|dns| {
                let v = evaluate(
                    snapshot,
                    &Flow {
                        src: Endpoint::Pod(pod),
                        dst: Endpoint::Pod(dns),
                        port: 53,
                        protocol: Protocol::Udp,
                    },
                );
                v.egress.decision == Decision::Denied
            })
        };
        if blocked {
            let entry = by_ns.entry(ns_of(pod)).or_default();
            entry
                .0
                .push(pod.metadata.name.as_deref().unwrap_or("<unnamed>"));
            for p in isolating {
                let id = policy_id(p);
                if !entry.1.contains(&id) {
                    entry.1.push(id);
                }
            }
        }
    }

    by_ns
        .into_iter()
        .map(|(ns, (pods, policies))| {
            let sample: Vec<&str> = pods.iter().take(5).copied().collect();
            let more = pods.len().saturating_sub(sample.len());
            Finding::new(
                "POL-001",
                Severity::Error,
                "policy",
                "Egress policies block DNS",
                format!(
                    "{} pod(s) in '{}' are egress-isolated by {} and no rule allows UDP 53 to \
                     cluster DNS: {}{}. Name resolution fails for them, which usually shows up \
                     as timeouts to every Service.",
                    pods.len(),
                    ns,
                    policies.join(", "),
                    sample.join(", "),
                    if more > 0 {
                        format!(" (+{more} more)")
                    } else {
                        String::new()
                    }
                ),
            )
            .resource(format!("namespace/{ns}"))
            .remediation(
                "Add an egress rule allowing UDP and TCP 53 to namespaceSelector \
                 {kubernetes.io/metadata.name: kube-system} + podSelector {k8s-app: kube-dns} \
                 (and to the NodeLocal DNSCache address if you run it).",
            )
        })
        .collect()
}

fn egress_policies<'a>(snapshot: &'a ClusterSnapshot, pod: &Pod) -> Vec<&'a NetworkPolicy> {
    selecting(snapshot, pod)
        .into_iter()
        .filter(|p| applies_to(p, Direction::Egress))
        .collect()
}

fn selecting<'a>(snapshot: &'a ClusterSnapshot, pod: &Pod) -> Vec<&'a NetworkPolicy> {
    snapshot
        .network_policies
        .iter()
        .filter(|p| {
            p.metadata.namespace.as_deref().unwrap_or("default") == ns_of(pod)
                && p.spec.as_ref().is_some_and(|s| {
                    selector_matches(&s.pod_selector, pod.metadata.labels.as_ref())
                })
        })
        .collect()
}

/// Does any egress rule of `policy` open `port`/`protocol`, ignoring peers?
fn opens_port(policy: &NetworkPolicy, port: u16, protocol: Protocol, src: &Pod) -> bool {
    let flow = Flow {
        src: Endpoint::Pod(src),
        dst: Endpoint::Pod(src),
        port,
        protocol,
    };
    policy
        .spec
        .iter()
        .flat_map(|s| s.egress.iter().flatten())
        .any(|rule| {
            let ports = rule.ports.as_deref().unwrap_or_default();
            // A named port cannot be resolved without the destination; count
            // it as opening the port rather than raise a false alarm.
            ports
                .iter()
                .any(|p| matches!(p.port, Some(IntOrString::String(_))))
                || ports_match(ports, &flow, None)
        })
}

fn check_policy(snapshot: &ClusterSnapshot, policy: &NetworkPolicy) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(spec) = policy.spec.as_ref() else {
        return findings;
    };
    let id = policy_id(policy);
    let policy_ns = policy.metadata.namespace.as_deref().unwrap_or("default");
    let resource = format!("networkpolicy/{id}");

    // A namespace-scoped snapshot only holds pods of that namespace.
    if snapshot
        .namespace
        .as_deref()
        .is_some_and(|scope| scope != policy_ns)
    {
        return findings;
    }

    let subjects: Vec<&Pod> = snapshot
        .pods
        .iter()
        .filter(|p| {
            ns_of(p) == policy_ns
                && selector_matches(&spec.pod_selector, p.metadata.labels.as_ref())
        })
        .collect();

    // POL-002: the policy selects nothing.
    if subjects.is_empty() {
        findings.push(
            Finding::new(
                "POL-002",
                Severity::Warning,
                "policy",
                "NetworkPolicy selects no pods",
                format!(
                    "podSelector {} matches no pod in namespace '{}', so this policy currently \
                     has no effect. A typo in a label is the usual cause.",
                    describe_selector(&spec.pod_selector),
                    policy_ns
                ),
            )
            .resource(resource.clone())
            .remediation(format!(
                "Compare with: kubectl -n {policy_ns} get pods --show-labels"
            )),
        );
        // Rule checks below need subject pods to resolve named ports against.
        return findings;
    }

    let ingress_rules = spec.ingress.iter().flatten().map(|r| {
        (
            Direction::Ingress,
            r.from.as_deref().unwrap_or_default(),
            r.ports.as_deref().unwrap_or_default(),
        )
    });
    let egress_rules = spec.egress.iter().flatten().map(|r| {
        (
            Direction::Egress,
            r.to.as_deref().unwrap_or_default(),
            r.ports.as_deref().unwrap_or_default(),
        )
    });

    for (index, (direction, peers, ports)) in ingress_rules.chain(egress_rules).enumerate() {
        if !applies_to(policy, direction) {
            continue;
        }
        let dir = match direction {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        };

        // POL-003: a selector peer that matches no pod anywhere.
        for peer in peers {
            if peer.ip_block.is_some() {
                continue;
            }
            // Cross-namespace peers need the whole cluster to judge.
            if peer.namespace_selector.is_some() && !cluster_wide(snapshot) {
                continue;
            }
            if !peer_matches_any(snapshot, peer, policy_ns) {
                findings.push(
                    Finding::new(
                        "POL-003",
                        Severity::Warning,
                        "policy",
                        "NetworkPolicy peer matches no pods",
                        format!(
                            "{dir} rule #{} has a peer ({}) that matches no pod, so it allows \
                             nothing. Remember that a podSelector without a namespaceSelector \
                             only matches pods in '{policy_ns}'.",
                            index + 1,
                            describe_peer(peer),
                        ),
                    )
                    .resource(resource.clone())
                    .remediation(
                        "Check the peer's labels against the intended pods and namespaces; add a \
                         namespaceSelector if the peer lives in another namespace.",
                    ),
                );
            }
        }

        // POL-004: a named port nothing defines.
        for port in ports {
            let Some(IntOrString::String(name)) = &port.port else {
                continue;
            };
            let proto = port.protocol.as_deref().unwrap_or("TCP");
            let defined = match direction {
                // Ingress named ports resolve on the selected pods.
                Direction::Ingress => subjects
                    .iter()
                    .any(|p| named_port(p, name, proto).is_some()),
                // Egress named ports resolve on whatever the destination is.
                Direction::Egress => {
                    !cluster_wide(snapshot)
                        || snapshot
                            .pods
                            .iter()
                            .any(|p| named_port(p, name, proto).is_some())
                }
            };
            if !defined {
                findings.push(
                    Finding::new(
                        "POL-004",
                        Severity::Warning,
                        "policy",
                        "NetworkPolicy references an undefined named port",
                        format!(
                            "{dir} rule #{} allows port '{name}' ({proto}), but no {} declares a \
                             container port with that name and protocol, so the rule matches no \
                             traffic.",
                            index + 1,
                            match direction {
                                Direction::Ingress => "pod selected by this policy",
                                Direction::Egress => "pod in the cluster",
                            }
                        ),
                    )
                    .resource(resource.clone())
                    .remediation(
                        "Name the containerPort in the pod spec, or use the numeric port in the \
                         policy.",
                    ),
                );
            }
        }
    }

    findings
}

fn peer_matches_any(snapshot: &ClusterSnapshot, peer: &NetworkPolicyPeer, policy_ns: &str) -> bool {
    if peer.namespace_selector.is_none() && peer.pod_selector.is_none() {
        return false;
    }
    snapshot.pods.iter().any(|pod| {
        let pod_ns = ns_of(pod);
        let ns_ok = match &peer.namespace_selector {
            Some(sel) => selector_matches(sel, Some(&namespace_labels(snapshot, pod_ns))),
            None => pod_ns == policy_ns,
        };
        ns_ok
            && peer.pod_selector.as_ref().map_or(true, |sel| {
                selector_matches(sel, pod.metadata.labels.as_ref())
            })
    })
}

fn describe_peer(peer: &NetworkPolicyPeer) -> String {
    let mut parts = Vec::new();
    if let Some(sel) = &peer.namespace_selector {
        parts.push(format!("namespaceSelector {}", describe_selector(sel)));
    }
    if let Some(sel) = &peer.pod_selector {
        parts.push(format!("podSelector {}", describe_selector(sel)));
    }
    if parts.is_empty() {
        "empty peer".to_string()
    } else {
        parts.join(" + ")
    }
}

fn describe_selector(
    sel: &k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector,
) -> String {
    let mut parts: Vec<String> = sel
        .match_labels
        .iter()
        .flatten()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    for e in sel.match_expressions.iter().flatten() {
        let values = e.values.as_deref().unwrap_or_default().join(",");
        parts.push(match e.operator.as_str() {
            "Exists" => e.key.clone(),
            "DoesNotExist" => format!("!{}", e.key),
            "In" => format!("{} in ({values})", e.key),
            "NotIn" => format!("{} notin ({values})", e.key),
            other => format!("{} {other} ({values})", e.key),
        });
    }
    if parts.is_empty() {
        "{}".to_string()
    } else {
        format!("{{{}}}", parts.join(", "))
    }
}
