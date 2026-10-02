//! Pod networking and IP address management: pods that never got a network,
//! address collisions, and node pod ranges that overlap or are running out.

use k8s_openapi::api::core::v1::{Node, Pod};
use k8s_openapi::jiff::Timestamp;
use std::collections::BTreeMap;
use std::net::IpAddr;

use super::policy::{cidr_contains, is_host_network, pod_ips};
use crate::model::{CniPlugin, CniRole, Finding, Severity};
use crate::snapshot::ClusterSnapshot;

/// A scheduled pod normally gets its sandbox (and IP) within seconds.
const SANDBOX_GRACE_SECONDS: i64 = 120;
/// Report a node pod range as nearly exhausted at this usage.
const EXHAUSTION_PERCENT: u64 = 90;

/// CNIs whose IPAM hands out pod IPs from each node's `spec.podCIDR`. Others
/// (Calico, Cilium, cloud VPC CNIs) manage their own pools, so the node
/// podCIDR says nothing about where their pod IPs come from.
const NODE_CIDR_IPAM: &[&str] = &["Flannel", "Canal", "kindnet", "kube-router"];

pub fn analyze(snapshot: &ClusterSnapshot, plugins: &[CniPlugin]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(overlapping_node_cidrs(snapshot));
    if snapshot.is_unknown("pods") {
        return findings;
    }
    findings.extend(pods_without_network(snapshot));
    findings.extend(duplicate_pod_ips(snapshot));

    let uses_node_cidr = plugins
        .iter()
        .filter(|p| p.role == CniRole::Primary)
        .any(|p| NODE_CIDR_IPAM.contains(&p.name.as_str()))
        && plugins
            .iter()
            .filter(|p| p.role == CniRole::Primary)
            .count()
            == 1;
    if uses_node_cidr && !snapshot.is_unknown("nodes") {
        findings.extend(node_cidr_checks(snapshot));
    }
    findings
}

fn is_terminal(pod: &Pod) -> bool {
    matches!(
        pod.status.as_ref().and_then(|s| s.phase.as_deref()),
        Some("Succeeded") | Some("Failed")
    )
}

fn pod_ref(pod: &Pod) -> String {
    format!(
        "{}/{}",
        pod.metadata.namespace.as_deref().unwrap_or("default"),
        pod.metadata.name.as_deref().unwrap_or("<unnamed>")
    )
}

/// Pods that own a pod-network address right now.
fn networked_pods(snapshot: &ClusterSnapshot) -> impl Iterator<Item = &Pod> {
    snapshot
        .pods
        .iter()
        .filter(|p| !is_terminal(p) && !is_host_network(p))
}

/// POD-001: scheduled, still ContainerCreating, and no IP after the grace
/// period. The sandbox is created before images are pulled, so a missing IP
/// rules out a slow pull: it is the CNI, or a volume that will not mount.
fn pods_without_network(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let Some(now) = snapshot
        .collected_at
        .as_deref()
        .and_then(|t| t.parse::<Timestamp>().ok())
    else {
        return Vec::new(); // no clock, no way to tell "stuck" from "just created"
    };

    // node -> stuck pods
    let mut by_node: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for pod in networked_pods(snapshot) {
        let (Some(spec), Some(status)) = (pod.spec.as_ref(), pod.status.as_ref()) else {
            continue;
        };
        let Some(node) = spec.node_name.as_deref() else {
            continue; // unscheduled: not a network problem
        };
        if status.phase.as_deref() != Some("Pending") || !pod_ips(pod).is_empty() {
            continue;
        }
        let creating = status.container_statuses.iter().flatten().any(|c| {
            c.state
                .as_ref()
                .and_then(|s| s.waiting.as_ref())
                .and_then(|w| w.reason.as_deref())
                == Some("ContainerCreating")
        });
        let since = status
            .start_time
            .as_ref()
            .or(pod.metadata.creation_timestamp.as_ref());
        let stuck =
            since.is_some_and(|t| (now.as_second() - t.0.as_second()) > SANDBOX_GRACE_SECONDS);
        if creating && stuck {
            by_node.entry(node).or_default().push(pod_ref(pod));
        }
    }

    by_node
        .into_iter()
        .map(|(node, pods)| {
            let sample: Vec<&str> = pods.iter().take(5).map(String::as_str).collect();
            let more = pods.len().saturating_sub(sample.len());
            Finding::new(
                "POD-001",
                Severity::Error,
                "pod",
                "Pods are stuck without a network sandbox",
                format!(
                    "{} pod(s) on node '{}' have been ContainerCreating for over {} minutes \
                     with no IP assigned: {}{}. The sandbox is created before images are \
                     pulled, so this is the CNI failing to set up the pod network, or a volume \
                     that will not mount.",
                    pods.len(),
                    node,
                    SANDBOX_GRACE_SECONDS / 60,
                    sample.join(", "),
                    if more > 0 {
                        format!(" (+{more} more)")
                    } else {
                        String::new()
                    }
                ),
            )
            .resource(format!("node/{node}"))
            .remediation(format!(
                "kubectl describe pod -n {} — FailedCreatePodSandBox points at the CNI (check \
                 its agent on {node}); FailedMount points at storage.",
                sample[0].replacen('/', " ", 1)
            ))
        })
        .collect()
}

/// POD-002: one address claimed by more than one pod.
fn duplicate_pod_ips(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut owners: BTreeMap<IpAddr, Vec<String>> = BTreeMap::new();
    for pod in networked_pods(snapshot) {
        for ip in pod_ips(pod) {
            owners.entry(ip).or_default().push(pod_ref(pod));
        }
    }
    owners
        .into_iter()
        .filter(|(_, pods)| pods.len() > 1)
        .map(|(ip, pods)| {
            Finding::new(
                "POD-002",
                Severity::Error,
                "pod",
                "Pod IP assigned to more than one pod",
                format!(
                    "{ip} is held by {}. Traffic to that address reaches whichever pod the \
                     dataplane last programmed; this is IPAM state corruption (often after a \
                     node reboot or a CNI data directory wipe).",
                    pods.join(", ")
                ),
            )
            .resource(format!("pod/{}", pods[0]))
            .remediation(
                "Delete the affected pods so they are re-allocated, then check the CNI IPAM \
                 store on the node(s) for stale reservations.",
            )
        })
        .collect()
}

fn node_cidrs(node: &Node) -> Vec<&str> {
    let Some(spec) = node.spec.as_ref() else {
        return Vec::new();
    };
    let mut cidrs: Vec<&str> = spec
        .pod_cidrs
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    if let Some(c) = spec.pod_cidr.as_deref() {
        if !cidrs.contains(&c) {
            cidrs.push(c);
        }
    }
    cidrs
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u32)> {
    let (addr, len) = cidr.split_once('/')?;
    let (addr, len) = (addr.parse::<IpAddr>().ok()?, len.parse::<u32>().ok()?);
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((addr, len))
}

/// Two CIDRs of the same family overlap when the shorter prefix contains the
/// other's network address.
pub fn cidrs_overlap(a: &str, b: &str) -> bool {
    let (Some((a_addr, a_len)), Some((b_addr, b_len))) = (parse_cidr(a), parse_cidr(b)) else {
        return false;
    };
    if a_len <= b_len {
        cidr_contains(a, b_addr)
    } else {
        cidr_contains(b, a_addr)
    }
}

/// POD-004: node pod ranges must be disjoint, whatever the CNI.
fn overlapping_node_cidrs(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let ranges: Vec<(&str, &str)> = snapshot
        .nodes
        .iter()
        .flat_map(|n| {
            let name = n.metadata.name.as_deref().unwrap_or("<unnamed>");
            node_cidrs(n).into_iter().map(move |c| (name, c))
        })
        .collect();

    let mut findings = Vec::new();
    for (i, (node_a, cidr_a)) in ranges.iter().enumerate() {
        for (node_b, cidr_b) in &ranges[i + 1..] {
            if node_a != node_b && cidrs_overlap(cidr_a, cidr_b) {
                findings.push(
                    Finding::new(
                        "POD-004",
                        Severity::Error,
                        "pod",
                        "Node pod CIDRs overlap",
                        format!(
                            "Node '{node_a}' has podCIDR {cidr_a} and node '{node_b}' has \
                             {cidr_b}. Both nodes can hand out the same addresses, and routes \
                             for the range point at only one of them."
                        ),
                    )
                    .resource(format!("node/{node_a}"))
                    .remediation(
                        "Node podCIDRs are immutable: drain and delete one of the nodes and let \
                         it re-register to get a fresh range. Check the controller-manager's \
                         --cluster-cidr / --node-cidr-mask-size.",
                    ),
                );
            }
        }
    }
    findings
}

/// POD-003 and POD-005, for CNIs that allocate from the node's podCIDR.
fn node_cidr_checks(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    let nodes: BTreeMap<&str, &Node> = snapshot
        .nodes
        .iter()
        .filter_map(|n| Some((n.metadata.name.as_deref()?, n)))
        .collect();

    // POD-003: pod IP outside its node's range.
    let mut used: BTreeMap<&str, u64> = BTreeMap::new();
    for pod in networked_pods(snapshot) {
        let Some(node_name) = pod.spec.as_ref().and_then(|s| s.node_name.as_deref()) else {
            continue;
        };
        let Some(node) = nodes.get(node_name) else {
            continue;
        };
        let cidrs = node_cidrs(node);
        if cidrs.is_empty() {
            continue;
        }
        for ip in pod_ips(pod) {
            // Only judge families the node has a range for.
            let same_family: Vec<&&str> = cidrs
                .iter()
                .filter(|c| parse_cidr(c).is_some_and(|(a, _)| a.is_ipv4() == ip.is_ipv4()))
                .collect();
            if same_family.is_empty() {
                continue;
            }
            if same_family.iter().any(|c| cidr_contains(c, ip)) {
                if ip.is_ipv4() {
                    *used.entry(node_name).or_default() += 1;
                }
            } else {
                findings.push(
                    Finding::new(
                        "POD-003",
                        Severity::Warning,
                        "pod",
                        "Pod IP is outside its node's pod CIDR",
                        format!(
                            "{ip} is not in the podCIDR of node '{node_name}' ({}). With a CNI \
                             that allocates from the node range, other nodes have no route to \
                             this address.",
                            cidrs.join(", ")
                        ),
                    )
                    .resource(format!("pod/{}", pod_ref(pod)))
                    .remediation(
                        "Usually a stale CNI config or IPAM directory from a previous cluster \
                         or CNI on that node. Clean /etc/cni/net.d and /var/lib/cni on the \
                         node, then recreate the pod.",
                    ),
                );
            }
        }
    }

    // POD-005: IPv4 range nearly full. Needs every pod in the cluster.
    if snapshot.namespace.is_none() {
        for (node_name, node) in &nodes {
            for cidr in node_cidrs(node) {
                let Some((addr, len)) = parse_cidr(cidr) else {
                    continue;
                };
                if !addr.is_ipv4() || len > 30 {
                    continue;
                }
                // Network and broadcast are unusable; the CNI bridge takes one more.
                let capacity = (1u64 << (32 - len)) - 3;
                let in_use = used.get(node_name).copied().unwrap_or(0);
                if in_use * 100 >= capacity * EXHAUSTION_PERCENT {
                    findings.push(
                        Finding::new(
                            "POD-005",
                            Severity::Warning,
                            "pod",
                            "Node pod CIDR is nearly exhausted",
                            format!(
                                "Node '{node_name}' uses {in_use} of about {capacity} pod \
                                 addresses in {cidr}. New pods on it will fail sandbox creation \
                                 once the range is full."
                            ),
                        )
                        .resource(format!("node/{node_name}"))
                        .remediation(
                            "Lower the node's max-pods, add nodes, or rebuild the cluster with \
                             a larger --node-cidr-mask-size. Leaked IPAM reservations in \
                             /var/lib/cni/networks can also fill the range.",
                        ),
                    );
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_detection() {
        assert!(cidrs_overlap("10.244.0.0/24", "10.244.0.0/24"));
        assert!(cidrs_overlap("10.244.0.0/16", "10.244.3.0/24"));
        assert!(cidrs_overlap("10.244.3.0/24", "10.244.0.0/16"));
        assert!(!cidrs_overlap("10.244.0.0/24", "10.244.1.0/24"));
        assert!(cidrs_overlap("fd00:10:244::/56", "fd00:10:244:1::/64"));
        assert!(!cidrs_overlap("fd00:10:244::/64", "fd00:10:244:1::/64"));
        // Different families and garbage never overlap.
        assert!(!cidrs_overlap("10.244.0.0/24", "fd00::/8"));
        assert!(!cidrs_overlap("10.244.0.0/24", "nonsense"));
    }
}
