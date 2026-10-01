//! NetworkPolicy reachability: would `networking.k8s.io/v1` policies let a
//! given flow through?
//!
//! Semantics follow the upstream API contract:
//!
//! - A pod is *isolated* for a direction only if at least one policy in its
//!   namespace selects it and applies to that direction. Non-isolated pods
//!   accept everything.
//! - For an isolated pod the flow is allowed if *any* selecting policy has a
//!   rule matching both the peer and the port (policies are additive; there
//!   is no deny rule).
//! - A flow between two pods must pass the source's egress check **and** the
//!   destination's ingress check.
//! - `policyTypes` defaults to `Ingress`, plus `Egress` when the policy has
//!   an `egress` section.
//!
//! This module is pure: it only reads a [`ClusterSnapshot`].

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::snapshot::ClusterSnapshot;

/// Label every namespace carries since Kubernetes 1.22; synthesized when the
/// Namespace object itself is not in the snapshot.
const NS_NAME_LABEL: &str = "kubernetes.io/metadata.name";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
    Sctp,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Sctp => "SCTP",
        }
    }
}

/// One side of a flow.
#[derive(Debug, Clone, Copy)]
pub enum Endpoint<'a> {
    Pod(&'a Pod),
    /// An address that is not a pod in the snapshot (external, node, ...).
    Ip(IpAddr),
}

#[derive(Debug, Clone, Copy)]
pub struct Flow<'a> {
    pub src: Endpoint<'a>,
    pub dst: Endpoint<'a>,
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// No policy selects the pod for this direction: everything is allowed.
    NotIsolated,
    /// Isolated, and at least one policy rule matches the flow.
    Allowed,
    /// Isolated, and no rule of any selecting policy matches the flow.
    Denied,
    /// This side is not a pod, so no NetworkPolicy applies to it.
    NotApplicable,
}

impl Decision {
    pub fn permits(self) -> bool {
        !matches!(self, Decision::Denied)
    }
}

/// Outcome for one direction (source egress or destination ingress).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectionVerdict {
    pub decision: Decision,
    /// `namespace/name` of the policies that isolate the pod in this direction.
    pub isolating: Vec<String>,
    /// Subset of `isolating` whose rules allow the flow.
    pub allowing: Vec<String>,
}

impl DirectionVerdict {
    fn not_applicable() -> Self {
        Self {
            decision: Decision::NotApplicable,
            isolating: Vec::new(),
            allowing: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub allowed: bool,
    /// Source pod's egress policies.
    pub egress: DirectionVerdict,
    /// Destination pod's ingress policies.
    pub ingress: DirectionVerdict,
    /// False when the verdict rests on missing data (see `caveats`).
    pub complete: bool,
    /// Things this evaluation cannot see or that are CNI-dependent.
    pub caveats: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Ingress,
    Egress,
}

/// Evaluate a flow against the NetworkPolicies in the snapshot.
pub fn evaluate(snapshot: &ClusterSnapshot, flow: &Flow<'_>) -> Verdict {
    let mut caveats = Vec::new();
    let mut complete = true;

    if snapshot.is_unknown("networkpolicies") {
        complete = false;
        caveats.push(
            "NetworkPolicies could not be listed; the verdict assumes none exist.".to_string(),
        );
    }
    if snapshot.is_unknown("namespaces") {
        caveats.push(
            "Namespaces could not be listed; namespaceSelector rules were matched on the \
             kubernetes.io/metadata.name label only."
                .to_string(),
        );
    }
    if let Some(scope) = &snapshot.namespace {
        let outside = [flow.src, flow.dst]
            .iter()
            .any(|e| matches!(e, Endpoint::Pod(p) if ns_of(p) != scope));
        if outside {
            complete = false;
            caveats.push(format!(
                "Snapshot is scoped to namespace '{scope}'; policies in other namespaces were \
                 not collected."
            ));
        }
    }

    // A pod talking to itself is never subject to policy.
    if let (Endpoint::Pod(a), Endpoint::Pod(b)) = (flow.src, flow.dst) {
        if same_pod(a, b) {
            caveats.push("Source and destination are the same pod.".to_string());
            return Verdict {
                allowed: true,
                egress: DirectionVerdict::not_applicable(),
                ingress: DirectionVerdict::not_applicable(),
                complete,
                caveats,
            };
        }
    }

    for (role, endpoint) in [("Source", flow.src), ("Destination", flow.dst)] {
        if let Endpoint::Pod(p) = endpoint {
            if is_host_network(p) {
                caveats.push(format!(
                    "{role} pod uses hostNetwork; most CNIs do not apply NetworkPolicy to it \
                     and see its traffic as coming from the node IP."
                ));
            }
        }
    }

    let mut used_ip_block_for_pod = false;
    let egress = match flow.src {
        Endpoint::Pod(pod) => evaluate_direction(
            snapshot,
            pod,
            flow.dst,
            flow,
            Direction::Egress,
            &mut used_ip_block_for_pod,
        ),
        Endpoint::Ip(_) => DirectionVerdict::not_applicable(),
    };
    let ingress = match flow.dst {
        Endpoint::Pod(pod) => evaluate_direction(
            snapshot,
            pod,
            flow.src,
            flow,
            Direction::Ingress,
            &mut used_ip_block_for_pod,
        ),
        Endpoint::Ip(_) => DirectionVerdict::not_applicable(),
    };

    if used_ip_block_for_pod {
        caveats.push(
            "Allowed only by an ipBlock that covers a pod IP; whether ipBlock applies to \
             in-cluster pod traffic is CNI-dependent (Cilium, for one, does not match it)."
                .to_string(),
        );
    }

    Verdict {
        allowed: egress.decision.permits() && ingress.decision.permits(),
        egress,
        ingress,
        complete,
        caveats,
    }
}

fn evaluate_direction(
    snapshot: &ClusterSnapshot,
    subject: &Pod,
    peer: Endpoint<'_>,
    flow: &Flow<'_>,
    direction: Direction,
    used_ip_block_for_pod: &mut bool,
) -> DirectionVerdict {
    let subject_ns = ns_of(subject);
    let subject_labels = subject.metadata.labels.as_ref();
    // Named ports always resolve against the pod receiving the traffic.
    let dst_pod = match flow.dst {
        Endpoint::Pod(p) => Some(p),
        Endpoint::Ip(_) => None,
    };

    let mut isolating = Vec::new();
    let mut allowing = Vec::new();
    // Tracks whether the *only* way in was an ipBlock matching a pod IP.
    let mut allowed_by_selector = false;
    let mut allowed_by_ip_block = false;

    for policy in &snapshot.network_policies {
        if policy.metadata.namespace.as_deref().unwrap_or("default") != subject_ns {
            continue;
        }
        let Some(spec) = policy.spec.as_ref() else {
            continue;
        };
        if !selector_matches(&spec.pod_selector, subject_labels) {
            continue;
        }
        if !applies_to(policy, direction) {
            continue;
        }
        let id = policy_id(policy);
        isolating.push(id.clone());

        // (peers, ports) per rule, normalized across the two rule types.
        let rules: Vec<(&[NetworkPolicyPeer], &[NetworkPolicyPort])> = match direction {
            Direction::Ingress => spec
                .ingress
                .iter()
                .flatten()
                .map(|r| {
                    (
                        r.from.as_deref().unwrap_or_default(),
                        r.ports.as_deref().unwrap_or_default(),
                    )
                })
                .collect(),
            Direction::Egress => spec
                .egress
                .iter()
                .flatten()
                .map(|r| {
                    (
                        r.to.as_deref().unwrap_or_default(),
                        r.ports.as_deref().unwrap_or_default(),
                    )
                })
                .collect(),
        };

        let mut policy_allows = false;
        for (peers, ports) in rules {
            if !ports_match(ports, flow, dst_pod) {
                continue;
            }
            // No peers listed means "any peer".
            if peers.is_empty() {
                policy_allows = true;
                allowed_by_selector = true;
                continue;
            }
            for p in peers {
                match peer_match(snapshot, p, peer, subject_ns) {
                    PeerMatch::Selector => {
                        policy_allows = true;
                        allowed_by_selector = true;
                    }
                    PeerMatch::IpBlockOnPod => {
                        policy_allows = true;
                        allowed_by_ip_block = true;
                    }
                    PeerMatch::IpBlock => {
                        policy_allows = true;
                        allowed_by_selector = true;
                    }
                    PeerMatch::No => {}
                }
            }
        }
        if policy_allows {
            allowing.push(id);
        }
    }

    if allowed_by_ip_block && !allowed_by_selector {
        *used_ip_block_for_pod = true;
    }

    let decision = if isolating.is_empty() {
        Decision::NotIsolated
    } else if allowing.is_empty() {
        Decision::Denied
    } else {
        Decision::Allowed
    };
    DirectionVerdict {
        decision,
        isolating,
        allowing,
    }
}

/// `policyTypes` with upstream defaulting.
pub(crate) fn applies_to(policy: &NetworkPolicy, direction: Direction) -> bool {
    let Some(spec) = policy.spec.as_ref() else {
        return false;
    };
    match spec.policy_types.as_deref() {
        Some(types) if !types.is_empty() => {
            let want = match direction {
                Direction::Ingress => "Ingress",
                Direction::Egress => "Egress",
            };
            types.iter().any(|t| t == want)
        }
        _ => match direction {
            Direction::Ingress => true,
            Direction::Egress => spec.egress.is_some(),
        },
    }
}

enum PeerMatch {
    No,
    Selector,
    /// ipBlock matched an address that is not a pod.
    IpBlock,
    /// ipBlock matched a pod's IP — CNI-dependent.
    IpBlockOnPod,
}

fn peer_match(
    snapshot: &ClusterSnapshot,
    rule_peer: &NetworkPolicyPeer,
    actual: Endpoint<'_>,
    policy_ns: &str,
) -> PeerMatch {
    if let Some(block) = &rule_peer.ip_block {
        // ipBlock is mutually exclusive with the selectors.
        let ips: Vec<IpAddr> = match actual {
            Endpoint::Ip(ip) => vec![ip],
            Endpoint::Pod(p) => pod_ips(p),
        };
        let hit = ips.iter().any(|ip| {
            cidr_contains(&block.cidr, *ip)
                && !block
                    .except
                    .iter()
                    .flatten()
                    .any(|ex| cidr_contains(ex, *ip))
        });
        return match (hit, actual) {
            (false, _) => PeerMatch::No,
            (true, Endpoint::Ip(_)) => PeerMatch::IpBlock,
            (true, Endpoint::Pod(_)) => PeerMatch::IpBlockOnPod,
        };
    }

    // Selectors only ever match pods.
    let Endpoint::Pod(pod) = actual else {
        return PeerMatch::No;
    };
    let pod_ns = ns_of(pod);

    let ns_ok = match &rule_peer.namespace_selector {
        Some(sel) => selector_matches(sel, Some(&namespace_labels(snapshot, pod_ns))),
        // Without a namespaceSelector the peer is limited to the policy's namespace.
        None => pod_ns == policy_ns,
    };
    if !ns_ok {
        return PeerMatch::No;
    }
    let pod_ok = match &rule_peer.pod_selector {
        Some(sel) => selector_matches(sel, pod.metadata.labels.as_ref()),
        None => true,
    };
    // A peer with no fields at all selects nothing.
    if rule_peer.namespace_selector.is_none() && rule_peer.pod_selector.is_none() {
        return PeerMatch::No;
    }
    if pod_ok {
        PeerMatch::Selector
    } else {
        PeerMatch::No
    }
}

pub(crate) fn ports_match(
    ports: &[NetworkPolicyPort],
    flow: &Flow<'_>,
    dst_pod: Option<&Pod>,
) -> bool {
    // No ports listed means "all ports, all protocols".
    if ports.is_empty() {
        return true;
    }
    ports.iter().any(|p| {
        let proto = p.protocol.as_deref().unwrap_or("TCP");
        if !proto.eq_ignore_ascii_case(flow.protocol.as_str()) {
            return false;
        }
        match &p.port {
            None => true,
            Some(IntOrString::Int(start)) => {
                let end = p.end_port.unwrap_or(*start);
                (*start..=end).contains(&i32::from(flow.port))
            }
            Some(IntOrString::String(name)) => dst_pod
                .is_some_and(|pod| named_port(pod, name, proto) == Some(i32::from(flow.port))),
        }
    })
}

/// Resolve a named container port on a pod.
pub(crate) fn named_port(pod: &Pod, name: &str, protocol: &str) -> Option<i32> {
    pod.spec
        .as_ref()?
        .containers
        .iter()
        .flat_map(|c| c.ports.iter().flatten())
        .find(|p| {
            p.name.as_deref() == Some(name)
                && p.protocol
                    .as_deref()
                    .unwrap_or("TCP")
                    .eq_ignore_ascii_case(protocol)
        })
        .map(|p| p.container_port)
}

/// Kubernetes label selector semantics. An empty selector matches everything.
pub fn selector_matches(
    selector: &LabelSelector,
    labels: Option<&BTreeMap<String, String>>,
) -> bool {
    let get = |k: &str| labels.and_then(|l| l.get(k));

    let labels_ok = selector
        .match_labels
        .iter()
        .flatten()
        .all(|(k, v)| get(k) == Some(v));
    if !labels_ok {
        return false;
    }
    selector.match_expressions.iter().flatten().all(|req| {
        let value = get(&req.key);
        let values = req.values.as_deref().unwrap_or_default();
        match req.operator.as_str() {
            "In" => value.is_some_and(|v| values.contains(v)),
            "NotIn" => !value.is_some_and(|v| values.contains(v)),
            "Exists" => value.is_some(),
            "DoesNotExist" => value.is_none(),
            // Unknown operator: the API server would have rejected it.
            _ => false,
        }
    })
}

pub(crate) fn namespace_labels(snapshot: &ClusterSnapshot, name: &str) -> BTreeMap<String, String> {
    let mut labels = snapshot
        .namespaces
        .iter()
        .find(|n| n.metadata.name.as_deref() == Some(name))
        .and_then(|n| n.metadata.labels.clone())
        .unwrap_or_default();
    labels
        .entry(NS_NAME_LABEL.to_string())
        .or_insert_with(|| name.to_string());
    labels
}

pub(crate) fn ns_of(pod: &Pod) -> &str {
    pod.metadata.namespace.as_deref().unwrap_or("default")
}

fn same_pod(a: &Pod, b: &Pod) -> bool {
    ns_of(a) == ns_of(b) && a.metadata.name.is_some() && a.metadata.name == b.metadata.name
}

pub(crate) fn is_host_network(pod: &Pod) -> bool {
    pod.spec
        .as_ref()
        .and_then(|s| s.host_network)
        .unwrap_or(false)
}

pub(crate) fn policy_id(policy: &NetworkPolicy) -> String {
    format!(
        "{}/{}",
        policy.metadata.namespace.as_deref().unwrap_or("default"),
        policy.metadata.name.as_deref().unwrap_or("<unnamed>")
    )
}

/// All IPs of a pod (dual-stack aware).
pub fn pod_ips(pod: &Pod) -> Vec<IpAddr> {
    let Some(status) = pod.status.as_ref() else {
        return Vec::new();
    };
    let mut ips: Vec<IpAddr> = status
        .pod_ips
        .iter()
        .flatten()
        .filter_map(|p| p.ip.as_deref())
        .filter_map(|s| s.parse().ok())
        .collect();
    if let Some(ip) = status.pod_ip.as_deref().and_then(|s| s.parse().ok()) {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}

/// Does `cidr` (e.g. `10.0.0.0/8`, `fd00::/8`) contain `ip`? Malformed CIDRs
/// and address-family mismatches contain nothing.
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((addr, len)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) if len <= 32 => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) if len <= 128 => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_containment() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(cidr_contains("10.0.0.0/8", ip("10.255.1.2")));
        assert!(!cidr_contains("10.0.0.0/8", ip("11.0.0.1")));
        assert!(cidr_contains("0.0.0.0/0", ip("8.8.8.8")));
        assert!(cidr_contains("192.168.1.7/32", ip("192.168.1.7")));
        assert!(!cidr_contains("192.168.1.7/32", ip("192.168.1.8")));
        assert!(cidr_contains("fd00::/8", ip("fd12:3456::1")));
        assert!(cidr_contains("::/0", ip("2001:db8::1")));
        // Family mismatch and garbage never match.
        assert!(!cidr_contains("0.0.0.0/0", ip("2001:db8::1")));
        assert!(!cidr_contains("::/0", ip("10.0.0.1")));
        assert!(!cidr_contains("10.0.0.0", ip("10.0.0.1")));
        assert!(!cidr_contains("10.0.0.0/33", ip("10.0.0.1")));
        assert!(!cidr_contains("nonsense/8", ip("10.0.0.1")));
    }
}
