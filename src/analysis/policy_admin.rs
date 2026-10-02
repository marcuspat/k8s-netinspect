//! Policy tiers around NetworkPolicy.
//!
//! - **AdminNetworkPolicy** (`policy.networking.k8s.io/v1alpha1`) is
//!   evaluated before NetworkPolicy. ANPs are ordered by `priority` (lower
//!   first); within one, rules are ordered. The first rule matching the flow
//!   decides: `Allow`, `Deny`, or `Pass` (skip the remaining ANPs and fall
//!   through to NetworkPolicy).
//! - **BaselineAdminNetworkPolicy** applies only when no NetworkPolicy
//!   isolates the pod for that direction.
//! - **CNI-native policies** (Cilium, Calico) are detected, not evaluated.
//!
//! The CRDs are read untyped, so field access is defensive: anything that
//! does not parse matches nothing.

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::core::DynamicObject;
use serde_json::Value;

use super::policy::{
    cidr_contains, named_port, namespace_labels, ns_of, selector_matches, Direction, Endpoint, Flow,
};
use crate::snapshot::ClusterSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Pass,
}

fn name_of(obj: &DynamicObject) -> &str {
    obj.metadata.name.as_deref().unwrap_or("<unnamed>")
}

fn selector(value: &Value) -> Option<LabelSelector> {
    serde_json::from_value(value.clone()).ok()
}

/// `{namespaces: <selector>}` or `{pods: {namespaceSelector, podSelector}}`.
fn selects_pod(snapshot: &ClusterSnapshot, spec: &Value, pod: &Pod) -> bool {
    let ns_labels = namespace_labels(snapshot, ns_of(pod));
    if let Some(sel) = spec.get("namespaces").and_then(selector) {
        return selector_matches(&sel, Some(&ns_labels));
    }
    if let Some(pods) = spec.get("pods") {
        let ns_ok = pods
            .get("namespaceSelector")
            .and_then(selector)
            .is_some_and(|s| selector_matches(&s, Some(&ns_labels)));
        let pod_ok = pods
            .get("podSelector")
            .and_then(selector)
            .is_some_and(|s| selector_matches(&s, pod.metadata.labels.as_ref()));
        return ns_ok && pod_ok;
    }
    false
}

fn peer_matches(snapshot: &ClusterSnapshot, peers: &Value, actual: Endpoint<'_>) -> bool {
    peers
        .as_array()
        .into_iter()
        .flatten()
        .any(|peer| match actual {
            Endpoint::Pod(pod) => selects_pod(snapshot, peer, pod),
            // Only egress `networks` peers can match a non-pod address.
            Endpoint::Ip(ip) => peer
                .get("networks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|cidr| cidr_contains(cidr, ip)),
        })
}

fn ports_match(ports: &Value, flow: &Flow<'_>) -> bool {
    let Some(ports) = ports.as_array() else {
        return true; // no ports listed: every port
    };
    let proto_ok = |p: &Value| {
        p.get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("TCP")
            .eq_ignore_ascii_case(&format!("{:?}", flow.protocol))
    };
    let port = i64::from(flow.port);
    ports.iter().any(|p| {
        if let Some(n) = p.get("portNumber") {
            return proto_ok(n) && n.get("port").and_then(Value::as_i64) == Some(port);
        }
        if let Some(r) = p.get("portRange") {
            let (start, end) = (
                r.get("start").and_then(Value::as_i64),
                r.get("end").and_then(Value::as_i64),
            );
            return proto_ok(r)
                && matches!((start, end), (Some(s), Some(e)) if (s..=e).contains(&port));
        }
        if let (Some(name), Endpoint::Pod(dst)) =
            (p.get("namedPort").and_then(Value::as_str), flow.dst)
        {
            let proto = format!("{:?}", flow.protocol).to_uppercase();
            return named_port(dst, name, &proto) == Some(i32::from(flow.port));
        }
        false
    })
}

/// First matching rule of one (Baseline)AdminNetworkPolicy, if any.
fn first_match(
    snapshot: &ClusterSnapshot,
    policy: &DynamicObject,
    subject: &Pod,
    peer: Endpoint<'_>,
    flow: &Flow<'_>,
    direction: Direction,
) -> Option<(Action, usize)> {
    let spec = &policy.data["spec"];
    if !selects_pod(snapshot, &spec["subject"], subject) {
        return None;
    }
    let (rules, peer_key) = match direction {
        Direction::Ingress => (&spec["ingress"], "from"),
        Direction::Egress => (&spec["egress"], "to"),
    };
    rules
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .find_map(|(i, rule)| {
            let action = match rule.get("action").and_then(Value::as_str)? {
                "Allow" => Action::Allow,
                "Deny" => Action::Deny,
                "Pass" => Action::Pass,
                _ => return None,
            };
            (peer_matches(snapshot, &rule[peer_key], peer) && ports_match(&rule["ports"], flow))
                .then_some((action, i + 1))
        })
}

fn describe(kind: &str, policy: &DynamicObject, direction: Direction, rule: usize) -> String {
    let dir = match direction {
        Direction::Ingress => "ingress",
        Direction::Egress => "egress",
    };
    format!("{kind} '{}' {dir} rule #{rule}", name_of(policy))
}

/// The AdminNetworkPolicy verdict for one direction, with what decided it.
pub(crate) fn admin_tier(
    snapshot: &ClusterSnapshot,
    subject: &Pod,
    peer: Endpoint<'_>,
    flow: &Flow<'_>,
    direction: Direction,
) -> Option<(Action, String)> {
    let mut policies: Vec<&DynamicObject> = snapshot.admin_network_policies.iter().collect();
    // Lower priority value wins; equal priorities are undefined upstream, so
    // order by name to stay deterministic.
    policies.sort_by_key(|p| {
        (
            p.data["spec"]["priority"].as_i64().unwrap_or(i64::MAX),
            name_of(p).to_string(),
        )
    });
    policies.into_iter().find_map(|p| {
        first_match(snapshot, p, subject, peer, flow, direction)
            .map(|(action, rule)| (action, describe("AdminNetworkPolicy", p, direction, rule)))
    })
}

/// The BaselineAdminNetworkPolicy verdict for one direction.
pub(crate) fn baseline_tier(
    snapshot: &ClusterSnapshot,
    subject: &Pod,
    peer: Endpoint<'_>,
    flow: &Flow<'_>,
    direction: Direction,
) -> Option<(Action, String)> {
    snapshot
        .baseline_admin_network_policies
        .iter()
        .find_map(|p| {
            first_match(snapshot, p, subject, peer, flow, direction).map(|(action, rule)| {
                (
                    action,
                    describe("BaselineAdminNetworkPolicy", p, direction, rule),
                )
            })
        })
}

/// CNI-native policies that could apply to any of the endpoints: namespaced
/// ones in an endpoint's namespace, and every cluster-wide one. Deliberately
/// conservative — their selectors are not interpreted.
pub fn cni_policies_in_play(snapshot: &ClusterSnapshot, endpoints: &[Endpoint<'_>]) -> Vec<String> {
    let namespaces: Vec<&str> = endpoints
        .iter()
        .filter_map(|e| match e {
            Endpoint::Pod(p) => Some(ns_of(p)),
            Endpoint::Ip(_) => None,
        })
        .collect();
    let mut hits: Vec<String> = snapshot
        .cni_policies
        .iter()
        .filter(|p| match p.metadata.namespace.as_deref() {
            Some(ns) => namespaces.contains(&ns),
            None => true,
        })
        .map(|p| {
            let kind = p.types.as_ref().map_or("Policy", |t| t.kind.as_str());
            match p.metadata.namespace.as_deref() {
                Some(ns) => format!("{kind} {ns}/{}", name_of(p)),
                None => format!("{kind} {}", name_of(p)),
            }
        })
        .collect();
    hits.sort();
    hits.dedup();
    hits
}
