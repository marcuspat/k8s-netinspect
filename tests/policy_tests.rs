//! NetworkPolicy reachability semantics, one upstream rule per test.

use k8s_netinspect::analysis::policy::{evaluate, Decision, Endpoint, Flow, Protocol, Verdict};
use k8s_netinspect::snapshot::{ClusterSnapshot, CollectionError};
use k8s_openapi::api::core::v1::{Namespace, Pod};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use serde_json::{json, Value};

fn pod(ns: &str, name: &str, ip: &str, labels: Value) -> Pod {
    serde_json::from_value(json!({
        "metadata": {"name": name, "namespace": ns, "labels": labels},
        "spec": {"containers": [{
            "name": "app", "image": "app:1",
            "ports": [
                {"name": "http", "containerPort": 8080},
                {"name": "dns", "containerPort": 53, "protocol": "UDP"}
            ]
        }]},
        "status": {"phase": "Running", "podIP": ip, "podIPs": [{"ip": ip}]}
    }))
    .unwrap()
}

fn namespace(name: &str, labels: Value) -> Namespace {
    serde_json::from_value(json!({"metadata": {"name": name, "labels": labels}})).unwrap()
}

fn policy(ns: &str, name: &str, spec: Value) -> NetworkPolicy {
    serde_json::from_value(json!({"metadata": {"name": name, "namespace": ns}, "spec": spec}))
        .unwrap()
}

/// shop: web (app=web), api (app=api), db (app=db, tier=data)
/// ops (team=platform): prom (app=prometheus)
/// other: stranger (app=web)
fn cluster(policies: Vec<NetworkPolicy>) -> ClusterSnapshot {
    ClusterSnapshot {
        schema_version: 1,
        namespaces: vec![
            namespace(
                "shop",
                json!({"kubernetes.io/metadata.name": "shop", "env": "prod"}),
            ),
            namespace(
                "ops",
                json!({"kubernetes.io/metadata.name": "ops", "team": "platform"}),
            ),
            namespace("other", json!({"kubernetes.io/metadata.name": "other"})),
        ],
        pods: vec![
            pod("shop", "web", "10.0.1.10", json!({"app": "web"})),
            pod("shop", "api", "10.0.1.11", json!({"app": "api"})),
            pod(
                "shop",
                "db",
                "10.0.1.12",
                json!({"app": "db", "tier": "data"}),
            ),
            pod("ops", "prom", "10.0.2.10", json!({"app": "prometheus"})),
            pod("other", "stranger", "10.0.3.10", json!({"app": "web"})),
        ],
        network_policies: policies,
        ..Default::default()
    }
}

fn find<'a>(snap: &'a ClusterSnapshot, ns: &str, name: &str) -> &'a Pod {
    snap.pods
        .iter()
        .find(|p| {
            p.metadata.namespace.as_deref() == Some(ns) && p.metadata.name.as_deref() == Some(name)
        })
        .unwrap()
}

fn check(snap: &ClusterSnapshot, from: (&str, &str), to: (&str, &str), port: u16) -> Verdict {
    check_proto(snap, from, to, port, Protocol::Tcp)
}

fn check_proto(
    snap: &ClusterSnapshot,
    from: (&str, &str),
    to: (&str, &str),
    port: u16,
    protocol: Protocol,
) -> Verdict {
    evaluate(
        snap,
        &Flow {
            src: Endpoint::Pod(find(snap, from.0, from.1)),
            dst: Endpoint::Pod(find(snap, to.0, to.1)),
            port,
            protocol,
        },
    )
}

const WEB: (&str, &str) = ("shop", "web");
const API: (&str, &str) = ("shop", "api");
const DB: (&str, &str) = ("shop", "db");
const PROM: (&str, &str) = ("ops", "prom");
const STRANGER: (&str, &str) = ("other", "stranger");

#[test]
fn no_policies_means_not_isolated_and_allowed() {
    let snap = cluster(vec![]);
    let v = check(&snap, WEB, DB, 5432);
    assert!(v.allowed && v.complete);
    assert_eq!(v.egress.decision, Decision::NotIsolated);
    assert_eq!(v.ingress.decision, Decision::NotIsolated);
    assert!(v.caveats.is_empty());
}

#[test]
fn default_deny_ingress_blocks_and_names_the_policy() {
    let snap = cluster(vec![policy(
        "shop",
        "default-deny",
        json!({"podSelector": {}, "policyTypes": ["Ingress"]}),
    )]);
    let v = check(&snap, WEB, DB, 5432);
    assert!(!v.allowed);
    assert_eq!(
        v.egress.decision,
        Decision::NotIsolated,
        "Ingress-only policy"
    );
    assert_eq!(v.ingress.decision, Decision::Denied);
    assert_eq!(v.ingress.isolating, vec!["shop/default-deny"]);
    assert!(v.ingress.allowing.is_empty());

    // Pods in other namespaces are not selected by it.
    assert!(check(&snap, WEB, PROM, 9090).allowed);
}

#[test]
fn empty_ingress_list_denies_all_but_one_empty_rule_allows_all() {
    let deny = cluster(vec![policy(
        "shop",
        "deny",
        json!({"podSelector": {"matchLabels": {"app": "db"}}, "ingress": []}),
    )]);
    assert!(!check(&deny, WEB, DB, 5432).allowed);
    assert!(check(&deny, WEB, API, 8080).allowed, "api is not selected");

    let allow = cluster(vec![policy(
        "shop",
        "allow-all",
        json!({"podSelector": {"matchLabels": {"app": "db"}}, "ingress": [{}]}),
    )]);
    let v = check(&allow, STRANGER, DB, 1);
    assert!(v.allowed);
    assert_eq!(v.ingress.decision, Decision::Allowed);
    assert_eq!(v.ingress.allowing, vec!["shop/allow-all"]);
}

#[test]
fn policies_are_additive() {
    let snap = cluster(vec![
        policy(
            "shop",
            "default-deny",
            json!({"podSelector": {}, "policyTypes": ["Ingress"]}),
        ),
        policy(
            "shop",
            "api-to-db",
            json!({
                "podSelector": {"matchLabels": {"app": "db"}},
                "ingress": [{
                    "from": [{"podSelector": {"matchLabels": {"app": "api"}}}],
                    "ports": [{"port": 5432}]
                }]
            }),
        ),
    ]);
    let v = check(&snap, API, DB, 5432);
    assert!(v.allowed);
    assert_eq!(
        v.ingress.isolating,
        vec!["shop/default-deny", "shop/api-to-db"]
    );
    assert_eq!(v.ingress.allowing, vec!["shop/api-to-db"]);

    assert!(!check(&snap, WEB, DB, 5432).allowed, "wrong peer");
    assert!(!check(&snap, API, DB, 5433).allowed, "wrong port");
    assert!(
        !check_proto(&snap, API, DB, 5432, Protocol::Udp).allowed,
        "protocol defaults to TCP"
    );
}

#[test]
fn bare_pod_selector_peer_is_limited_to_the_policy_namespace() {
    let snap = cluster(vec![policy(
        "shop",
        "from-web",
        json!({
            "podSelector": {"matchLabels": {"app": "db"}},
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]}]
        }),
    )]);
    assert!(check(&snap, WEB, DB, 5432).allowed);
    // other/stranger also has app=web, but lives in another namespace.
    assert!(!check(&snap, STRANGER, DB, 5432).allowed);
}

#[test]
fn namespace_and_pod_selector_in_one_peer_are_anded_separate_peers_are_ored() {
    let anded = cluster(vec![policy(
        "shop",
        "prom-only",
        json!({
            "podSelector": {},
            "ingress": [{"from": [{
                "namespaceSelector": {"matchLabels": {"team": "platform"}},
                "podSelector": {"matchLabels": {"app": "prometheus"}}
            }]}]
        }),
    )]);
    assert!(check(&anded, PROM, DB, 9187).allowed);
    assert!(
        !check(&anded, API, DB, 9187).allowed,
        "right label set, wrong namespace"
    );

    let ored = cluster(vec![policy(
        "shop",
        "platform-or-api",
        json!({
            "podSelector": {},
            "ingress": [{"from": [
                {"namespaceSelector": {"matchLabels": {"team": "platform"}}},
                {"podSelector": {"matchLabels": {"app": "api"}}}
            ]}]
        }),
    )]);
    assert!(check(&ored, PROM, DB, 1).allowed);
    assert!(check(&ored, API, DB, 1).allowed);
    assert!(!check(&ored, STRANGER, DB, 1).allowed);
}

#[test]
fn empty_namespace_selector_matches_every_namespace() {
    let snap = cluster(vec![policy(
        "shop",
        "from-anywhere-in-cluster",
        json!({"podSelector": {}, "ingress": [{"from": [{"namespaceSelector": {}}]}]}),
    )]);
    assert!(check(&snap, STRANGER, DB, 1).allowed);
    assert!(check(&snap, PROM, DB, 1).allowed);
}

#[test]
fn namespace_name_label_is_synthesized_when_namespaces_are_missing() {
    let mut snap = cluster(vec![policy(
        "shop",
        "from-ops",
        json!({
            "podSelector": {},
            "ingress": [{"from": [{"namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "ops"}
            }}]}]
        }),
    )]);
    snap.namespaces.clear();
    snap.collection_errors.push(CollectionError {
        resource: "namespaces".into(),
        message: "forbidden".into(),
    });
    let v = check(&snap, PROM, DB, 1);
    assert!(v.allowed);
    assert!(v
        .caveats
        .iter()
        .any(|c| c.contains("Namespaces could not be listed")));
    assert!(!check(&snap, STRANGER, DB, 1).allowed);
}

#[test]
fn match_expressions_operators() {
    let with = |expr: Value| {
        cluster(vec![policy(
            "shop",
            "expr",
            json!({
                "podSelector": {"matchLabels": {"app": "db"}},
                "ingress": [{"from": [{"podSelector": {"matchExpressions": [expr]}}]}]
            }),
        )])
    };
    let s = with(json!({"key": "app", "operator": "In", "values": ["api", "worker"]}));
    assert!(check(&s, API, DB, 1).allowed);
    assert!(!check(&s, WEB, DB, 1).allowed);

    let s = with(json!({"key": "app", "operator": "NotIn", "values": ["web"]}));
    assert!(check(&s, API, DB, 1).allowed);
    assert!(!check(&s, WEB, DB, 1).allowed);

    let s = with(json!({"key": "tier", "operator": "DoesNotExist"}));
    assert!(check(&s, API, DB, 1).allowed);

    let s = with(json!({"key": "tier", "operator": "Exists"}));
    assert!(!check(&s, API, DB, 1).allowed);
}

#[test]
fn port_ranges_and_named_ports() {
    let snap = cluster(vec![policy(
        "shop",
        "ports",
        json!({
            "podSelector": {"matchLabels": {"app": "api"}},
            "ingress": [{"ports": [
                {"port": 9000, "endPort": 9010},
                {"port": "http"},
                {"port": "dns", "protocol": "UDP"},
                {"protocol": "SCTP"}
            ]}]
        }),
    )]);
    assert!(check(&snap, WEB, API, 9000).allowed);
    assert!(check(&snap, WEB, API, 9010).allowed);
    assert!(!check(&snap, WEB, API, 9011).allowed);
    assert!(
        check(&snap, WEB, API, 8080).allowed,
        "named port http -> 8080"
    );
    assert!(!check(&snap, WEB, API, 80).allowed);
    assert!(
        check_proto(&snap, WEB, API, 53, Protocol::Udp).allowed,
        "named UDP port"
    );
    assert!(!check(&snap, WEB, API, 53).allowed, "dns is UDP-only");
    assert!(
        check_proto(&snap, WEB, API, 4242, Protocol::Sctp).allowed,
        "protocol with no port = all ports"
    );
}

#[test]
fn egress_named_port_resolves_on_the_destination_pod() {
    let snap = cluster(vec![policy(
        "shop",
        "web-egress",
        json!({
            "podSelector": {"matchLabels": {"app": "web"}},
            "policyTypes": ["Egress"],
            "egress": [{"to": [{"podSelector": {"matchLabels": {"app": "api"}}}], "ports": [{"port": "http"}]}]
        }),
    )]);
    let v = check(&snap, WEB, API, 8080);
    assert!(v.allowed);
    assert_eq!(v.egress.decision, Decision::Allowed);
    assert_eq!(v.ingress.decision, Decision::NotIsolated);
    assert!(
        !check(&snap, WEB, DB, 8080).allowed,
        "db is not an allowed destination"
    );
}

#[test]
fn policy_types_default_to_ingress_plus_egress_only_when_egress_is_present() {
    // Only an egress section, no policyTypes: isolates BOTH directions, and
    // with no ingress rules that means all ingress to the pod is denied.
    let snap = cluster(vec![policy(
        "shop",
        "egress-only-spec",
        json!({"podSelector": {"matchLabels": {"app": "api"}}, "egress": [{}]}),
    )]);
    assert!(
        check(&snap, API, DB, 5432).allowed,
        "egress rule {{}} allows everything out"
    );
    let v = check(&snap, WEB, API, 8080);
    assert!(!v.allowed, "ingress is implicitly isolated");
    assert_eq!(v.ingress.decision, Decision::Denied);

    // No egress section, no policyTypes: egress is untouched.
    let snap = cluster(vec![policy(
        "shop",
        "ingress-only-spec",
        json!({"podSelector": {"matchLabels": {"app": "api"}}, "ingress": []}),
    )]);
    assert_eq!(
        check(&snap, API, DB, 5432).egress.decision,
        Decision::NotIsolated
    );
}

#[test]
fn both_directions_must_allow_and_the_blocking_side_is_identifiable() {
    let snap = cluster(vec![
        policy(
            "shop",
            "web-egress-to-db",
            json!({
                "podSelector": {"matchLabels": {"app": "web"}},
                "policyTypes": ["Egress"],
                "egress": [{"to": [{"podSelector": {"matchLabels": {"app": "db"}}}]}]
            }),
        ),
        policy(
            "shop",
            "db-from-api-only",
            json!({
                "podSelector": {"matchLabels": {"app": "db"}},
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "api"}}}]}]
            }),
        ),
    ]);
    let v = check(&snap, WEB, DB, 5432);
    assert!(!v.allowed);
    assert_eq!(v.egress.decision, Decision::Allowed);
    assert_eq!(v.ingress.decision, Decision::Denied);
    assert_eq!(v.ingress.isolating, vec!["shop/db-from-api-only"]);
}

#[test]
fn ip_block_with_except_for_external_destinations() {
    let snap = cluster(vec![policy(
        "shop",
        "web-egress-internet",
        json!({
            "podSelector": {"matchLabels": {"app": "web"}},
            "policyTypes": ["Egress"],
            "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["169.254.0.0/16", "10.0.0.0/8"]}}],
                        "ports": [{"port": 443}]}]
        }),
    )]);
    let to_ip = |ip: &str, port: u16| {
        evaluate(
            &snap,
            &Flow {
                src: Endpoint::Pod(find(&snap, "shop", "web")),
                dst: Endpoint::Ip(ip.parse().unwrap()),
                port,
                protocol: Protocol::Tcp,
            },
        )
    };
    let v = to_ip("93.184.216.34", 443);
    assert!(v.allowed);
    assert_eq!(v.ingress.decision, Decision::NotApplicable);
    assert!(v.caveats.is_empty());
    assert!(
        !to_ip("169.254.169.254", 443).allowed,
        "metadata endpoint excluded"
    );
    assert!(!to_ip("93.184.216.34", 80).allowed);
    // Pod IPs are in the excepted 10/8, and selectors never match a bare IP.
    assert!(!check(&snap, WEB, API, 443).allowed);
}

#[test]
fn ip_block_matching_a_pod_ip_is_allowed_with_a_cni_caveat() {
    let snap = cluster(vec![policy(
        "shop",
        "db-from-cidr",
        json!({
            "podSelector": {"matchLabels": {"app": "db"}},
            "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.1.0/24"}}]}]
        }),
    )]);
    let v = check(&snap, WEB, DB, 5432);
    assert!(v.allowed);
    assert!(
        v.caveats.iter().any(|c| c.contains("CNI-dependent")),
        "{:?}",
        v.caveats
    );
    assert!(
        !check(&snap, PROM, DB, 5432).allowed,
        "10.0.2.10 is outside the block"
    );
}

#[test]
fn external_source_into_isolated_pod_needs_an_ip_block() {
    let snap = cluster(vec![policy(
        "shop",
        "web-from-lb",
        json!({
            "podSelector": {"matchLabels": {"app": "web"}},
            "ingress": [
                {"from": [{"ipBlock": {"cidr": "203.0.113.0/24"}}]},
                {"from": [{"namespaceSelector": {}}]}
            ]
        }),
    )]);
    let from_ip = |ip: &str| {
        evaluate(
            &snap,
            &Flow {
                src: Endpoint::Ip(ip.parse().unwrap()),
                dst: Endpoint::Pod(find(&snap, "shop", "web")),
                port: 8080,
                protocol: Protocol::Tcp,
            },
        )
    };
    assert!(from_ip("203.0.113.9").allowed);
    let v = from_ip("198.51.100.1");
    assert!(
        !v.allowed,
        "namespaceSelector {{}} does not cover non-pod sources"
    );
    assert_eq!(v.egress.decision, Decision::NotApplicable);
}

#[test]
fn same_pod_and_host_network_are_called_out() {
    let mut snap = cluster(vec![policy(
        "shop",
        "default-deny",
        json!({"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}),
    )]);
    let v = check(&snap, WEB, WEB, 8080);
    assert!(v.allowed);
    assert!(v.caveats.iter().any(|c| c.contains("same pod")));

    snap.pods[0].spec.as_mut().unwrap().host_network = Some(true);
    let v = check(&snap, WEB, API, 8080);
    assert!(v.caveats.iter().any(|c| c.contains("hostNetwork")));
}

#[test]
fn missing_policy_data_makes_the_verdict_incomplete() {
    let mut snap = cluster(vec![]);
    snap.collection_errors.push(CollectionError {
        resource: "networkpolicies".into(),
        message: "forbidden".into(),
    });
    let v = check(&snap, WEB, DB, 5432);
    assert!(v.allowed);
    assert!(!v.complete);
    assert!(v.caveats[0].contains("could not be listed"));

    // Namespace-scoped snapshot cannot see policies of a pod elsewhere.
    let mut snap = cluster(vec![]);
    snap.namespace = Some("shop".into());
    assert!(check(&snap, WEB, DB, 1).complete);
    assert!(!check(&snap, WEB, PROM, 1).complete);
}

#[test]
fn verdict_serializes_with_stable_field_names() {
    let snap = cluster(vec![policy(
        "shop",
        "default-deny",
        json!({"podSelector": {}, "policyTypes": ["Ingress"]}),
    )]);
    let v = serde_json::to_value(check(&snap, WEB, DB, 5432)).unwrap();
    assert_eq!(v["allowed"], false);
    assert_eq!(v["egress"]["decision"], "not_isolated");
    assert_eq!(v["ingress"]["decision"], "denied");
    assert_eq!(v["ingress"]["isolating"][0], "shop/default-deny");
}
