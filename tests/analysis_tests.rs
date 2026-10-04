//! Fixture-driven tests: every analyzer runs offline against recorded
//! snapshots in `tests/fixtures/`, so no cluster is needed.

use k8s_netinspect::analysis;
use k8s_netinspect::model::{CniRole, Report, Severity};
use k8s_netinspect::snapshot::{ClusterSnapshot, SCHEMA_VERSION};
use std::path::PathBuf;
use std::process::Command;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.json"))
}

fn report(name: &str) -> Report {
    analysis::analyze(&ClusterSnapshot::load(&fixture_path(name)).unwrap())
}

fn ids(report: &Report) -> Vec<&str> {
    report.findings.iter().map(|f| f.id.as_str()).collect()
}

#[test]
fn healthy_cilium_is_clean() {
    let r = report("healthy-cilium");
    assert_eq!(
        r.cni.len(),
        1,
        "cilium-envoy and node-exporter must not match"
    );
    assert_eq!(r.cni[0].name, "Cilium");
    assert_eq!(r.cni[0].version.as_deref(), Some("v1.16.1"));
    assert_eq!(r.cni[0].source, "daemonset/kube-system/cilium");
    assert_eq!((r.cni[0].ready, r.cni[0].desired), (Some(3), Some(3)));
    assert_eq!(r.cni_label(), "Cilium v1.16.1");
    assert_eq!(r.summary.nodes, 3);
    assert_eq!(r.summary.pods, 3);
    assert!(r.findings.is_empty(), "unexpected: {:?}", r.findings);
    assert_eq!(r.max_severity(), None);
}

#[test]
fn calico_degraded_reports_agent_and_node_faults() {
    let r = report("calico-degraded");
    // Detected in a non-kube-system namespace, from a registry with a port.
    assert_eq!(r.cni_label(), "Calico v3.28.0");
    assert_eq!(r.cni[0].source, "daemonset/calico-system/calico-node");

    assert_eq!(
        ids(&r),
        vec!["CNI-002", "NODE-002", "NODE-003", "COLLECT-001"],
        "sorted most severe first, then by id"
    );
    let cni = &r.findings[0];
    assert_eq!(
        cni.severity,
        Severity::Error,
        "partial outage is Error, not Critical"
    );
    assert!(cni.detail.contains("2 of 3"));
    assert!(cni
        .remediation
        .as_deref()
        .unwrap()
        .contains("-n calico-system"));
    assert_eq!(r.findings[1].resource.as_deref(), Some("node/node-c"));
    assert_eq!(r.findings[3].severity, Severity::Info);
    assert_eq!(r.max_severity(), Some(Severity::Error));
}

#[test]
fn k3s_embedded_flannel_falls_back_to_node_annotations() {
    let r = report("k3s-flannel");
    assert_eq!(r.cni.len(), 1);
    assert_eq!(r.cni[0].name, "Flannel");
    assert_eq!(r.cni[0].source, "node-annotation");
    assert_eq!(r.cni[0].desired, None);
    assert!(r.findings.is_empty(), "unexpected: {:?}", r.findings);
}

#[test]
fn half_finished_migration_flags_both_cnis() {
    let r = report("migration-two-cnis");
    let primaries: Vec<&str> = r
        .cni
        .iter()
        .filter(|p| p.role == CniRole::Primary)
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(primaries, vec!["Flannel", "Cilium"]);
    assert!(r
        .cni
        .iter()
        .any(|p| p.name == "Istio CNI" && p.role == CniRole::Chained));

    assert_eq!(ids(&r), vec!["CNI-002", "CNI-003"]);
    assert_eq!(r.findings[0].severity, Severity::Critical, "0 ready agents");
    assert!(r.findings[1].detail.contains("Flannel, Cilium"));
}

#[test]
fn no_cni_is_a_warning_but_unknown_daemonsets_is_only_info() {
    let mut snap = ClusterSnapshot::load(&fixture_path("k3s-flannel")).unwrap();
    for n in &mut snap.nodes {
        n.metadata.annotations = None;
    }
    let r = analysis::analyze(&snap);
    assert_eq!(r.cni_label(), "Unknown CNI");
    assert_eq!(ids(&r), vec!["CNI-001"]);
    assert_eq!(r.findings[0].severity, Severity::Warning);

    snap.daemon_sets.clear();
    snap.collection_errors
        .push(k8s_netinspect::snapshot::CollectionError {
            resource: "daemonsets".into(),
            message: "forbidden".into(),
        });
    let r = analysis::analyze(&snap);
    assert_eq!(ids(&r), vec!["CNI-001", "COLLECT-001"]);
    assert!(r.findings.iter().all(|f| f.severity == Severity::Info));
}

#[test]
fn empty_cluster_reports_no_nodes_only() {
    let r = analysis::analyze(&ClusterSnapshot::default());
    assert_eq!(ids(&r), vec!["NODE-001"]);
}

#[test]
fn snapshot_round_trips_and_rejects_newer_schema() {
    let snap = ClusterSnapshot::load(&fixture_path("calico-degraded")).unwrap();
    let again = ClusterSnapshot::from_json(&snap.to_json().unwrap()).unwrap();
    assert_eq!(analysis::analyze(&snap), analysis::analyze(&again));

    let newer = format!(r#"{{"schema_version": {}}}"#, SCHEMA_VERSION + 1);
    let err = ClusterSnapshot::from_json(&newer).unwrap_err();
    assert!(err.plain_message().contains("newer than this build"));
    assert!(ClusterSnapshot::from_json("not json").is_err());
}

#[test]
fn redaction_strips_env_values_and_last_applied() {
    let raw = r#"{
      "schema_version": 1,
      "pods": [{
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
          "name": "db", "namespace": "default",
          "annotations": {
            "kubectl.kubernetes.io/last-applied-configuration": "{\"password\":\"hunter2\"}",
            "keep": "me"
          },
          "managedFields": [{"manager": "kubectl"}]
        },
        "spec": {
          "containers": [{"name": "db", "image": "postgres:16", "env": [
            {"name": "POSTGRES_PASSWORD", "value": "hunter2"},
            {"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}
          ]}],
          "initContainers": [{"name": "init", "image": "busybox", "env": [
            {"name": "TOKEN", "value": "abc123"}
          ]}]
        }
      }]
    }"#;
    let mut snap = ClusterSnapshot::from_json(raw).unwrap();
    snap.redact();
    let out = snap.to_json().unwrap();
    assert!(!out.contains("hunter2"), "literal env value leaked");
    assert!(!out.contains("abc123"), "init container env value leaked");
    assert!(!out.contains("last-applied-configuration"));
    assert!(!out.contains("managedFields"));
    assert!(out.contains("POSTGRES_PASSWORD"), "env names are kept");
    assert!(out.contains("secretKeyRef"), "references are kept");
    assert!(out.contains("\"keep\": \"me\""));
}

/// End-to-end through the real binary: no kubeconfig, no cluster.
#[test]
fn cli_diagnoses_a_snapshot_as_json_without_a_cluster() {
    let out = Command::new(env!("CARGO_BIN_EXE_k8s-netinspect"))
        .args(["diagnose", "--output", "json", "--from-snapshot"])
        .arg(fixture_path("calico-degraded"))
        .env("KUBECONFIG", "/nonexistent/kubeconfig")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Report = serde_json::from_slice(&out.stdout).expect("stdout is pure JSON");
    assert_eq!(parsed, report("calico-degraded"));
}

#[test]
fn cli_text_output_lists_findings_and_version_needs_no_kubeconfig() {
    let out = Command::new(env!("CARGO_BIN_EXE_k8s-netinspect"))
        .args(["diagnose", "--from-snapshot"])
        .arg(fixture_path("calico-degraded"))
        .env("NO_COLOR", "1")
        .env("KUBECONFIG", "/nonexistent/kubeconfig")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("CNI detected: Calico v3.28.0"), "{text}");
    assert!(text.contains("Found 3 nodes"));
    assert!(text.contains("Findings (4)"));
    assert!(text.contains("[CNI-002]"));
    assert!(text.contains("node/node-c"));

    let version = Command::new(env!("CARGO_BIN_EXE_k8s-netinspect"))
        .arg("version")
        .env("NO_COLOR", "1")
        .env("KUBECONFIG", "/nonexistent/kubeconfig")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));

    let missing = Command::new(env!("CARGO_BIN_EXE_k8s-netinspect"))
        .args(["diagnose", "--from-snapshot", "/nonexistent/snap.json"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
}

// ---- NetworkPolicy findings and can-reach (fixture: shop-policies) ----

fn netinspect(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_k8s-netinspect"))
        .args(args)
        .env("NO_COLOR", "1")
        .env("KUBECONFIG", "/nonexistent/kubeconfig")
        .output()
        .unwrap()
}

#[test]
fn policy_findings_on_shop_fixture() {
    let r = report("shop-policies");
    assert_eq!(r.cni_label(), "Calico v3.28.0");
    assert_eq!(ids(&r), vec!["POL-001", "POL-002", "POL-003", "POL-004"]);

    let dns = &r.findings[0];
    assert_eq!(dns.severity, Severity::Error);
    assert_eq!(dns.resource.as_deref(), Some("namespace/shop"));
    // web, api, db are blocked; the Succeeded job pod is not counted.
    assert!(
        dns.detail.starts_with("3 pod(s) in 'shop'"),
        "{}",
        dns.detail
    );
    assert!(!dns.detail.contains("migrate"));
    assert!(dns.detail.contains("shop/default-deny"));

    assert_eq!(
        r.findings[1].resource.as_deref(),
        Some("networkpolicy/shop/frontend-ingress")
    );
    assert!(r.findings[1].detail.contains("{app=frontend}"));

    assert_eq!(
        r.findings[2].resource.as_deref(),
        Some("networkpolicy/shop/api-from-web")
    );
    assert!(r.findings[2].detail.contains("ingress rule #2"));
    assert!(r.findings[2]
        .detail
        .contains("namespaceSelector {team=observability}"));

    assert_eq!(
        r.findings[3].resource.as_deref(),
        Some("networkpolicy/shop/db-from-api")
    );
    assert!(r.findings[3].detail.contains("'postgres'"));
}

#[test]
fn allowing_dns_egress_clears_pol_001() {
    let mut snap = ClusterSnapshot::load(&fixture_path("shop-policies")).unwrap();
    snap.network_policies.push(
        serde_json::from_value(serde_json::json!({
            "metadata": {"name": "allow-dns", "namespace": "shop"},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [{
                    "to": [{
                        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}
                    }],
                    "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]
                }]
            }
        }))
        .unwrap(),
    );
    let r = analysis::analyze(&snap);
    assert!(!ids(&r).contains(&"POL-001"), "{:?}", ids(&r));
}

#[test]
fn policy_rules_stay_quiet_without_the_data_to_judge() {
    // Pods unknown: "selects no pods" would be a guess.
    let mut snap = ClusterSnapshot::load(&fixture_path("shop-policies")).unwrap();
    snap.pods.clear();
    snap.collection_errors
        .push(k8s_netinspect::snapshot::CollectionError {
            resource: "pods".into(),
            message: "forbidden".into(),
        });
    let r = analysis::analyze(&snap);
    assert!(
        ids(&r).iter().all(|id| !id.starts_with("POL-")),
        "{:?}",
        ids(&r)
    );

    // Namespace-scoped snapshot: cross-namespace peers cannot be judged, and
    // with no DNS pods visible the DNS rule falls back to a port-only check.
    let mut snap = ClusterSnapshot::load(&fixture_path("shop-policies")).unwrap();
    snap.namespace = Some("shop".into());
    snap.pods
        .retain(|p| p.metadata.namespace.as_deref() == Some("shop"));
    snap.services
        .retain(|s| s.metadata.namespace.as_deref() == Some("shop"));
    snap.endpoint_slices.clear();
    let r = analysis::analyze(&snap);
    assert_eq!(ids(&r), vec!["POL-001", "POL-002", "POL-004"]);
}

#[test]
fn can_reach_allowed_flow_exits_zero() {
    let fixture = fixture_path("shop-policies");
    let out = netinspect(&[
        "can-reach",
        "--from",
        "shop/web",
        "--to",
        "shop/api",
        "--port",
        "8080",
        "--from-snapshot",
        fixture.to_str().unwrap(),
    ]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("ALLOWED by NetworkPolicy"), "{text}");
    assert!(
        text.contains("egress  (shop/web): allowed by shop/web-to-api"),
        "{text}"
    );
    assert!(
        text.contains("ingress (shop/api): allowed by shop/api-from-web"),
        "{text}"
    );
}

#[test]
fn can_reach_blocked_flow_exits_six_and_names_the_side() {
    let fixture = fixture_path("shop-policies");
    // api -> db: api has no egress allowance, and db's only rule uses an
    // undefined named port.
    let out = netinspect(&[
        "can-reach",
        "--from",
        "shop/api",
        "--to",
        "shop/db",
        "-p",
        "5432",
        "-o",
        "json",
        "--from-snapshot",
        fixture.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(6));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["from"], "shop/api");
    assert_eq!(v["to"], "shop/db");
    assert_eq!(v["port"], 5432);
    assert_eq!(v["protocol"], "TCP");
    assert_eq!(v["allowed"], false);
    assert_eq!(v["egress"]["decision"], "denied");
    assert_eq!(v["egress"]["isolating"][0], "shop/default-deny");
    assert_eq!(v["ingress"]["decision"], "denied");
    assert_eq!(v["complete"], true);

    // ops/prom is not isolated for egress; only the ingress side blocks.
    let out = netinspect(&[
        "can-reach",
        "--from",
        "ops/prom",
        "--to",
        "shop/api",
        "--port",
        "8080",
        "--from-snapshot",
        fixture.to_str().unwrap(),
    ]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(6));
    assert!(text.contains("BLOCKED on ingress to shop/api"), "{text}");
    assert!(text.contains("egress  (ops/prom): not isolated"), "{text}");
}

#[test]
fn can_reach_accepts_ips_and_reports_unknown_pods() {
    let fixture = fixture_path("shop-policies");
    let f = fixture.to_str().unwrap();

    // A pod's IP resolves to the pod, so selector rules apply to it.
    let out = netinspect(&[
        "can-reach",
        "--from",
        "10.0.1.10",
        "--to",
        "10.0.1.11",
        "--port",
        "8080",
        "-o",
        "json",
        "--from-snapshot",
        f,
    ]);
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["from"], "shop/web");
    assert_eq!(v["to"], "shop/api");

    // External destination from an egress-isolated pod.
    let out = netinspect(&[
        "can-reach",
        "--from",
        "shop/web",
        "--to",
        "93.184.216.34",
        "--port",
        "443",
        "--from-snapshot",
        f,
    ]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(6));
    assert!(text.contains("BLOCKED on egress from shop/web"), "{text}");
    assert!(
        text.contains("ingress (93.184.216.34): not a pod"),
        "{text}"
    );

    let out = netinspect(&[
        "can-reach",
        "--from",
        "shop/nope",
        "--to",
        "shop/api",
        "--port",
        "80",
        "--from-snapshot",
        f,
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "ResourceNotFound, distinct from blocked (6)"
    );
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Pod 'nope' not found in namespace 'shop'")
    );
}

// ---- Service diagnostics (fixture: services-broken) ----

fn by_resource<'a>(r: &'a Report, resource: &str) -> Vec<&'a k8s_netinspect::model::Finding> {
    r.findings
        .iter()
        .filter(|f| f.resource.as_deref() == Some(resource))
        .collect()
}

#[test]
fn service_findings_on_broken_fixture() {
    let r = report("services-broken");
    let svc_ids: Vec<(&str, &str)> = r
        .findings
        .iter()
        .filter(|f| f.category == "service")
        .map(|f| (f.id.as_str(), f.resource.as_deref().unwrap()))
        .collect();
    assert_eq!(
        svc_ids,
        vec![
            ("SVC-002", "service/shop/db"),
            ("SVC-003", "service/shop/cache"),
            ("SVC-001", "service/shop/orders"),
            ("SVC-001", "service/shop/worker"),
            ("SVC-003", "service/shop/api"),
            ("SVC-003", "service/shop/web-metrics"),
            ("SVC-004", "service/shop/public"),
            ("SVC-005", "service/shop/legacy-db"),
        ],
        "errors first, then warnings by id and resource"
    );

    let db = by_resource(&r, "service/shop/db")[0];
    assert_eq!(db.severity, Severity::Error);
    assert!(db
        .detail
        .contains("1 pod(s) match the selector but none is Ready (db-0)"));

    // Named targetPort missing on every backend is an Error...
    let cache = by_resource(&r, "service/shop/cache")[0];
    assert_eq!(cache.severity, Severity::Error);
    assert!(cache.detail.contains("named port 'redis'"));
    assert!(cache.detail.contains("none of the 1 matching pod(s)"));
    // ...on only some of them, a Warning.
    let api = by_resource(&r, "service/shop/api")[0];
    assert_eq!(api.severity, Severity::Warning);
    assert!(api.detail.contains("only 1 of the 2 matching pod(s)"));

    let metrics = by_resource(&r, "service/shop/web-metrics")[0];
    assert!(metrics.detail.contains("targets port 9100"));
    assert!(metrics.detail.contains("declare only port (8080)"));

    let orders = by_resource(&r, "service/shop/orders")[0];
    assert!(orders.detail.contains("{app=orders, tier=backend}"));
    // The only app=worker pod has Succeeded: it is not a backend.
    assert_eq!(by_resource(&r, "service/shop/worker")[0].id, "SVC-001");
}

#[test]
fn healthy_and_special_services_produce_no_findings() {
    let r = report("services-broken");
    for clean in [
        "service/shop/web",
        "service/shop/web-headless",
        "service/shop/public-ok",
        "service/shop/billing-ext",   // ExternalName
        "service/default/kubernetes", // selector-less with an EndpointSlice
        "service/shop/raw",           // pods declare no ports: nothing to compare
    ] {
        assert!(
            by_resource(&r, clean).is_empty(),
            "{clean}: {:?}",
            by_resource(&r, clean)
        );
    }
}

#[test]
fn service_rules_respect_missing_data_and_publish_not_ready() {
    let mut snap = ClusterSnapshot::load(&fixture_path("services-broken")).unwrap();
    for s in &mut snap.services {
        if s.metadata.name.as_deref() == Some("db") {
            s.spec.as_mut().unwrap().publish_not_ready_addresses = Some(true);
        }
    }
    // EndpointSlices forbidden: the selector-less check must not fire.
    snap.endpoint_slices.clear();
    snap.collection_errors
        .push(k8s_netinspect::snapshot::CollectionError {
            resource: "endpointslices".into(),
            message: "forbidden".into(),
        });
    let r = analysis::analyze(&snap);
    assert!(by_resource(&r, "service/shop/db").is_empty());
    assert!(!ids(&r).contains(&"SVC-005"));

    // Pods forbidden: selector-based checks are skipped, LoadBalancer status is not.
    snap.pods.clear();
    snap.collection_errors
        .push(k8s_netinspect::snapshot::CollectionError {
            resource: "pods".into(),
            message: "forbidden".into(),
        });
    let r = analysis::analyze(&snap);
    let svc: Vec<&str> = r
        .findings
        .iter()
        .filter(|f| f.category == "service")
        .map(|f| f.id.as_str())
        .collect();
    assert_eq!(svc, vec!["SVC-004"]);

    // Services forbidden: nothing at all.
    snap.services.clear();
    snap.collection_errors
        .push(k8s_netinspect::snapshot::CollectionError {
            resource: "services".into(),
            message: "forbidden".into(),
        });
    assert!(analysis::analyze(&snap)
        .findings
        .iter()
        .all(|f| f.category != "service"));
}

// ---- DNS diagnostics (fixture: dns-broken) ----

fn mutate(name: &str, f: impl FnOnce(&mut ClusterSnapshot)) -> Report {
    let mut snap = ClusterSnapshot::load(&fixture_path(name)).unwrap();
    f(&mut snap);
    analysis::analyze(&snap)
}

fn dns_ids(r: &Report) -> Vec<(&str, Severity)> {
    r.findings
        .iter()
        .filter(|f| f.category == "dns")
        .map(|f| (f.id.as_str(), f.severity))
        .collect()
}

#[test]
fn dns_findings_on_broken_fixture() {
    let r = report("dns-broken");
    assert_eq!(
        dns_ids(&r),
        vec![
            ("DNS-005", Severity::Error),
            ("DNS-006", Severity::Error),
            ("DNS-006", Severity::Error),
            ("DNS-008", Severity::Error),
            ("DNS-001", Severity::Warning),
        ]
    );
    let details: Vec<&str> = r
        .findings
        .iter()
        .filter(|f| f.id == "DNS-006")
        .map(|f| f.detail.as_str())
        .collect();
    assert!(details
        .iter()
        .any(|d| d.contains("10.96.0.10") && d.contains("own ClusterIP")));
    assert!(details
        .iter()
        .any(|d| d.contains("127.0.0.53:53") && d.contains("loopback")));
    let degraded = r.findings.iter().find(|f| f.id == "DNS-001").unwrap();
    assert!(degraded.detail.contains("1 of 2 replicas"));
    assert_eq!(
        degraded.resource.as_deref(),
        Some("deployment/kube-system/coredns")
    );
    let nld = r.findings.iter().find(|f| f.id == "DNS-008").unwrap();
    assert!(nld.detail.contains("2 of 3"));
}

#[test]
fn dns_outage_severities() {
    // No ready replica: Critical, and the Service has no ready endpoints.
    let r = mutate("healthy-cilium", |s| {
        s.deployments[0].status.as_mut().unwrap().ready_replicas = Some(0);
        for slice in &mut s.endpoint_slices {
            for e in slice.endpoints.iter_mut().flatten() {
                e.conditions.as_mut().unwrap().ready = Some(false);
            }
        }
    });
    assert_eq!(
        dns_ids(&r),
        vec![
            ("DNS-001", Severity::Critical),
            ("DNS-003", Severity::Critical)
        ]
    );

    // Scaled to zero.
    let r = mutate("healthy-cilium", |s| {
        s.deployments[0].spec.as_mut().unwrap().replicas = Some(0);
    });
    assert_eq!(r.findings[0].title, "Cluster DNS is scaled to zero");

    // Service deleted.
    let r = mutate("healthy-cilium", |s| s.services.clear());
    assert_eq!(dns_ids(&r), vec![("DNS-004", Severity::Error)]);

    // No DNS workload at all.
    let r = mutate("healthy-cilium", |s| s.deployments.clear());
    assert_eq!(dns_ids(&r), vec![("DNS-002", Severity::Warning)]);
}

#[test]
fn corefile_without_forward_only_warns() {
    let r = mutate("healthy-cilium", |s| {
        s.config_maps[0].data.as_mut().unwrap().insert(
            "Corefile".into(),
            ".:53 {\n    kubernetes cluster.local in-addr.arpa ip6.arpa\n    cache 30\n}\n".into(),
        );
    });
    assert_eq!(dns_ids(&r), vec![("DNS-007", Severity::Warning)]);
}

#[test]
fn dns_rules_stay_quiet_without_the_data_to_judge() {
    let forbid = |s: &mut ClusterSnapshot, resource: &str| {
        s.collection_errors
            .push(k8s_netinspect::snapshot::CollectionError {
                resource: resource.into(),
                message: "forbidden".into(),
            })
    };
    // Deployments forbidden: cannot claim DNS is missing; Corefile unknown too.
    let r = mutate("healthy-cilium", |s| {
        s.deployments.clear();
        s.config_maps.clear();
        forbid(s, "deployments");
    });
    assert!(dns_ids(&r).is_empty(), "{:?}", dns_ids(&r));

    // Snapshot scoped to another namespace: kube-system Services are not in it.
    let r = mutate("healthy-cilium", |s| {
        s.namespace = Some("default".into());
        s.services.clear();
        s.endpoint_slices.clear();
    });
    assert!(dns_ids(&r).is_empty(), "{:?}", dns_ids(&r));

    // EndpointSlices forbidden: no "no ready endpoints" claim.
    let r = mutate("healthy-cilium", |s| {
        s.endpoint_slices.clear();
        forbid(s, "endpointslices");
    });
    assert!(dns_ids(&r).is_empty(), "{:?}", dns_ids(&r));

    // GKE-style kube-dns Deployment with no CoreDNS ConfigMap is healthy.
    let r = mutate("healthy-cilium", |s| {
        s.deployments[0].metadata.name = Some("kube-dns".into());
        s.config_maps.clear();
    });
    assert!(dns_ids(&r).is_empty(), "{:?}", dns_ids(&r));
}

// ---- Service proxy (fixture: proxy-broken) ----

fn proxy_findings(r: &Report) -> Vec<(&str, Severity, &str)> {
    r.findings
        .iter()
        .filter(|f| f.category == "proxy")
        .map(|f| (f.id.as_str(), f.severity, f.title.as_str()))
        .collect()
}

#[test]
fn service_proxy_is_identified_per_fixture() {
    let label = |name: &str| report(name).service_proxy.map(|p| p.label());
    assert_eq!(
        label("healthy-cilium").as_deref(),
        Some("Cilium (kube-proxy replacement)")
    );
    assert_eq!(
        label("calico-degraded").as_deref(),
        Some("kube-proxy (ipvs) v1.30.4")
    );
    // Empty mode in the ConfigMap means the Linux default.
    assert_eq!(
        label("shop-policies").as_deref(),
        Some("kube-proxy (iptables) v1.30.4")
    );
    assert_eq!(
        label("services-broken").as_deref(),
        Some("kube-proxy (nftables) v1.30.4")
    );
    // k3s embeds kube-proxy: nothing to identify, and no false alarm.
    let k3s = report("k3s-flannel");
    assert_eq!(k3s.service_proxy, None);
    assert!(proxy_findings(&k3s).is_empty());
}

#[test]
fn proxy_findings_on_broken_fixture() {
    let r = report("proxy-broken");
    assert_eq!(
        proxy_findings(&r),
        vec![
            (
                "PROXY-001",
                Severity::Error,
                "kube-proxy is not ready on every node"
            ),
            (
                "PROXY-003",
                Severity::Warning,
                "kube-proxy runs alongside a kube-proxy replacement"
            ),
            (
                "PROXY-004",
                Severity::Warning,
                "kube-proxy is too old for the API server"
            ),
            (
                "PROXY-004",
                Severity::Warning,
                "kube-proxy and kubelet versions are too far apart"
            ),
        ]
    );
    let skew = r
        .findings
        .iter()
        .find(|f| f.title.contains("too old for the API server"))
        .unwrap();
    assert!(
        skew.detail.contains("v1.26.15 is 4 minor versions behind"),
        "{}",
        skew.detail
    );
}

#[test]
fn proxy_edge_cases() {
    // No kube-proxy and Cilium without replacement enabled: nothing serves Services.
    let r = mutate("healthy-cilium", |s| {
        s.config_maps
            .retain(|c| c.metadata.name.as_deref() != Some("cilium-config"))
    });
    assert_eq!(
        proxy_findings(&r),
        vec![("PROXY-002", Severity::Warning, "No Service proxy detected")]
    );

    // ...unless kube-proxy runs as static pods (GKE, RKE2).
    let r = mutate("healthy-cilium", |s| {
        s.config_maps
            .retain(|c| c.metadata.name.as_deref() != Some("cilium-config"));
        let mut pod = s.pods[0].clone();
        pod.metadata.namespace = Some("kube-system".into());
        pod.metadata.name = Some("kube-proxy-gke-pool-1-abcd".into());
        s.pods.push(pod);
    });
    assert!(proxy_findings(&r).is_empty());
    assert_eq!(
        r.service_proxy.unwrap().implementation,
        "kube-proxy (static pods)"
    );

    // All kube-proxy pods down is Critical.
    let r = mutate("shop-policies", |s| {
        for d in &mut s.daemon_sets {
            if d.metadata.name.as_deref() == Some("kube-proxy") {
                d.status.as_mut().unwrap().number_ready = 0;
            }
        }
    });
    assert_eq!(proxy_findings(&r)[0].1, Severity::Critical);

    // kube-proxy newer than the API server.
    let r = mutate("shop-policies", |s| {
        s.cluster_version = Some("v1.29.2".into())
    });
    assert_eq!(
        proxy_findings(&r),
        vec![(
            "PROXY-004",
            Severity::Warning,
            "kube-proxy is newer than the API server"
        )]
    );

    // DaemonSets forbidden, or a snapshot scoped away from kube-system: no claims.
    let r = mutate("healthy-cilium", |s| {
        s.config_maps.clear();
        s.daemon_sets.clear();
        s.collection_errors
            .push(k8s_netinspect::snapshot::CollectionError {
                resource: "daemonsets".into(),
                message: "forbidden".into(),
            });
    });
    assert!(proxy_findings(&r).is_empty());
    let r = mutate("healthy-cilium", |s| {
        s.config_maps.clear();
        s.namespace = Some("default".into());
        s.services.clear();
        s.endpoint_slices.clear();
    });
    assert!(proxy_findings(&r).is_empty());
}

// ---- Pod networking and IPAM (fixture: ipam-broken) ----

fn pod_findings(r: &Report) -> Vec<(&str, &str)> {
    r.findings
        .iter()
        .filter(|f| f.category == "pod")
        .map(|f| (f.id.as_str(), f.resource.as_deref().unwrap()))
        .collect()
}

#[test]
fn ipam_findings_on_broken_fixture() {
    let r = report("ipam-broken");
    assert_eq!(r.cni_label(), "Flannel v0.25.6");
    assert_eq!(
        pod_findings(&r),
        vec![
            ("POD-001", "node/node-a"),
            ("POD-002", "pod/apps/web-1"),
            ("POD-004", "node/node-a"),
            ("POD-003", "pod/apps/legacy-1"),
            ("POD-005", "node/node-b"),
        ]
    );
    let find = |id: &str| r.findings.iter().find(|f| f.id == id).unwrap();

    // Only the two long-stuck pods: not the 20-second-old one, not the one
    // that has an IP (image pull), not the unscheduled one.
    let stuck = find("POD-001");
    assert!(
        stuck.detail.starts_with("2 pod(s) on node 'node-a'"),
        "{}",
        stuck.detail
    );
    assert!(stuck.detail.contains("apps/stuck-1, apps/stuck-2"));
    assert!(stuck
        .remediation
        .as_deref()
        .unwrap()
        .contains("-n apps stuck-1"));

    // hostNetwork pods legitimately share the node IP.
    let dup = find("POD-002");
    assert!(dup
        .detail
        .contains("10.244.0.5 is held by apps/web-1, apps/web-2"));
    assert_eq!(r.findings.iter().filter(|f| f.id == "POD-002").count(), 1);

    assert!(find("POD-003")
        .detail
        .contains("10.88.0.4 is not in the podCIDR of node 'node-a'"));
    assert!(
        find("POD-004").detail.contains("10.244.0.0/24")
            && find("POD-004").detail.contains("10.244.0.128/25")
    );
    // /28 = 13 usable; 12 running pods (the Succeeded one has released its IP).
    assert!(
        find("POD-005").detail.contains("uses 12 of about 13"),
        "{}",
        find("POD-005").detail
    );
}

#[test]
fn ipam_rules_depend_on_the_cni_and_on_available_data() {
    // Calico runs its own IPAM: node podCIDR checks do not apply.
    let r = mutate("ipam-broken", |s| {
        s.daemon_sets[0].metadata.name = Some("calico-node".into());
        s.daemon_sets[0]
            .spec
            .as_mut()
            .unwrap()
            .template
            .spec
            .as_mut()
            .unwrap()
            .containers[0]
            .image = Some("docker.io/calico/node:v3.28.0".into());
    });
    let ids: Vec<&str> = pod_findings(&r).iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec!["POD-001", "POD-002", "POD-004"]);

    // No collection timestamp: "stuck" cannot be told from "just created".
    let r = mutate("ipam-broken", |s| s.collected_at = None);
    assert!(!pod_findings(&r).iter().any(|(id, _)| *id == "POD-001"));

    // Namespace-scoped snapshot undercounts per-node usage: no exhaustion claim.
    let r = mutate("ipam-broken", |s| s.namespace = Some("apps".into()));
    assert!(!pod_findings(&r).iter().any(|(id, _)| *id == "POD-005"));

    // Pods forbidden: only the node-level overlap check remains.
    let r = mutate("ipam-broken", |s| {
        s.pods.clear();
        s.collection_errors
            .push(k8s_netinspect::snapshot::CollectionError {
                resource: "pods".into(),
                message: "forbidden".into(),
            });
    });
    assert_eq!(pod_findings(&r), vec![("POD-004", "node/node-a")]);
}

#[test]
fn dual_stack_pod_ips_are_checked_per_family() {
    let r = mutate("ipam-broken", |s| {
        let node = s.nodes[0].spec.as_mut().unwrap();
        node.pod_cidrs = Some(vec!["10.244.0.0/24".into(), "fd00:10:244::/64".into()]);
        for p in &mut s.pods {
            if p.metadata.name.as_deref() == Some("legacy-1") {
                let st = p.status.as_mut().unwrap();
                st.pod_ip = Some("10.244.0.77".into());
                st.pod_ips = Some(
                    serde_json::from_value(serde_json::json!([
                        {"ip": "10.244.0.77"}, {"ip": "fd00:10:244:1::7"}
                    ]))
                    .unwrap(),
                );
            }
        }
    });
    let bad: Vec<&str> = r
        .findings
        .iter()
        .filter(|f| f.id == "POD-003")
        .map(|f| f.detail.as_str())
        .collect();
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].starts_with("fd00:10:244:1::7 is not in the podCIDR"));
}

// ---- Ingress and Gateway API (fixture: ingress-broken) ----

fn north_south(r: &Report) -> Vec<(&str, &str)> {
    r.findings
        .iter()
        .filter(|f| f.category == "ingress" || f.category == "gateway")
        .map(|f| (f.id.as_str(), f.resource.as_deref().unwrap()))
        .collect()
}

#[test]
fn ingress_and_gateway_findings_on_broken_fixture() {
    let r = report("ingress-broken");
    assert_eq!(
        north_south(&r),
        vec![
            ("GW-001", "httproute/shop/orphan"),
            ("GW-002", "httproute/shop/bad-backend"),
            ("GW-002", "httproute/shop/bad-backend"),
            ("GW-003", "httproute/shop/cross-ns"),
            ("ING-001", "ingress/shop/missing-svc"),
            ("ING-002", "ingress/shop/bad-port"),
            ("ING-002", "ingress/shop/bad-port"),
            ("GW-004", "gateway/infra/internal"),
            ("GW-005", "httproute/shop/rejected"),
            ("ING-003", "ingress/shop/no-class"),
            ("ING-003", "ingress/shop/typo-class"),
            ("ING-004", "ingress/shop/no-class"),
            ("ING-004", "ingress/shop/typo-class"),
        ]
    );
    let details = |id: &str| -> Vec<&str> {
        r.findings
            .iter()
            .filter(|f| f.id == id)
            .map(|f| f.detail.as_str())
            .collect()
    };
    assert!(details("ING-001")[0].starts_with("shop.example.com/cart routes to Service 'cart'"));
    assert!(details("ING-002")[0].contains("Service 'api' port 80, but that Service exposes: 8080"));
    assert!(details("ING-002")[1].contains("Service 'web' port 'https'"));
    assert!(details("ING-003")[0].contains("no default IngressClass"));
    assert!(details("ING-003")[1].contains("'ngnix' does not match any IngressClass"));
    assert!(details("GW-001")[0].contains("Gateway 'infra/edge'"));
    assert!(details("GW-002")[0].contains("'shop/cart', which does not exist"));
    assert!(details("GW-002")[1].contains("port 9999"));
    // payments/ledger has no grant; billing/invoices does.
    assert!(details("GW-003")[0].contains("'payments/ledger'"));
    assert_eq!(details("GW-003").len(), 1);
    assert!(details("GW-004")[0].starts_with("Programmed is not True (AddressNotAssigned)"));
    assert!(details("GW-005")[0].contains("Accepted=False (NotAllowedByListeners)"));
}

#[test]
fn ingress_rules_respect_defaults_scope_and_missing_data() {
    // A default IngressClass makes a class-less Ingress valid.
    let r = mutate("ingress-broken", |s| {
        s.ingress_classes[0]
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                "ingressclass.kubernetes.io/is-default-class".into(),
                "true".into(),
            );
    });
    let class: Vec<&str> = r
        .findings
        .iter()
        .filter(|f| f.id == "ING-003")
        .map(|f| f.resource.as_deref().unwrap())
        .collect();
    assert_eq!(class, vec!["ingress/shop/typo-class"]);

    // A ReferenceGrant restricted to another Service name does not help.
    let r = mutate("ingress-broken", |s| {
        s.reference_grants[0].data["spec"]["to"][0]["name"] = "other".into();
    });
    assert_eq!(r.findings.iter().filter(|f| f.id == "GW-003").count(), 2);

    // Forbidden lists: no claims built on them.
    let forbid = |s: &mut ClusterSnapshot, resource: &str| {
        s.collection_errors
            .push(k8s_netinspect::snapshot::CollectionError {
                resource: resource.into(),
                message: "forbidden".into(),
            })
    };
    let r = mutate("ingress-broken", |s| {
        s.services.clear();
        s.ingress_classes.clear();
        s.gateways.clear();
        s.reference_grants.clear();
        for res in ["services", "ingressclasses", "gateways", "referencegrants"] {
            forbid(s, res);
        }
    });
    let ids: Vec<&str> = north_south(&r).iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids,
        vec!["GW-005", "ING-004", "ING-004"],
        "only status-based findings remain"
    );

    // Namespace-scoped snapshot: objects in other namespaces are out of view.
    let r = mutate("ingress-broken", |s| {
        s.namespace = Some("shop".into());
        s.services
            .retain(|x| x.metadata.namespace.as_deref() == Some("shop"));
        s.pods
            .retain(|x| x.metadata.namespace.as_deref() == Some("shop"));
        s.endpoint_slices.clear();
        s.gateways.clear();
    });
    let ids: Vec<&str> = north_south(&r).iter().map(|(id, _)| *id).collect();
    assert!(
        !ids.contains(&"GW-001"),
        "Gateways live in infra, outside the scope"
    );
    assert_eq!(
        ids.iter().filter(|i| **i == "GW-002").count(),
        2,
        "shop-local backends still checked"
    );
}

#[test]
fn snapshot_without_ingress_fields_still_loads() {
    // Snapshots written before these fields existed must stay readable.
    let snap = ClusterSnapshot::from_json(r#"{"schema_version": 1, "nodes": []}"#).unwrap();
    assert!(snap.ingresses.is_empty() && snap.http_routes.is_empty());
    let round = ClusterSnapshot::from_json(
        &ClusterSnapshot::load(&fixture_path("ingress-broken"))
            .unwrap()
            .to_json()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(round.http_routes.len(), 5);
    assert_eq!(
        round.gateways[1].data["status"]["conditions"][1]["reason"],
        "AddressNotAssigned"
    );
}
