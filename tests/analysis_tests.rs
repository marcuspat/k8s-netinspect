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
    assert_eq!(r.summary.pods, 2);
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
