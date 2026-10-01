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
