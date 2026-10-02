//! CI-facing surface: rule catalog, filters, exit status, SARIF and JUnit.

use k8s_netinspect::analysis;
use k8s_netinspect::output::{render_junit, render_sarif};
use k8s_netinspect::rules::{self, Filter, RULES};
use k8s_netinspect::snapshot::ClusterSnapshot;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture(name: &str) -> String {
    fixtures_dir()
        .join(format!("{name}.json"))
        .to_str()
        .unwrap()
        .to_string()
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_k8s-netinspect"))
        .args(args)
        .env("NO_COLOR", "1")
        .env("KUBECONFIG", "/nonexistent/kubeconfig")
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn every_rule_id_in_the_analyzers_is_in_the_catalog() {
    let id = regex::Regex::new(r#""([A-Z]+-\d{3})""#).unwrap();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/analysis");
    let mut emitted = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let source = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        for cap in id.captures_iter(&source) {
            emitted.insert(cap[1].to_string());
        }
    }
    let catalog: BTreeSet<String> = RULES.iter().map(|r| r.id.to_string()).collect();
    assert_eq!(emitted, catalog, "analyzers and rules.rs disagree");
}

#[test]
fn no_fixture_finding_exceeds_its_rule_severity() {
    let mut seen = 0;
    for entry in std::fs::read_dir(fixtures_dir()).unwrap() {
        let snap = ClusterSnapshot::load(&entry.unwrap().path()).unwrap();
        for f in analysis::analyze(&snap).findings {
            let rule = rules::find(&f.id).unwrap_or_else(|| panic!("{} not in catalog", f.id));
            assert!(
                f.severity <= rule.severity,
                "{} reported {}",
                f.id,
                f.severity
            );
            assert_eq!(f.category, rule.category, "{}", f.id);
            seen += 1;
        }
    }
    assert!(
        seen > 30,
        "fixtures should exercise the rules ({seen} findings)"
    );
}

#[test]
fn rules_md_is_up_to_date() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/RULES.md");
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        rules::markdown(),
        "regenerate with: cargo run -- rules --format markdown > docs/RULES.md"
    );
    let out = run(&["rules"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out).lines().count(), RULES.len());
    assert!(stdout(&out).contains("DNS-006"));
}

#[test]
fn fail_on_sets_exit_status_seven() {
    let degraded = fixture("calico-degraded"); // worst finding: error
    let base = ["diagnose", "--from-snapshot", degraded.as_str()];
    let with = |extra: &[&str]| run(&[&base[..], extra].concat()).status.code();

    assert_eq!(
        with(&[]),
        Some(0),
        "without --fail-on findings never fail the run"
    );
    assert_eq!(with(&["--fail-on", "warning"]), Some(7));
    assert_eq!(with(&["--fail-on", "error"]), Some(7));
    assert_eq!(with(&["--fail-on", "critical"]), Some(0));
    // Filters apply before the threshold.
    assert_eq!(with(&["--fail-on", "error", "--skip", "CNI,NODE"]), Some(0));
    assert_eq!(with(&["--fail-on", "info", "--only", "COLLECT"]), Some(7));

    let healthy = fixture("healthy-cilium");
    let out = run(&["diagnose", "--from-snapshot", &healthy, "--fail-on", "info"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("No issues found"));
}

#[test]
fn only_and_skip_select_rules_and_reject_typos() {
    let f = fixture("shop-policies");
    let ids = |args: &[&str]| -> Vec<String> {
        let out = run(&[
            &["diagnose", "-o", "json", "--from-snapshot", f.as_str()],
            args,
        ]
        .concat());
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(ids(&[]), ["POL-001", "POL-002", "POL-003", "POL-004"]);
    assert_eq!(ids(&["--only", "POL-001,pol-004"]), ["POL-001", "POL-004"]);
    assert_eq!(
        ids(&["--skip", "POL-002", "--skip", "POL-003"]),
        ["POL-001", "POL-004"]
    );
    assert!(ids(&["--only", "dns"]).is_empty());

    let out = run(&["diagnose", "--from-snapshot", &f, "--only", "POLICY"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Unknown rule selector(s): POLICY"));
}

#[test]
fn sarif_output_is_valid_and_complete() {
    let out = run(&[
        "diagnose",
        "-o",
        "sarif",
        "--from-snapshot",
        &fixture("calico-degraded"),
    ]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("pure JSON on stdout");
    assert_eq!(v["version"], "2.1.0");
    let run0 = &v["runs"][0];
    let driver = &run0["tool"]["driver"];
    assert_eq!(driver["name"], "k8s-netinspect");
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(driver["rules"].as_array().unwrap().len(), RULES.len());

    let results = run0["results"].as_array().unwrap();
    assert_eq!(results.len(), 4);
    for r in results {
        let id = r["ruleId"].as_str().unwrap();
        let index = r["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(
            driver["rules"][index]["id"], id,
            "ruleIndex must point at the rule"
        );
        assert!(["error", "warning", "note"].contains(&r["level"].as_str().unwrap()));
        assert!(!r["message"]["text"].as_str().unwrap().is_empty());
    }
    assert_eq!(results[0]["ruleId"], "CNI-002");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(
        results[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
        "daemonset/calico-system/calico-node"
    );
    assert_eq!(results[3]["ruleId"], "COLLECT-001");
    assert_eq!(results[3]["level"], "note");

    // A clean cluster still yields a valid log with zero results.
    let snap = ClusterSnapshot::load(&fixtures_dir().join("healthy-cilium.json")).unwrap();
    let clean = render_sarif(&analysis::analyze(&snap));
    assert_eq!(clean["runs"][0]["results"].as_array().unwrap().len(), 0);
}

#[test]
fn junit_output_counts_rules_and_failures() {
    let out = run(&[
        "diagnose",
        "-o",
        "junit",
        "--from-snapshot",
        &fixture("calico-degraded"),
    ]);
    assert!(out.status.success());
    let xml = stdout(&out);
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites "));
    assert!(xml.trim_end().ends_with("</testsuites>"));
    assert_eq!(xml.matches("<testcase ").count(), RULES.len());
    // CNI-002, NODE-002, NODE-003 fail; COLLECT-001 is info and only logged.
    assert!(xml.contains(&format!("tests=\"{}\" failures=\"3\"", RULES.len())));
    assert_eq!(xml.matches("<failure ").count(), 3);
    assert_eq!(xml.matches("<system-out>").count(), 1);
    assert!(xml.contains("name=\"CNI-002 CNI agent is not ready on every node\""));
    assert!(xml.contains("<failure type=\"error\" message=\"node/node-c: Node is not Ready\">"));
    // Every tag opened is closed.
    assert_eq!(
        xml.matches("<testcase ").count(),
        xml.matches("</testcase>").count() + xml.matches("\"/>").count()
    );

    // With a filter, only in-scope rules become test cases.
    let out = run(&[
        "diagnose",
        "-o",
        "junit",
        "--only",
        "NODE",
        "--from-snapshot",
        &fixture("calico-degraded"),
    ]);
    let xml = stdout(&out);
    assert_eq!(xml.matches("<testcase ").count(), 3);
    assert!(xml.contains("tests=\"3\" failures=\"2\""));
}

#[test]
fn junit_escapes_markup_in_finding_text() {
    let mut snap = ClusterSnapshot::load(&fixtures_dir().join("calico-degraded.json")).unwrap();
    for n in &mut snap.nodes {
        for c in n.status.as_mut().unwrap().conditions.as_mut().unwrap() {
            if c.status != "True" || c.type_ == "NetworkUnavailable" {
                c.message = Some("route <none> & \"cni\" 'down'\u{7}".into());
            }
        }
    }
    let xml = render_junit(&analysis::analyze(&snap), &Filter::default());
    assert!(xml.contains("route &lt;none&gt; &amp; &quot;cni&quot; &apos;down&apos;"));
    assert!(!xml.contains("<none>"));
    assert!(
        !xml.contains('\u{7}'),
        "control characters are not valid XML 1.0"
    );
}

#[test]
fn can_reach_rejects_report_only_formats() {
    let out = run(&[
        "can-reach",
        "--from",
        "shop/web",
        "--to",
        "shop/api",
        "-p",
        "8080",
        "-o",
        "sarif",
        "--from-snapshot",
        &fixture("shop-policies"),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("supports --output text or json"));
}

// ---- can-reach --probe: everything that can be checked without a cluster ----

#[test]
fn probe_is_refused_without_a_live_cluster_or_without_opt_in() {
    let f = fixture("shop-policies");
    let base = [
        "can-reach",
        "--from",
        "shop/web",
        "--to",
        "shop/api",
        "-p",
        "8080",
    ];

    let out = run(&[&base[..], &["--probe", "--from-snapshot", f.as_str()]].concat());
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--probe needs a live cluster"));
    assert!(out.stdout.is_empty(), "nothing is evaluated or printed");

    // Probe tuning flags are meaningless without --probe.
    let out = run(&[
        &base[..],
        &["--probe-image", "alpine", "--from-snapshot", f.as_str()],
    ]
    .concat());
    assert_eq!(out.status.code(), Some(2));
    let out = run(&[&base[..], &["--probe", "--probe-timeout", "0"]].concat());
    assert_eq!(out.status.code(), Some(2), "timeout must be 1..=60");

    // Without --probe nothing about the probe appears in the output.
    let out = run(&[&base[..], &["-o", "json", "--from-snapshot", f.as_str()]].concat());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.get("probe").is_none());
}

#[test]
fn probe_endpoints_require_a_pod_source_and_resolve_the_target_address() {
    use k8s_netinspect::commands::probe_endpoints;
    let snap = ClusterSnapshot::load(&fixtures_dir().join("shop-policies.json")).unwrap();

    let (ns, pod, target) = probe_endpoints(&snap, "shop/web", "shop/db").unwrap();
    assert_eq!((ns.as_str(), pod.as_str()), ("shop", "web"));
    assert_eq!(target.to_string(), "10.0.1.12");

    let (_, _, target) = probe_endpoints(&snap, "shop/web", "93.184.216.34").unwrap();
    assert_eq!(target.to_string(), "93.184.216.34");

    // A pod's own IP as --from still resolves to that pod.
    let (_, pod, _) = probe_endpoints(&snap, "10.0.1.10", "shop/db").unwrap();
    assert_eq!(pod, "web");

    let err = probe_endpoints(&snap, "203.0.113.9", "shop/db").unwrap_err();
    assert!(err.plain_message().contains("--from must be a pod"));
}
