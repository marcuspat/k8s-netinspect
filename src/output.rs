//! Report rendering. `text` is for humans, `json` is the stable machine
//! contract (see `model::Report`).

use clap::ValueEnum;
use colored::*;

use crate::errors::{NetInspectError, NetInspectResult};
use crate::model::{Finding, Report, Severity};
use crate::rules::{self, Filter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    /// SARIF 2.1.0, for code-scanning dashboards
    Sarif,
    /// JUnit XML, one test case per rule
    Junit,
    /// Prometheus text exposition (e.g. for the node-exporter textfile collector)
    Prometheus,
}

pub fn render(report: &Report, format: OutputFormat) -> NetInspectResult<String> {
    match format {
        OutputFormat::Text => Ok(render_text(report)),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|e| NetInspectError::Runtime(format!("Failed to serialize report: {e}"))),
        OutputFormat::Sarif => serde_json::to_string_pretty(&render_sarif(report))
            .map_err(|e| NetInspectError::Runtime(format!("Failed to serialize SARIF: {e}"))),
        OutputFormat::Junit => Ok(render_junit(report, &Filter::default())),
        OutputFormat::Prometheus => Ok(render_prometheus(report, &Filter::default())),
    }
}

pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    let ok = "✓".green().bold();
    let warn = "⚠".yellow().bold();

    if report.cni.is_empty() {
        out.push_str(&format!(
            "{} CNI detected: {}\n",
            warn,
            "Unknown CNI".yellow()
        ));
    } else {
        out.push_str(&format!(
            "{} CNI detected: {}\n",
            ok,
            report.cni_label().green()
        ));
        for p in &report.cni {
            if let (Some(ready), Some(desired)) = (p.ready, p.desired) {
                out.push_str(&format!(
                    "  {} {} ({}): {}/{} agents ready\n",
                    "•".dimmed(),
                    p.name,
                    p.source,
                    ready,
                    desired
                ));
            }
        }
    }

    if let Some(proxy) = &report.service_proxy {
        out.push_str(&format!(
            "{} Service proxy: {}\n",
            ok,
            proxy.label().green()
        ));
    }

    if report.summary.nodes == 0 {
        out.push_str(&format!(
            "{} {}\n",
            warn,
            "No nodes found in cluster".yellow()
        ));
    } else {
        out.push_str(&format!(
            "{} Found {} nodes\n",
            ok,
            report.summary.nodes.to_string().yellow()
        ));
    }

    match &report.summary.namespace {
        Some(ns) => out.push_str(&format!(
            "{} Found {} pods in namespace '{}'\n",
            ok,
            report.summary.pods.to_string().yellow(),
            ns.yellow()
        )),
        None => out.push_str(&format!(
            "{} Found {} pods cluster-wide\n",
            ok,
            report.summary.pods.to_string().yellow()
        )),
    }

    // NODE-001 is already shown by the node count line above.
    let listed: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.id != "NODE-001")
        .collect();

    if listed.is_empty() {
        out.push_str(&format!("{} No issues found\n", ok));
        return out;
    }

    out.push_str(&format!(
        "\n{}\n",
        format!("Findings ({})", listed.len()).bold()
    ));
    for f in listed {
        let badge = match f.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::Error => "ERROR".red(),
            Severity::Warning => "WARNING".yellow(),
            Severity::Info => "INFO".blue(),
        };
        out.push_str(&format!("{} [{}] {}", badge, f.id, f.title.bold()));
        if let Some(r) = &f.resource {
            out.push_str(&format!(" — {}", r.cyan()));
        }
        out.push('\n');
        out.push_str(&format!("    {}\n", f.detail));
        if let Some(fix) = &f.remediation {
            out.push_str(&format!("    {} {}\n", "→".green(), fix));
        }
    }
    out
}

const INFO_URI: &str = "https://github.com/marcuspat/k8s-netinspect";

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

/// SARIF 2.1.0. Findings are about cluster objects, not files, so each
/// result carries a logical location (`kind/namespace/name`).
pub fn render_sarif(report: &Report) -> serde_json::Value {
    use serde_json::json;

    let rules: Vec<serde_json::Value> = rules::RULES
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.title,
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.description},
                "helpUri": format!("{INFO_URI}/blob/main/docs/RULES.md"),
                "defaultConfiguration": {"level": sarif_level(r.severity)},
                "properties": {"category": r.category, "maxSeverity": r.severity.to_string()},
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut text = format!("{}: {}", f.title, f.detail);
            if let Some(fix) = &f.remediation {
                text.push_str(&format!(" Fix: {fix}"));
            }
            let mut result = json!({
                "ruleId": f.id,
                "level": sarif_level(f.severity),
                "message": {"text": text},
                "properties": {"severity": f.severity.to_string(), "category": f.category},
            });
            if let Some(index) = rules::RULES.iter().position(|r| r.id == f.id) {
                result["ruleIndex"] = json!(index);
            }
            if let Some(resource) = &f.resource {
                result["locations"] = json!([{
                    "logicalLocations": [{"fullyQualifiedName": resource, "kind": "resource"}]
                }]);
            }
            result
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "k8s-netinspect",
                "version": report.tool_version,
                "informationUri": INFO_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 forbids most control characters outright.
            c if c.is_control() && c != '\n' && c != '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// JUnit XML: one test case per rule that was in scope. A rule with findings
/// at Warning or above fails, with one `<failure>` per finding; Info findings
/// are attached as `<system-out>` and do not fail the case.
pub fn render_junit(report: &Report, filter: &Filter) -> String {
    let in_scope: Vec<&rules::Rule> = rules::RULES
        .iter()
        .filter(|r| filter.allows(r.id))
        .collect();
    let failed = in_scope
        .iter()
        .filter(|r| {
            report
                .findings
                .iter()
                .any(|f| f.id == r.id && f.severity >= Severity::Warning)
        })
        .count();

    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuites name=\"k8s-netinspect\" tests=\"{0}\" failures=\"{1}\">\n  <testsuite name=\"k8s-netinspect\" tests=\"{0}\" failures=\"{1}\" errors=\"0\" skipped=\"0\">\n",
        in_scope.len(),
        failed
    ));
    for r in in_scope {
        out.push_str(&format!(
            "    <testcase classname=\"k8s-netinspect.{}\" name=\"{} {}\"",
            xml_escape(r.category),
            r.id,
            xml_escape(r.title)
        ));
        let findings: Vec<&Finding> = report.findings.iter().filter(|f| f.id == r.id).collect();
        if findings.is_empty() {
            out.push_str("/>\n");
            continue;
        }
        out.push_str(">\n");
        for f in &findings {
            let resource = f.resource.as_deref().unwrap_or("cluster");
            let mut body = f.detail.clone();
            if let Some(fix) = &f.remediation {
                body.push_str(&format!("\nFix: {fix}"));
            }
            if f.severity >= Severity::Warning {
                out.push_str(&format!(
                    "      <failure type=\"{}\" message=\"{}\">{}</failure>\n",
                    f.severity,
                    xml_escape(&format!("{}: {}", resource, f.title)),
                    xml_escape(&body)
                ));
            } else {
                out.push_str(&format!(
                    "      <system-out>{}</system-out>\n",
                    xml_escape(&format!("{}: {} — {}", resource, f.title, body))
                ));
            }
        }
        out.push_str("    </testcase>\n");
    }
    out.push_str("  </testsuite>\n</testsuites>\n");
    out
}

fn prom_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Prometheus text exposition format. One `k8s_netinspect_rule_findings`
/// series per in-scope rule — zero when clean, so alerts never depend on a
/// series being absent — plus per-severity totals.
pub fn render_prometheus(report: &Report, filter: &Filter) -> String {
    let mut out = String::new();
    out.push_str("# HELP k8s_netinspect_info Tool version that produced this scrape.\n");
    out.push_str("# TYPE k8s_netinspect_info gauge\n");
    out.push_str(&format!(
        "k8s_netinspect_info{{version=\"{}\"}} 1\n",
        prom_label(&report.tool_version)
    ));

    out.push_str("# HELP k8s_netinspect_rule_findings Findings currently reported, per rule.\n");
    out.push_str("# TYPE k8s_netinspect_rule_findings gauge\n");
    for r in rules::RULES.iter().filter(|r| filter.allows(r.id)) {
        let count = report.findings.iter().filter(|f| f.id == r.id).count();
        out.push_str(&format!(
            "k8s_netinspect_rule_findings{{rule=\"{}\",category=\"{}\"}} {}\n",
            r.id,
            prom_label(r.category),
            count
        ));
    }

    out.push_str("# HELP k8s_netinspect_findings Findings currently reported, per severity.\n");
    out.push_str("# TYPE k8s_netinspect_findings gauge\n");
    for severity in [
        Severity::Critical,
        Severity::Error,
        Severity::Warning,
        Severity::Info,
    ] {
        let count = report
            .findings
            .iter()
            .filter(|f| f.severity == severity)
            .count();
        out.push_str(&format!(
            "k8s_netinspect_findings{{severity=\"{severity}\"}} {count}\n"
        ));
    }

    out.push_str("# HELP k8s_netinspect_nodes Nodes in the analyzed snapshot.\n");
    out.push_str("# TYPE k8s_netinspect_nodes gauge\n");
    out.push_str(&format!("k8s_netinspect_nodes {}\n", report.summary.nodes));
    out.push_str("# HELP k8s_netinspect_pods Pods in the analyzed snapshot.\n");
    out.push_str("# TYPE k8s_netinspect_pods gauge\n");
    out.push_str(&format!("k8s_netinspect_pods {}\n", report.summary.pods));
    out
}
