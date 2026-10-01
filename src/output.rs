//! Report rendering. `text` is for humans, `json` is the stable machine
//! contract (see `model::Report`).

use clap::ValueEnum;
use colored::*;

use crate::errors::{NetInspectError, NetInspectResult};
use crate::model::{Finding, Report, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

pub fn render(report: &Report, format: OutputFormat) -> NetInspectResult<String> {
    match format {
        OutputFormat::Text => Ok(render_text(report)),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|e| NetInspectError::Runtime(format!("Failed to serialize report: {e}"))),
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
