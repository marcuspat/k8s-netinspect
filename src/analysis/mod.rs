//! Pure analysis over a [`ClusterSnapshot`]: no I/O, no clock, no API calls.
//! Each submodule owns one check family and a block of stable finding ids.

pub mod cni;
pub mod node;

use crate::model::{Finding, Report, Severity, Summary};
use crate::snapshot::ClusterSnapshot;

/// Run every analyzer and assemble the report. Findings are ordered most
/// severe first, then by id and resource, so output is deterministic.
pub fn analyze(snapshot: &ClusterSnapshot) -> Report {
    let plugins = cni::detect(snapshot);

    let mut findings = Vec::new();
    findings.extend(collection_findings(snapshot));
    findings.extend(cni::analyze(snapshot, &plugins));
    findings.extend(node::analyze(snapshot));

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.resource.cmp(&b.resource))
    });

    Report {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        summary: Summary {
            nodes: snapshot.nodes.len(),
            pods: snapshot.pods.len(),
            namespace: snapshot.namespace.clone(),
        },
        cni: plugins,
        findings,
    }
}

/// A list that failed to collect means checks depending on it were skipped;
/// say so instead of silently reporting a clean bill of health.
fn collection_findings(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    snapshot
        .collection_errors
        .iter()
        .map(|e| {
            Finding::new(
                "COLLECT-001",
                Severity::Info,
                "collection",
                format!("Could not collect {}", e.resource),
                format!("{} — checks that depend on it were skipped.", e.message),
            )
            .resource(e.resource.clone())
            .remediation(format!(
                "Grant get/list on {} to run those checks.",
                e.resource
            ))
        })
        .collect()
}
