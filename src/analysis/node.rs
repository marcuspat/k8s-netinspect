//! Node-level network health.

use crate::model::{Finding, Severity};
use crate::snapshot::ClusterSnapshot;

pub fn analyze(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();

    if snapshot.nodes.is_empty() && !snapshot.is_unknown("nodes") {
        findings.push(Finding::new(
            "NODE-001",
            Severity::Warning,
            "node",
            "No nodes found in cluster",
            "The node list is empty, so no workload can be scheduled or networked.",
        ));
        return findings;
    }

    for node in &snapshot.nodes {
        let name = node.metadata.name.as_deref().unwrap_or("<unnamed>");
        let conditions = node
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_deref())
            .unwrap_or_default();

        for c in conditions {
            let reason = c.reason.as_deref().unwrap_or("no reason given");
            let message = c.message.as_deref().unwrap_or("");
            match (c.type_.as_str(), c.status.as_str()) {
                // Set by the CNI / cloud route controller when node routes are missing.
                ("NetworkUnavailable", "True") => findings.push(
                    Finding::new(
                        "NODE-002",
                        Severity::Error,
                        "node",
                        "Node network is unavailable",
                        format!("NetworkUnavailable=True ({reason}) {message}")
                            .trim()
                            .to_string(),
                    )
                    .resource(format!("node/{name}"))
                    .remediation(
                        "The CNI agent or cloud route controller has not configured this node. \
                         Check the CNI agent pod on it and the node's podCIDR/route allocation.",
                    ),
                ),
                ("Ready", status) if status != "True" => findings.push(
                    Finding::new(
                        "NODE-003",
                        Severity::Error,
                        "node",
                        "Node is not Ready",
                        format!("Ready={status} ({reason}) {message}")
                            .trim()
                            .to_string(),
                    )
                    .resource(format!("node/{name}"))
                    .remediation(format!("Check: kubectl describe node {name}")),
                ),
                _ => {}
            }
        }
    }

    findings
}
