//! Structured diagnostic model: every check produces [`Finding`]s, and a
//! [`Report`] is what gets rendered (text) or serialized (JSON).

use serde::{Deserialize, Serialize};
use std::fmt;

/// How bad a finding is. Ordered: `Info < Warning < Error < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        })
    }
}

/// One diagnosed condition, with the evidence and a suggested next step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `CNI-002`. Safe to match on in CI.
    pub id: String,
    pub severity: Severity,
    /// Check family: `cni`, `node`, `collection`, ...
    pub category: String,
    pub title: String,
    /// What was observed, concretely.
    pub detail: String,
    /// `kind/namespace/name` (or `kind/name`) of the offending object.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remediation: Option<String>,
}

impl Finding {
    pub fn new(
        id: &str,
        severity: Severity,
        category: &str,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.to_string(),
            severity,
            category: category.to_string(),
            title: title.into(),
            detail: detail.into(),
            resource: None,
            remediation: None,
        }
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// A detected CNI plugin (or CNI-adjacent dataplane component).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniPlugin {
    pub name: String,
    /// `primary` plugins own pod networking; `chained`/`meta` plugins sit on top.
    pub role: CniRole,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,
    /// How it was identified: `daemonset/<ns>/<name>` or `node-annotation`.
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub desired: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ready: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CniRole {
    Primary,
    Chained,
    Meta,
}

/// Counts of what the report was computed from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub nodes: usize,
    pub pods: usize,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub namespace: Option<String>,
}

/// Full result of a `diagnose` run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub tool_version: String,
    pub summary: Summary,
    pub cni: Vec<CniPlugin>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Highest severity present, if any finding exists.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Human label for the detected CNI, matching the legacy one-line output.
    pub fn cni_label(&self) -> String {
        let primaries: Vec<&CniPlugin> = self
            .cni
            .iter()
            .filter(|p| p.role == CniRole::Primary)
            .collect();
        let pick = if primaries.is_empty() {
            self.cni.iter().collect::<Vec<_>>()
        } else {
            primaries
        };
        if pick.is_empty() {
            return "Unknown CNI".to_string();
        }
        pick.iter()
            .map(|p| match &p.version {
                Some(v) => format!("{} {}", p.name, v),
                None => p.name.clone(),
            })
            .collect::<Vec<_>>()
            .join(" + ")
    }
}
