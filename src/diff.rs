//! Compare two diagnoses: what is new, what got resolved, what changed.
//! Used by `diff <before> <after>` (incident before/after, upgrade
//! verification) and by `diagnose --watch` to print only deltas.

use colored::*;
use serde::Serialize;
use std::collections::BTreeMap;

use crate::model::{Finding, Report, Severity};

/// A finding present on both sides whose severity or evidence differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub before: Finding,
    pub after: Finding,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Diff {
    /// In `after` only.
    pub new: Vec<Finding>,
    /// In `before` only.
    pub resolved: Vec<Finding>,
    pub changed: Vec<Change>,
    /// Count of findings identical on both sides.
    pub unchanged: usize,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.resolved.is_empty() && self.changed.is_empty()
    }

    /// Worst severity among findings that are new or got more severe.
    pub fn worst_regression(&self) -> Option<Severity> {
        self.new
            .iter()
            .map(|f| f.severity)
            .chain(
                self.changed
                    .iter()
                    .filter(|c| c.after.severity > c.before.severity)
                    .map(|c| c.after.severity),
            )
            .max()
    }
}

/// What makes two findings "the same problem": rule, object and title. The
/// detail text may differ (e.g. "1 of 3 ready" → "2 of 3 ready").
type Identity = (String, Option<String>, String);

fn identity(f: &Finding) -> Identity {
    (f.id.clone(), f.resource.clone(), f.title.clone())
}

fn group(findings: &[Finding]) -> BTreeMap<Identity, Vec<&Finding>> {
    let mut map: BTreeMap<Identity, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        map.entry(identity(f)).or_default().push(f);
    }
    map
}

fn sort(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.resource.cmp(&b.resource))
    });
}

pub fn diff(before: &Report, after: &Report) -> Diff {
    let (old, new) = (group(&before.findings), group(&after.findings));
    let mut out = Diff::default();

    for (key, after_group) in &new {
        match old.get(key) {
            None => out.new.extend(after_group.iter().map(|f| (*f).clone())),
            // The usual case: one finding per identity on each side.
            Some(before_group) if before_group.len() == 1 && after_group.len() == 1 => {
                if before_group[0] == after_group[0] {
                    out.unchanged += 1;
                } else {
                    out.changed.push(Change {
                        before: before_group[0].clone(),
                        after: after_group[0].clone(),
                    });
                }
            }
            // Several findings share an identity (e.g. two bad backends on
            // one route): pair up identical ones, report the rest.
            Some(before_group) => {
                let mut remaining: Vec<&Finding> = before_group.clone();
                for f in after_group {
                    match remaining.iter().position(|b| b == f) {
                        Some(i) => {
                            remaining.swap_remove(i);
                            out.unchanged += 1;
                        }
                        None => out.new.push((*f).clone()),
                    }
                }
                out.resolved.extend(remaining.into_iter().cloned());
            }
        }
    }
    for (key, before_group) in &old {
        if !new.contains_key(key) {
            out.resolved
                .extend(before_group.iter().map(|f| (*f).clone()));
        }
    }

    sort(&mut out.new);
    sort(&mut out.resolved);
    out.changed.sort_by(|a, b| {
        b.after
            .severity
            .cmp(&a.after.severity)
            .then_with(|| a.after.id.cmp(&b.after.id))
            .then_with(|| a.after.resource.cmp(&b.after.resource))
    });
    out
}

fn line(f: &Finding) -> String {
    let resource = f
        .resource
        .as_deref()
        .map(|r| format!(" — {r}"))
        .unwrap_or_default();
    format!("[{}] {} {}{}", f.id, f.severity, f.title, resource)
}

pub fn render_text(d: &Diff) -> String {
    if d.is_empty() {
        return format!(
            "{} No changes ({} finding(s) unchanged)\n",
            "✓".green().bold(),
            d.unchanged
        );
    }
    let mut out = format!(
        "{} new, {} resolved, {} changed, {} unchanged\n",
        d.new.len(),
        d.resolved.len(),
        d.changed.len(),
        d.unchanged
    );
    for f in &d.new {
        out.push_str(&format!(
            "{} {}\n    {}\n",
            "+".red().bold(),
            line(f),
            f.detail
        ));
    }
    for c in &d.changed {
        out.push_str(&format!("{} {}\n", "~".yellow().bold(), line(&c.after)));
        if c.before.severity != c.after.severity {
            out.push_str(&format!(
                "    severity: {} → {}\n",
                c.before.severity, c.after.severity
            ));
        }
        if c.before.detail != c.after.detail {
            out.push_str(&format!(
                "    was: {}\n    now: {}\n",
                c.before.detail, c.after.detail
            ));
        }
    }
    for f in &d.resolved {
        out.push_str(&format!("{} {}\n", "-".green().bold(), line(f)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            tool_version: "t".into(),
            summary: Default::default(),
            cni: vec![],
            service_proxy: None,
            findings,
        }
    }

    fn f(id: &str, sev: Severity, resource: &str, detail: &str) -> Finding {
        Finding::new(id, sev, "x", format!("title {id}"), detail).resource(resource)
    }

    #[test]
    fn classifies_new_resolved_changed_and_unchanged() {
        use Severity::*;
        let before = report(vec![
            f("A-001", Error, "pod/a", "same"),
            f("B-001", Warning, "pod/b", "1 of 3 ready"),
            f("C-001", Error, "pod/c", "gone later"),
        ]);
        let after = report(vec![
            f("A-001", Error, "pod/a", "same"),
            f("B-001", Critical, "pod/b", "0 of 3 ready"),
            f("D-001", Info, "pod/d", "brand new"),
        ]);
        let d = diff(&before, &after);
        assert_eq!(d.unchanged, 1);
        assert_eq!(
            d.new.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            vec!["D-001"]
        );
        assert_eq!(d.resolved[0].id, "C-001");
        assert_eq!(d.changed.len(), 1);
        assert_eq!(
            (d.changed[0].before.severity, d.changed[0].after.severity),
            (Warning, Critical)
        );
        // New Info, and B got worse to Critical.
        assert_eq!(d.worst_regression(), Some(Critical));

        // The same rule on a different object is a different problem.
        let d = diff(
            &report(vec![f("A-001", Error, "pod/a", "x")]),
            &report(vec![f("A-001", Error, "pod/z", "x")]),
        );
        assert_eq!((d.new.len(), d.resolved.len(), d.changed.len()), (1, 1, 0));

        let same = diff(&before, &before);
        assert!(same.is_empty());
        assert_eq!(same.unchanged, 3);
        assert_eq!(same.worst_regression(), None);
    }

    #[test]
    fn an_improvement_is_a_change_but_not_a_regression() {
        use Severity::*;
        let d = diff(
            &report(vec![f("B-001", Critical, "pod/b", "0 of 3")]),
            &report(vec![f("B-001", Warning, "pod/b", "2 of 3")]),
        );
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.worst_regression(), None);
    }

    #[test]
    fn duplicate_identities_are_paired_by_content() {
        use Severity::*;
        let before = report(vec![
            f("G-002", Error, "route/r", "backend cart missing"),
            f("G-002", Error, "route/r", "backend api port 9999"),
        ]);
        let after = report(vec![
            f("G-002", Error, "route/r", "backend api port 9999"),
            f("G-002", Error, "route/r", "backend pay missing"),
        ]);
        let d = diff(&before, &after);
        assert_eq!(d.unchanged, 1);
        assert_eq!(d.new[0].detail, "backend pay missing");
        assert_eq!(d.resolved[0].detail, "backend cart missing");
    }
}
