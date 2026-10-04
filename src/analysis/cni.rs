//! CNI detection and health, computed from a snapshot.
//!
//! Primary signal: the CNI agent DaemonSet (name or container image). That is
//! what actually programs the dataplane, and it carries version and rollout
//! health. Node annotations are only a fallback, for distributions that embed
//! the CNI in the node agent (k3s' built-in flannel has no DaemonSet).

use k8s_openapi::api::apps::v1::DaemonSet;

use crate::model::{CniPlugin, CniRole, Finding, Severity};
use crate::snapshot::ClusterSnapshot;

struct Signature {
    name: &'static str,
    role: CniRole,
    /// Exact DaemonSet names.
    daemon_sets: &'static [&'static str],
    /// Substrings of a container image repository path.
    images: &'static [&'static str],
    /// Substrings of node annotation keys (fallback only).
    node_annotations: &'static [&'static str],
}

/// Order matters only for display. Canal is listed before Calico/Flannel
/// because it ships both images.
const SIGNATURES: &[Signature] = &[
    Signature {
        name: "Cilium",
        role: CniRole::Primary,
        daemon_sets: &["cilium"],
        images: &["/cilium/cilium", "cilium/cilium"],
        node_annotations: &["io.cilium", "cilium.io"],
    },
    Signature {
        name: "Canal",
        role: CniRole::Primary,
        daemon_sets: &["canal", "rke2-canal"],
        images: &[],
        node_annotations: &[],
    },
    Signature {
        name: "Calico",
        role: CniRole::Primary,
        daemon_sets: &["calico-node"],
        images: &["calico/node"],
        node_annotations: &["projectcalico.org"],
    },
    Signature {
        name: "Flannel",
        role: CniRole::Primary,
        daemon_sets: &["kube-flannel-ds", "kube-flannel", "flannel"],
        images: &["flannel/flannel", "flannelcni/flannel", "coreos/flannel"],
        node_annotations: &["flannel.alpha.coreos.com"],
    },
    Signature {
        name: "Weave Net",
        role: CniRole::Primary,
        daemon_sets: &["weave-net"],
        images: &["weaveworks/weave-kube", "weave-kube"],
        node_annotations: &["weave.works"],
    },
    Signature {
        name: "AWS VPC CNI",
        role: CniRole::Primary,
        daemon_sets: &["aws-node"],
        images: &["amazon-k8s-cni", "amazon/aws-network-policy-agent"],
        node_annotations: &[],
    },
    Signature {
        name: "Azure CNI",
        role: CniRole::Primary,
        daemon_sets: &["azure-cns", "azure-cni", "azure-cni-networkmonitor"],
        images: &["azure-cns", "azure-cni"],
        node_annotations: &[],
    },
    Signature {
        name: "GKE Dataplane V2",
        role: CniRole::Primary,
        daemon_sets: &["anetd"],
        images: &[],
        node_annotations: &[],
    },
    Signature {
        name: "GKE netd",
        role: CniRole::Primary,
        daemon_sets: &["netd"],
        images: &[],
        node_annotations: &[],
    },
    Signature {
        name: "Antrea",
        role: CniRole::Primary,
        daemon_sets: &["antrea-agent"],
        images: &["antrea/antrea"],
        node_annotations: &[],
    },
    Signature {
        name: "OVN-Kubernetes",
        role: CniRole::Primary,
        daemon_sets: &["ovnkube-node"],
        images: &["ovn-kubernetes", "ovn-kube"],
        node_annotations: &["k8s.ovn.org"],
    },
    Signature {
        name: "kube-router",
        role: CniRole::Primary,
        daemon_sets: &["kube-router"],
        images: &["cloudnativelabs/kube-router"],
        node_annotations: &[],
    },
    Signature {
        name: "kindnet",
        role: CniRole::Primary,
        daemon_sets: &["kindnet"],
        images: &["kindest/kindnetd"],
        node_annotations: &[],
    },
    Signature {
        name: "Multus",
        role: CniRole::Meta,
        daemon_sets: &["kube-multus-ds", "multus"],
        images: &["k8snetworkplumbingwg/multus"],
        node_annotations: &[],
    },
    Signature {
        name: "Istio CNI",
        role: CniRole::Chained,
        daemon_sets: &["istio-cni-node"],
        images: &["istio/install-cni"],
        node_annotations: &[],
    },
    Signature {
        name: "Linkerd CNI",
        role: CniRole::Chained,
        daemon_sets: &["linkerd-cni"],
        images: &["linkerd/cni-plugin"],
        node_annotations: &[],
    },
];

/// Detect CNI plugins present in the snapshot.
pub fn detect(snapshot: &ClusterSnapshot) -> Vec<CniPlugin> {
    let mut plugins: Vec<CniPlugin> = Vec::new();

    for ds in &snapshot.daemon_sets {
        let Some(sig) = match_daemon_set(ds) else {
            continue;
        };
        // One plugin per name: a cluster may run several DaemonSets of the
        // same CNI (per-arch, per-node-pool); keep the worst rollout.
        let candidate = plugin_from_daemon_set(sig, ds);
        match plugins.iter_mut().find(|p| p.name == sig.name) {
            Some(existing) => {
                if missing(&candidate) > missing(existing) {
                    *existing = candidate;
                }
            }
            None => plugins.push(candidate),
        }
    }

    // Canal bundles Calico policy + Flannel networking; don't double-report.
    if plugins.iter().any(|p| p.name == "Canal") {
        plugins.retain(|p| p.name != "Calico" && p.name != "Flannel");
    }

    // Annotation fallback only when no primary CNI DaemonSet was identified.
    if !plugins.iter().any(|p| p.role == CniRole::Primary) {
        for sig in SIGNATURES.iter().filter(|s| !s.node_annotations.is_empty()) {
            let hit = snapshot.nodes.iter().any(|n| {
                n.metadata.annotations.as_ref().is_some_and(|a| {
                    a.keys()
                        .any(|k| sig.node_annotations.iter().any(|needle| k.contains(needle)))
                })
            });
            if hit {
                plugins.push(CniPlugin {
                    name: sig.name.to_string(),
                    role: sig.role,
                    version: None,
                    source: "node-annotation".to_string(),
                    desired: None,
                    ready: None,
                });
            }
        }
    }

    plugins
}

/// Findings about the CNI layer itself.
pub fn analyze(snapshot: &ClusterSnapshot, plugins: &[CniPlugin]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let primaries: Vec<&CniPlugin> = plugins
        .iter()
        .filter(|p| p.role == CniRole::Primary)
        .collect();

    if primaries.is_empty() {
        if snapshot.nodes.is_empty() && !snapshot.is_unknown("nodes") {
            // Nothing to detect on; the node analyzer reports the empty cluster.
        } else if snapshot.is_unknown("daemonsets") {
            findings.push(
                Finding::new(
                    "CNI-001",
                    Severity::Info,
                    "cni",
                    "CNI could not be identified",
                    "DaemonSets could not be listed and no node annotation identifies a CNI.",
                )
                .remediation(
                    "Grant list on daemonsets.apps (at least in kube-system) to identify the CNI.",
                ),
            );
        } else {
            findings.push(
                Finding::new(
                    "CNI-001",
                    Severity::Warning,
                    "cni",
                    "No CNI plugin detected",
                    "No known CNI agent DaemonSet or node annotation was found. Pods will stay \
                     in ContainerCreating without a CNI; if this cluster uses an unlisted plugin, \
                     this is a detection gap rather than a fault.",
                )
                .remediation("Check: kubectl get daemonsets -A; ls /etc/cni/net.d on a node"),
            );
        }
    }

    if primaries.len() > 1 {
        let names: Vec<&str> = primaries.iter().map(|p| p.name.as_str()).collect();
        findings.push(
            Finding::new(
                "CNI-003",
                Severity::Warning,
                "cni",
                "Multiple primary CNI plugins detected",
                format!(
                    "Found {}. Two plugins competing for pod networking usually means a \
                     half-finished migration; which one a node uses depends on file order in \
                     /etc/cni/net.d.",
                    names.join(", ")
                ),
            )
            .remediation(
                "Remove the DaemonSet and CNI config of the plugin you migrated away from.",
            ),
        );
    }

    for p in plugins {
        let (Some(desired), Some(ready)) = (p.desired, p.ready) else {
            continue;
        };
        if desired > 0 && ready < desired {
            let severity = if ready == 0 {
                Severity::Critical
            } else {
                Severity::Error
            };
            findings.push(
                Finding::new(
                    "CNI-002",
                    severity,
                    "cni",
                    format!("{} agent is not ready on every node", p.name),
                    format!(
                        "{} of {} desired agent pods are ready. Pods on the affected nodes \
                         cannot get network set up or policy programmed.",
                        ready, desired
                    ),
                )
                .resource(p.source.clone())
                .remediation(format!(
                    "Check: kubectl -n {} get pods -o wide | grep -v Running; then kubectl logs \
                     on the failing agent pod",
                    p.source.split('/').nth(1).unwrap_or("kube-system")
                )),
            );
        }
    }

    findings
}

fn missing(p: &CniPlugin) -> i32 {
    p.desired.unwrap_or(0) - p.ready.unwrap_or(0)
}

fn match_daemon_set(ds: &DaemonSet) -> Option<&'static Signature> {
    let name = ds.metadata.name.as_deref().unwrap_or_default();
    if let Some(sig) = SIGNATURES.iter().find(|s| s.daemon_sets.contains(&name)) {
        return Some(sig);
    }
    let images = images_of(ds);
    SIGNATURES.iter().find(|s| {
        s.images
            .iter()
            .any(|needle| images.iter().any(|img| repo_of(img).contains(needle)))
    })
}

fn plugin_from_daemon_set(sig: &Signature, ds: &DaemonSet) -> CniPlugin {
    let ns = ds.metadata.namespace.as_deref().unwrap_or("default");
    let name = ds.metadata.name.as_deref().unwrap_or_default();
    let images = images_of(ds);
    // Prefer the image that matched the signature for the version tag.
    let version = images
        .iter()
        .find(|img| sig.images.iter().any(|n| repo_of(img).contains(n)))
        .or(images.first())
        .and_then(|img| tag_of(img));
    let status = ds.status.as_ref();
    CniPlugin {
        name: sig.name.to_string(),
        role: sig.role,
        version,
        source: format!("daemonset/{ns}/{name}"),
        desired: status.map(|s| s.desired_number_scheduled),
        ready: status.map(|s| s.number_ready),
    }
}

fn images_of(ds: &DaemonSet) -> Vec<&str> {
    ds.spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .map(|spec| {
            spec.containers
                .iter()
                .filter_map(|c| c.image.as_deref())
                .collect()
        })
        .unwrap_or_default()
}

/// Image reference without tag or digest.
fn repo_of(image: &str) -> &str {
    let no_digest = image.split('@').next().unwrap_or(image);
    // A ':' after the last '/' is a tag; one before it is a registry port.
    match no_digest.rfind(':') {
        Some(i) if !no_digest[i..].contains('/') => &no_digest[..i],
        _ => no_digest,
    }
}

/// Tag of an image reference, if it has a meaningful one.
fn tag_of(image: &str) -> Option<String> {
    let no_digest = image.split('@').next().unwrap_or(image);
    let i = no_digest.rfind(':')?;
    let tag = &no_digest[i + 1..];
    if tag.is_empty() || tag.contains('/') || tag == "latest" {
        return None;
    }
    Some(tag.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_parsing_handles_registry_ports_and_digests() {
        assert_eq!(
            repo_of("quay.io/cilium/cilium:v1.16.1@sha256:abc"),
            "quay.io/cilium/cilium"
        );
        assert_eq!(
            tag_of("quay.io/cilium/cilium:v1.16.1@sha256:abc").as_deref(),
            Some("v1.16.1")
        );
        assert_eq!(
            repo_of("registry.local:5000/calico/node"),
            "registry.local:5000/calico/node"
        );
        assert_eq!(tag_of("registry.local:5000/calico/node"), None);
        assert_eq!(
            tag_of("registry.local:5000/calico/node:v3.28.0").as_deref(),
            Some("v3.28.0")
        );
        assert_eq!(tag_of("flannel/flannel:latest"), None);
        assert_eq!(tag_of("flannel/flannel@sha256:abc"), None);
    }
}
