//! Service proxy: what turns a ClusterIP into backend pods on each node —
//! kube-proxy (and in which mode), or a CNI that replaces it.

use k8s_openapi::api::apps::v1::DaemonSet;

use crate::model::{CniPlugin, Finding, ServiceProxy, Severity};
use crate::snapshot::ClusterSnapshot;

const SYSTEM_NAMESPACE: &str = "kube-system";
const KUBE_PROXY: &str = "kube-proxy";
/// kube-proxy may trail the API server / kubelet by this many minor versions.
const MAX_MINOR_SKEW: u32 = 3;

/// CNIs that implement Services themselves, with no kube-proxy.
const ALWAYS_REPLACES: &[&str] = &["kube-router", "GKE Dataplane V2", "OVN-Kubernetes"];

fn kube_proxy_daemon_set(snapshot: &ClusterSnapshot) -> Option<&DaemonSet> {
    snapshot.daemon_sets.iter().find(|d| {
        d.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE)
            && d.metadata
                .name
                .as_deref()
                .is_some_and(|n| n == KUBE_PROXY || n.starts_with("kube-proxy-"))
    })
}

/// kube-proxy as static pods (GKE, RKE2), which have no DaemonSet.
fn kube_proxy_static_pods(snapshot: &ClusterSnapshot) -> usize {
    snapshot
        .pods
        .iter()
        .filter(|p| {
            p.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE)
                && p.metadata
                    .name
                    .as_deref()
                    .is_some_and(|n| n.starts_with("kube-proxy-"))
        })
        .count()
}

/// Cilium's `kube-proxy-replacement` setting, when its ConfigMap was collected.
fn cilium_replaces_kube_proxy(snapshot: &ClusterSnapshot) -> bool {
    snapshot
        .config_maps
        .iter()
        .find(|c| c.metadata.name.as_deref() == Some("cilium-config"))
        .and_then(|c| c.data.as_ref())
        .and_then(|d| d.get("kube-proxy-replacement"))
        .is_some_and(|v| matches!(v.trim(), "true" | "strict"))
}

fn replacement(snapshot: &ClusterSnapshot, plugins: &[CniPlugin]) -> Option<String> {
    if let Some(p) = plugins
        .iter()
        .find(|p| ALWAYS_REPLACES.contains(&p.name.as_str()))
    {
        return Some(p.name.clone());
    }
    (plugins.iter().any(|p| p.name == "Cilium") && cilium_replaces_kube_proxy(snapshot))
        .then(|| "Cilium (kube-proxy replacement)".to_string())
}

/// kube-proxy mode from its ConfigMap (`config.conf`, a KubeProxyConfiguration).
/// An empty `mode` means the platform default, which is iptables on Linux.
pub fn kube_proxy_mode(snapshot: &ClusterSnapshot) -> Option<String> {
    let data = snapshot
        .config_maps
        .iter()
        .find(|c| c.metadata.name.as_deref() == Some(KUBE_PROXY))?
        .data
        .as_ref()?;
    let conf = data.get("config.conf").or_else(|| data.get("config"))?;
    conf.lines()
        // Top-level key only: nested blocks (ipvs:, iptables:) are indented.
        .find_map(|l| l.strip_prefix("mode:"))
        .map(|v| {
            let v = v.split('#').next().unwrap_or_default().trim();
            let v = v.trim_matches(|c| c == '"' || c == '\'');
            if v.is_empty() {
                "iptables".to_string()
            } else {
                v.to_lowercase()
            }
        })
}

fn image_tag(ds: &DaemonSet) -> Option<String> {
    let image = ds
        .spec
        .as_ref()?
        .template
        .spec
        .as_ref()?
        .containers
        .first()?
        .image
        .as_deref()?;
    let no_digest = image.split('@').next()?;
    let (_, tag) = no_digest.rsplit_once(':')?;
    (!tag.contains('/') && tag != "latest").then(|| tag.to_string())
}

pub fn detect(snapshot: &ClusterSnapshot, plugins: &[CniPlugin]) -> Option<ServiceProxy> {
    if let Some(ds) = kube_proxy_daemon_set(snapshot) {
        return Some(ServiceProxy {
            implementation: KUBE_PROXY.to_string(),
            mode: kube_proxy_mode(snapshot),
            version: image_tag(ds),
        });
    }
    if kube_proxy_static_pods(snapshot) > 0 {
        return Some(ServiceProxy {
            implementation: "kube-proxy (static pods)".to_string(),
            mode: kube_proxy_mode(snapshot),
            version: None,
        });
    }
    replacement(snapshot, plugins).map(|implementation| ServiceProxy {
        implementation,
        mode: None,
        version: None,
    })
}

pub fn analyze(
    snapshot: &ClusterSnapshot,
    plugins: &[CniPlugin],
    proxy: Option<&ServiceProxy>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if snapshot.is_unknown("daemonsets") || snapshot.nodes.is_empty() {
        return findings;
    }

    let ds = kube_proxy_daemon_set(snapshot);

    // PROXY-001: kube-proxy rollout health.
    if let Some(ds) = ds {
        let name = ds.metadata.name.as_deref().unwrap_or(KUBE_PROXY);
        if let Some(status) = ds.status.as_ref() {
            let (desired, ready) = (status.desired_number_scheduled, status.number_ready);
            if desired > 0 && ready < desired {
                findings.push(
                    Finding::new(
                        "PROXY-001",
                        if ready == 0 {
                            Severity::Critical
                        } else {
                            Severity::Error
                        },
                        "proxy",
                        "kube-proxy is not ready on every node",
                        format!(
                            "{ready} of {desired} kube-proxy pods are ready. On the other nodes \
                             Service rules are stale or missing, so ClusterIP and NodePort \
                             traffic from or through them fails or reaches removed backends."
                        ),
                    )
                    .resource(format!("daemonset/kube-system/{name}"))
                    .remediation(
                        "Check: kubectl -n kube-system get pods -l k8s-app=kube-proxy -o wide; \
                         kubectl -n kube-system logs <failing kube-proxy pod>",
                    ),
                );
            }
        }
    }

    // PROXY-002: nothing appears to implement Services.
    if proxy.is_none() && !embeds_kube_proxy(snapshot) {
        // Static-pod detection needs kube-system pods in the snapshot.
        let pods_visible = !snapshot.is_unknown("pods")
            && snapshot
                .namespace
                .as_deref()
                .is_none_or(|ns| ns == SYSTEM_NAMESPACE);
        if pods_visible {
            findings.push(
                Finding::new(
                    "PROXY-002",
                    Severity::Warning,
                    "proxy",
                    "No Service proxy detected",
                    "No kube-proxy DaemonSet or static pods were found, and the detected CNI is \
                     not known to replace kube-proxy. Without one, ClusterIPs are not routable. \
                     If your distribution embeds kube-proxy in the node agent, this is a \
                     detection gap rather than a fault.",
                )
                .remediation(
                    "Check: kubectl -n kube-system get ds,pods | grep -i proxy; for Cilium, \
                     kubectl -n kube-system get cm cilium-config -o yaml | grep \
                     kube-proxy-replacement",
                ),
            );
        }
    }

    // PROXY-003: kube-proxy next to a full replacement.
    if ds.is_some() {
        if let Some(other) = replacement(snapshot, plugins) {
            findings.push(
                Finding::new(
                    "PROXY-003",
                    Severity::Warning,
                    "proxy",
                    "kube-proxy runs alongside a kube-proxy replacement",
                    format!(
                        "{other} already implements Services, and a kube-proxy DaemonSet is \
                         also deployed. Both program Service handling on every node; the \
                         duplicate rules add overhead and make behaviour depend on which one \
                         sees a packet first."
                    ),
                )
                .resource("daemonset/kube-system/kube-proxy")
                .remediation(
                    "Remove kube-proxy (and clean its iptables/ipvs rules) once the replacement \
                     is confirmed healthy, or disable the replacement.",
                ),
            );
        }
    }

    // PROXY-004: version skew.
    if let Some(proxy_version) = ds.and_then(image_tag) {
        if let Some(proxy_minor) = minor(&proxy_version) {
            let resource = "daemonset/kube-system/kube-proxy";
            let fix = "Upgrade order: control plane first, then kube-proxy, then kubelets. \
                       Align kube-proxy with the control plane version.";
            let api_minor = snapshot.cluster_version.as_deref().and_then(minor);
            if let Some(api) = api_minor.filter(|api| proxy_minor > *api) {
                findings.push(
                    Finding::new(
                        "PROXY-004",
                        Severity::Warning,
                        "proxy",
                        "kube-proxy is newer than the API server",
                        format!(
                            "kube-proxy {proxy_version} is newer than the API server (minor \
                             {api}). kube-proxy must not be newer than kube-apiserver."
                        ),
                    )
                    .resource(resource)
                    .remediation(fix),
                );
            } else if let Some(api) =
                api_minor.filter(|api| api.saturating_sub(proxy_minor) > MAX_MINOR_SKEW)
            {
                findings.push(
                    Finding::new(
                        "PROXY-004",
                        Severity::Warning,
                        "proxy",
                        "kube-proxy is too old for the API server",
                        format!(
                            "kube-proxy {proxy_version} is {} minor versions behind the API \
                             server (minor {api}); the supported skew is {MAX_MINOR_SKEW}.",
                            api - proxy_minor
                        ),
                    )
                    .resource(resource)
                    .remediation(fix),
                );
            }

            // Against the kubelets it shares nodes with.
            let mut skewed: Vec<(String, String)> = snapshot
                .nodes
                .iter()
                .filter_map(|n| {
                    let version = n
                        .status
                        .as_ref()?
                        .node_info
                        .as_ref()?
                        .kubelet_version
                        .clone();
                    let m = minor(&version)?;
                    (m.abs_diff(proxy_minor) > MAX_MINOR_SKEW)
                        .then(|| (n.metadata.name.clone().unwrap_or_default(), version))
                })
                .collect();
            skewed.sort();
            if let Some((node, version)) = skewed.first() {
                findings.push(
                    Finding::new(
                        "PROXY-004",
                        Severity::Warning,
                        "proxy",
                        "kube-proxy and kubelet versions are too far apart",
                        format!(
                            "kube-proxy {proxy_version} differs by more than {MAX_MINOR_SKEW} \
                             minor versions from the kubelet on {} node(s), e.g. {node} \
                             ({version}).",
                            skewed.len()
                        ),
                    )
                    .resource(resource)
                    .remediation(fix),
                );
            }
        }
    }

    findings
}

/// k3s runs kube-proxy inside the k3s process: no DaemonSet, no pods.
fn embeds_kube_proxy(snapshot: &ClusterSnapshot) -> bool {
    snapshot.nodes.iter().any(|n| {
        n.status
            .as_ref()
            .and_then(|s| s.node_info.as_ref())
            .is_some_and(|i| i.kubelet_version.contains("+k3s"))
    })
}

/// Minor version from `v1.30.4`, `1.30`, `v1.30.4-eks-a1b2c3`, `v1.29.8+k3s1`.
pub fn minor(version: &str) -> Option<u32> {
    let v = version.trim_start_matches('v');
    let mut parts = v.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    if major != 1 {
        return None;
    }
    let minor: String = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    minor.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minor_versions() {
        assert_eq!(minor("v1.30.4"), Some(30));
        assert_eq!(minor("1.28"), Some(28));
        assert_eq!(minor("v1.29.8+k3s1"), Some(29));
        assert_eq!(minor("v1.31.0-eks-a737599"), Some(31));
        assert_eq!(minor("v1.30+"), Some(30));
        assert_eq!(minor("3.28.0"), None, "not a Kubernetes version");
        assert_eq!(minor("latest"), None);
    }
}
