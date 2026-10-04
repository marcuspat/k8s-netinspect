//! Cluster DNS health: is CoreDNS running, reachable through its Service,
//! and configured so that cluster and external names can resolve?

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::model::{Finding, Severity};
use crate::snapshot::ClusterSnapshot;

const SYSTEM_NAMESPACE: &str = "kube-system";
const DNS_LABEL: (&str, &str) = ("k8s-app", "kube-dns");
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";
/// Well-known names for the cluster DNS workload across distributions.
const DNS_WORKLOAD_NAMES: &[&str] = &["coredns", "kube-dns", "rke2-coredns-rke2-coredns"];
const NODE_LOCAL_DNS: &str = "node-local-dns";

pub fn analyze(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(workload_health(snapshot));
    findings.extend(service_health(snapshot));
    findings.extend(corefile_checks(snapshot));
    findings.extend(node_local_dns(snapshot));
    findings
}

fn is_dns_workload(name: Option<&str>, labels: Option<&BTreeMap<String, String>>) -> bool {
    name.is_some_and(|n| DNS_WORKLOAD_NAMES.contains(&n))
        || labels
            .and_then(|l| l.get(DNS_LABEL.0))
            .is_some_and(|v| v == DNS_LABEL.1)
}

/// DNS-001 / DNS-002: the DNS Deployment (or DaemonSet) and its replicas.
fn workload_health(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    if snapshot.is_unknown("deployments") {
        return findings;
    }

    let deployments: Vec<&Deployment> = snapshot
        .deployments
        .iter()
        .filter(|d| d.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE))
        .filter(|d| is_dns_workload(d.metadata.name.as_deref(), d.metadata.labels.as_ref()))
        .collect();
    let daemon_sets: Vec<&DaemonSet> = snapshot
        .daemon_sets
        .iter()
        .filter(|d| d.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE))
        .filter(|d| is_dns_workload(d.metadata.name.as_deref(), d.metadata.labels.as_ref()))
        .collect();

    if deployments.is_empty() && daemon_sets.is_empty() {
        // An empty cluster snapshot (no nodes) is reported elsewhere.
        if !snapshot.nodes.is_empty() && !snapshot.is_unknown("daemonsets") {
            findings.push(
                Finding::new(
                    "DNS-002",
                    Severity::Warning,
                    "dns",
                    "No cluster DNS workload found",
                    "No Deployment or DaemonSet in kube-system is named coredns/kube-dns or \
                     labelled k8s-app=kube-dns. If DNS runs under another name this is a \
                     detection gap; otherwise Service names cannot resolve.",
                )
                .remediation("Check: kubectl -n kube-system get deploy,ds,pods | grep -i dns"),
            );
        }
        return findings;
    }

    for d in deployments {
        let name = d.metadata.name.as_deref().unwrap_or("<unnamed>");
        let desired = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
        let ready = d
            .status
            .as_ref()
            .and_then(|s| s.ready_replicas)
            .unwrap_or(0);
        if let Some(f) = replica_finding(desired, ready, format!("deployment/kube-system/{name}")) {
            findings.push(f);
        }
    }
    for d in daemon_sets {
        let name = d.metadata.name.as_deref().unwrap_or("<unnamed>");
        let (desired, ready) = d
            .status
            .as_ref()
            .map(|s| (s.desired_number_scheduled, s.number_ready))
            .unwrap_or((0, 0));
        if let Some(f) = replica_finding(desired, ready, format!("daemonset/kube-system/{name}")) {
            findings.push(f);
        }
    }
    findings
}

fn replica_finding(desired: i32, ready: i32, resource: String) -> Option<Finding> {
    let name = resource.rsplit('/').next().unwrap_or_default().to_string();
    let fix = format!(
        "Check: kubectl -n kube-system get pods -l k8s-app=kube-dns; kubectl -n kube-system \
         logs -l k8s-app=kube-dns --tail=50 ({name})"
    );
    if desired == 0 {
        return Some(
            Finding::new(
                "DNS-001",
                Severity::Critical,
                "dns",
                "Cluster DNS is scaled to zero",
                "The DNS workload wants 0 replicas, so nothing answers DNS queries.",
            )
            .resource(resource)
            .remediation(format!(
                "Scale it back up: kubectl -n kube-system scale deployment {name} --replicas=2"
            )),
        );
    }
    if ready == 0 {
        return Some(
            Finding::new(
                "DNS-001",
                Severity::Critical,
                "dns",
                "Cluster DNS has no ready replicas",
                format!(
                    "0 of {desired} replicas are ready. Every lookup of a Service name fails \
                     until one becomes ready."
                ),
            )
            .resource(resource)
            .remediation(fix),
        );
    }
    if ready < desired {
        return Some(
            Finding::new(
                "DNS-001",
                Severity::Warning,
                "dns",
                "Cluster DNS is running degraded",
                format!(
                    "{ready} of {desired} replicas are ready. DNS still answers, with reduced \
                     capacity and redundancy."
                ),
            )
            .resource(resource)
            .remediation(fix),
        );
    }
    None
}

/// DNS-003 / DNS-004: the kube-dns Service and its endpoints. Needs
/// kube-system Services in the snapshot, i.e. not scoped elsewhere.
fn service_health(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    let in_scope = snapshot
        .namespace
        .as_deref()
        .is_none_or(|ns| ns == SYSTEM_NAMESPACE);
    if !in_scope || snapshot.is_unknown("services") {
        return findings;
    }
    // Only meaningful once we know a DNS workload should exist.
    let dns_expected = snapshot
        .deployments
        .iter()
        .any(|d| is_dns_workload(d.metadata.name.as_deref(), d.metadata.labels.as_ref()))
        || snapshot.daemon_sets.iter().any(|d| {
            d.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE)
                && is_dns_workload(d.metadata.name.as_deref(), d.metadata.labels.as_ref())
        });
    if !dns_expected {
        return findings;
    }

    let service = snapshot.services.iter().find(|s| {
        s.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE)
            && is_dns_workload(s.metadata.name.as_deref(), s.metadata.labels.as_ref())
    });
    let Some(service) = service else {
        findings.push(
            Finding::new(
                "DNS-004",
                Severity::Error,
                "dns",
                "Cluster DNS Service not found",
                "A DNS workload runs in kube-system but no kube-dns Service exposes it. Pods \
                 are configured with the Service's ClusterIP as their resolver, so lookups \
                 time out.",
            )
            .remediation("Check: kubectl -n kube-system get service kube-dns"),
        );
        return findings;
    };
    let name = service.metadata.name.as_deref().unwrap_or("kube-dns");

    if snapshot.is_unknown("endpointslices") {
        return findings;
    }
    let ready_endpoints = snapshot
        .endpoint_slices
        .iter()
        .filter(|s| {
            s.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE)
                && s.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get(SERVICE_NAME_LABEL))
                    .map(String::as_str)
                    == Some(name)
        })
        .flat_map(|s| s.endpoints.iter().flatten())
        .filter(|e| {
            !e.addresses.is_empty() && e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true)
        })
        .count();
    if ready_endpoints == 0 {
        findings.push(
            Finding::new(
                "DNS-003",
                Severity::Critical,
                "dns",
                "Cluster DNS Service has no ready endpoints",
                "No EndpointSlice for the DNS Service lists a ready address, so queries to the \
                 cluster DNS IP are dropped.",
            )
            .resource(format!("service/kube-system/{name}"))
            .remediation(format!(
                "Check: kubectl -n kube-system get endpointslices -l {SERVICE_NAME_LABEL}={name}"
            )),
        );
    }
    findings
}

/// One `zones { plugins }` block of a Corefile.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerBlock {
    pub zones: Vec<String>,
    /// (plugin name, arguments on the same line)
    pub plugins: Vec<(String, Vec<String>)>,
}

/// Minimal Corefile parser: server blocks and their top-level plugin lines.
/// Nested plugin blocks are skipped; `#` starts a comment.
pub fn parse_corefile(corefile: &str) -> Vec<ServerBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<ServerBlock> = None;
    let mut depth = 0usize;

    for raw in corefile.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let opens = line.ends_with('{');
        let body = line.trim_end_matches('{').trim();
        let tokens: Vec<String> = body.split_whitespace().map(str::to_string).collect();

        if line == "}" {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                if let Some(b) = current.take() {
                    blocks.push(b);
                }
            }
            continue;
        }
        match depth {
            0 if opens => {
                current = Some(ServerBlock {
                    zones: tokens,
                    plugins: Vec::new(),
                });
                depth = 1;
            }
            1 => {
                if let (Some(block), Some((name, args))) = (current.as_mut(), tokens.split_first())
                {
                    block.plugins.push((name.clone(), args.to_vec()));
                }
                if opens {
                    depth += 1;
                }
            }
            _ if opens => depth += 1,
            _ => {}
        }
    }
    blocks
}

/// DNS-005..007: static checks on the CoreDNS Corefile.
fn corefile_checks(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(corefile) = snapshot
        .config_maps
        .iter()
        .find(|c| c.metadata.name.as_deref() == Some("coredns"))
        .and_then(|c| c.data.as_ref())
        .and_then(|d| d.get("Corefile"))
    else {
        return findings;
    };
    let resource = "configmap/kube-system/coredns";
    let blocks = parse_corefile(corefile);
    if blocks.is_empty() {
        return findings;
    }
    let plugins = || blocks.iter().flat_map(|b| b.plugins.iter());

    if !plugins().any(|(name, _)| name == "kubernetes") {
        findings.push(
            Finding::new(
                "DNS-005",
                Severity::Error,
                "dns",
                "Corefile has no kubernetes plugin",
                "No server block enables the `kubernetes` plugin, so CoreDNS does not answer \
                 for cluster.local: Service and pod names do not resolve.",
            )
            .resource(resource)
            .remediation(
                "Restore the default block: kubernetes cluster.local in-addr.arpa ip6.arpa { \
                 pods insecure; fallthrough in-addr.arpa ip6.arpa }",
            ),
        );
    }

    // Addresses that would send CoreDNS's upstream queries back to itself.
    let own_ips: Vec<IpAddr> = snapshot
        .services
        .iter()
        .filter(|s| {
            s.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE)
                && is_dns_workload(s.metadata.name.as_deref(), s.metadata.labels.as_ref())
        })
        .filter_map(|s| s.spec.as_ref())
        .flat_map(|s| s.cluster_ips.iter().flatten().chain(s.cluster_ip.iter()))
        .filter_map(|ip| ip.parse().ok())
        .collect();

    let mut has_upstream = false;
    for (name, args) in plugins().filter(|(n, _)| n == "forward" || n == "proxy") {
        has_upstream = true;
        // `forward FROM TO...`
        for target in args.iter().skip(1) {
            let host = upstream_host(target);
            let Ok(ip) = host.parse::<IpAddr>() else {
                continue; // a file path such as /etc/resolv.conf
            };
            let reason = if ip.is_loopback() {
                Some("a loopback address")
            } else if own_ips.contains(&ip) {
                Some("the cluster DNS Service's own ClusterIP")
            } else {
                None
            };
            if let Some(reason) = reason {
                findings.push(
                    Finding::new(
                        "DNS-006",
                        Severity::Error,
                        "dns",
                        "CoreDNS forwards to itself",
                        format!(
                            "`{name} {}` sends upstream queries to {target}, which is {reason}. \
                             Queries loop until they time out; the `loop` plugin, if enabled, \
                             makes CoreDNS exit and crash-loop instead.",
                            args.join(" ")
                        ),
                    )
                    .resource(resource)
                    .remediation(
                        "Point forward at real upstream resolvers (or /etc/resolv.conf on nodes \
                         whose resolv.conf does not list 127.0.0.53).",
                    ),
                );
            }
        }
    }

    if !has_upstream {
        findings.push(
            Finding::new(
                "DNS-007",
                Severity::Warning,
                "dns",
                "Corefile has no upstream resolver",
                "No `forward` plugin is configured, so names outside the cluster domain do not \
                 resolve from pods.",
            )
            .resource(resource)
            .remediation("Add: forward . /etc/resolv.conf"),
        );
    }

    findings
}

/// Host part of a `forward` target: strips `dns://`/`tls://` and the port.
fn upstream_host(target: &str) -> &str {
    let t = target.split("://").last().unwrap_or(target);
    if let Some(rest) = t.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    // host:port for IPv4/hostnames; a bare IPv6 address has several colons.
    match t.matches(':').count() {
        1 => t.split(':').next().unwrap_or(t),
        _ => t,
    }
}

/// DNS-008: NodeLocal DNSCache agents. Pods on a node whose agent is down
/// lose DNS entirely, because they resolve through the node-local address.
fn node_local_dns(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    snapshot
        .daemon_sets
        .iter()
        .filter(|d| {
            d.metadata.namespace.as_deref() == Some(SYSTEM_NAMESPACE)
                && d.metadata.name.as_deref() == Some(NODE_LOCAL_DNS)
        })
        .filter_map(|d| {
            let s = d.status.as_ref()?;
            let (desired, ready) = (s.desired_number_scheduled, s.number_ready);
            (desired > 0 && ready < desired).then(|| {
                Finding::new(
                    "DNS-008",
                    Severity::Error,
                    "dns",
                    "NodeLocal DNSCache is not ready on every node",
                    format!(
                        "{ready} of {desired} node-local-dns agents are ready. Pods on the \
                         other nodes resolve through the node-local address and get no answers."
                    ),
                )
                .resource(format!("daemonset/kube-system/{NODE_LOCAL_DNS}"))
                .remediation(
                    "Check: kubectl -n kube-system get pods -l k8s-app=node-local-dns -o wide",
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_default_corefile() {
        let blocks = parse_corefile(
            r#"
            # default kubeadm Corefile
            .:53 {
                errors
                health {
                   lameduck 5s
                }
                ready
                kubernetes cluster.local in-addr.arpa ip6.arpa {
                   pods insecure
                   fallthrough in-addr.arpa ip6.arpa
                   ttl 30
                }
                prometheus :9153
                forward . /etc/resolv.conf {
                   max_concurrent 1000
                }
                cache 30
                loop
                reload
                loadbalance
            }
            example.org:53 consul.local:53 {
                forward . 10.1.2.3:53   # trailing comment
            }
            "#,
        );
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].zones, vec![".:53"]);
        let names: Vec<&str> = blocks[0].plugins.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "errors",
                "health",
                "ready",
                "kubernetes",
                "prometheus",
                "forward",
                "cache",
                "loop",
                "reload",
                "loadbalance"
            ],
            "nested plugin options must not be mistaken for plugins"
        );
        assert_eq!(blocks[0].plugins[5].1, vec![".", "/etc/resolv.conf"]);
        assert_eq!(blocks[1].zones, vec!["example.org:53", "consul.local:53"]);
        assert_eq!(blocks[1].plugins[0].1, vec![".", "10.1.2.3:53"]);
    }

    #[test]
    fn upstream_host_strips_scheme_and_port() {
        assert_eq!(upstream_host("8.8.8.8"), "8.8.8.8");
        assert_eq!(upstream_host("127.0.0.1:5353"), "127.0.0.1");
        assert_eq!(upstream_host("tls://1.1.1.1:853"), "1.1.1.1");
        assert_eq!(upstream_host("[::1]:53"), "::1");
        assert_eq!(
            upstream_host("2001:4860:4860::8888"),
            "2001:4860:4860::8888"
        );
        assert_eq!(upstream_host("/etc/resolv.conf"), "/etc/resolv.conf");
    }
}
