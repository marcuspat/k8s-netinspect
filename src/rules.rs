//! Rule catalog: one entry per finding id the analyzers can emit. It backs
//! the `rules` command, `docs/RULES.md`, SARIF rule metadata, JUnit test
//! cases, and `--only` / `--skip` filtering.

use crate::model::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub id: &'static str,
    pub category: &'static str,
    /// Highest severity the rule can report; some rules report lower when
    /// the condition is partial (e.g. degraded rather than down).
    pub severity: Severity,
    pub title: &'static str,
    pub description: &'static str,
}

const fn rule(
    id: &'static str,
    category: &'static str,
    severity: Severity,
    title: &'static str,
    description: &'static str,
) -> Rule {
    Rule {
        id,
        category,
        severity,
        title,
        description,
    }
}

use Severity::{Critical, Error, Info, Warning};

pub const RULES: &[Rule] = &[
    rule("COLLECT-001", "collection", Info, "A resource list could not be collected",
        "The API refused or timed out a list call. Checks that depend on that data are skipped rather than reported as healthy."),
    rule("CNI-001", "cni", Warning, "No CNI plugin detected",
        "No known CNI agent DaemonSet or node annotation was found. Info when DaemonSets could not be listed."),
    rule("CNI-002", "cni", Critical, "CNI agent is not ready on every node",
        "The CNI agent DaemonSet has fewer ready pods than desired. Critical when none is ready, Error otherwise."),
    rule("CNI-003", "cni", Warning, "Multiple primary CNI plugins detected",
        "Two plugins that both own pod networking are deployed, usually a half-finished migration."),
    rule("NODE-001", "node", Warning, "No nodes found in cluster",
        "The node list is empty."),
    rule("NODE-002", "node", Error, "Node network is unavailable",
        "A node reports NetworkUnavailable=True: the CNI or cloud route controller has not configured it."),
    rule("NODE-003", "node", Error, "Node is not Ready",
        "A node's Ready condition is not True."),
    rule("POD-001", "pod", Error, "Pods are stuck without a network sandbox",
        "Scheduled pods have been ContainerCreating with no IP for over two minutes. Inferred from pod status and age, not from Events."),
    rule("POD-002", "pod", Error, "Pod IP assigned to more than one pod",
        "Two or more running pod-network pods hold the same address."),
    rule("POD-003", "pod", Warning, "Pod IP is outside its node's pod CIDR",
        "Only for CNIs that allocate from the node podCIDR (Flannel, Canal, kindnet, kube-router)."),
    rule("POD-004", "pod", Error, "Node pod CIDRs overlap",
        "Two nodes have overlapping spec.podCIDR ranges."),
    rule("POD-005", "pod", Warning, "Node pod CIDR is nearly exhausted",
        "A node uses 90% or more of its IPv4 pod range. Only for node-range IPAM CNIs and cluster-wide snapshots."),
    rule("POL-001", "policy", Error, "Egress policies block DNS",
        "Pods are egress-isolated and no rule allows UDP 53 to cluster DNS."),
    rule("POL-002", "policy", Warning, "NetworkPolicy selects no pods",
        "The policy's podSelector matches no pod in its namespace, so it has no effect."),
    rule("POL-003", "policy", Warning, "NetworkPolicy peer matches no pods",
        "A from/to selector matches no pod, so the rule allows nothing."),
    rule("POL-004", "policy", Warning, "NetworkPolicy references an undefined named port",
        "A rule allows a named port that no relevant pod declares."),
    rule("POL-005", "policy", Info, "CNI-native policies are present but not evaluated",
        "CiliumNetworkPolicy or Calico policy objects exist; reachability verdicts do not account for them."),
    rule("SVC-001", "service", Warning, "Service selector matches no pods",
        "No running pod in the namespace carries the Service's selector labels."),
    rule("SVC-002", "service", Error, "Service has no ready endpoints",
        "Pods match the selector but none is Ready."),
    rule("SVC-003", "service", Error, "Service targetPort is not exposed by its pods",
        "A named targetPort is missing on the backends (Error if on all, Warning if on some), or a numeric targetPort matches no declared container port (Warning)."),
    rule("SVC-004", "service", Warning, "LoadBalancer has no external address",
        "status.loadBalancer.ingress is empty."),
    rule("SVC-005", "service", Warning, "Service without selector has no endpoints",
        "A selector-less Service has no EndpointSlice with addresses."),
    rule("DNS-001", "dns", Critical, "Cluster DNS is down, degraded or scaled to zero",
        "Critical with no ready replica or zero desired replicas, Warning when some replicas are not ready."),
    rule("DNS-002", "dns", Warning, "No cluster DNS workload found",
        "No Deployment or DaemonSet in kube-system looks like CoreDNS or kube-dns."),
    rule("DNS-003", "dns", Critical, "Cluster DNS Service has no ready endpoints",
        "No EndpointSlice of the DNS Service lists a ready address."),
    rule("DNS-004", "dns", Error, "Cluster DNS Service not found",
        "A DNS workload runs but no kube-dns Service exposes it."),
    rule("DNS-005", "dns", Error, "Corefile has no kubernetes plugin",
        "CoreDNS does not serve the cluster domain."),
    rule("DNS-006", "dns", Error, "CoreDNS forwards to itself",
        "A forward target is a loopback address or the DNS Service's own ClusterIP."),
    rule("DNS-007", "dns", Warning, "Corefile has no upstream resolver",
        "No forward plugin: names outside the cluster domain do not resolve."),
    rule("DNS-008", "dns", Error, "NodeLocal DNSCache is not ready on every node",
        "The node-local-dns DaemonSet has fewer ready pods than desired."),
    rule("ING-001", "ingress", Error, "Ingress backend Service does not exist",
        "An Ingress rule or default backend names a Service that is not in the Ingress's namespace."),
    rule("ING-002", "ingress", Error, "Ingress backend port is not a port of the Service",
        "The backend's port number or name is not defined on the Service."),
    rule("ING-003", "ingress", Warning, "Ingress has no usable IngressClass",
        "The Ingress names an IngressClass that does not exist, or names none while the cluster has no default class."),
    rule("ING-004", "ingress", Info, "Ingress has no address",
        "status.loadBalancer.ingress is empty: no controller has published an address for it. Some controllers never do."),
    rule("GW-001", "gateway", Error, "HTTPRoute parent Gateway does not exist",
        "A parentRef names a Gateway that is not in the snapshot."),
    rule("GW-002", "gateway", Error, "HTTPRoute backend does not resolve",
        "A backendRef names a Service that does not exist, or a port the Service does not define."),
    rule("GW-003", "gateway", Error, "Cross-namespace backendRef lacks a ReferenceGrant",
        "The backend Service is in another namespace and no ReferenceGrant there permits HTTPRoutes from the route's namespace."),
    rule("GW-004", "gateway", Warning, "Gateway is not programmed",
        "The Gateway's Accepted or Programmed condition is not True."),
    rule("GW-005", "gateway", Warning, "HTTPRoute was not accepted by its parent",
        "The controller reports Accepted=False or ResolvedRefs=False for the route."),
    rule("PROXY-001", "proxy", Critical, "kube-proxy is not ready on every node",
        "Critical when no kube-proxy pod is ready, Error otherwise."),
    rule("PROXY-002", "proxy", Warning, "No Service proxy detected",
        "No kube-proxy and no CNI known to replace it."),
    rule("PROXY-003", "proxy", Warning, "kube-proxy runs alongside a kube-proxy replacement",
        "Both kube-proxy and a full replacement program Service handling."),
    rule("PROXY-004", "proxy", Warning, "kube-proxy version skew",
        "kube-proxy is newer than the API server, or more than three minor versions from the API server or a kubelet."),
];

pub fn find(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id.eq_ignore_ascii_case(id))
}

/// `--only` / `--skip` selection. Each selector is a full rule id
/// (`DNS-006`) or a family prefix (`DNS`), case-insensitive.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub only: Vec<String>,
    pub skip: Vec<String>,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.only.is_empty() && self.skip.is_empty()
    }

    /// Selectors that match no rule in the catalog (probable typos).
    pub fn unknown_selectors(&self) -> Vec<&str> {
        self.only
            .iter()
            .chain(&self.skip)
            .map(String::as_str)
            .filter(|s| !RULES.iter().any(|r| selector_matches(s, r.id)))
            .collect()
    }

    pub fn allows(&self, id: &str) -> bool {
        let hit = |list: &[String]| list.iter().any(|s| selector_matches(s, id));
        (self.only.is_empty() || hit(&self.only)) && !hit(&self.skip)
    }

    pub fn apply(&self, findings: &mut Vec<Finding>) {
        findings.retain(|f| self.allows(&f.id));
    }
}

fn selector_matches(selector: &str, id: &str) -> bool {
    let s = selector.trim();
    if s.is_empty() {
        return false;
    }
    if id.eq_ignore_ascii_case(s) {
        return true;
    }
    // Family prefix: "DNS" matches "DNS-001" but "DN" does not.
    id.split_once('-')
        .is_some_and(|(family, _)| family.eq_ignore_ascii_case(s))
}

/// The catalog as a Markdown document (`docs/RULES.md`).
pub fn markdown() -> String {
    let mut out = String::from(
        "# Rules\n\n\
         Generated by `k8s-netinspect rules --format markdown`. Do not edit by hand.\n\n\
         Severity is the highest a rule can report; the description notes when it reports \
         lower. Select rules with `--only` / `--skip` using an id (`DNS-006`) or a family \
         (`DNS`).\n\n\
         | Rule | Severity | Title | Description |\n\
         |------|----------|-------|-------------|\n",
    );
    for r in RULES {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            r.id, r.severity, r.title, r.description
        ));
    }
    out
}

/// The catalog as an aligned plain-text table.
pub fn text() -> String {
    let mut out = String::new();
    for r in RULES {
        out.push_str(&format!("{:<12} {:<9} {}\n", r.id, r.severity, r.title));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_well_formed() {
        for (i, r) in RULES.iter().enumerate() {
            assert!(
                RULES[..i].iter().all(|o| o.id != r.id),
                "duplicate rule id {}",
                r.id
            );
            let (family, number) = r.id.split_once('-').expect("FAMILY-NNN");
            assert!(family.chars().all(|c| c.is_ascii_uppercase()), "{}", r.id);
            assert!(
                number.len() == 3 && number.chars().all(|c| c.is_ascii_digit()),
                "{}",
                r.id
            );
            assert!(!r.description.contains('|'), "{} breaks the table", r.id);
        }
    }

    #[test]
    fn filter_selectors() {
        let f = Filter {
            only: vec!["dns".into(), "POL-001".into()],
            skip: vec!["DNS-007".into()],
        };
        assert!(f.allows("DNS-001"));
        assert!(f.allows("POL-001"));
        assert!(!f.allows("DNS-007"), "skip wins over only");
        assert!(!f.allows("POL-002"));
        assert!(!f.allows("SVC-001"));
        assert!(Filter::default().allows("ANYTHING-001"));

        let typo = Filter {
            only: vec!["DN".into()],
            skip: vec!["SVC-999".into(), "pod".into()],
        };
        assert_eq!(typo.unknown_selectors(), vec!["DN", "SVC-999"]);
    }
}
