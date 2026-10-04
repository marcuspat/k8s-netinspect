//! Service wiring: does each Service actually have somewhere to send traffic?
//!
//! Backends are derived the way the endpoints controller does it — pods in
//! the Service's namespace matching its selector, excluding terminal pods —
//! so the checks explain *why* a Service has no endpoints rather than just
//! reporting an empty list.

use k8s_openapi::api::core::v1::{Pod, Service, ServicePort};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use std::collections::BTreeMap;

use crate::model::{Finding, Severity};
use crate::snapshot::ClusterSnapshot;

const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

pub fn analyze(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    if snapshot.is_unknown("services") {
        return findings;
    }
    let pods_known = !snapshot.is_unknown("pods");

    for svc in &snapshot.services {
        let Some(spec) = svc.spec.as_ref() else {
            continue;
        };
        let ns = svc.metadata.namespace.as_deref().unwrap_or("default");
        let name = svc.metadata.name.as_deref().unwrap_or("<unnamed>");
        let resource = format!("service/{ns}/{name}");
        let svc_type = spec.type_.as_deref().unwrap_or("ClusterIP");

        // ExternalName is a DNS alias: no selector, no endpoints, no ports to wire.
        if svc_type == "ExternalName" {
            continue;
        }

        if svc_type == "LoadBalancer" && !has_lb_address(svc) {
            findings.push(
                Finding::new(
                    "SVC-004",
                    Severity::Warning,
                    "service",
                    "LoadBalancer has no external address",
                    "status.loadBalancer.ingress is empty: the cloud controller or load-balancer \
                     implementation (MetalLB, kube-vip, ...) has not assigned an address, so the \
                     Service is unreachable from outside the cluster.",
                )
                .resource(resource.clone())
                .remediation(format!(
                    "Check: kubectl -n {ns} describe service {name} (Events) and the \
                     load-balancer controller's logs"
                )),
            );
        }

        let selector = spec.selector.as_ref().filter(|s| !s.is_empty());
        let Some(selector) = selector else {
            // Selector-less Service: endpoints are managed by hand or by a controller.
            if !snapshot.is_unknown("endpointslices") && !has_slice_addresses(snapshot, ns, name) {
                findings.push(
                    Finding::new(
                        "SVC-005",
                        Severity::Warning,
                        "service",
                        "Service without selector has no endpoints",
                        "The Service has no selector and no EndpointSlice with addresses points \
                         at it, so connections to it are refused or time out.",
                    )
                    .resource(resource)
                    .remediation(format!(
                        "Create an EndpointSlice labelled {SERVICE_NAME_LABEL}={name}, or add a \
                         selector to the Service."
                    )),
                );
            }
            continue;
        };

        if !pods_known {
            continue;
        }

        let backends: Vec<&Pod> = snapshot
            .pods
            .iter()
            .filter(|p| p.metadata.namespace.as_deref().unwrap_or("default") == ns)
            .filter(|p| !is_terminal(p))
            .filter(|p| matches_selector(selector, p))
            .collect();

        if backends.is_empty() {
            findings.push(
                Finding::new(
                    "SVC-001",
                    Severity::Warning,
                    "service",
                    "Service selector matches no pods",
                    format!(
                        "Selector {} matches no running pod in namespace '{}', so the Service \
                         has no endpoints.",
                        describe(selector),
                        ns
                    ),
                )
                .resource(resource)
                .remediation(format!(
                    "Compare with: kubectl -n {ns} get pods --show-labels (a label typo or a \
                     workload scaled to zero are the usual causes)"
                )),
            );
            continue;
        }

        let publish_not_ready = spec.publish_not_ready_addresses.unwrap_or(false);
        let ready = backends.iter().filter(|p| is_ready(p)).count();
        if ready == 0 && !publish_not_ready {
            let names: Vec<&str> = backends
                .iter()
                .take(5)
                .map(|p| p.metadata.name.as_deref().unwrap_or("<unnamed>"))
                .collect();
            findings.push(
                Finding::new(
                    "SVC-002",
                    Severity::Error,
                    "service",
                    "Service has no ready endpoints",
                    format!(
                        "{} pod(s) match the selector but none is Ready ({}), so the Service \
                         routes to nothing.",
                        backends.len(),
                        names.join(", ")
                    ),
                )
                .resource(resource.clone())
                .remediation(format!(
                    "Check readiness probes and container state: kubectl -n {ns} describe pod {}",
                    names[0]
                )),
            );
        }

        for port in spec.ports.iter().flatten() {
            if let Some(f) = check_target_port(port, &backends, &resource) {
                findings.push(f);
            }
        }
    }

    findings
}

/// SVC-003: the Service forwards to a port the backends do not expose.
fn check_target_port(port: &ServicePort, backends: &[&Pod], resource: &str) -> Option<Finding> {
    let protocol = port.protocol.as_deref().unwrap_or("TCP");
    let label = match &port.name {
        Some(n) => format!("port '{}' ({}/{})", n, port.port, protocol),
        None => format!("port {}/{}", port.port, protocol),
    };

    match port
        .target_port
        .clone()
        .unwrap_or(IntOrString::Int(port.port))
    {
        IntOrString::String(name) => {
            let with = backends
                .iter()
                .filter(|p| {
                    container_ports(p).any(|(n, _, proto)| n == Some(&name) && proto == protocol)
                })
                .count();
            if with == backends.len() {
                return None;
            }
            // A named targetPort is resolved per pod; pods that lack it are
            // simply left out of the endpoints for that port.
            let (severity, scope) = if with == 0 {
                (Severity::Error, "none of the".to_string())
            } else {
                (Severity::Warning, format!("only {with} of the"))
            };
            Some(
                Finding::new(
                    "SVC-003",
                    severity,
                    "service",
                    "Service targetPort is not exposed by its pods",
                    format!(
                        "{label} targets named port '{name}', but {scope} {} matching pod(s) \
                         declare a {protocol} container port with that name. Pods without it \
                         receive no traffic on this port.",
                        backends.len()
                    ),
                )
                .resource(resource.to_string())
                .remediation(format!(
                    "Name the containerPort '{name}' in the pod template, or set targetPort to \
                     the numeric port."
                )),
            )
        }
        IntOrString::Int(number) => {
            // containerPort declarations are informational: a container can
            // listen on an undeclared port. Only flag a mismatch when every
            // backend declares ports and none declares this one — that
            // pattern is almost always a wrong number.
            let all_declare = backends.iter().all(|p| container_ports(p).next().is_some());
            let any_match = backends
                .iter()
                .any(|p| container_ports(p).any(|(_, n, proto)| n == number && proto == protocol));
            if !all_declare || any_match {
                return None;
            }
            let mut declared: Vec<i32> = backends
                .iter()
                .flat_map(|p| container_ports(p).map(|(_, n, _)| n))
                .collect();
            declared.sort_unstable();
            declared.dedup();
            let declared: Vec<String> = declared.iter().map(i32::to_string).collect();
            Some(
                Finding::new(
                    "SVC-003",
                    Severity::Warning,
                    "service",
                    "Service targetPort is not exposed by its pods",
                    format!(
                        "{label} targets port {number}, but the matching pods declare only \
                         {} ({}). Unless the container listens on an undeclared port, \
                         connections are refused.",
                        if declared.len() == 1 { "port" } else { "ports" },
                        declared.join(", ")
                    ),
                )
                .resource(resource.to_string())
                .remediation(
                    "Set targetPort to the port the container listens on, or declare the port \
                     in the pod template if it is correct.",
                ),
            )
        }
    }
}

/// (name, containerPort, protocol) for every declared container port.
fn container_ports(pod: &Pod) -> impl Iterator<Item = (Option<&String>, i32, &str)> {
    pod.spec
        .iter()
        .flat_map(|s| s.containers.iter())
        .flat_map(|c| c.ports.iter().flatten())
        .map(|p| {
            (
                p.name.as_ref(),
                p.container_port,
                p.protocol.as_deref().unwrap_or("TCP"),
            )
        })
}

fn matches_selector(selector: &BTreeMap<String, String>, pod: &Pod) -> bool {
    let labels = pod.metadata.labels.as_ref();
    selector
        .iter()
        .all(|(k, v)| labels.and_then(|l| l.get(k)) == Some(v))
}

fn is_terminal(pod: &Pod) -> bool {
    matches!(
        pod.status.as_ref().and_then(|s| s.phase.as_deref()),
        Some("Succeeded") | Some("Failed")
    )
}

fn is_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|c| c.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
}

fn has_lb_address(svc: &Service) -> bool {
    svc.status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .is_some_and(|i| !i.is_empty())
}

fn has_slice_addresses(snapshot: &ClusterSnapshot, ns: &str, service: &str) -> bool {
    snapshot.endpoint_slices.iter().any(|s| {
        s.metadata.namespace.as_deref().unwrap_or("default") == ns
            && s.metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(SERVICE_NAME_LABEL))
                .map(String::as_str)
                == Some(service)
            && s.endpoints
                .iter()
                .flatten()
                .any(|e| !e.addresses.is_empty())
    })
}

fn describe(selector: &BTreeMap<String, String>) -> String {
    let parts: Vec<String> = selector.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("{{{}}}", parts.join(", "))
}
