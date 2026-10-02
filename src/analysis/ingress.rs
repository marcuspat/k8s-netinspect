//! North-south wiring: Ingress and Gateway API objects that point at
//! Services, ports, classes or Gateways which are not there.

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::networking::v1::{Ingress, IngressBackend};
use kube::core::DynamicObject;
use serde_json::Value;

use crate::model::{Finding, Severity};
use crate::snapshot::{ClusterSnapshot, GATEWAY_GROUP};

const LEGACY_CLASS_ANNOTATION: &str = "kubernetes.io/ingress.class";
const DEFAULT_CLASS_ANNOTATION: &str = "ingressclass.kubernetes.io/is-default-class";

pub fn analyze(snapshot: &ClusterSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ingress in &snapshot.ingresses {
        findings.extend(check_ingress(snapshot, ingress));
    }
    for gateway in &snapshot.gateways {
        findings.extend(check_gateway(gateway));
    }
    for route in &snapshot.http_routes {
        findings.extend(check_route(snapshot, route));
    }
    findings
}

/// Can Services in `ns` be looked up in this snapshot?
fn services_visible(snapshot: &ClusterSnapshot, ns: &str) -> bool {
    !snapshot.is_unknown("services") && snapshot.namespace.as_deref().is_none_or(|s| s == ns)
}

fn find_service<'a>(snapshot: &'a ClusterSnapshot, ns: &str, name: &str) -> Option<&'a Service> {
    snapshot.services.iter().find(|s| {
        s.metadata.namespace.as_deref().unwrap_or("default") == ns
            && s.metadata.name.as_deref() == Some(name)
    })
}

fn service_has_port(service: &Service, number: Option<i64>, name: Option<&str>) -> bool {
    let ports = service.spec.iter().flat_map(|s| s.ports.iter().flatten());
    match (number, name) {
        (Some(n), _) => ports.into_iter().any(|p| i64::from(p.port) == n),
        (None, Some(name)) => ports.into_iter().any(|p| p.name.as_deref() == Some(name)),
        (None, None) => true,
    }
}

fn service_ports(service: &Service) -> String {
    let ports: Vec<String> = service
        .spec
        .iter()
        .flat_map(|s| s.ports.iter().flatten())
        .map(|p| match &p.name {
            Some(n) => format!("{} ({})", p.port, n),
            None => p.port.to_string(),
        })
        .collect();
    if ports.is_empty() {
        "none".to_string()
    } else {
        ports.join(", ")
    }
}

fn check_ingress(snapshot: &ClusterSnapshot, ingress: &Ingress) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");
    let name = ingress.metadata.name.as_deref().unwrap_or("<unnamed>");
    let resource = format!("ingress/{ns}/{name}");
    let Some(spec) = ingress.spec.as_ref() else {
        return findings;
    };

    // (where it is used, backend)
    let mut backends: Vec<(String, &IngressBackend)> = Vec::new();
    if let Some(b) = &spec.default_backend {
        backends.push(("default backend".to_string(), b));
    }
    for rule in spec.rules.iter().flatten() {
        let host = rule.host.as_deref().unwrap_or("*");
        for path in rule.http.iter().flat_map(|h| h.paths.iter()) {
            backends.push((
                format!("{}{}", host, path.path.as_deref().unwrap_or("/")),
                &path.backend,
            ));
        }
    }

    if services_visible(snapshot, ns) {
        for (place, backend) in &backends {
            // `resource` backends (e.g. object storage) are not Services.
            let Some(svc_ref) = backend.service.as_ref() else {
                continue;
            };
            let Some(service) = find_service(snapshot, ns, &svc_ref.name) else {
                findings.push(
                    Finding::new(
                        "ING-001",
                        Severity::Error,
                        "ingress",
                        "Ingress backend Service does not exist",
                        format!(
                            "{place} routes to Service '{}', which does not exist in namespace \
                             '{ns}'. The controller answers 503 for it.",
                            svc_ref.name
                        ),
                    )
                    .resource(resource.clone())
                    .remediation(format!(
                        "Check: kubectl -n {ns} get services (an Ingress can only reference \
                         Services in its own namespace)"
                    )),
                );
                continue;
            };
            let port = svc_ref.port.as_ref();
            let number = port.and_then(|p| p.number).map(i64::from);
            let port_name = port.and_then(|p| p.name.as_deref());
            if !service_has_port(service, number, port_name) {
                let wanted = match (number, port_name) {
                    (Some(n), _) => n.to_string(),
                    (None, Some(n)) => format!("'{n}'"),
                    (None, None) => "<none>".to_string(),
                };
                findings.push(
                    Finding::new(
                        "ING-002",
                        Severity::Error,
                        "ingress",
                        "Ingress backend port is not a port of the Service",
                        format!(
                            "{place} routes to Service '{}' port {wanted}, but that Service \
                             exposes: {}.",
                            svc_ref.name,
                            service_ports(service)
                        ),
                    )
                    .resource(resource.clone())
                    .remediation(
                        "Use one of the Service's ports (its `port`, not the pod's targetPort).",
                    ),
                );
            }
        }
    }

    if !snapshot.is_unknown("ingressclasses") {
        let legacy = ingress
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(LEGACY_CLASS_ANNOTATION));
        let class_exists = |name: &str| {
            snapshot
                .ingress_classes
                .iter()
                .any(|c| c.metadata.name.as_deref() == Some(name))
        };
        let has_default = snapshot.ingress_classes.iter().any(|c| {
            c.metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(DEFAULT_CLASS_ANNOTATION))
                .is_some_and(|v| v == "true")
        });
        let problem = match (spec.ingress_class_name.as_deref(), legacy) {
            (Some(class), _) if !class_exists(class) => Some(format!(
                "ingressClassName '{class}' does not match any IngressClass, so no controller \
                 claims this Ingress."
            )),
            (None, None) if !has_default => Some(
                "It sets no ingressClassName and the cluster has no default IngressClass, so \
                 no controller claims it."
                    .to_string(),
            ),
            // The legacy annotation is matched by controllers directly.
            _ => None,
        };
        if let Some(detail) = problem {
            let available: Vec<&str> = snapshot
                .ingress_classes
                .iter()
                .filter_map(|c| c.metadata.name.as_deref())
                .collect();
            findings.push(
                Finding::new(
                    "ING-003",
                    Severity::Warning,
                    "ingress",
                    "Ingress has no usable IngressClass",
                    detail,
                )
                .resource(resource.clone())
                .remediation(if available.is_empty() {
                    "No IngressClass exists: install an ingress controller.".to_string()
                } else {
                    format!(
                        "Set spec.ingressClassName to one of: {}",
                        available.join(", ")
                    )
                }),
            );
        }
    }

    let has_address = ingress
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .is_some_and(|i| !i.is_empty());
    if !has_address {
        findings.push(
            Finding::new(
                "ING-004",
                Severity::Info,
                "ingress",
                "Ingress has no address",
                "status.loadBalancer.ingress is empty: no controller has published an address \
                 for this Ingress. Some controllers never do; otherwise it has not been \
                 admitted.",
            )
            .resource(resource)
            .remediation(format!(
                "Check: kubectl -n {ns} describe ingress {name} (Events)"
            )),
        );
    }

    findings
}

fn meta(obj: &DynamicObject) -> (&str, &str) {
    (
        obj.metadata.namespace.as_deref().unwrap_or("default"),
        obj.metadata.name.as_deref().unwrap_or("<unnamed>"),
    )
}

/// Conditions whose status is not "True", as (type, reason, message).
fn failing<'a>(conditions: &'a Value, types: &[&str]) -> Vec<(&'a str, &'a str, &'a str)> {
    conditions
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            let type_ = c.get("type")?.as_str()?;
            let status = c.get("status")?.as_str()?;
            (types.contains(&type_) && status != "True").then(|| {
                (
                    type_,
                    c.get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("no reason"),
                    c.get("message").and_then(Value::as_str).unwrap_or(""),
                )
            })
        })
        .collect()
}

fn check_gateway(gateway: &DynamicObject) -> Vec<Finding> {
    let (ns, name) = meta(gateway);
    failing(
        &gateway.data["status"]["conditions"],
        &["Accepted", "Programmed"],
    )
    .into_iter()
    .map(|(type_, reason, message)| {
        Finding::new(
            "GW-004",
            Severity::Warning,
            "gateway",
            "Gateway is not programmed",
            format!("{type_} is not True ({reason}) {message}")
                .trim()
                .to_string(),
        )
        .resource(format!("gateway/{ns}/{name}"))
        .remediation(format!(
            "Check: kubectl -n {ns} describe gateway {name}; verify its gatewayClassName has \
                 a running controller."
        ))
    })
    .collect()
}

fn str_or<'a>(value: &'a Value, key: &str, default: &'a str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or(default)
}

fn check_route(snapshot: &ClusterSnapshot, route: &DynamicObject) -> Vec<Finding> {
    let mut findings = Vec::new();
    let (ns, name) = meta(route);
    let resource = format!("httproute/{ns}/{name}");
    let spec = &route.data["spec"];
    let in_scope = |target: &str| snapshot.namespace.as_deref().is_none_or(|s| s == target);

    // GW-001: parentRefs.
    if !snapshot.is_unknown("gateways") {
        for parent in spec["parentRefs"].as_array().into_iter().flatten() {
            if str_or(parent, "group", GATEWAY_GROUP) != GATEWAY_GROUP
                || str_or(parent, "kind", "Gateway") != "Gateway"
            {
                continue; // e.g. a Service parent in a mesh
            }
            let parent_ns = str_or(parent, "namespace", ns);
            let Some(parent_name) = parent.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !in_scope(parent_ns) {
                continue;
            }
            let exists = snapshot
                .gateways
                .iter()
                .any(|g| meta(g) == (parent_ns, parent_name));
            if !exists {
                findings.push(
                    Finding::new(
                        "GW-001",
                        Severity::Error,
                        "gateway",
                        "HTTPRoute parent Gateway does not exist",
                        format!(
                            "parentRef points at Gateway '{parent_ns}/{parent_name}', which \
                             does not exist, so the route is attached to nothing."
                        ),
                    )
                    .resource(resource.clone())
                    .remediation("Check: kubectl get gateways -A"),
                );
            }
        }
    }

    // GW-002 / GW-003: backendRefs.
    for (i, rule) in spec["rules"].as_array().into_iter().flatten().enumerate() {
        for backend in rule["backendRefs"].as_array().into_iter().flatten() {
            if !str_or(backend, "group", "").is_empty()
                || str_or(backend, "kind", "Service") != "Service"
            {
                continue;
            }
            let Some(backend_name) = backend.get("name").and_then(Value::as_str) else {
                continue;
            };
            let backend_ns = str_or(backend, "namespace", ns);

            if backend_ns != ns
                && !snapshot.is_unknown("referencegrants")
                && !grant_allows(snapshot, ns, backend_ns, backend_name)
            {
                findings.push(
                    Finding::new(
                        "GW-003",
                        Severity::Error,
                        "gateway",
                        "Cross-namespace backendRef lacks a ReferenceGrant",
                        format!(
                            "rule #{} references Service '{backend_ns}/{backend_name}' from \
                             namespace '{ns}', but no ReferenceGrant in '{backend_ns}' allows \
                             HTTPRoutes from '{ns}' to reference Services. The route gets \
                             ResolvedRefs=False and returns 500 for this backend.",
                            i + 1
                        ),
                    )
                    .resource(resource.clone())
                    .remediation(format!(
                        "Create a ReferenceGrant in '{backend_ns}' with from: {{group: \
                         {GATEWAY_GROUP}, kind: HTTPRoute, namespace: {ns}}} and to: {{group: \
                         \"\", kind: Service}}."
                    )),
                );
            }

            if !services_visible(snapshot, backend_ns) {
                continue;
            }
            let port = backend.get("port").and_then(Value::as_i64);
            let detail = match find_service(snapshot, backend_ns, backend_name) {
                None => Some(format!(
                    "rule #{} references Service '{backend_ns}/{backend_name}', which does not \
                     exist.",
                    i + 1
                )),
                Some(svc) if !service_has_port(svc, port, None) => Some(format!(
                    "rule #{} references Service '{backend_ns}/{backend_name}' port {}, but \
                     that Service exposes: {}.",
                    i + 1,
                    port.unwrap_or_default(),
                    service_ports(svc)
                )),
                Some(_) => None,
            };
            if let Some(detail) = detail {
                findings.push(
                    Finding::new(
                        "GW-002",
                        Severity::Error,
                        "gateway",
                        "HTTPRoute backend does not resolve",
                        detail,
                    )
                    .resource(resource.clone())
                    .remediation(format!("Check: kubectl -n {backend_ns} get services")),
                );
            }
        }
    }

    // GW-005: what the controller itself reports.
    for parent in route.data["status"]["parents"]
        .as_array()
        .into_iter()
        .flatten()
    {
        for (type_, reason, message) in
            failing(&parent["conditions"], &["Accepted", "ResolvedRefs"])
        {
            let parent_name = str_or(&parent["parentRef"], "name", "<unknown>");
            findings.push(
                Finding::new(
                    "GW-005",
                    Severity::Warning,
                    "gateway",
                    "HTTPRoute was not accepted by its parent",
                    format!("Parent '{parent_name}' reports {type_}=False ({reason}) {message}")
                        .trim()
                        .to_string(),
                )
                .resource(resource.clone())
                .remediation(format!("Check: kubectl -n {ns} describe httproute {name}")),
            );
        }
    }

    findings
}

/// Does a ReferenceGrant in `to_ns` let HTTPRoutes from `from_ns` reference
/// the Service `service`?
fn grant_allows(snapshot: &ClusterSnapshot, from_ns: &str, to_ns: &str, service: &str) -> bool {
    snapshot
        .reference_grants
        .iter()
        .filter(|g| g.metadata.namespace.as_deref() == Some(to_ns))
        .any(|g| {
            let spec = &g.data["spec"];
            let from_ok = spec["from"].as_array().into_iter().flatten().any(|f| {
                str_or(f, "group", "") == GATEWAY_GROUP
                    && str_or(f, "kind", "") == "HTTPRoute"
                    && str_or(f, "namespace", "") == from_ns
            });
            let to_ok = spec["to"].as_array().into_iter().flatten().any(|t| {
                str_or(t, "group", "").is_empty()
                    && str_or(t, "kind", "") == "Service"
                    && t.get("name")
                        .and_then(Value::as_str)
                        .is_none_or(|n| n.is_empty() || n == service)
            });
            from_ok && to_ok
        })
}
