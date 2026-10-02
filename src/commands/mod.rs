use colored::*;
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use serde::Serialize;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

use crate::analysis;
use crate::analysis::policy::{
    self, Decision, DirectionVerdict, Endpoint, Flow, Protocol, Verdict,
};
use crate::errors::{NetInspectError, NetInspectResult};
use crate::model::Report;
use crate::output::{self, OutputFormat};
use crate::probe::{self, Observation, ProbeReport, ProbeSpec};
use crate::rules::Filter;
use crate::snapshot::ClusterSnapshot;
use crate::validation::Validator;

/// Where `diagnose` gets its data from.
pub enum Source<'a> {
    /// Collect from the cluster in the current kubeconfig context.
    Live { namespace: Option<&'a str> },
    /// Analyze a snapshot file written by the `snapshot` command.
    File(&'a Path),
}

pub async fn diagnose(
    source: Source<'_>,
    format: OutputFormat,
    filter: &Filter,
) -> NetInspectResult<Report> {
    let unknown = filter.unknown_selectors();
    if !unknown.is_empty() {
        return Err(NetInspectError::InvalidInput(format!(
            "Unknown rule selector(s): {}. Run `k8s-netinspect rules` for the catalog.",
            unknown.join(", ")
        )));
    }
    if format == OutputFormat::Text {
        println!("{}", "🔍 Starting network diagnosis...".cyan().bold());
    }

    let snapshot = match source {
        Source::Live { namespace } => collect_snapshot(namespace).await?,
        Source::File(path) => ClusterSnapshot::load(path)?,
    };

    let mut report = analysis::analyze(&snapshot);
    filter.apply(&mut report.findings);
    match format {
        // JUnit lists the rules that were in scope, so it needs the filter.
        OutputFormat::Junit => print!("{}", output::render_junit(&report, filter)),
        OutputFormat::Text => print!("{}", output::render(&report, format)?),
        _ => println!("{}", output::render(&report, format)?),
    }
    Ok(report)
}

/// Print the rule catalog.
pub fn rules(markdown: bool) {
    if markdown {
        print!("{}", crate::rules::markdown());
    } else {
        print!("{}", crate::rules::text());
    }
}

/// Write a redacted cluster network snapshot to `file`, or stdout.
pub async fn snapshot(namespace: Option<&str>, file: Option<&Path>) -> NetInspectResult<()> {
    let snap = collect_snapshot(namespace).await?;
    let json = snap.to_json()?;
    match file {
        Some(path) => {
            std::fs::write(path, json).map_err(|e| {
                NetInspectError::Configuration(format!(
                    "Cannot write snapshot '{}': {}",
                    path.display(),
                    e
                ))
            })?;
            eprintln!(
                "{} Snapshot written to {} ({} nodes, {} pods, {} lists unavailable)",
                "✓".green().bold(),
                path.display(),
                snap.nodes.len(),
                snap.pods.len(),
                snap.collection_errors.len()
            );
        }
        None => println!("{json}"),
    }
    Ok(())
}

async fn collect_snapshot(namespace: Option<&str>) -> NetInspectResult<ClusterSnapshot> {
    let client = create_kubernetes_client().await?;
    match timeout(
        Duration::from_secs(60),
        ClusterSnapshot::collect(&client, namespace),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(NetInspectError::Timeout(
            "Cluster snapshot collection timed out after 60 seconds".to_string(),
        )),
    }
}

/// A `can-reach` query and its answer, as serialized for `--output json`.
#[derive(Debug, Serialize)]
pub struct ReachReport {
    pub from: String,
    pub to: String,
    pub port: u16,
    pub protocol: Protocol,
    #[serde(flatten)]
    pub verdict: Verdict,
    /// Present when `--probe` ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeReport>,
}

/// Options for the opt-in in-cluster probe.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub image: String,
    pub timeout_secs: u32,
}

/// Would NetworkPolicy let `from` talk to `to` on `port`? Endpoints are
/// `namespace/pod`, a bare pod name (namespace `default`), or an IP address.
pub async fn can_reach(
    source: Source<'_>,
    from: &str,
    to: &str,
    port: u16,
    protocol: Protocol,
    format: OutputFormat,
    probe: Option<&ProbeOptions>,
) -> NetInspectResult<ReachReport> {
    if matches!(format, OutputFormat::Sarif | OutputFormat::Junit) {
        return Err(NetInspectError::InvalidInput(
            "can-reach supports --output text or json".to_string(),
        ));
    }
    if probe.is_some() {
        if matches!(source, Source::File(_)) {
            return Err(NetInspectError::InvalidInput(
                "--probe needs a live cluster; it cannot be combined with --from-snapshot"
                    .to_string(),
            ));
        }
        if protocol != Protocol::Tcp {
            return Err(NetInspectError::InvalidInput(
                "--probe only supports TCP: a UDP or SCTP probe cannot tell a dropped packet \
                 from a silent listener"
                    .to_string(),
            ));
        }
    }

    let snapshot = match source {
        Source::Live { namespace } => collect_snapshot(namespace).await?,
        Source::File(path) => ClusterSnapshot::load(path)?,
    };
    let mut report = evaluate_reach(&snapshot, from, to, port, protocol)?;

    if let Some(options) = probe {
        let (namespace, pod, target) = probe_endpoints(&snapshot, from, to)?;
        let spec = ProbeSpec {
            image: options.image.clone(),
            target,
            port,
            timeout_secs: options.timeout_secs,
        };
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let name = probe::container_name(suffix);
        eprintln!(
            "{} Adding ephemeral container '{}' ({}) to {}/{}. It runs one TCP connect and \
             exits, but stays listed in the pod spec until the pod is deleted.",
            "ℹ".blue().bold(),
            name,
            spec.image,
            namespace,
            pod
        );
        let client = create_kubernetes_client().await?;
        let (exit_code, logs) = probe::run(client, &namespace, &pod, &name, &spec).await?;
        report.probe = Some(probe::compare(
            report.verdict.allowed,
            probe::classify(exit_code, &logs),
            &name,
        ));
    }

    match format {
        OutputFormat::Text => print!("{}", render_reach(&report)),
        _ => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| NetInspectError::Runtime(
                format!("Failed to serialize verdict: {e}")
            ))?
        ),
    }
    Ok(report)
}

/// What the probe needs: the source pod to run in and an address to dial.
pub fn probe_endpoints(
    snapshot: &ClusterSnapshot,
    from: &str,
    to: &str,
) -> NetInspectResult<(String, String, IpAddr)> {
    let Endpoint::Pod(src) = resolve_endpoint(snapshot, from)? else {
        return Err(NetInspectError::InvalidInput(
            "--probe runs inside the source, so --from must be a pod, not an external IP"
                .to_string(),
        ));
    };
    let target = match resolve_endpoint(snapshot, to)? {
        Endpoint::Ip(ip) => ip,
        Endpoint::Pod(dst) => policy::pod_ips(dst).into_iter().next().ok_or_else(|| {
            NetInspectError::ResourceNotFound(format!(
                "Destination pod '{to}' has no IP address yet"
            ))
        })?,
    };
    Ok((
        src.metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string()),
        src.metadata.name.clone().unwrap_or_default(),
        target,
    ))
}

/// Pure part of `can-reach`: resolve the endpoints and evaluate the flow.
pub fn evaluate_reach(
    snapshot: &ClusterSnapshot,
    from: &str,
    to: &str,
    port: u16,
    protocol: Protocol,
) -> NetInspectResult<ReachReport> {
    let src = resolve_endpoint(snapshot, from)?;
    let dst = resolve_endpoint(snapshot, to)?;
    let verdict = policy::evaluate(
        snapshot,
        &Flow {
            src,
            dst,
            port,
            protocol,
        },
    );
    Ok(ReachReport {
        from: endpoint_label(&src),
        to: endpoint_label(&dst),
        port,
        protocol,
        verdict,
        probe: None,
    })
}

fn resolve_endpoint<'a>(
    snapshot: &'a ClusterSnapshot,
    spec: &str,
) -> NetInspectResult<Endpoint<'a>> {
    if let Ok(ip) = spec.parse::<IpAddr>() {
        // An IP that belongs to a pod is that pod: selectors apply to it.
        let owner = snapshot
            .pods
            .iter()
            .find(|p| policy::pod_ips(p).contains(&ip));
        return Ok(owner.map_or(Endpoint::Ip(ip), Endpoint::Pod));
    }
    let (ns, name) = spec.split_once('/').unwrap_or(("default", spec));
    Validator::validate_namespace(ns)?;
    Validator::validate_pod_name(name)?;
    snapshot
        .pods
        .iter()
        .find(|p| {
            p.metadata.namespace.as_deref().unwrap_or("default") == ns
                && p.metadata.name.as_deref() == Some(name)
        })
        .map(Endpoint::Pod)
        .ok_or_else(|| {
            let scope = match &snapshot.namespace {
                Some(scope) if scope != ns => {
                    format!(" (the snapshot only covers namespace '{scope}')")
                }
                _ => String::new(),
            };
            NetInspectError::ResourceNotFound(format!(
                "Pod '{name}' not found in namespace '{ns}'{scope}"
            ))
        })
}

fn endpoint_label(endpoint: &Endpoint<'_>) -> String {
    match endpoint {
        Endpoint::Ip(ip) => ip.to_string(),
        Endpoint::Pod(p) => format!(
            "{}/{}",
            p.metadata.namespace.as_deref().unwrap_or("default"),
            p.metadata.name.as_deref().unwrap_or("<unnamed>")
        ),
    }
}

fn render_reach(report: &ReachReport) -> String {
    let v = &report.verdict;
    let proto = format!("{:?}", report.protocol).to_uppercase();
    let mut out = format!(
        "{} Can {} reach {} on {} {}?\n",
        "🔍".cyan(),
        report.from.yellow(),
        report.to.yellow(),
        proto,
        report.port
    );
    if v.allowed {
        out.push_str(&format!(
            "{} {} by NetworkPolicy\n",
            "✓".green().bold(),
            "ALLOWED".green().bold()
        ));
    } else {
        let side = match (v.egress.decision, v.ingress.decision) {
            (Decision::Denied, Decision::Denied) => {
                format!("egress from {} and ingress to {}", report.from, report.to)
            }
            (Decision::Denied, _) => format!("egress from {}", report.from),
            _ => format!("ingress to {}", report.to),
        };
        out.push_str(&format!(
            "{} {} on {}\n",
            "✗".red().bold(),
            "BLOCKED".red().bold(),
            side
        ));
    }
    out.push_str(&format!(
        "  egress  ({}): {}\n",
        report.from,
        describe_direction(&v.egress, "egress")
    ));
    out.push_str(&format!(
        "  ingress ({}): {}\n",
        report.to,
        describe_direction(&v.ingress, "ingress")
    ));
    for caveat in &v.caveats {
        out.push_str(&format!("  {} {}\n", "⚠".yellow().bold(), caveat));
    }
    if !v.complete {
        out.push_str(&format!(
            "  {} Verdict is incomplete — treat it as a lower bound, not proof.\n",
            "⚠".yellow().bold()
        ));
    }
    if let Some(p) = &report.probe {
        let observed = match p.observed {
            Observation::Connected => "connected",
            Observation::Refused => "connection refused",
            Observation::TimedOut => "timed out",
            Observation::Inconclusive => "inconclusive",
        };
        let mark = if p.agrees {
            "✓".green().bold()
        } else {
            "✗".red().bold()
        };
        out.push_str(&format!(
            "{} Probe from inside {}: {} — {}\n",
            mark, report.from, observed, p.explanation
        ));
    }
    out
}

fn describe_direction(d: &DirectionVerdict, dir: &str) -> String {
    if let Some(by) = &d.decided_by {
        let word = if d.decision == Decision::Denied {
            "denied"
        } else {
            "allowed"
        };
        return format!("{word} by {by}");
    }
    match d.decision {
        Decision::NotApplicable => "not a pod — NetworkPolicy does not apply to this side".into(),
        Decision::NotIsolated => format!("not isolated — no policy selects this pod for {dir}"),
        Decision::Allowed => format!("allowed by {}", d.allowing.join(", ")),
        Decision::Denied => format!(
            "denied — isolated by {}; none of their rules match this flow",
            d.isolating.join(", ")
        ),
    }
}

pub async fn test_pod(pod_name: &str, namespace: &str) -> NetInspectResult<()> {
    println!(
        "{} Testing connectivity for pod: {}/{}",
        "🔍".cyan(),
        namespace.yellow(),
        pod_name.yellow()
    );

    println!(
        "{} This HTTP check runs from this machine, not from inside the cluster; for an \
         in-cluster test use: can-reach --from <pod> --to {}/{} --port 80 --probe",
        "ℹ".blue().bold(),
        namespace,
        pod_name
    );

    // Create client with better error handling
    let client = create_kubernetes_client().await?;
    let pods: Api<Pod> = Api::namespaced(client, namespace);

    // Get pod with timeout and better error handling
    let pod_result = timeout(Duration::from_secs(10), pods.get(pod_name)).await;

    let pod = match pod_result {
        Ok(Ok(pod)) => pod,
        Ok(Err(kube::Error::Api(api_err))) if api_err.code == 404 => {
            return Err(NetInspectError::ResourceNotFound(format!(
                "Pod '{}' not found in namespace '{}'",
                pod_name, namespace
            )));
        }
        Ok(Err(e)) => return Err(NetInspectError::from(e)),
        Err(_) => {
            return Err(NetInspectError::Timeout(
                "Pod lookup timed out after 10 seconds".to_string(),
            ))
        }
    };

    // Enhanced pod status checking
    let status = pod.status.as_ref().ok_or_else(|| {
        NetInspectError::ResourceNotFound(format!(
            "Pod '{}' has no status information - it may be initializing",
            pod_name
        ))
    })?;

    // Check pod phase
    if let Some(phase) = &status.phase {
        match phase.as_str() {
            "Pending" => {
                println!(
                    "{} Pod is in Pending phase - not yet scheduled",
                    "⚠".yellow().bold()
                );
                return Err(NetInspectError::ResourceNotFound(
                    "Pod is pending and has no IP address yet".to_string(),
                ));
            }
            "Failed" | "Succeeded" => {
                println!(
                    "{} Pod is in {} phase - not running",
                    "⚠".yellow().bold(),
                    phase
                );
                return Err(NetInspectError::ResourceNotFound(format!(
                    "Pod is in {} phase and cannot be tested",
                    phase
                )));
            }
            "Running" => {
                println!("{} Pod is running", "✓".green().bold());
            }
            _ => {
                println!("{} Pod phase: {}", "ℹ".blue().bold(), phase.yellow());
            }
        }
    }

    let pod_ip = status.pod_ip.as_ref().ok_or_else(|| {
        NetInspectError::ResourceNotFound(format!(
            "Pod '{}' has no IP address assigned - check if it's running",
            pod_name
        ))
    })?;

    // Validate IP address format
    Validator::validate_pod_ip(pod_ip)?;

    println!("{} Pod IP: {}", "ℹ".blue().bold(), pod_ip.cyan());

    // Enhanced connectivity test with retries
    match test_connectivity_with_retries(pod_ip, 3).await {
        Ok(()) => {
            println!(
                "{} Connectivity test: {}",
                "✓".green().bold(),
                "PASS".green().bold()
            );
            Ok(())
        }
        Err(e) => {
            println!(
                "{} Connectivity test: {} - {}",
                "✗".red().bold(),
                "FAIL".red().bold(),
                e
            );
            Err(e)
        }
    }
}

pub fn version() {
    println!(
        "{} k8s-netinspect v{}",
        "🔧".yellow().bold(),
        env!("CARGO_PKG_VERSION").green()
    );
    println!("A minimal Kubernetes network inspection tool");
}

async fn test_connectivity_with_retries(pod_ip: &str, max_retries: u32) -> NetInspectResult<()> {
    for attempt in 1..=max_retries {
        match test_connectivity(pod_ip).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt < max_retries {
                    println!(
                        "{} Attempt {} failed, retrying... ({})",
                        "⚠".yellow().bold(),
                        attempt,
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(1000 * attempt as u64)).await;
                } else {
                    return Err(e);
                }
            }
        }
    }
    unreachable!()
}

async fn test_connectivity(pod_ip: &str) -> NetInspectResult<()> {
    let url = pod_url(pod_ip);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| NetInspectError::Runtime(format!("Failed to create HTTP client: {}", e)))?;

    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(NetInspectError::NetworkConnectivity(format!(
            "HTTP {} - {}",
            response.status(),
            response
                .status()
                .canonical_reason()
                .unwrap_or("Unknown error")
        )))
    }
}

/// `http://<ip>:80`, with the brackets an IPv6 literal needs in a URL.
fn pod_url(pod_ip: &str) -> String {
    if pod_ip.contains(':') {
        format!("http://[{pod_ip}]:80")
    } else {
        format!("http://{pod_ip}:80")
    }
}

/// Create Kubernetes client with enhanced error handling
async fn create_kubernetes_client() -> NetInspectResult<Client> {
    Client::try_default().await.map_err(NetInspectError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_url_brackets_ipv6() {
        assert_eq!(pod_url("10.0.1.4"), "http://10.0.1.4:80");
        assert_eq!(pod_url("fd00:10:244::1a"), "http://[fd00:10:244::1a]:80");
    }
}
