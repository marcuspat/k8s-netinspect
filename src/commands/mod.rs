use colored::*;
use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

use crate::analysis;
use crate::errors::{NetInspectError, NetInspectResult};
use crate::model::Report;
use crate::output::{self, OutputFormat};
use crate::snapshot::ClusterSnapshot;
use crate::validation::Validator;

/// Where `diagnose` gets its data from.
pub enum Source<'a> {
    /// Collect from the cluster in the current kubeconfig context.
    Live { namespace: Option<&'a str> },
    /// Analyze a snapshot file written by the `snapshot` command.
    File(&'a Path),
}

pub async fn diagnose(source: Source<'_>, format: OutputFormat) -> NetInspectResult<Report> {
    if format == OutputFormat::Text {
        println!("{}", "🔍 Starting network diagnosis...".cyan().bold());
    }

    let snapshot = match source {
        Source::Live { namespace } => collect_snapshot(namespace).await?,
        Source::File(path) => ClusterSnapshot::load(path)?,
    };

    let report = analysis::analyze(&snapshot);
    print!("{}", output::render(&report, format)?);
    if format == OutputFormat::Json {
        println!();
    }
    Ok(report)
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

pub async fn test_pod(pod_name: &str, namespace: &str) -> NetInspectResult<()> {
    println!(
        "{} Testing connectivity for pod: {}/{}",
        "🔍".cyan(),
        namespace.yellow(),
        pod_name.yellow()
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
    let url = format!("http://{}:80", pod_ip);

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

/// Create Kubernetes client with enhanced error handling
async fn create_kubernetes_client() -> NetInspectResult<Client> {
    Client::try_default().await.map_err(NetInspectError::from)
}
