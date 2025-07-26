use colored::*;
use kube::{Api, Client};
use k8s_openapi::api::core::v1::{Pod, Node};
use std::time::Duration;
use tokio::time::timeout;

use crate::errors::{NetInspectError, NetInspectResult};
use crate::validation::Validator;


pub async fn diagnose(namespace: Option<&str>) -> NetInspectResult<()> {
    println!("{}", "🔍 Starting network diagnosis...".cyan().bold());
    
    // Create client with better error handling
    let client = create_kubernetes_client().await?;
    
    // Detect CNI with timeout
    let cni_result = timeout(
        Duration::from_secs(30),
        detect_cni(&client)
    ).await;
    
    let cni_type = match cni_result {
        Ok(Ok(cni)) => cni,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(NetInspectError::Timeout(
            "CNI detection timed out after 30 seconds".to_string()
        )),
    };
    
    println!("{} CNI detected: {}", "✓".green().bold(), cni_type.green());
    
    // Check basic cluster connectivity with timeout
    let nodes_result = timeout(
        Duration::from_secs(15),
        get_cluster_nodes(&client)
    ).await;
    
    let node_count = match nodes_result {
        Ok(Ok(count)) => count,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(NetInspectError::Timeout(
            "Node listing timed out after 15 seconds".to_string()
        )),
    };
    
    if node_count == 0 {
        println!("{} {}", "⚠".yellow().bold(), "No nodes found in cluster".yellow());
    } else {
        println!("{} Found {} nodes", "✓".green().bold(), node_count.to_string().yellow());
    }
    
    // Check pods in specified namespace or cluster-wide
    let pod_result = timeout(
        Duration::from_secs(15),
        check_pods_in_namespace(&client, namespace)
    ).await;
    
    match pod_result {
        Ok(Ok(pod_count)) => {
            if let Some(ns) = namespace {
                println!("{} Found {} pods in namespace '{}'", 
                         "✓".green().bold(), 
                         pod_count.to_string().yellow(),
                         ns.yellow());
            } else {
                println!("{} Found {} pods cluster-wide", 
                         "✓".green().bold(), 
                         pod_count.to_string().yellow());
            }
        },
        Ok(Err(e)) => {
            println!("{} Failed to check pods: {}", "⚠".yellow().bold(), e);
        },
        Err(_) => {
            println!("{} Pod listing timed out after 15 seconds", "⚠".yellow().bold());
        }
    }
    
    Ok(())
}

pub async fn test_pod(pod_name: &str, namespace: &str) -> NetInspectResult<()> {
    println!("{} Testing connectivity for pod: {}/{}", 
             "🔍".cyan(), namespace.yellow(), pod_name.yellow());
    
    // Create client with better error handling
    let client = create_kubernetes_client().await?;
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    
    // Get pod with timeout and better error handling
    let pod_result = timeout(
        Duration::from_secs(10),
        pods.get(pod_name)
    ).await;
    
    let pod = match pod_result {
        Ok(Ok(pod)) => pod,
        Ok(Err(kube::Error::Api(api_err))) if api_err.code == 404 => {
            return Err(NetInspectError::ResourceNotFound(
                format!("Pod '{}' not found in namespace '{}'", pod_name, namespace)
            ));
        },
        Ok(Err(e)) => return Err(NetInspectError::from(e)),
        Err(_) => return Err(NetInspectError::Timeout(
            "Pod lookup timed out after 10 seconds".to_string()
        )),
    };
    
    // Enhanced pod status checking
    let status = pod.status.as_ref().ok_or_else(|| {
        NetInspectError::ResourceNotFound(
            format!("Pod '{}' has no status information - it may be initializing", pod_name)
        )
    })?;
    
    // Check pod phase
    if let Some(phase) = &status.phase {
        match phase.as_str() {
            "Pending" => {
                println!("{} Pod is in Pending phase - not yet scheduled", "⚠".yellow().bold());
                return Err(NetInspectError::ResourceNotFound(
                    "Pod is pending and has no IP address yet".to_string()
                ));
            },
            "Failed" | "Succeeded" => {
                println!("{} Pod is in {} phase - not running", "⚠".yellow().bold(), phase);
                return Err(NetInspectError::ResourceNotFound(
                    format!("Pod is in {} phase and cannot be tested", phase)
                ));
            },
            "Running" => {
                println!("{} Pod is running", "✓".green().bold());
            },
            _ => {
                println!("{} Pod phase: {}", "ℹ".blue().bold(), phase.yellow());
            }
        }
    }
    
    let pod_ip = status.pod_ip.as_ref().ok_or_else(|| {
        NetInspectError::ResourceNotFound(
            format!("Pod '{}' has no IP address assigned - check if it's running", pod_name)
        )
    })?;
    
    // Validate IP address format
    Validator::validate_pod_ip(pod_ip)?;
    
    println!("{} Pod IP: {}", "ℹ".blue().bold(), pod_ip.cyan());
    
    // Enhanced connectivity test with retries
    match test_connectivity_with_retries(pod_ip, 3).await {
        Ok(()) => {
            println!("{} Connectivity test: {}", "✓".green().bold(), "PASS".green().bold());
            Ok(())
        }
        Err(e) => {
            println!("{} Connectivity test: {} - {}", "✗".red().bold(), "FAIL".red().bold(), e);
            Err(e)
        }
    }
}

pub fn version() {
    println!("{} k8s-netinspect v{}", 
             "🔧".yellow().bold(), 
             env!("CARGO_PKG_VERSION").green());
    println!("A minimal Kubernetes network inspection tool");
}

async fn detect_cni(client: &Client) -> NetInspectResult<String> {
    let nodes_list = get_cluster_nodes_list(client).await?;
    
    if nodes_list.is_empty() {
        return Ok("No nodes available for CNI detection".to_string());
    }
    
    let mut detected_cnis = Vec::new();
    
    for node in &nodes_list {
        if let Some(status) = &node.status {
            if let Some(node_info) = &status.node_info {
                // Enhanced CNI detection logic
                let runtime = &node_info.container_runtime_version;
                
                // Check annotations for CNI-specific markers
                if let Some(annotations) = &node.metadata.annotations {
                    // Calico detection
                    if annotations.keys().any(|k| k.contains("calico") || k.contains("projectcalico")) {
                        detected_cnis.push("Calico".to_string());
                        continue;
                    }
                    
                    // Flannel detection
                    if annotations.keys().any(|k| k.contains("flannel")) {
                        detected_cnis.push("Flannel".to_string());
                        continue;
                    }
                    
                    // Weave detection
                    if annotations.keys().any(|k| k.contains("weave")) {
                        detected_cnis.push("Weave Net".to_string());
                        continue;
                    }
                    
                    // Cilium detection
                    if annotations.keys().any(|k| k.contains("cilium")) {
                        detected_cnis.push("Cilium".to_string());
                        continue;
                    }
                }
                
                // Fallback to runtime detection
                if runtime.contains("containerd") {
                    detected_cnis.push("Generic CNI (containerd)".to_string());
                } else if runtime.contains("docker") {
                    detected_cnis.push("Generic CNI (docker)".to_string());
                }
            }
        }
    }
    
    if detected_cnis.is_empty() {
        Ok("Unknown CNI".to_string())
    } else {
        // Return the most common CNI or first detected
        Ok(detected_cnis.into_iter().next().unwrap())
    }
}

async fn test_connectivity_with_retries(pod_ip: &str, max_retries: u32) -> NetInspectResult<()> {
    for attempt in 1..=max_retries {
        match test_connectivity(pod_ip).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt < max_retries {
                    println!("{} Attempt {} failed, retrying... ({})", 
                             "⚠".yellow().bold(), attempt, e);
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
        .map_err(|e| NetInspectError::Runtime(
            format!("Failed to create HTTP client: {}", e)
        ))?;
    
    let response = client.get(&url).send().await?;
    
    if response.status().is_success() {
        Ok(())
    } else {
        Err(NetInspectError::NetworkConnectivity(
            format!("HTTP {} - {}", 
                response.status(), 
                response.status().canonical_reason().unwrap_or("Unknown error"))
        ))
    }
}

/// Create Kubernetes client with enhanced error handling
async fn create_kubernetes_client() -> NetInspectResult<Client> {
    Client::try_default().await.map_err(NetInspectError::from)
}

/// Get cluster nodes with enhanced error handling
async fn get_cluster_nodes(client: &Client) -> NetInspectResult<usize> {
    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes.list(&Default::default()).await
        .map_err(NetInspectError::from)?;
    Ok(node_list.items.len())
}

/// Get cluster nodes list for CNI detection
async fn get_cluster_nodes_list(client: &Client) -> NetInspectResult<Vec<Node>> {
    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes.list(&Default::default()).await
        .map_err(NetInspectError::from)?;
    Ok(node_list.items)
}


/// Check pods in specified namespace or cluster-wide
async fn check_pods_in_namespace(client: &Client, namespace: Option<&str>) -> NetInspectResult<usize> {
    let pods = if let Some(ns) = namespace {
        // Pods in specific namespace
        let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
        pods.list(&Default::default()).await
            .map_err(NetInspectError::from)?
    } else {
        // All pods cluster-wide
        let pods: Api<Pod> = Api::all(client.clone());
        pods.list(&Default::default()).await
            .map_err(NetInspectError::from)?
    };
    
    Ok(pods.items.len())
}

/// Quick connectivity test for summary (shorter timeout)
async fn test_connectivity_quick(pod_ip: &str) -> NetInspectResult<()> {
    let url = format!("http://{}:80", pod_ip);
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))  // Shorter timeout for summary
        .connect_timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| NetInspectError::Runtime(
            format!("Failed to create HTTP client: {}", e)
        ))?;
    
    let response = client.get(&url).send().await?;
    
    if response.status().is_success() {
        Ok(())
    } else {
        Err(NetInspectError::NetworkConnectivity(
            format!("HTTP {} - {}", 
                response.status(), 
                response.status().canonical_reason().unwrap_or("Unknown error"))
        ))
    }
}