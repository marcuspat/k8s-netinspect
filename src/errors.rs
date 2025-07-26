use std::fmt;
use colored::*;

/// Custom error types for k8s-netinspect with specific error codes
#[derive(Debug)]
pub enum NetInspectError {
    /// Kubernetes API connection errors (exit code 3)
    KubernetesConnection(String),
    /// RBAC/Permission errors (exit code 5)
    PermissionDenied(String),
    /// Configuration errors (exit code 2)
    Configuration(String),
    /// Network connectivity issues (exit code 4)
    NetworkConnectivity(String),
    /// Invalid input/arguments (exit code 2)
    InvalidInput(String),
    /// Resource not found (exit code 4)
    ResourceNotFound(String),
    /// Timeout errors
    Timeout(String),
    /// General runtime errors (exit code 1)
    Runtime(String),
}

impl fmt::Display for NetInspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetInspectError::KubernetesConnection(msg) => {
                write!(f, "{} {}", "Kubernetes Connection Error:".red().bold(), msg)
            }
            NetInspectError::PermissionDenied(msg) => {
                write!(f, "{} {}", "Permission Denied:".yellow().bold(), msg)
            }
            NetInspectError::Configuration(msg) => {
                write!(f, "{} {}", "Configuration Error:".purple().bold(), msg)
            }
            NetInspectError::NetworkConnectivity(msg) => {
                write!(f, "{} {}", "Network Error:".red().bold(), msg)
            }
            NetInspectError::InvalidInput(msg) => {
                write!(f, "{} {}", "Invalid Input:".yellow().bold(), msg)
            }
            NetInspectError::ResourceNotFound(msg) => {
                write!(f, "{} {}", "Resource Not Found:".blue().bold(), msg)
            }
            NetInspectError::Timeout(msg) => {
                write!(f, "{} {}", "Timeout:".red().bold(), msg)
            }
            NetInspectError::Runtime(msg) => {
                write!(f, "{} {}", "Runtime Error:".red().bold(), msg)
            }
        }
    }
}

impl std::error::Error for NetInspectError {}

impl NetInspectError {
    /// Get the exit code for this error type
    pub fn exit_code(&self) -> i32 {
        match self {
            NetInspectError::KubernetesConnection(_) => 3,
            NetInspectError::PermissionDenied(_) => 5,
            NetInspectError::Configuration(_) => 2,
            NetInspectError::NetworkConnectivity(_) => 4,
            NetInspectError::InvalidInput(_) => 2,
            NetInspectError::ResourceNotFound(_) => 4,
            NetInspectError::Timeout(_) => 4,
            NetInspectError::Runtime(_) => 1,
        }
    }

    /// Create a user-friendly error message with troubleshooting hints
    pub fn detailed_message(&self) -> String {
        match self {
            NetInspectError::KubernetesConnection(msg) => {
                format!(
                    "{}\n{} Ensure kubeconfig is valid and cluster is accessible\n{} Check: kubectl cluster-info",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
            NetInspectError::PermissionDenied(msg) => {
                format!(
                    "{}\n{} Check RBAC permissions for your service account\n{} Required: pods/get, nodes/list",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
            NetInspectError::Configuration(msg) => {
                format!(
                    "{}\n{} Verify kubeconfig file and context\n{} Check: kubectl config current-context",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
            NetInspectError::NetworkConnectivity(msg) => {
                format!(
                    "{}\n{} Network connectivity issue detected\n{} Pod may not be running or port may be closed",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
            NetInspectError::InvalidInput(msg) => {
                format!(
                    "{}\n{} Check command syntax and arguments\n{} Use --help for usage information",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
            NetInspectError::ResourceNotFound(msg) => {
                format!(
                    "{}\n{} Verify resource exists in the specified namespace\n{} Check: kubectl get pods -n <namespace>",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
            NetInspectError::Timeout(msg) => {
                format!(
                    "{}\n{} Operation timed out - cluster may be slow or unreachable\n{} Try again or use kubectl directly to test connectivity",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
            NetInspectError::Runtime(msg) => {
                format!(
                    "{}\n{} Unexpected error occurred\n{} Please check logs and try again",
                    msg,
                    "💡 Troubleshooting:".cyan().bold(),
                    "  •".blue()
                )
            }
        }
    }
}

/// Convert from kube::Error to NetInspectError
impl From<kube::Error> for NetInspectError {
    fn from(err: kube::Error) -> Self {
        match err {
            kube::Error::Api(api_err) => {
                match api_err.code {
                    401 | 403 => NetInspectError::PermissionDenied(
                        format!("Kubernetes API access denied: {}", api_err.message)
                    ),
                    404 => NetInspectError::ResourceNotFound(
                        format!("Resource not found: {}", api_err.message)
                    ),
                    _ => NetInspectError::KubernetesConnection(
                        format!("Kubernetes API error: {}", api_err.message)
                    ),
                }
            }
            kube::Error::HttpError(http_err) => {
                NetInspectError::KubernetesConnection(
                    format!("HTTP error connecting to Kubernetes: {}", http_err)
                )
            }
            kube::Error::Auth(auth_err) => {
                NetInspectError::PermissionDenied(
                    format!("Authentication failed: {}", auth_err)
                )
            }
            kube::Error::Discovery(discovery_err) => {
                NetInspectError::KubernetesConnection(
                    format!("Service discovery failed: {}", discovery_err)
                )
            }
            _ => NetInspectError::KubernetesConnection(
                format!("Kubernetes client error: {}", err)
            ),
        }
    }
}

/// Convert from reqwest::Error to NetInspectError
impl From<reqwest::Error> for NetInspectError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            NetInspectError::Timeout(
                "HTTP request timed out - pod may be unreachable".to_string()
            )
        } else if err.is_connect() {
            NetInspectError::NetworkConnectivity(
                format!("Failed to connect to pod: {}", err)
            )
        } else {
            NetInspectError::NetworkConnectivity(
                format!("HTTP request failed: {}", err)
            )
        }
    }
}

/// Convert from anyhow::Error to NetInspectError
impl From<anyhow::Error> for NetInspectError {
    fn from(err: anyhow::Error) -> Self {
        NetInspectError::Runtime(err.to_string())
    }
}

/// Result type alias for convenience
pub type NetInspectResult<T> = Result<T, NetInspectError>;