use clap::{Parser, Subcommand};
use std::process;

mod commands;
mod errors;
mod validation;

use errors::NetInspectError;
use validation::Validator;

#[derive(Parser)]
#[command(name = "k8s-netinspect")]
#[command(about = "A minimal Kubernetes network inspection tool")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Diagnose CNI and basic network configuration
    Diagnose {
        /// Target namespace for pod diagnostics (default: cluster-wide)
        #[arg(short, long)]
        namespace: Option<String>,
    },
    /// Test pod connectivity
    TestPod {
        /// Pod name to test
        #[arg(short, long)]
        pod: String,
        /// Namespace (default: default)
        #[arg(short, long, default_value = "default")]
        namespace: String,
    },
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    // Validate environment before executing commands
    if let Err(e) = Validator::validate_environment() {
        eprintln!("{}", e.detailed_message());
        process::exit(e.exit_code());
    }
    
    let result = match &cli.command {
        Commands::Diagnose { namespace } => {
            if let Err(e) = Validator::validate_kubernetes_access().await {
                Err(e)
            } else {
                // Validate namespace if provided
                if let Some(ns) = namespace {
                    if let Err(e) = Validator::validate_namespace(ns) {
                        Err(e)
                    } else if let Err(e) = Validator::validate_namespace_exists(ns).await {
                        Err(e)
                    } else {
                        commands::diagnose(namespace.as_deref()).await
                    }
                } else {
                    commands::diagnose(None).await
                }
            }
        },
        Commands::TestPod { pod, namespace } => {
            // Validate inputs
            if let Err(e) = Validator::validate_pod_name(pod) {
                Err(e)
            } else if let Err(e) = Validator::validate_namespace(namespace) {
                Err(e)
            } else if let Err(e) = Validator::validate_kubernetes_access().await {
                Err(e)
            } else {
                commands::test_pod(pod, namespace).await
            }
        },
        Commands::Version => {
            commands::version();
            Ok(())
        }
    };
    
    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("{}", e.detailed_message());
            process::exit(e.exit_code());
        }
    }
}