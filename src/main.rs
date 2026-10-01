use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

use k8s_netinspect::analysis::policy::Protocol;
use k8s_netinspect::commands::{self, Source};
use k8s_netinspect::errors::NetInspectResult;
use k8s_netinspect::output::OutputFormat;
use k8s_netinspect::validation::Validator;

#[derive(Parser)]
#[command(name = "k8s-netinspect")]
#[command(about = "A minimal Kubernetes network inspection tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Diagnose CNI and basic network configuration
    Diagnose {
        /// Target namespace for pod diagnostics (default: cluster-wide)
        #[arg(short, long, conflicts_with = "from_snapshot")]
        namespace: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
        /// Analyze a snapshot file instead of a live cluster (no API access needed)
        #[arg(long, value_name = "FILE")]
        from_snapshot: Option<PathBuf>,
    },
    /// Capture a redacted snapshot of the cluster's network state as JSON
    Snapshot {
        /// Scope workload objects to one namespace (default: cluster-wide)
        #[arg(short, long)]
        namespace: Option<String>,
        /// Write to this file instead of stdout
        #[arg(short, long, value_name = "FILE")]
        file: Option<PathBuf>,
    },
    /// Check whether NetworkPolicy allows a flow, and name the policy that blocks it
    ///
    /// Exits 0 when allowed, 6 when blocked.
    CanReach {
        /// Source: namespace/pod, pod (namespace "default"), or an IP address
        #[arg(long, value_name = "ENDPOINT")]
        from: String,
        /// Destination: namespace/pod, pod (namespace "default"), or an IP address
        #[arg(long, value_name = "ENDPOINT")]
        to: String,
        /// Destination port
        #[arg(short, long)]
        port: u16,
        /// Transport protocol
        #[arg(long, value_enum, default_value_t = ProtocolArg::Tcp)]
        protocol: ProtocolArg,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
        /// Evaluate against a snapshot file instead of a live cluster
        #[arg(long, value_name = "FILE")]
        from_snapshot: Option<PathBuf>,
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

#[derive(Clone, Copy, clap::ValueEnum)]
enum ProtocolArg {
    Tcp,
    Udp,
    Sctp,
}

impl From<ProtocolArg> for Protocol {
    fn from(p: ProtocolArg) -> Self {
        match p {
            ProtocolArg::Tcp => Protocol::Tcp,
            ProtocolArg::Udp => Protocol::Udp,
            ProtocolArg::Sctp => Protocol::Sctp,
        }
    }
}

/// Exit status of `can-reach` when the flow is blocked. Distinct from every
/// error exit code so scripts can tell "blocked" from "could not evaluate".
const EXIT_BLOCKED: i32 = 6;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match run(&cli.command).await {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("{}", e.detailed_message());
            process::exit(e.exit_code());
        }
    }
}

async fn run(command: &Commands) -> NetInspectResult<()> {
    match command {
        Commands::Diagnose {
            namespace,
            output,
            from_snapshot,
        } => {
            if let Some(path) = from_snapshot {
                commands::diagnose(Source::File(path), *output).await?;
                return Ok(());
            }
            let namespace = namespace.as_deref();
            validate_live(namespace).await?;
            commands::diagnose(Source::Live { namespace }, *output).await?;
            Ok(())
        }
        Commands::Snapshot { namespace, file } => {
            let namespace = namespace.as_deref();
            validate_live(namespace).await?;
            commands::snapshot(namespace, file.as_deref()).await
        }
        Commands::CanReach {
            from,
            to,
            port,
            protocol,
            output,
            from_snapshot,
        } => {
            let source = match from_snapshot {
                Some(path) => Source::File(path),
                None => {
                    // Policies and peers can live in any namespace.
                    validate_live(None).await?;
                    Source::Live { namespace: None }
                }
            };
            let report =
                commands::can_reach(source, from, to, *port, (*protocol).into(), *output).await?;
            if !report.verdict.allowed {
                process::exit(EXIT_BLOCKED);
            }
            Ok(())
        }
        Commands::TestPod { pod, namespace } => {
            Validator::validate_pod_name(pod)?;
            Validator::validate_namespace(namespace)?;
            Validator::validate_environment()?;
            Validator::validate_kubernetes_access().await?;
            commands::test_pod(pod, namespace).await
        }
        Commands::Version => {
            commands::version();
            Ok(())
        }
    }
}

/// Pre-flight for commands that talk to a cluster.
async fn validate_live(namespace: Option<&str>) -> NetInspectResult<()> {
    if let Some(ns) = namespace {
        Validator::validate_namespace(ns)?;
    }
    Validator::validate_environment()?;
    Validator::validate_kubernetes_access().await?;
    if let Some(ns) = namespace {
        Validator::validate_namespace_exists(ns).await?;
    }
    Ok(())
}
