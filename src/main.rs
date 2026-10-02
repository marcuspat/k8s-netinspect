use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

use k8s_netinspect::analysis::policy::Protocol;
use k8s_netinspect::commands::{self, ProbeOptions, ReachQuery, Source};
use k8s_netinspect::errors::{NetInspectError, NetInspectResult};
use k8s_netinspect::mcp::{Server, SnapshotSource};
use k8s_netinspect::model::Severity;
use k8s_netinspect::output::OutputFormat;
use k8s_netinspect::probe;
use k8s_netinspect::rules::Filter;
use k8s_netinspect::validation::Validator;

#[derive(Parser)]
#[command(name = "k8s-netinspect")]
#[command(
    about = "Kubernetes network diagnostics: what is broken, and which object is responsible"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run every network check and report findings with a suggested fix
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
        /// Exit with status 7 if any finding is at or above this severity
        #[arg(long, value_enum, value_name = "SEVERITY")]
        fail_on: Option<Severity>,
        /// Report only these rules: ids (DNS-006) or families (DNS), comma-separated
        #[arg(long, value_delimiter = ',', value_name = "RULES")]
        only: Vec<String>,
        /// Do not report these rules: ids or families, comma-separated
        #[arg(long, value_delimiter = ',', value_name = "RULES")]
        skip: Vec<String>,
        /// Re-run every N seconds and print only what changed (text output)
        #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..))]
        watch: Option<u64>,
        /// With --watch: stop after this many rounds instead of running until interrupted
        #[arg(long, value_name = "N", requires = "watch", value_parser = clap::value_parser!(u32).range(1..))]
        watch_count: Option<u32>,
    },
    /// Compare two snapshots: new, resolved and changed findings
    ///
    /// Exits 7 with --fail-on when a new or worsened finding meets the severity.
    Diff {
        /// Snapshot taken first
        before: PathBuf,
        /// Snapshot taken later
        after: PathBuf,
        /// Output format (text or json)
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        output: OutputFormat,
        /// Exit with status 7 if a new or worsened finding is at or above this severity
        #[arg(long, value_enum, value_name = "SEVERITY")]
        fail_on: Option<Severity>,
        /// Compare only these rules: ids or families, comma-separated
        #[arg(long, value_delimiter = ',', value_name = "RULES")]
        only: Vec<String>,
        /// Ignore these rules: ids or families, comma-separated
        #[arg(long, value_delimiter = ',', value_name = "RULES")]
        skip: Vec<String>,
    },
    /// Serve read-only diagnostics to AI agents over the Model Context Protocol (stdio)
    Mcp {
        /// Answer from a snapshot file instead of a live cluster
        #[arg(long, value_name = "FILE")]
        from_snapshot: Option<PathBuf>,
    },
    /// Explain one rule: what it means and how to investigate it
    Explain {
        /// Rule id, e.g. DNS-006
        rule: String,
    },
    /// List every rule diagnose can report
    Rules {
        /// Output format
        #[arg(long, value_enum, default_value_t = RulesFormat::Text)]
        format: RulesFormat,
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
        /// When blocked, print the NetworkPolicy that would allow the flow (never applied)
        #[arg(long)]
        suggest: bool,
        /// Also test for real: run one TCP connect from inside the source pod
        ///
        /// Adds an ephemeral container to the source pod (it cannot be removed
        /// afterwards) and needs `patch` on pods/ephemeralcontainers. Exits 8
        /// when the result contradicts the policy verdict.
        #[arg(long)]
        probe: bool,
        /// Image for the probe container; must provide `nc`
        #[arg(long, value_name = "IMAGE", default_value = probe::DEFAULT_IMAGE, requires = "probe")]
        probe_image: String,
        /// TCP connect timeout for the probe, in seconds
        #[arg(long, value_name = "SECONDS", default_value_t = 5, requires = "probe",
              value_parser = clap::value_parser!(u32).range(1..=60))]
        probe_timeout: u32,
    },
    /// HTTP GET to a pod IP on port 80, from this machine (legacy; see can-reach --probe)
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

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum RulesFormat {
    Text,
    Markdown,
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

/// Exit status of `can-reach --probe` when the observed result contradicts
/// the policy verdict.
const EXIT_PROBE_MISMATCH: i32 = 8;

/// Exit status of `diagnose --fail-on` when a finding meets the threshold.
const EXIT_FINDINGS: i32 = 7;

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
            fail_on,
            only,
            skip,
            watch,
            watch_count,
        } => {
            let filter = Filter {
                only: only.clone(),
                skip: skip.clone(),
            };
            if watch.is_some() && *output != OutputFormat::Text {
                return Err(NetInspectError::InvalidInput(
                    "--watch prints deltas as text; it cannot be combined with --output"
                        .to_string(),
                ));
            }
            let source = match from_snapshot {
                Some(path) => Source::File(path),
                None => {
                    let namespace = namespace.as_deref();
                    validate_live(namespace).await?;
                    Source::Live { namespace }
                }
            };
            let report = match watch {
                Some(seconds) => {
                    let interval = std::time::Duration::from_secs(*seconds);
                    commands::watch(source, &filter, interval, *watch_count).await?
                }
                None => commands::diagnose(source, *output, &filter).await?,
            };
            if let (Some(threshold), Some(worst)) = (fail_on, report.max_severity()) {
                if worst >= *threshold {
                    process::exit(EXIT_FINDINGS);
                }
            }
            Ok(())
        }
        Commands::Diff {
            before,
            after,
            output,
            fail_on,
            only,
            skip,
        } => {
            let filter = Filter {
                only: only.clone(),
                skip: skip.clone(),
            };
            let delta = commands::diff_snapshots(before, after, *output, &filter)?;
            if let (Some(threshold), Some(worst)) = (fail_on, delta.worst_regression()) {
                if worst >= *threshold {
                    process::exit(EXIT_FINDINGS);
                }
            }
            Ok(())
        }
        Commands::Mcp { from_snapshot } => {
            let source = match from_snapshot {
                Some(path) => SnapshotSource::File(path.clone()),
                None => {
                    // Fail before the handshake, on stderr, if there is no cluster.
                    validate_live(None).await?;
                    SnapshotSource::Live
                }
            };
            Server::new(source).serve().await
        }
        Commands::Explain { rule } => commands::explain(rule),
        Commands::Rules { format } => {
            commands::rules(*format == RulesFormat::Markdown);
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
            suggest,
            probe,
            probe_image,
            probe_timeout,
        } => {
            let source = match from_snapshot {
                Some(path) => Source::File(path),
                None => {
                    // Policies and peers can live in any namespace.
                    validate_live(None).await?;
                    Source::Live { namespace: None }
                }
            };
            let query = ReachQuery {
                from,
                to,
                port: *port,
                protocol: (*protocol).into(),
                format: *output,
                probe: probe.then(|| ProbeOptions {
                    image: probe_image.clone(),
                    timeout_secs: *probe_timeout,
                }),
                suggest: *suggest,
            };
            let report = commands::can_reach(source, &query).await?;
            if report.probe.as_ref().is_some_and(|p| !p.agrees) {
                process::exit(EXIT_PROBE_MISMATCH);
            }
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
