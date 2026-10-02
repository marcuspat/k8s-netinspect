//! Model Context Protocol server over stdio, so coding and ops agents can
//! query cluster network state.
//!
//! Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout. Nothing else
//! is ever written to stdout; diagnostics go to stderr.
//!
//! Every tool is **read-only**. The in-cluster probe (`can-reach --probe`),
//! which modifies a pod, is deliberately not exposed here: an agent should
//! not be able to change a cluster through a diagnostics server.

use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::analysis;
use crate::analysis::policy::Protocol;
use crate::commands;
use crate::errors::{NetInspectError, NetInspectResult};
use crate::rules::{self, Filter};
use crate::snapshot::ClusterSnapshot;
use crate::suggest;

/// Protocol revisions this server can speak; the newest is offered when the
/// client asks for one we do not know.
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// Where tool calls get cluster state from.
#[derive(Debug, Clone)]
pub enum SnapshotSource {
    /// Collect from the current kubeconfig context on every call.
    Live,
    /// Serve a fixed snapshot file (no cluster access at all).
    File(PathBuf),
}

pub struct Server {
    source: SnapshotSource,
}

fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

fn result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// Tool definitions advertised by `tools/list`.
pub fn tools() -> Value {
    let read_only = json!({"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true});
    json!([
        {
            "name": "diagnose",
            "description": "Run all network diagnostics (CNI, nodes, pod IPAM, NetworkPolicy, \
                Services, DNS, kube-proxy, Ingress, Gateway API) and return findings with \
                severity, evidence and a suggested fix. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "Limit workload objects to one namespace (live clusters only). Omit for cluster-wide."},
                    "only": {"type": "array", "items": {"type": "string"}, "description": "Report only these rule ids or families, e.g. [\"DNS\", \"POL-001\"]."},
                    "skip": {"type": "array", "items": {"type": "string"}, "description": "Do not report these rule ids or families."}
                },
                "additionalProperties": false
            },
            "annotations": read_only
        },
        {
            "name": "can_reach",
            "description": "Decide whether policy (AdminNetworkPolicy, NetworkPolicy, \
                BaselineAdminNetworkPolicy) allows a flow, and name the policy that blocks it. \
                Evaluated from policy objects; no traffic is sent. `allowed` means no evaluated \
                policy blocks the flow, not that the connection will succeed; check `complete` \
                and `caveats`. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Source: namespace/pod, a pod name in namespace default, or an IP address."},
                    "to": {"type": "string", "description": "Destination: namespace/pod, a pod name in namespace default, or an IP address."},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "protocol": {"type": "string", "enum": ["TCP", "UDP", "SCTP"], "default": "TCP"},
                    "suggest": {"type": "boolean", "default": false, "description": "Also return the minimal NetworkPolicy that would allow a blocked flow. It is returned as text, never applied."}
                },
                "required": ["from", "to", "port"],
                "additionalProperties": false
            },
            "annotations": read_only
        },
        {
            "name": "explain_rule",
            "description": "Describe one diagnostic rule: what it means and how to investigate it.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string", "description": "Rule id, e.g. DNS-006."}},
                "required": ["id"],
                "additionalProperties": false
            },
            "annotations": read_only
        },
        {
            "name": "list_rules",
            "description": "List every rule `diagnose` can report, with its family and highest severity.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "annotations": read_only
        }
    ])
}

fn string_list(args: &Value, key: &str) -> Result<Vec<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{key}` must be an array of strings"))
            })
            .collect(),
        Some(_) => Err(format!("`{key}` must be an array of strings")),
    }
}

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("`{key}` is required and must be a non-empty string"))
}

/// Tools that need no cluster data.
fn call_static_tool(name: &str, args: &Value) -> Option<Result<Value, String>> {
    match name {
        "list_rules" => Some(Ok(json!({
            "rules": rules::RULES.iter().map(|r| json!({
                "id": r.id, "category": r.category,
                "max_severity": r.severity.to_string(), "title": r.title,
            })).collect::<Vec<_>>()
        }))),
        "explain_rule" => Some(required_str(args, "id").and_then(|id| {
            let rule = rules::find(id).ok_or_else(|| format!("unknown rule '{id}'"))?;
            Ok(json!({
                "id": rule.id, "category": rule.category,
                "max_severity": rule.severity.to_string(), "title": rule.title,
                "description": rule.description, "explanation": rules::explain(rule),
            }))
        })),
        _ => None,
    }
}

/// Tools that analyze a snapshot. Pure: all I/O happened before this.
pub fn call_snapshot_tool(
    snapshot: &ClusterSnapshot,
    name: &str,
    args: &Value,
) -> Result<Value, String> {
    match name {
        "diagnose" => {
            let filter = Filter {
                only: string_list(args, "only")?,
                skip: string_list(args, "skip")?,
            };
            let unknown = filter.unknown_selectors();
            if !unknown.is_empty() {
                return Err(format!("unknown rule selector(s): {}", unknown.join(", ")));
            }
            let mut report = analysis::analyze(snapshot);
            filter.apply(&mut report.findings);
            serde_json::to_value(&report).map_err(|e| e.to_string())
        }
        "can_reach" => {
            let from = required_str(args, "from")?;
            let to = required_str(args, "to")?;
            let port = args
                .get("port")
                .and_then(Value::as_u64)
                .filter(|p| (1..=65535).contains(p))
                .ok_or("`port` is required and must be an integer between 1 and 65535")?
                as u16;
            let protocol = match args
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("TCP")
            {
                p if p.eq_ignore_ascii_case("tcp") => Protocol::Tcp,
                p if p.eq_ignore_ascii_case("udp") => Protocol::Udp,
                p if p.eq_ignore_ascii_case("sctp") => Protocol::Sctp,
                other => {
                    return Err(format!(
                        "`protocol` must be TCP, UDP or SCTP, not '{other}'"
                    ))
                }
            };
            let mut report = commands::evaluate_reach(snapshot, from, to, port, protocol)
                .map_err(|e| e.plain_message())?;
            if args
                .get("suggest")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let flow = commands::resolve_flow(snapshot, from, to, port, protocol)
                    .map_err(|e| e.plain_message())?;
                report.suggestion = Some(suggest::suggest(snapshot, &flow));
            }
            serde_json::to_value(&report).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown tool '{other}'")),
    }
}

impl Server {
    pub fn new(source: SnapshotSource) -> Self {
        Self { source }
    }

    async fn snapshot(&self, namespace: Option<&str>) -> NetInspectResult<ClusterSnapshot> {
        match &self.source {
            SnapshotSource::File(path) => ClusterSnapshot::load(path),
            SnapshotSource::Live => commands::collect_snapshot(namespace).await,
        }
    }

    async fn call_tool(&self, name: &str, args: &Value) -> Result<Value, String> {
        if let Some(outcome) = call_static_tool(name, args) {
            return outcome;
        }
        if !matches!(name, "diagnose" | "can_reach") {
            return Err(format!("unknown tool '{name}'"));
        }
        // Only `diagnose` may be namespace-scoped; reachability needs every
        // namespace's pods and policies.
        let namespace = match name {
            "diagnose" => args.get("namespace").and_then(Value::as_str),
            _ => None,
        };
        let snapshot = self
            .snapshot(namespace)
            .await
            .map_err(|e: NetInspectError| e.plain_message())?;
        call_snapshot_tool(&snapshot, name, args)
    }

    /// Handle one JSON-RPC message. Returns `None` for notifications.
    pub async fn handle(&self, message: &Value) -> Option<Value> {
        let Some(obj) = message.as_object() else {
            return Some(error(
                Value::Null,
                INVALID_REQUEST,
                "expected a JSON-RPC request object (batches are not supported)",
            ));
        };
        let id = obj.get("id").cloned();
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            return Some(error(
                id.unwrap_or(Value::Null),
                INVALID_REQUEST,
                "missing `method`",
            ));
        };
        // No id means a notification: act on it, never answer.
        let id = id?;
        let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));

        Some(match method {
            "initialize" => {
                let requested = params.get("protocolVersion").and_then(Value::as_str);
                let version = requested
                    .filter(|v| SUPPORTED_PROTOCOLS.contains(v))
                    .unwrap_or(SUPPORTED_PROTOCOLS[0]);
                result(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {"name": "k8s-netinspect", "version": env!("CARGO_PKG_VERSION")},
                        "instructions": "Read-only Kubernetes network diagnostics. Start with \
                            `diagnose`; use `can_reach` to ask whether policy allows a specific \
                            flow. No tool changes the cluster.",
                    }),
                )
            }
            "ping" => result(id, json!({})),
            "tools/list" => result(id, json!({"tools": tools()})),
            "tools/call" => {
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    return Some(error(id, INVALID_PARAMS, "`params.name` is required"));
                };
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if !args.is_object() {
                    return Some(error(
                        id,
                        INVALID_PARAMS,
                        "`params.arguments` must be an object",
                    ));
                }
                if !tools()
                    .as_array()
                    .is_some_and(|t| t.iter().any(|t| t["name"] == name))
                {
                    return Some(error(id, INVALID_PARAMS, format!("unknown tool '{name}'")));
                }
                // Tool failures are results the model can read, not protocol errors.
                match self.call_tool(name, &args).await {
                    Ok(value) => result(
                        id,
                        json!({
                            "content": [{"type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default()}],
                            "structuredContent": value,
                            "isError": false,
                        }),
                    ),
                    Err(message) => result(
                        id,
                        json!({"content": [{"type": "text", "text": message}], "isError": true}),
                    ),
                }
            }
            other => error(id, METHOD_NOT_FOUND, format!("method '{other}' not found")),
        })
    }

    /// Handle one line of input; `None` when no reply is due.
    pub async fn handle_line(&self, line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let reply = match serde_json::from_str::<Value>(line) {
            Ok(message) => self.handle(&message).await?,
            Err(e) => error(Value::Null, PARSE_ERROR, format!("invalid JSON: {e}")),
        };
        // Compact, single-line: the framing is one message per line.
        Some(reply.to_string())
    }

    /// Serve until stdin closes.
    pub async fn serve(&self) -> NetInspectResult<()> {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut stdout = tokio::io::stdout();
        let io_err = |e: std::io::Error| NetInspectError::Runtime(format!("MCP stdio error: {e}"));
        while let Some(line) = lines.next_line().await.map_err(io_err)? {
            if let Some(reply) = self.handle_line(&line).await {
                stdout.write_all(reply.as_bytes()).await.map_err(io_err)?;
                stdout.write_all(b"\n").await.map_err(io_err)?;
                stdout.flush().await.map_err(io_err)?;
            }
        }
        Ok(())
    }
}
