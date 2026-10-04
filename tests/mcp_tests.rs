//! MCP server protocol tests: through the library handler, and end to end
//! through the real binary's stdin/stdout.

use k8s_netinspect::mcp::{Server, SnapshotSource};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.json"))
}

fn server(name: &str) -> Server {
    Server::new(SnapshotSource::File(fixture(name)))
}

async fn call(server: &Server, message: Value) -> Value {
    let reply = server
        .handle_line(&message.to_string())
        .await
        .expect("a reply");
    assert!(!reply.contains('\n'), "one message per line");
    serde_json::from_str(&reply).unwrap()
}

async fn tool(server: &Server, name: &str, arguments: Value) -> Value {
    let reply = call(
        server,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}),
    )
    .await;
    assert_eq!(reply["id"], 7);
    reply["result"].clone()
}

#[tokio::test]
async fn initialize_negotiates_the_protocol_version() {
    let s = server("healthy-cilium");
    let init = |version: &str| {
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": version, "capabilities": {},
                          "clientInfo": {"name": "test", "version": "0"}}})
    };
    let r = call(&s, init("2024-11-05")).await;
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], 1);
    assert_eq!(
        r["result"]["protocolVersion"], "2024-11-05",
        "echo a version we support"
    );
    assert_eq!(r["result"]["serverInfo"]["name"], "k8s-netinspect");
    assert_eq!(
        r["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert!(r["result"]["capabilities"]["tools"].is_object());

    let r = call(&s, init("1999-01-01")).await;
    assert_eq!(
        r["result"]["protocolVersion"], "2025-06-18",
        "offer our newest otherwise"
    );
}

#[tokio::test]
async fn notifications_get_no_reply_and_ping_does() {
    let s = server("healthy-cilium");
    let none = s
        .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .await;
    assert!(none.is_none());
    assert!(s.handle_line("   ").await.is_none());
    let r = call(&s, json!({"jsonrpc": "2.0", "id": "p1", "method": "ping"})).await;
    assert_eq!(r, json!({"jsonrpc": "2.0", "id": "p1", "result": {}}));
}

#[tokio::test]
async fn tools_list_is_read_only_and_has_no_probe() {
    let s = server("healthy-cilium");
    let r = call(
        &s,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;
    let tools = r["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec!["diagnose", "can_reach", "explain_rule", "list_rules"]
    );
    for t in tools {
        assert_eq!(t["inputSchema"]["type"], "object", "{}", t["name"]);
        assert_eq!(t["annotations"]["readOnlyHint"], true);
        assert_eq!(t["annotations"]["destructiveHint"], false);
        assert!(!t["description"].as_str().unwrap().is_empty());
    }
    // The pod-modifying probe must not be reachable through MCP.
    let all = r.to_string();
    assert!(!all.contains("probe"), "no probe tool or parameter");
    assert_eq!(
        tools[1]["inputSchema"]["required"],
        json!(["from", "to", "port"])
    );
}

#[tokio::test]
async fn diagnose_tool_returns_the_report_and_honours_filters() {
    let s = server("calico-degraded");
    let r = tool(&s, "diagnose", json!({})).await;
    assert_eq!(r["isError"], false);
    let report = &r["structuredContent"];
    assert_eq!(report["cni"][0]["name"], "Calico");
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["CNI-002", "NODE-002", "NODE-003", "COLLECT-001"]);
    // The text block is the same report, for clients without structured output.
    let text: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, report);

    let r = tool(
        &s,
        "diagnose",
        json!({"only": ["NODE"], "skip": ["NODE-003"]}),
    )
    .await;
    assert_eq!(
        r["structuredContent"]["findings"].as_array().unwrap().len(),
        1
    );
    assert_eq!(r["structuredContent"]["findings"][0]["id"], "NODE-002");

    let r = tool(&s, "diagnose", json!({"only": ["NOPE"]})).await;
    assert_eq!(r["isError"], true);
    assert!(r["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("unknown rule selector"));
    let r = tool(&s, "diagnose", json!({"only": "DNS"})).await;
    assert_eq!(r["isError"], true, "`only` must be an array");
}

#[tokio::test]
async fn can_reach_tool_verdicts_suggestions_and_errors() {
    let s = server("shop-policies");
    let r = tool(
        &s,
        "can_reach",
        json!({"from": "shop/web", "to": "shop/api", "port": 8080}),
    )
    .await;
    assert_eq!(r["isError"], false);
    assert_eq!(r["structuredContent"]["allowed"], true);
    assert!(r["structuredContent"].get("suggestion").is_none());

    let r = tool(
        &s,
        "can_reach",
        json!({"from": "ops/prom", "to": "shop/api", "port": 8080, "suggest": true}),
    )
    .await;
    let v = &r["structuredContent"];
    assert_eq!(v["allowed"], false);
    assert_eq!(v["ingress"]["decision"], "denied");
    assert_eq!(v["suggestion"]["verified"], true);
    assert!(v["suggestion"]["yaml"]
        .as_str()
        .unwrap()
        .contains("kind: NetworkPolicy"));

    let r = tool(
        &s,
        "can_reach",
        json!({"from": "shop/web", "to": "shop/api", "port": 53, "protocol": "udp"}),
    )
    .await;
    assert_eq!(r["structuredContent"]["protocol"], "UDP");

    // Bad input is a tool error the model can read and correct.
    for (args, needle) in [
        (
            json!({"from": "shop/web", "to": "shop/api"}),
            "`port` is required",
        ),
        (
            json!({"from": "shop/web", "to": "shop/api", "port": 70000}),
            "`port` is required",
        ),
        (json!({"to": "shop/api", "port": 80}), "`from` is required"),
        (
            json!({"from": "shop/ghost", "to": "shop/api", "port": 80}),
            "Pod 'ghost' not found",
        ),
        (
            json!({"from": "shop/web", "to": "shop/api", "port": 80, "protocol": "icmp"}),
            "TCP, UDP or SCTP",
        ),
    ] {
        let r = tool(&s, "can_reach", args).await;
        assert_eq!(r["isError"], true);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(needle), "{text}");
    }
}

#[tokio::test]
async fn rule_tools_work_without_cluster_data() {
    // A snapshot path that does not exist: static tools must not touch it.
    let s = Server::new(SnapshotSource::File("/nonexistent/snapshot.json".into()));
    let r = tool(&s, "list_rules", json!({})).await;
    assert_eq!(
        r["structuredContent"]["rules"].as_array().unwrap().len(),
        k8s_netinspect::rules::RULES.len()
    );
    let r = tool(&s, "explain_rule", json!({"id": "pol-001"})).await;
    assert_eq!(r["structuredContent"]["id"], "POL-001");
    assert!(r["structuredContent"]["explanation"]
        .as_str()
        .unwrap()
        .contains("How to investigate"));
    let r = tool(&s, "explain_rule", json!({"id": "X-999"})).await;
    assert_eq!(r["isError"], true);

    // And a tool that does need data reports the load failure as a tool error.
    let r = tool(&s, "diagnose", json!({})).await;
    assert_eq!(r["isError"], true);
    assert!(r["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Cannot read snapshot"));
}

#[tokio::test]
async fn protocol_errors_use_json_rpc_codes() {
    let s = server("healthy-cilium");
    let parse: Value = serde_json::from_str(&s.handle_line("{not json").await.unwrap()).unwrap();
    assert_eq!(parse["error"]["code"], -32700);
    assert_eq!(parse["id"], Value::Null);

    let r = call(
        &s,
        json!({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
    )
    .await;
    assert_eq!(r["error"]["code"], -32601);
    assert_eq!(r["id"], 3);

    let r = call(
        &s,
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {}}),
    )
    .await;
    assert_eq!(r["error"]["code"], -32602);
    let r = call(
        &s,
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "rm_rf"}}),
    )
    .await;
    assert_eq!(r["error"]["code"], -32602);
    let r = call(
        &s,
        json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
               "params": {"name": "diagnose", "arguments": [1, 2]}}),
    )
    .await;
    assert_eq!(r["error"]["code"], -32602);

    let batch: Value = serde_json::from_str(
        &s.handle_line(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(batch["error"]["code"], -32600);
}

/// The real binary: only JSON-RPC on stdout, one line per reply, clean exit
/// when stdin closes.
#[test]
fn binary_serves_a_session_over_stdio() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_k8s-netinspect"))
        .args(["mcp", "--from-snapshot"])
        .arg(fixture("shop-policies"))
        .env("KUBECONFIG", "/nonexistent/kubeconfig")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let requests = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "t", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
               "params": {"name": "can_reach",
                          "arguments": {"from": "shop/api", "to": "shop/db", "port": 5432}}}),
    ];
    {
        let mut stdin = child.stdin.take().unwrap();
        for r in &requests {
            writeln!(stdin, "{r}").unwrap();
        }
    } // closing stdin ends the session
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let lines: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every stdout line is JSON"))
        .collect();
    assert_eq!(lines.len(), 3, "the notification gets no reply");
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 4);
    assert_eq!(lines[2]["id"], 3);
    assert_eq!(lines[2]["result"]["structuredContent"]["allowed"], false);
    assert_eq!(lines[2]["result"]["structuredContent"]["from"], "shop/api");
}
