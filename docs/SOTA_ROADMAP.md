# SOTA roadmap

Goal: take k8s-netinspect from "detect the CNI and count pods" to a tool that
answers the questions people actually debug: *can A reach B, and if not, which
object is responsible?* — offline-testable, CI-friendly, and usable by agents.

Work happens on `claude/sota-loop` in one draft PR. One loop = one item below.

## Loop contract

1. Take the first unchecked item. If it is too big for one loop, ship a
   coherent slice, tick nothing, and add a `remainder:` line under the item.
2. Analysis stays pure: new checks are functions over `ClusterSnapshot` that
   return `Finding`s with a stable id. Anything new that must be read from the
   cluster is added to the snapshot (best-effort, recorded in
   `collection_errors` when forbidden) — analyzers never call the API.
3. Every check gets a fixture in `tests/fixtures/` and a test proving both the
   positive and the clean case. Unknown data (failed list) must not be reported
   as a fault.
4. Gates, by exit code, all three green before committing:
   `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.
5. Commit, push, tick the item, update the README feature list if user-visible.

Standing constraints:

- No live cluster is available in the loop environment. Anything only
  verifiable against a real cluster is labelled **untested against a live
  cluster** in the README until someone runs it. No invented test results.
- CI was removed by owner decision (`49816af`). Do not re-add it.
- Do not merge to `main`, do not publish to crates.io, no paid API calls.
- Existing text output lines (`CNI detected`, `Found N nodes`, `Found N pods`)
  and exit codes stay backward compatible.

## Done

- [x] **L0 — Foundation.** Snapshot → analysis → report architecture
  (`snapshot.rs`, `analysis/`, `model.rs`, `output.rs`); `snapshot` command with
  redaction; `diagnose --from-snapshot` and `--output json`; CNI detection from
  agent DaemonSets (16 plugins, version, rollout health) with node-annotation
  fallback; node network conditions; partial diagnosis under restricted RBAC;
  `version` no longer requires a kubeconfig; unused `axum` dependency dropped.
  Rules: `CNI-001..003`, `NODE-001..003`, `COLLECT-001`.

## Loops

- [ ] **L1 — NetworkPolicy reachability engine.** `analysis/policy.rs`: pure
  evaluator for `networking.k8s.io/v1` — pod/namespace selectors
  (matchLabels + matchExpressions), `ipBlock` with `except`, numeric and named
  ports, `endPort`, protocol, `policyTypes` defaulting, isolation semantics
  (a pod is isolated per direction only if some policy selects it). Returns a
  verdict with the policies that allowed, or the ones that isolated without
  allowing. Table-driven tests covering the upstream semantics edge cases.
- [ ] **L2 — `can-reach` command + policy findings.**
  `can-reach --from ns/pod --to ns/pod --port N [--protocol]`, text and JSON,
  works live or `--from-snapshot`; evaluates egress on the source and ingress
  on the destination and names the blocking side. Rules: default-deny egress
  with no DNS allowance, policy selecting no pods, peer selector matching no
  namespace/pod, named port that no selected pod defines.
- [ ] **L3 — Service and EndpointSlice diagnostics.** Selector matches no pods;
  no ready endpoints; matched pods not Ready; `targetPort` (number or name)
  not exposed by the backing containers; LoadBalancer stuck without ingress
  address; headless/ExternalName handled without false positives.
- [ ] **L4 — DNS diagnostics.** CoreDNS deployment readiness; `kube-dns`
  Service has ready endpoints; Corefile parsing (missing `kubernetes` plugin,
  `forward` to itself / loop risk, no upstream); NodeLocal DNSCache presence
  and health; link to the L2 "DNS egress blocked" rule.
- [ ] **L5 — kube-proxy and dataplane mode.** Mode from the kube-proxy
  ConfigMap (iptables / ipvs / nftables); kube-proxy DaemonSet health;
  kube-proxy absent without a replacement (Cilium KPR, kube-router,
  Dataplane V2); kube-proxy/kubelet version skew beyond the supported window.
- [ ] **L6 — Pod networking and IPAM.** Pods stuck in ContainerCreating with a
  network sandbox reason; duplicate pod IPs; pod IP outside its node's
  `podCIDR`; overlapping node `podCIDR`s; per-node IP exhaustion; `hostPort`
  collisions. Replace the regex IP validation with `std::net::IpAddr` so
  compressed IPv6 and dual-stack `podIPs` work.
- [ ] **L7 — CI-grade output.** `--fail-on <severity>` exit status; SARIF
  2.1.0 and JUnit XML formats; `--only` / `--skip` rule filters; a `rules`
  command and generated `docs/RULES.md` catalog (id, severity, meaning, fix).
- [ ] **L8 — Ingress and Gateway API.** Ingress backends pointing at missing
  Services or ports, missing/unknown IngressClass, TLS secret references;
  Gateway API via the dynamic client: HTTPRoute `parentRefs`/`backendRefs`
  that do not resolve, cross-namespace refs without a ReferenceGrant,
  Gateways not Programmed.
- [ ] **L9 — CNI-native and admin policies.** Collect CiliumNetworkPolicy /
  CiliumClusterwideNetworkPolicy, Calico NetworkPolicy / GlobalNetworkPolicy,
  and AdminNetworkPolicy / BaselineAdminNetworkPolicy via the dynamic client.
  Evaluate ANP/BANP tiers in the engine; for CNI-native policies that select
  an endpoint, mark the `can-reach` verdict *incomplete* instead of claiming
  certainty.
- [ ] **L10 — In-cluster probe.** `test-pod` currently issues an HTTP GET to
  the pod IP from wherever the CLI runs, which is the wrong vantage point.
  Add an opt-in `--probe` that runs a TCP connect from inside the cluster
  (short-lived probe pod on a chosen node/namespace, explicit image, always
  cleaned up, RBAC pre-check), and report observed vs policy-predicted
  verdict; a mismatch is a finding. Pod-spec builder and result parser are
  unit-tested; the live path is labelled untested until run on a cluster.
- [ ] **L11 — Remediation.** `can-reach --suggest` emits the minimal
  NetworkPolicy YAML that would allow a blocked flow (never applies it);
  `explain <RULE-ID>`; remediation text carries copy-pasteable commands with
  the real namespace/name filled in.
- [ ] **L12 — MCP server.** `k8s-netinspect mcp`: stdio JSON-RPC
  (`initialize`, `tools/list`, `tools/call`) exposing read-only tools —
  `diagnose`, `can_reach`, `explain_rule`, `snapshot` — so coding/ops agents
  can query network state. No mutating tools. Protocol handler tests.
- [ ] **L13 — Dependency and runtime modernization.** kube 0.87 → current,
  matching k8s-openapi, reqwest 0.12, compile regexes once; in-cluster config
  support (the pre-flight currently rejects a pod with no kubeconfig);
  decide and document the MSRV; `cargo audit` if the advisory DB is reachable.
- [ ] **L14 — Snapshot diff and watch.** `diff <before> <after>`: new,
  resolved and changed findings between two snapshots (incident before/after,
  upgrade verification); `diagnose --watch <interval>` printing only deltas;
  Prometheus text exposition of finding counts by rule and severity.
- [ ] **L15 — Wrap-up.** README rewritten around the new commands with real
  output captured from fixtures; `CHANGELOG.md`; `docs/ARCHITECTURE.md`;
  stale shell test scripts reconciled or removed; version set to `0.2.0`;
  PR description finalized with what is and is not verified. No merge, no
  publish.

## Status log

- 2026-10-01 — L0 landed. 25 tests (was 14). Verified offline only.
