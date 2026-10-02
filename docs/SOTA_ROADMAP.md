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
- MSRV is Rust 1.89 (set by kube 4.x) as of L13.
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

- [x] **L1 — NetworkPolicy reachability engine.** `analysis/policy.rs`: pure
  evaluator for `networking.k8s.io/v1` — pod/namespace selectors
  (matchLabels + matchExpressions), `ipBlock` with `except`, numeric and named
  ports, `endPort`, protocol, `policyTypes` defaulting, isolation semantics
  (a pod is isolated per direction only if some policy selects it). Returns a
  verdict with the policies that allowed, or the ones that isolated without
  allowing. Table-driven tests covering the upstream semantics edge cases.
- [x] **L2 — `can-reach` command + policy findings.**
  `can-reach --from ns/pod --to ns/pod --port N [--protocol]`, text and JSON,
  works live or `--from-snapshot`; evaluates egress on the source and ingress
  on the destination and names the blocking side. Rules: default-deny egress
  with no DNS allowance, policy selecting no pods, peer selector matching no
  namespace/pod, named port that no selected pod defines.
- [x] **L3 — Service and EndpointSlice diagnostics.** Selector matches no pods;
  no ready endpoints; matched pods not Ready; `targetPort` (number or name)
  not exposed by the backing containers; LoadBalancer stuck without ingress
  address; headless/ExternalName handled without false positives.
- [x] **L4 — DNS diagnostics.** CoreDNS deployment readiness; `kube-dns`
  Service has ready endpoints; Corefile parsing (missing `kubernetes` plugin,
  `forward` to itself / loop risk, no upstream); NodeLocal DNSCache presence
  and health; link to the L2 "DNS egress blocked" rule.
- [x] **L5 — kube-proxy and dataplane mode.** Mode from the kube-proxy
  ConfigMap (iptables / ipvs / nftables); kube-proxy DaemonSet health;
  kube-proxy absent without a replacement (Cilium KPR, kube-router,
  Dataplane V2); kube-proxy/kubelet version skew beyond the supported window.
- [x] **L6 — Pod networking and IPAM.** Pods stuck in ContainerCreating with a
  network sandbox reason; duplicate pod IPs; pod IP outside its node's
  `podCIDR`; overlapping node `podCIDR`s; per-node IP exhaustion; `hostPort`
  collisions. Replace the regex IP validation with `std::net::IpAddr` so
  compressed IPv6 and dual-stack `podIPs` work.
- [x] **L7 — CI-grade output.** `--fail-on <severity>` exit status; SARIF
  2.1.0 and JUnit XML formats; `--only` / `--skip` rule filters; a `rules`
  command and generated `docs/RULES.md` catalog (id, severity, meaning, fix).
- [x] **L8 — Ingress and Gateway API.** Ingress backends pointing at missing
  Services or ports, missing/unknown IngressClass, TLS secret references;
  Gateway API via the dynamic client: HTTPRoute `parentRefs`/`backendRefs`
  that do not resolve, cross-namespace refs without a ReferenceGrant,
  Gateways not Programmed.
- [x] **L9 — CNI-native and admin policies.** Collect CiliumNetworkPolicy /
  CiliumClusterwideNetworkPolicy, Calico NetworkPolicy / GlobalNetworkPolicy,
  and AdminNetworkPolicy / BaselineAdminNetworkPolicy via the dynamic client.
  Evaluate ANP/BANP tiers in the engine; for CNI-native policies that select
  an endpoint, mark the `can-reach` verdict *incomplete* instead of claiming
  certainty.
- [x] **L10 — In-cluster probe.** `test-pod` currently issues an HTTP GET to
  the pod IP from wherever the CLI runs, which is the wrong vantage point.
  Add an opt-in `--probe` that runs a TCP connect from inside the cluster
  (short-lived probe pod on a chosen node/namespace, explicit image, always
  cleaned up, RBAC pre-check), and report observed vs policy-predicted
  verdict; a mismatch is a finding. Pod-spec builder and result parser are
  unit-tested; the live path is labelled untested until run on a cluster.
- [x] **L11 — Remediation.** `can-reach --suggest` emits the minimal
  NetworkPolicy YAML that would allow a blocked flow (never applies it);
  `explain <RULE-ID>`; remediation text carries copy-pasteable commands with
  the real namespace/name filled in.
- [x] **L12 — MCP server.** `k8s-netinspect mcp`: stdio JSON-RPC
  (`initialize`, `tools/list`, `tools/call`) exposing read-only tools —
  `diagnose`, `can_reach`, `explain_rule`, `snapshot` — so coding/ops agents
  can query network state. No mutating tools. Protocol handler tests.
- [x] **L13 — Dependency and runtime modernization.** kube 0.87 → current,
  matching k8s-openapi, reqwest 0.12, compile regexes once; in-cluster config
  support (the pre-flight currently rejects a pod with no kubeconfig);
  decide and document the MSRV; `cargo audit` if the advisory DB is reachable.
- [x] **L14 — Snapshot diff and watch.** `diff <before> <after>`: new,
  resolved and changed findings between two snapshots (incident before/after,
  upgrade verification); `diagnose --watch <interval>` printing only deltas;
  Prometheus text exposition of finding counts by rule and severity.
- [x] **L15 — Wrap-up.** README rewritten around the new commands with real
  output captured from fixtures; `CHANGELOG.md`; `docs/ARCHITECTURE.md`;
  stale shell test scripts reconciled or removed; version set to `0.2.0`;
  PR description finalized with what is and is not verified. No merge, no
  publish.

## Status at end of round (2026-10-02)

All 15 loops ran; every item is ticked. The branch is one draft PR (#2),
not merged, not published.

**Verdict:** the code is complete for what the round set out to do and is
consistently green offline — but it is **not release-ready until someone
runs it against a real cluster.** Every analyzer is covered by fixtures; no
line of the API-facing code has executed against an API server.

**Shipped**

| Loop | Result |
|------|--------|
| L0 | Snapshot → analysis → report architecture; CNI detection v2; JSON output; offline analysis |
| L1 | NetworkPolicy reachability engine |
| L2 | `can-reach`; `POL-001..004` |
| L3 | Service checks `SVC-001..005` |
| L4 | DNS checks `DNS-001..008`, Corefile parser |
| L5 | Service proxy detection, `PROXY-001..004` |
| L6 | Pod / IPAM checks `POD-001..005`; real IPv6 parsing |
| L7 | `--fail-on`, SARIF, JUnit, rule filters, rule catalog |
| L8 | Ingress `ING-001..004`, Gateway API `GW-001..005` |
| L9 | AdminNetworkPolicy tiers; CNI-native policy awareness `POL-005` |
| L10 | `can-reach --probe` |
| L11 | `can-reach --suggest`, `explain` |
| L12 | MCP server |
| L13 | kube 4.2 and friends; MSRV 1.89; in-cluster config; `cargo audit` clean |
| L14 | `diff`, `--watch`, Prometheus output |
| L15 | README, CHANGELOG, ARCHITECTURE, `scripts/live-smoke.sh`, version 0.2.0 |

Tests: 14 on `main` → 121. Rules: 43.

**Skipped or cut, with reasons**

- `hostPort` collision check (L6): the scheduler already prevents them.
- TLS secret reference check (L8): would require reading Secrets.
- MCP `snapshot` tool (L12): too large and too revealing for an agent.
- A separate probe pod (L10): replaced by an ephemeral container, since a
  label-copying pod would be adopted by the source's ReplicaSet.
- RBAC pre-check for `--probe` (L10): a 403 is translated instead.
- reqwest 0.13 (L13): stayed on 0.12.
- CI: not re-added, per the owner's earlier decision.

**Untested against a live cluster — everything that touches the API**

- `ClusterSnapshot::collect`, including every dynamic-client list (Gateway
  API, admin policies, Cilium, Calico) and the 404-means-not-installed path.
- `diagnose`, `snapshot`, `can-reach` and `mcp` without `--from-snapshot`.
- `can-reach --probe`: patching the pod, polling, reading logs.
- `diagnose --watch` in live mode.
- The kube 0.87 → 4.2 upgrade, beyond compiling and passing fixtures.

Also unverified: SARIF against the official schema, the Prometheus output
against a real scraper, the MCP server against a real client, the musl
cross-build after the dependency upgrade, and AdminNetworkPolicy semantics
against a conformance suite.

**Known detection gaps**

- Calico eBPF and Antrea `proxyAll` are not recognised as kube-proxy
  replacements; distributions other than k3s that embed kube-proxy get a
  false `PROXY-002`.
- CNI-native policies are flagged by namespace, not by their own selector,
  so they over-report.
- `POD-001` infers sandbox failure from status and age; it does not read
  Events.
- Only HTTPRoute is analysed among Gateway API route types.

**First steps on a real cluster**

1. `cargo build --release && scripts/live-smoke.sh` on a throwaway cluster
   (kind or k3s); read the output for collection errors and false findings.
2. `kubectl apply -f test-resources.yaml`, then `can-reach` between two of
   those pods, then the same with `--probe`.
3. Repeat on one cluster per CNI you care about; PROXY and POD rules are the
   most CNI-sensitive.

## Status log

- 2026-10-01 — L0 landed. 25 tests (was 14). Verified offline only.
- 2026-10-01 — L1 landed: `analysis/policy.rs` evaluator (not yet wired to a
  command — that is L2). 45 tests. Verdicts carry `complete` + `caveats` for
  missing policy data, hostNetwork pods, and ipBlock-on-pod-IP (CNI-dependent).
- 2026-10-01 — L2 landed: `can-reach` (exit 0 allowed / 6 blocked), rules
  `POL-001..004`. 51 tests. `can-reach` sees only `networking.k8s.io/v1`
  policies until L9.
- 2026-10-01 — L3 landed: rules `SVC-001..005`. 54 tests. A numeric
  `targetPort` mismatch is only flagged when every backend declares ports and
  none matches, since containers may listen on undeclared ports.
- 2026-10-02 — L4 landed: rules `DNS-001..008` and a small Corefile parser.
  60 tests. Fixtures now carry a healthy CoreDNS so they resemble real
  clusters. Not detectable from the API: a node `resolv.conf` pointing at
  127.0.0.53 (the usual cause of the CoreDNS loop crash).
- 2026-10-02 — L5 landed: `service_proxy` in the report, rules
  `PROXY-001..004`, snapshot now records the API server version and the
  `cilium-config` ConfigMap. 64 tests. Known gaps: Calico eBPF and Antrea
  `proxyAll` are not recognised as kube-proxy replacements; distributions
  other than k3s that embed kube-proxy would get a `PROXY-002` warning.
- 2026-10-02 — L6 landed: rules `POD-001..005`; IP validation uses
  `std::net::IpAddr` (compressed IPv6 was rejected before) and `test-pod`
  brackets IPv6 literals in its URL. 69 tests. Dropped from the item:
  `hostPort` collisions — the scheduler already refuses to co-locate
  conflicting hostPorts, so the rule could never fire. POD-001 infers a
  sandbox failure from pod status and age; it does not read Events.
- 2026-10-02 — L7 landed: `--fail-on` (exit 7), `-o sarif|junit`, `--only` /
  `--skip`, `rules` command, `src/rules.rs` catalog and generated
  `docs/RULES.md` (33 rules). 80 tests, including one that fails if an
  analyzer emits an id missing from the catalog. SARIF results carry logical
  locations only (cluster objects, not files), so GitHub code scanning may
  not display them inline; SARIF was not validated against the official
  JSON schema here.
- 2026-10-02 — L8 landed: snapshot collects Ingress, IngressClass and (via
  the dynamic client, 404 = not installed) Gateway / HTTPRoute /
  ReferenceGrant; rules `ING-001..004`, `GW-001..005` (42 rules total).
  83 tests. Dropped from the item: TLS secret references — checking them
  means listing Secrets, which this tool deliberately does not read. Only
  HTTPRoute is analysed (no GRPCRoute / TLSRoute), and Gateway listener
  `allowedRoutes` is not evaluated — GW-005 relays the controller's own
  verdict instead.
- 2026-10-02 — L9 landed: AdminNetworkPolicy / BaselineAdminNetworkPolicy
  (v1alpha1) evaluated as tiers around NetworkPolicy (priority, rule order,
  Allow / Deny / Pass, `networks` egress peers); Cilium and Calico policies
  collected and reported (`POL-005`, incomplete verdicts) but not
  interpreted. 90 tests, 43 rules. Limits: ANP `nodes` peers and
  `sameLabels` are not matched; CNI-native detection is by namespace, not by
  the policy's own selector, so it over-reports rather than under-reports;
  ANP semantics follow the v1alpha1 spec as I understand it and were not
  checked against a conformance suite.
- 2026-10-02 — L10 landed: `can-reach --probe` (exit 8 on mismatch),
  `src/probe.rs`. 96 tests. **Untested against a live cluster**: only the
  container spec, classification, comparison and argument handling are
  tested. Deviations from the item: the probe is an ephemeral container in
  the source pod rather than a separate probe pod — a separate pod would
  not be selected by the source's policies unless it copied the source's
  labels, and a label-copying pod gets adopted by the source's ReplicaSet
  and receives its Service traffic. It hangs off `can-reach` (where there
  is a prediction to compare with), not `test-pod`, which now prints a note
  about its vantage point. No RBAC pre-check: a 403 on the patch is mapped
  to a message naming the missing permission.
- 2026-10-02 — L11 landed: `can-reach --suggest` (`src/suggest.rs`, with a
  small JSON→YAML emitter — no new dependency) and `explain <RULE-ID>`.
  104 tests. Suggested manifests were round-tripped through PyYAML once by
  hand and matched the generated objects; they were not applied to a
  cluster. `explain` gives per-family investigation steps, not per-rule
  ones; per-finding remediation text already carries the real object names.
- 2026-10-02 — L12 landed: `k8s-netinspect mcp [--from-snapshot]`
  (`src/mcp.rs`, hand-written JSON-RPC, no SDK dependency). Tools:
  `diagnose`, `can_reach`, `explain_rule`, `list_rules`. 112 tests,
  including a full session through the binary's stdio. The planned
  `snapshot` tool was left out: a raw snapshot is large and carries more
  cluster detail than an agent needs, and `diagnose` already returns the
  analysis. Not exercised with a real MCP client; in live mode every
  `diagnose` / `can_reach` call re-collects the cluster (no caching).
- 2026-10-02 — L13 landed: kube 0.87 → 4.2, k8s-openapi 0.20 → 0.28
  (`latest`, i.e. v1.36 types), reqwest 0.11 → 0.12, colored 2 → 3, unused
  kube `runtime` feature dropped, `cargo update` across the lockfile.
  `cargo audit`: 0 vulnerabilities (the pre-update lockfile had 2, in
  `bytes` and `slab`). Regexes compile once; the pre-flight accepts the
  in-cluster service account and treats `KUBECONFIG` as a path list. 114
  tests. **MSRV went from 1.70 to 1.89** — forced by kube 4.x; the earlier
  1.70 pins existed for the CI that has since been removed. Porting notes:
  timestamps are `jiff` not `chrono`, `EndpointSlice.endpoints` and
  NetworkPolicy `podSelector` became optional (an omitted selector is
  treated as "all pods"). Not done: reqwest 0.13 (0.12 kept to limit
  churn); the musl cross-build was not re-run after the upgrade.
- 2026-10-02 — L14 landed: `diff <before> <after>` (text/json, `--fail-on`
  for regressions only), `diagnose --watch N [--watch-count M]`, and
  `-o prometheus` (zero-filled per-rule gauge plus per-severity totals).
  120 tests. `--watch` against a live cluster re-collects everything each
  round and was only exercised against a snapshot file; the Prometheus
  output was checked for shape, not scraped by a real Prometheus.
- 2026-10-02 — L15 landed: README rewritten with outputs captured from
  fixtures (a test keeps them in sync), `CHANGELOG.md`,
  `docs/ARCHITECTURE.md`, stale shell scripts replaced by
  `scripts/live-smoke.sh`, version `0.2.0`. 121 tests. Round complete.
