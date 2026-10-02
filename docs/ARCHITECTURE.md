# Architecture

One rule shapes the code: **analysis never talks to the cluster.** The API is
read once into a snapshot; everything that decides anything is a pure function
of that snapshot. That is what makes every check testable offline and lets the
same code analyse a live cluster, a file from a support ticket, or a fixture.

```
            ┌────────────────────┐
 cluster ──▶│ snapshot::collect  │──┐
            └────────────────────┘  │   ┌──────────────────┐   ┌───────────────┐
                                    ├──▶│ analysis::analyze │──▶│ model::Report │
 file ─────▶ snapshot::load ────────┘   └──────────────────┘   └───────┬───────┘
                                                                       │
              output (text, json, sarif, junit, prometheus) ◀──────────┤
              diff (two reports)                            ◀──────────┤
              mcp (JSON-RPC tools)                          ◀──────────┘
```

## Modules

| Module | Role | I/O? |
|--------|------|------|
| `snapshot` | `ClusterSnapshot`: collect from the API, load/save JSON, redact | API, files |
| `analysis::*` | One file per check family; each returns `Vec<Finding>` | none |
| `analysis::policy` | Reachability engine: evaluates one flow against NetworkPolicy | none |
| `analysis::policy_admin` | AdminNetworkPolicy / Baseline tiers, CNI-native policy detection | none |
| `model` | `Finding`, `Severity`, `Report` — the JSON contract | none |
| `rules` | Rule catalog, `--only` / `--skip` filter, `explain` text | none |
| `output` | Renderers | none |
| `diff` | Compare two reports | none |
| `suggest` | Build the NetworkPolicy that would allow a flow; YAML emitter | none |
| `probe` | Ephemeral-container TCP probe; spec/classify/compare are pure | API (`run` only) |
| `mcp` | MCP server: JSON-RPC over stdio | stdio; API via `commands` |
| `commands` | Glue: pick a source, call analysis, print | API, stdout |
| `validation` | Input validation and the RBAC pre-flight | API |
| `main` | CLI definition and exit codes | — |

## The snapshot

`ClusterSnapshot` is a plain serde struct of typed Kubernetes objects, plus
`DynamicObject`s for CRDs that may not be installed (Gateway API, admin
policies, Cilium, Calico).

- **Best-effort collection.** Each list call can fail on its own. A failure is
  recorded in `collection_errors`; the snapshot is still returned. Only failing
  to list both nodes and pods aborts. A 404 on a CRD list means "not
  installed" and is not an error.
- **Unknown is not empty.** Analyzers call `snapshot.is_unknown("pods")` before
  concluding anything from an empty list. A forbidden list must never produce
  "selects no pods"-style findings; it produces a `COLLECT-001` instead.
- **Scope.** A namespace-scoped snapshot holds only that namespace's workload
  objects. Checks that need the whole cluster (cross-namespace selectors, IP
  exhaustion) test `snapshot.namespace` and stay silent.
- **Redaction** runs on every collected snapshot: literal env values,
  `last-applied-configuration`, `managedFields`. Secrets are never listed.
- `schema_version` is bumped on incompatible changes; all fields default, so
  older files keep loading.

## Adding a check

1. If it needs data the snapshot lacks, add a field and collect it
   best-effort in `ClusterSnapshot::collect`.
2. Write the analyzer as a function of `&ClusterSnapshot` in
   `src/analysis/<family>.rs` and call it from `analysis::analyze`.
3. Add the rule to `rules::RULES`. A test fails if an analyzer emits an id
   that is not in the catalog, and another if `docs/RULES.md` is stale.
4. Add a fixture under `tests/fixtures/` and a test that covers the finding,
   the clean case, and the "data missing" case.

Fixtures are JSON snapshots. `tests/analysis_tests.rs` has a `mutate` helper
for deriving variants from one in a few lines.

## The reachability engine

`policy::evaluate(snapshot, flow)` returns a `Verdict` with one
`DirectionVerdict` for the source's egress and one for the destination's
ingress; the flow is allowed only if both permit it. Per direction, in order:

1. AdminNetworkPolicy, by ascending `priority`; the first matching rule
   decides (`Allow`, `Deny`) or hands over (`Pass`).
2. NetworkPolicy: a pod is isolated only if a policy selects it for that
   direction; isolated pods need some rule to match (policies are additive).
3. BaselineAdminNetworkPolicy, only when no NetworkPolicy isolates the pod.

`Verdict.complete` is false, with `caveats`, whenever the answer rests on data
that is missing or on policies the engine does not interpret. Callers should
surface that rather than present the verdict as certain.

## What mutates a cluster

Exactly one code path: `probe::run`, reached only through
`can-reach --probe`. It patches `pods/ephemeralcontainers` on the source pod.
It is not reachable from `diagnose`, `snapshot`, `diff` or the MCP server.
