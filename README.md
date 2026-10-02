# k8s-netinspect

Kubernetes network diagnostics from the command line: it tells you what is broken and which object is responsible, and it can answer "can A reach B?" from the policy objects without sending a packet.

![k8s-netinspect version check, diagnose, and help output](k8s-netinspect-demo.gif)

*The recording shows v0.1.1; `diagnose` now also lists findings (see the examples below).*

> **Verification status.** Every analysis in this tool is tested offline against recorded cluster snapshots (`tests/fixtures/`, 121 tests). **Nothing in 0.2 has been run against a live cluster yet** — collection from the API, `--watch` on a live cluster and `--probe` compile but are unverified in the field. `scripts/live-smoke.sh` is a read-only script for doing that first run.

## What it checks

`diagnose` collects the cluster's network-relevant objects once and runs every check over that snapshot. Findings carry a stable rule id, a severity, the evidence, and a suggested next step. The full catalog is in [docs/RULES.md](docs/RULES.md) (`k8s-netinspect rules`).

| Area | What it finds |
|------|---------------|
| CNI | Which plugin runs (16 recognised, with version), agents not ready on every node, two competing primary CNIs |
| Nodes | `NetworkUnavailable`, NotReady |
| Pods / IPAM | Pods stuck without a network sandbox, duplicate pod IPs, overlapping node pod CIDRs, pod IPs outside the node range, ranges about to run out |
| NetworkPolicy | Egress policies that block DNS, policies that select nothing, peers that match nothing, undefined named ports |
| Services | Selector matches no pods, no ready endpoints, `targetPort` the pods do not expose, LoadBalancer without an address |
| DNS | CoreDNS down / degraded, kube-dns Service without endpoints, Corefile without the `kubernetes` plugin or forwarding to itself, NodeLocal DNSCache down |
| Service proxy | kube-proxy mode and version or the CNI replacing it; not ready on every node, missing, duplicated, version skew |
| Ingress / Gateway API | Backends pointing at missing Services or ports, unclaimed Ingresses, orphan HTTPRoutes, cross-namespace backends without a ReferenceGrant |

When a list is forbidden by RBAC, the checks that need it are reported as skipped — never as healthy.

## Install

```bash
git clone https://github.com/marcuspat/k8s-netinspect.git
cd k8s-netinspect
cargo build --release          # Rust 1.89+
./target/release/k8s-netinspect --help
```

`cargo install k8s-netinspect` installs the last published release (0.1.1), which predates everything described here.

## Commands

### diagnose

```bash
k8s-netinspect diagnose                      # whole cluster
k8s-netinspect diagnose --namespace shop     # workload objects from one namespace
```

A healthy cluster:

<!-- output: diagnose --from-snapshot tests/fixtures/healthy-cilium.json -->
```text
🔍 Starting network diagnosis...
✓ CNI detected: Cilium v1.16.1
  • Cilium (daemonset/kube-system/cilium): 3/3 agents ready
✓ Service proxy: Cilium (kube-proxy replacement)
✓ Found 3 nodes
✓ Found 3 pods cluster-wide
✓ No issues found
```

A cluster with a CNI agent down on one node, analysed with restricted RBAC:

<!-- output: diagnose --from-snapshot tests/fixtures/calico-degraded.json -->
```text
🔍 Starting network diagnosis...
✓ CNI detected: Calico v3.28.0
  • Calico (daemonset/calico-system/calico-node): 2/3 agents ready
✓ Service proxy: kube-proxy (ipvs) v1.30.4
✓ Found 3 nodes
✓ Found 2 pods cluster-wide

Findings (4)
ERROR [CNI-002] Calico agent is not ready on every node — daemonset/calico-system/calico-node
    2 of 3 desired agent pods are ready. Pods on the affected nodes cannot get network set up or policy programmed.
    → Check: kubectl -n calico-system get pods -o wide | grep -v Running; then kubectl logs on the failing agent pod
ERROR [NODE-002] Node network is unavailable — node/node-c
    NetworkUnavailable=True (NoRouteCreated) Node created without a route
    → The CNI agent or cloud route controller has not configured this node. Check the CNI agent pod on it and the node's podCIDR/route allocation.
ERROR [NODE-003] Node is not Ready — node/node-c
    Ready=False (KubeletNotReady) container runtime network not ready: cni plugin not initialized
    → Check: kubectl describe node node-c
INFO [COLLECT-001] Could not collect networkpolicies — networkpolicies
    Kubernetes API access denied: networkpolicies.networking.k8s.io is forbidden — checks that depend on it were skipped.
    → Grant get/list on networkpolicies to run those checks.
```

### can-reach

```bash
# Endpoints are namespace/pod, a bare pod name (namespace "default"), or an IP
k8s-netinspect can-reach --from shop/web --to shop/db --port 5432
k8s-netinspect can-reach --from shop/web --to 93.184.216.34 --port 443
```

<!-- output: can-reach --from ops/prom --to shop/api --port 8080 --suggest --from-snapshot tests/fixtures/shop-policies.json -->
```text
🔍 Can ops/prom reach shop/api on TCP 8080?
✗ BLOCKED on ingress to shop/api
  egress  (ops/prom): not isolated — no policy selects this pod for egress
  ingress (shop/api): denied — isolated by shop/default-deny, shop/api-from-web; none of their rules match this flow

Suggested NetworkPolicy — review before applying; nothing has been changed (re-evaluated: with this added, the flow is allowed):

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-from-prometheus-8080
  namespace: shop
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ops
      podSelector:
        matchLabels:
          app: prometheus
    ports:
    - port: 8080
      protocol: TCP
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress

  • Selectors use workload labels, so every pod carrying them is covered — check that is the scope you intend.
```

What it evaluates, and what it does not:

- **Evaluated:** `networking.k8s.io/v1` NetworkPolicy, plus the AdminNetworkPolicy and BaselineAdminNetworkPolicy tiers (`policy.networking.k8s.io/v1alpha1`), in the order the dataplane applies them.
- **Detected, not interpreted:** CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, Calico NetworkPolicy and GlobalNetworkPolicy. When one could apply to either endpoint, the verdict is marked incomplete and names it.
- **Invisible:** service meshes, host and cloud firewalls.
- No traffic is sent. "Allowed" means no evaluated policy blocks the flow — not that the connection will succeed.

`--suggest` prints the smallest NetworkPolicy that would allow a blocked flow: one per blocked direction, selecting workloads by stable labels (never `pod-template-hash`), allowing only that peer and port. It is re-evaluated before being shown and is never applied. If an AdminNetworkPolicy is what blocks the flow, it says that no NetworkPolicy can override it.

#### --probe: test it for real

```bash
k8s-netinspect can-reach --from shop/web --to shop/db --port 5432 --probe
k8s-netinspect can-reach --from shop/web --to shop/db --port 5432 --probe \
  --probe-image registry.internal/tools/busybox:1.36 --probe-timeout 3
```

Runs one TCP connect from inside the source pod's network namespace and compares the result with the policy verdict.

> **Untested against a live cluster.** The container spec, result classification and comparison are unit-tested; the code that patches the pod and reads the result has never run on a real cluster.

Read this before using it:

- It **modifies the source pod**: an ephemeral container (`netinspect-probe-<timestamp>`) is added, as `kubectl debug` does. It exits after one connect but stays listed in the pod spec until the pod is deleted.
- It needs `patch` on `pods/ephemeralcontainers` in the source namespace, and the cluster must be able to pull the image (`busybox:1.36` by default; any image with `nc`).
- The container is unprivileged — all capabilities dropped, no privilege escalation — and runs a fixed argv (`nc -z -w <timeout> <ip> <port>`), not a shell string.
- TCP only; needs a live cluster.

### snapshot, offline analysis and diff

```bash
k8s-netinspect snapshot --file cluster.json                 # capture
k8s-netinspect diagnose --from-snapshot cluster.json        # analyse anywhere, no cluster access
k8s-netinspect can-reach --from a/x --to b/y -p 80 --from-snapshot cluster.json
k8s-netinspect diff before.json after.json                  # what changed
k8s-netinspect diff before.json after.json --fail-on error  # exit 7 on a new or worsened error
```

A snapshot holds nodes, namespaces, pods, Services, EndpointSlices, policies, Ingress and Gateway objects, CNI DaemonSets, the kube-system Deployments, and five named kube-system ConfigMaps (`coredns`, `kube-proxy`, `node-local-dns`, `kube-dns`, `cilium-config`). It never reads Secrets. Literal container `env` values, `last-applied-configuration` annotations and `managedFields` are stripped; everything else — names, labels, images, IPs — is in the file, so treat it like any other cluster dump.

`diff` treats a finding as the same problem when its rule, object and title match, so "1 of 3 ready" becoming "2 of 3 ready" shows as *changed*. Only new findings and ones that got more severe count towards `--fail-on`.

<!-- output: diff tests/fixtures/healthy-cilium.json tests/fixtures/proxy-broken.json -->
```text
4 new, 0 resolved, 0 changed, 0 unchanged
+ [PROXY-001] error kube-proxy is not ready on every node — daemonset/kube-system/kube-proxy
    1 of 3 kube-proxy pods are ready. On the other nodes Service rules are stale or missing, so ClusterIP and NodePort traffic from or through them fails or reaches removed backends.
+ [PROXY-003] warning kube-proxy runs alongside a kube-proxy replacement — daemonset/kube-system/kube-proxy
    Cilium (kube-proxy replacement) already implements Services, and a kube-proxy DaemonSet is also deployed. Both program Service handling on every node; the duplicate rules add overhead and make behaviour depend on which one sees a packet first.
+ [PROXY-004] warning kube-proxy and kubelet versions are too far apart — daemonset/kube-system/kube-proxy
    kube-proxy v1.26.15 differs by more than 3 minor versions from the kubelet on 3 node(s), e.g. node-a (v1.30.4).
+ [PROXY-004] warning kube-proxy is too old for the API server — daemonset/kube-system/kube-proxy
    kube-proxy v1.26.15 is 4 minor versions behind the API server (minor 30); the supported skew is 3.
```

### CI and monitoring

```bash
k8s-netinspect diagnose --fail-on error             # exit 7 if any finding is error or worse
k8s-netinspect diagnose --only DNS,POL-001          # by rule id or family
k8s-netinspect diagnose --skip SVC-004 --fail-on warning
k8s-netinspect diagnose --output json               # also: sarif, junit, prometheus
k8s-netinspect diagnose --watch 30                  # full report once, then only deltas
k8s-netinspect diagnose -o prometheus > /var/lib/node_exporter/textfile/netinspect.prom
```

- `json` is the stable machine-readable report.
- `sarif` is SARIF 2.1.0 with logical locations (cluster objects, not files).
- `junit` has one test case per rule in scope; Warning and above fail.
- `prometheus` has one gauge per rule, zero when clean.

### MCP server (for AI agents)

```bash
k8s-netinspect mcp                               # live cluster
k8s-netinspect mcp --from-snapshot cluster.json  # fixed snapshot, no cluster access
```

A [Model Context Protocol](https://modelcontextprotocol.io) server over stdio. Register it as a stdio server in your MCP client, for example in a project `.mcp.json`:

```json
{
  "mcpServers": {
    "k8s-netinspect": { "command": "k8s-netinspect", "args": ["mcp"] }
  }
}
```

Tools: `diagnose`, `can_reach` (optionally with the suggested NetworkPolicy), `explain_rule`, `list_rules`. All are read-only; `--probe` is deliberately not exposed, so an agent cannot change the cluster through this server. Tested at the protocol level and through the binary's stdio, not yet with a real MCP client.

### rules, explain, version

```bash
k8s-netinspect rules             # the catalog
k8s-netinspect explain DNS-006   # what a rule means and how to investigate it
k8s-netinspect version
```

### test-pod (legacy)

```bash
k8s-netinspect test-pod --pod nginx-abc123 --namespace default
```

An HTTP GET to the pod's IP on port 80 **from the machine running the CLI**. Outside the cluster that usually cannot reach a pod IP at all, so a failure says little. Prefer `can-reach`, with `--probe` when you need a real connection attempt.

## Exit status

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime error |
| `2` | Bad input or configuration |
| `3` | Cannot connect to the cluster |
| `4` | Resource not found, or a `test-pod` connectivity failure |
| `5` | Permission denied |
| `6` | `can-reach`: the flow is blocked |
| `7` | `--fail-on` threshold met (`diagnose`, `diff`) |
| `8` | `can-reach --probe`: the observed result contradicts the policy verdict |

## Access it needs

- **Connection:** `KUBECONFIG` (a path list, as kubectl), then `~/.kube/config`, then the in-cluster service account when run in a pod.
- **Required:** `get` / `list` on nodes, pods and namespaces.
- **For full coverage:** `list` on services, endpointslices, networkpolicies, ingresses, ingressclasses, daemonsets, deployments (kube-system), the Gateway API (`gateways`, `httproutes`, `referencegrants`), `adminnetworkpolicies` / `baselineadminnetworkpolicies`, Cilium and Calico policy CRDs, and `get` on the five ConfigMaps listed above. Anything missing is reported as a skipped check.
- **Only for `--probe`:** `patch` on `pods/ephemeralcontainers`.

Set `NO_COLOR=1` to disable colours.

## Development

```bash
cargo test                                   # all analysis is tested against tests/fixtures/
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run -- rules --format markdown > docs/RULES.md   # after changing the rule catalog
scripts/live-smoke.sh                        # read-only run against your current context
kubectl apply -f test-resources.yaml         # sample workloads for a test cluster
```

How it fits together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). What changed: [CHANGELOG.md](CHANGELOG.md). Known gaps and what is unverified: [docs/SOTA_ROADMAP.md](docs/SOTA_ROADMAP.md).

## License

MIT — see [LICENSE](LICENSE).
