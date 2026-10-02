# k8s-netinspect

A minimal Kubernetes network inspection tool for diagnosing CNI and pod connectivity.

## Demo

![k8s-netinspect version check, diagnose, and help output](k8s-netinspect-demo.gif)

*Recorded from the actual binary with [asciinema](https://asciinema.org) + [agg](https://github.com/asciinema/agg).*


## Features

- CNI detection from the agent DaemonSet — Cilium, Calico, Canal, Flannel, Weave Net, AWS VPC CNI, Azure CNI, GKE Dataplane V2, Antrea, OVN-Kubernetes, kube-router, kindnet, plus Multus / Istio CNI / Linkerd CNI — with version and rollout health; falls back to node annotations (k3s embedded flannel)
- Findings with stable rule ids, severity, evidence and a suggested fix (CNI agent not ready, competing CNIs, node `NetworkUnavailable` / NotReady)
- `can-reach`: answers "would NetworkPolicy let A talk to B on this port?" and names the policy that blocks it — evaluated from the policy objects, no traffic sent
- NetworkPolicy findings: egress policies that block DNS, policies that select no pods, peers that match nothing, undefined named ports
- Service findings: selector matches no pods, no ready endpoints, `targetPort` the backing pods do not expose, LoadBalancer without an address, selector-less Service without endpoints
- DNS findings: CoreDNS down, degraded or scaled to zero; kube-dns Service missing or without ready endpoints; Corefile with no `kubernetes` plugin, no upstream, or a `forward` that points back at CoreDNS; NodeLocal DNSCache agents not ready
- Service proxy: identifies kube-proxy (mode and version) or the CNI replacing it; flags kube-proxy not ready on every node, no Service proxy at all, kube-proxy left running next to a full replacement, and version skew against the API server and kubelets
- Pod networking and IPAM: pods stuck without a network sandbox (grouped by node), duplicate pod IPs, overlapping node pod CIDRs, and — for CNIs that allocate from the node range — pod IPs outside it and ranges about to run out; IPv6 and dual-stack aware
- `--output json` for scripts and CI
- Offline analysis: `snapshot` captures a redacted cluster state file, `diagnose --from-snapshot` analyzes it with no cluster access
- Partial diagnosis under restricted RBAC — lists that are forbidden are reported as skipped, not as healthy
- Pod connectivity testing with HTTP checks
- Namespace support for targeted diagnostics
- RBAC permission validation with detailed error messages
- Colored terminal output with NO_COLOR support

## Installation

### From Crates.io (Recommended)

```bash
cargo install k8s-netinspect
```

### Build from Source

```bash
git clone https://github.com/marcuspat/k8s-netinspect.git
cd k8s-netinspect
cargo build --release
# Add to PATH or copy to local bin directory
export PATH="$PWD/target/release:$PATH"
```

### Development Build

For development and testing:

```bash
git clone https://github.com/marcuspat/k8s-netinspect.git
cd k8s-netinspect
cargo build
# Run directly with cargo
cargo run -- --version
cargo run -- diagnose
cargo run -- test-pod --pod nginx --namespace default
```

## Usage

### Diagnose Network

```bash
# Cluster-wide diagnosis
k8s-netinspect diagnose

# Namespace-specific
k8s-netinspect diagnose --namespace production
```

### Can A reach B?

```bash
# Endpoints are namespace/pod, a bare pod name (namespace "default"), or an IP
k8s-netinspect can-reach --from shop/web --to shop/db --port 5432
k8s-netinspect can-reach --from shop/web --to 93.184.216.34 --port 443 --protocol tcp
k8s-netinspect can-reach --from shop/api --to shop/db -p 5432 -o json --from-snapshot cluster.json
```

Exit status: `0` allowed, `6` blocked, anything else is an error (for example `4` when a pod does not exist).

This evaluates `networking.k8s.io/v1` NetworkPolicy only. It does not see CNI-native policies (CiliumNetworkPolicy, Calico GlobalNetworkPolicy), AdminNetworkPolicy, service meshes or cloud firewalls, and it sends no traffic — "allowed" means no NetworkPolicy blocks the flow, not that the connection will succeed.

### JSON output

```bash
k8s-netinspect diagnose --output json
```

### Snapshot and offline analysis

```bash
# Capture network-relevant objects (env values, last-applied-configuration
# and managedFields are stripped) to attach to a ticket or analyze later
k8s-netinspect snapshot --file cluster.json

# Analyze it anywhere — no kubeconfig or cluster access required
k8s-netinspect diagnose --from-snapshot cluster.json
```

### Test Pod Connectivity

```bash
# Test specific pod
k8s-netinspect test-pod --pod nginx-abc123 --namespace default
```

### Version

```bash
k8s-netinspect --version
```

## Example Output

### Cluster-wide Diagnosis
```
🔍 Starting network diagnosis...
✓ CNI detected: Flannel
✓ Found 2 nodes
✓ Found 8 pods cluster-wide
```

### Diagnosis with findings
```
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
*(Output of `diagnose --from-snapshot tests/fixtures/calico-degraded.json`.)*

### can-reach
```
🔍 Can ops/prom reach shop/api on TCP 8080?
✗ BLOCKED on ingress to shop/api
  egress  (ops/prom): not isolated — no policy selects this pod for egress
  ingress (shop/api): denied — isolated by shop/default-deny, shop/api-from-web; none of their rules match this flow
```
*(Output of `can-reach --from ops/prom --to shop/api --port 8080 --from-snapshot tests/fixtures/shop-policies.json`.)*

### Namespace-specific Diagnosis
```
🔍 Starting network diagnosis...
✓ CNI detected: Flannel
✓ Found 2 nodes
✓ Found 5 pods in namespace 'kube-system'
```

### Pod Connectivity Test
```
🔍 Testing connectivity for pod: default/nginx
✓ Pod is running
ℹ Pod IP: 10.42.1.4
✗ Connectivity test: FAIL - Timeout: HTTP request timed out
```

### Error Handling
```
🔍 Testing connectivity for pod: default/nonexistent-pod
Pod 'nonexistent-pod' not found in namespace 'default'
💡 Troubleshooting: Verify resource exists in the specified namespace
  • Check: kubectl get pods -n <namespace>
```

## Advanced Usage

### All CLI Options

```bash
# Show version information
k8s-netinspect --version
k8s-netinspect version

# Show help
k8s-netinspect --help
k8s-netinspect diagnose --help
k8s-netinspect test-pod --help

# Diagnose with short flags
k8s-netinspect diagnose -n kube-system
k8s-netinspect test-pod -p nginx -n default

# Disable colored output
NO_COLOR=1 k8s-netinspect diagnose
```

### Development and Testing

```bash
# Run tests
cargo test

# Check code
cargo check

# Run with development build
cargo run -- diagnose --namespace kube-system

# Build release version
cargo build --release

# Run release binary directly
./target/release/k8s-netinspect diagnose
```

## Requirements

- **Rust**: 1.70+ (for building from source)
- **Kubernetes cluster access** via kubeconfig  
- **RBAC permissions**: `get/list` on pods, nodes, namespaces. Optional, for fuller diagnosis: `list` on services, endpointslices, networkpolicies, daemonsets, and `get` on the `coredns` / `kube-proxy` ConfigMaps in `kube-system`
- **Network connectivity** to Kubernetes API server

## Configuration

- Uses `~/.kube/config` or `KUBECONFIG` environment variable
- Set `NO_COLOR=1` to disable colored output
- Uses current kubectl context
- Supports all standard kubeconfig configurations

## 🧪 Testing & Validation

### Validation

This tool has been tested against real Kubernetes clusters:

#### 📊 Test Results Summary
- **CLI commands manually verified** - diagnose, test-pod, version, and help all exercised against a live cluster
- **✅ Real Cluster Validation** - Tested against live K3s clusters  
- **✅ CNI Detection Verified** - Confirmed working with Flannel, Calico
- **✅ Error Handling Validated** - Professional error messages with troubleshooting
- **✅ Cross-Platform Tested** - Works in GitHub Codespaces, local environments

#### 🎯 Validation Evidence

Test scripts included in this repository:

- **[live-cluster-test.sh](./live-cluster-test.sh)** - Comprehensive testing script for live clusters
- **[test-comprehensive.sh](./test-comprehensive.sh)** - Build validation, unit tests, and benchmarking script

#### 🧪 Quick Test

Verify it works on your cluster:

```bash
# Build and test
git clone https://github.com/marcuspat/k8s-netinspect.git
cd k8s-netinspect
cargo build --release

# Test basic functionality
./target/release/k8s-netinspect --version
./target/release/k8s-netinspect diagnose
./target/release/k8s-netinspect diagnose --namespace kube-system
```

#### 🚀 Run Comprehensive Tests

Test against your own cluster with our testing framework:

```bash
# Run comprehensive testing suite
./test-comprehensive.sh

# Test against live cluster (requires cluster access)
./live-cluster-test.sh
```

**Expected Output:**
```
🔍 Starting network diagnosis...
✓ CNI detected: Flannel
✓ Found 2 nodes  
✓ Found 8 pods cluster-wide
```

### 🚀 Performance & Reliability

- **Fast execution** - Diagnosis completes in seconds
- **Lightweight binary** - ~14MB standalone executable
- **Memory efficient** - Minimal resource usage
- **Error resilient** - Graceful handling of network timeouts
- **Professional output** - Clean, colored terminal display

## 🔧 Error Handling & Troubleshooting

The tool provides detailed error messages with actionable troubleshooting:

### Exit Codes
- `0` - Success
- `1` - Runtime error  
- `2` - Configuration/Input error
- `3` - Kubernetes connection error
- `4` - Network connectivity/Resource not found
- `5` - Permission denied

### Common Issues & Solutions

**Cluster Connection Issues:**
```bash
# Verify kubectl works
kubectl cluster-info

# Check kubeconfig  
echo $KUBECONFIG
ls -la ~/.kube/config
```

**RBAC Permission Issues:**
```bash
# Test required permissions
kubectl auth can-i get pods
kubectl auth can-i list nodes
kubectl auth can-i get namespaces
```

**Network Timeout Issues:**
- Expected in some container environments (Codespaces, etc.)
- Tool still detects CNI and provides useful information
- Retry or use different network settings

## 🤝 Contributing

Contributions welcome! This project follows standard Rust development practices:

```bash
# Development setup
git clone https://github.com/marcuspat/k8s-netinspect.git
cd k8s-netinspect
cargo check
cargo test
cargo run -- --help

# Submit changes
# 1. Fork the repository
# 2. Create a feature branch
# 3. Add tests for new functionality  
# 4. Ensure all tests pass
# 5. Submit a pull request
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**⭐ If this tool helped you, please give it a star on GitHub!**
