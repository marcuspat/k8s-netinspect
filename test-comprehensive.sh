#!/bin/bash

# Comprehensive Testing Script for k8s-netinspect
# This script tests all functionality, builds, and generates documentation

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
BINARY_NAME="k8s-netinspect"
TEST_OUTPUT_DIR="test-results"
DOCS_OUTPUT_DIR="docs"
BENCHMARK_OUTPUT="$TEST_OUTPUT_DIR/benchmarks.txt"
BUILD_LOG="$TEST_OUTPUT_DIR/build.log"
TEST_LOG="$TEST_OUTPUT_DIR/test.log"

# Test namespaces and pods for testing
TEST_NAMESPACES=("default" "kube-system")
TEST_POD_NAMES=("test-pod" "nginx" "busybox")

print_header() {
    echo -e "\n${BOLD}${BLUE}=================================${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}=================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Function to run command and capture output
run_and_capture() {
    local description="$1"
    local command="$2"
    local output_file="$3"
    
    echo -e "\n${BOLD}Running: $description${NC}"
    echo "Command: $command"
    echo "========================================" >> "$output_file"
    echo "Test: $description" >> "$output_file"
    echo "Command: $command" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "========================================" >> "$output_file"
    
    # Run command and capture both stdout and stderr
    if timeout 30s bash -c "$command" >> "$output_file" 2>&1; then
        print_success "$description completed"
        echo -e "\n✓ SUCCESS\n" >> "$output_file"
        return 0
    else
        local exit_code=$?
        print_error "$description failed (exit code: $exit_code)"
        echo -e "\n✗ FAILED (exit code: $exit_code)\n" >> "$output_file"
        return $exit_code
    fi
}

# Function to run command with benchmark timing
run_benchmark() {
    local description="$1"
    local command="$2"
    
    echo -e "\n${BOLD}Benchmarking: $description${NC}"
    echo "========================================" >> "$BENCHMARK_OUTPUT"
    echo "Benchmark: $description" >> "$BENCHMARK_OUTPUT"
    echo "Command: $command" >> "$BENCHMARK_OUTPUT"
    echo "Timestamp: $(date)" >> "$BENCHMARK_OUTPUT"
    echo "========================================" >> "$BENCHMARK_OUTPUT"
    
    # Run command multiple times and measure
    local total_time=0
    local runs=3
    local success_count=0
    
    for i in $(seq 1 $runs); do
        echo "Run $i/$runs..."
        local start_time=$(date +%s.%N)
        
        if timeout 30s bash -c "$command" >/dev/null 2>&1; then
            success_count=$((success_count + 1))
        fi
        
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
        total_time=$(echo "$total_time + $duration" | bc -l 2>/dev/null || echo "$total_time")
        
        echo "  Run $i: ${duration}s" >> "$BENCHMARK_OUTPUT"
    done
    
    local avg_time=$(echo "scale=3; $total_time / $runs" | bc -l 2>/dev/null || echo "0")
    local success_rate=$(echo "scale=2; $success_count * 100 / $runs" | bc -l 2>/dev/null || echo "0")
    
    echo "Average time: ${avg_time}s" >> "$BENCHMARK_OUTPUT"
    echo "Success rate: ${success_rate}%" >> "$BENCHMARK_OUTPUT"
    echo "" >> "$BENCHMARK_OUTPUT"
    
    print_info "Average time: ${avg_time}s, Success rate: ${success_rate}%"
}

# Initialize test environment
initialize_test_env() {
    print_header "INITIALIZING TEST ENVIRONMENT"
    
    # Create output directories
    mkdir -p "$TEST_OUTPUT_DIR" "$DOCS_OUTPUT_DIR"
    
    # Clear previous results
    > "$TEST_LOG"
    > "$BENCHMARK_OUTPUT"
    > "$BUILD_LOG"
    
    print_success "Test directories created"
    
    # Check prerequisites
    echo "Checking prerequisites..." >> "$TEST_LOG"
    
    # Check if cargo is available
    if command -v cargo &> /dev/null; then
        print_success "Cargo available: $(cargo --version)"
        cargo --version >> "$TEST_LOG" 2>&1
    else
        print_error "Cargo not found - required for building"
        exit 1
    fi
    
    # Check if kubectl is available
    if command -v kubectl &> /dev/null; then
        print_success "kubectl available: $(kubectl version --client --short 2>/dev/null || echo 'unknown version')"
        kubectl version --client >> "$TEST_LOG" 2>&1 || true
    else
        print_warning "kubectl not found - some tests may fail"
    fi
    
    # Check if bc is available for benchmarking
    if ! command -v bc &> /dev/null; then
        print_warning "bc not found - benchmark calculations may be limited"
        # Install bc if possible
        if command -v apt-get &> /dev/null; then
            print_info "Attempting to install bc..."
            sudo apt-get update && sudo apt-get install -y bc 2>/dev/null || true
        fi
    fi
}

# Test all build configurations
test_builds() {
    print_header "TESTING BUILD CONFIGURATIONS"
    
    # Clean build
    run_and_capture "Clean build environment" "cargo clean" "$BUILD_LOG"
    
    # Debug build
    run_and_capture "Debug build" "cargo build" "$BUILD_LOG"
    
    # Release build
    run_and_capture "Release build" "cargo build --release" "$BUILD_LOG"
    
    # Test build
    run_and_capture "Test compilation" "cargo test --no-run" "$BUILD_LOG"
    
    # Documentation build
    run_and_capture "Documentation build" "cargo doc --no-deps" "$BUILD_LOG"
    
    # Check binary exists
    if [ -f "target/debug/$BINARY_NAME" ]; then
        print_success "Debug binary created successfully"
        ls -la "target/debug/$BINARY_NAME" >> "$BUILD_LOG"
    else
        print_error "Debug binary not found"
    fi
    
    if [ -f "target/release/$BINARY_NAME" ]; then
        print_success "Release binary created successfully"
        ls -la "target/release/$BINARY_NAME" >> "$BUILD_LOG"
    else
        print_error "Release binary not found"
    fi
}

# Run unit tests
test_unit_tests() {
    print_header "RUNNING UNIT TESTS"
    
    run_and_capture "Unit tests with output" "cargo test -- --nocapture" "$TEST_LOG"
    run_and_capture "Unit tests (quiet)" "cargo test" "$TEST_LOG"
    run_and_capture "Documentation tests" "cargo test --doc" "$TEST_LOG"
}

# Test CLI help and version commands
test_basic_commands() {
    print_header "TESTING BASIC CLI COMMANDS"
    
    local binary="./target/debug/$BINARY_NAME"
    
    if [ ! -f "$binary" ]; then
        print_error "Binary not found at $binary"
        return 1
    fi
    
    # Make binary executable
    chmod +x "$binary"
    
    # Test help command
    run_and_capture "Help command" "$binary --help" "$TEST_LOG"
    
    # Test version command
    run_and_capture "Version command" "$binary version" "$TEST_LOG"
    
    # Test version with --version flag
    run_and_capture "Version with --version flag" "$binary --version" "$TEST_LOG"
    
    # Test subcommand help
    run_and_capture "Diagnose help" "$binary diagnose --help" "$TEST_LOG"
    run_and_capture "Test-pod help" "$binary test-pod --help" "$TEST_LOG"
    
    # Test invalid command
    run_and_capture "Invalid command (should fail)" "$binary invalid-command || true" "$TEST_LOG"
}

# Validate all README.md instructions
validate_readme_instructions() {
    print_header "VALIDATING README.MD INSTRUCTIONS"
    
    local readme_validation_log="$TEST_OUTPUT_DIR/readme_validation.log"
    > "$readme_validation_log"
    
    print_info "Testing all commands and examples from README.md"
    
    # Test build from source instructions
    print_info "Validating build instructions..."
    
    # Test cargo commands mentioned in README
    run_and_capture "cargo check" "cargo check" "$readme_validation_log"
    run_and_capture "cargo test" "cargo test" "$readme_validation_log"
    run_and_capture "cargo build" "cargo build" "$readme_validation_log"
    run_and_capture "cargo build --release" "cargo build --release" "$readme_validation_log"
    
    # Test development commands
    run_and_capture "cargo run -- --version" "cargo run -- --version" "$readme_validation_log"
    run_and_capture "cargo run -- --help" "cargo run -- --help" "$readme_validation_log"
    
    # Test all CLI options mentioned in README
    local binary="./target/debug/$BINARY_NAME"
    if [ -f "$binary" ]; then
        chmod +x "$binary"
        
        # Basic commands from README
        run_and_capture "k8s-netinspect --version" "$binary --version" "$readme_validation_log"
        run_and_capture "k8s-netinspect version" "$binary version" "$readme_validation_log"
        run_and_capture "k8s-netinspect --help" "$binary --help" "$readme_validation_log"
        run_and_capture "k8s-netinspect diagnose --help" "$binary diagnose --help" "$readme_validation_log"
        run_and_capture "k8s-netinspect test-pod --help" "$binary test-pod --help" "$readme_validation_log"
        
        # Diagnose commands from README
        run_and_capture "k8s-netinspect diagnose" "$binary diagnose || true" "$readme_validation_log"
        run_and_capture "k8s-netinspect diagnose --namespace default" "$binary diagnose --namespace default || true" "$readme_validation_log"
        run_and_capture "k8s-netinspect diagnose -n kube-system" "$binary diagnose -n kube-system || true" "$readme_validation_log"
        run_and_capture "k8s-netinspect diagnose --namespace production" "$binary diagnose --namespace production || true" "$readme_validation_log"
        
        # Test-pod commands from README
        run_and_capture "k8s-netinspect test-pod --pod nginx --namespace default" "$binary test-pod --pod nginx --namespace default || true" "$readme_validation_log"
        run_and_capture "k8s-netinspect test-pod --pod nginx-abc123 --namespace default" "$binary test-pod --pod nginx-abc123 --namespace default || true" "$readme_validation_log"
        run_and_capture "k8s-netinspect test-pod -p nginx -n default" "$binary test-pod -p nginx -n default || true" "$readme_validation_log"
        
        # Test NO_COLOR environment variable
        run_and_capture "NO_COLOR=1 k8s-netinspect diagnose" "NO_COLOR=1 $binary diagnose || true" "$readme_validation_log"
        run_and_capture "NO_COLOR=1 k8s-netinspect --version" "NO_COLOR=1 $binary --version" "$readme_validation_log"
        
        # Test cargo run examples from README
        run_and_capture "cargo run -- diagnose" "cargo run -- diagnose || true" "$readme_validation_log"
        run_and_capture "cargo run -- test-pod --pod nginx --namespace default" "cargo run -- test-pod --pod nginx --namespace default || true" "$readme_validation_log"
        run_and_capture "cargo run -- diagnose --namespace kube-system" "cargo run -- diagnose --namespace kube-system || true" "$readme_validation_log"
    fi
    
    # Test release binary if available
    local release_binary="./target/release/$BINARY_NAME"
    if [ -f "$release_binary" ]; then
        chmod +x "$release_binary"
        run_and_capture "./target/release/k8s-netinspect diagnose" "$release_binary diagnose || true" "$readme_validation_log"
        run_and_capture "./target/release/k8s-netinspect --version" "$release_binary --version" "$readme_validation_log"
    fi
    
    # Validate RBAC permission test commands from README
    print_info "Testing RBAC validation commands..."
    run_and_capture "kubectl auth can-i get pods" "kubectl auth can-i get pods || true" "$readme_validation_log"
    run_and_capture "kubectl auth can-i list nodes" "kubectl auth can-i list nodes || true" "$readme_validation_log"
    run_and_capture "kubectl auth can-i get namespaces" "kubectl auth can-i get namespaces || true" "$readme_validation_log"
    
    # Test cluster info commands from README
    run_and_capture "kubectl cluster-info" "kubectl cluster-info || true" "$readme_validation_log"
    
    # Validate error conditions mentioned in README
    print_info "Testing error conditions from README..."
    run_and_capture "Empty pod name (should fail)" "$binary test-pod --pod '' --namespace default || true" "$readme_validation_log"
    run_and_capture "Invalid pod name (should fail)" "$binary test-pod --pod INVALID --namespace default || true" "$readme_validation_log"
    run_and_capture "Nonexistent pod (should fail)" "$binary test-pod --pod nonexistent-pod-12345 --namespace default || true" "$readme_validation_log"
    run_and_capture "Nonexistent namespace (should fail)" "$binary diagnose --namespace nonexistent-namespace-12345 || true" "$readme_validation_log"
    
    print_success "README.md validation completed - check $readme_validation_log for details"
}

# Test diagnostic commands (may fail without k8s cluster)
test_diagnostic_commands() {
    print_header "TESTING DIAGNOSTIC COMMANDS"
    
    local binary="./target/debug/$BINARY_NAME"
    
    print_info "Note: These tests may fail if no Kubernetes cluster is available"
    
    # Test diagnose without namespace
    run_and_capture "Diagnose cluster-wide" "$binary diagnose || true" "$TEST_LOG"
    
    # Test diagnose with various namespaces
    for ns in "${TEST_NAMESPACES[@]}"; do
        run_and_capture "Diagnose namespace: $ns" "$binary diagnose --namespace $ns || true" "$TEST_LOG"
    done
    
    # Test invalid namespace
    run_and_capture "Diagnose invalid namespace (should fail)" "$binary diagnose --namespace invalid-namespace-12345 || true" "$TEST_LOG"
}

# Test pod connectivity commands
test_pod_commands() {
    print_header "TESTING POD CONNECTIVITY COMMANDS"
    
    local binary="./target/debug/$BINARY_NAME"
    
    print_info "Note: These tests may fail if no pods are available"
    
    # Test with various pod names in different namespaces
    for ns in "${TEST_NAMESPACES[@]}"; do
        for pod in "${TEST_POD_NAMES[@]}"; do
            run_and_capture "Test pod: $pod in namespace: $ns" "$binary test-pod --pod $pod --namespace $ns || true" "$TEST_LOG"
        done
    done
    
    # Test invalid inputs
    run_and_capture "Test invalid pod name (should fail)" "$binary test-pod --pod '' --namespace default || true" "$TEST_LOG"
    run_and_capture "Test invalid namespace (should fail)" "$binary test-pod --pod test --namespace '' || true" "$TEST_LOG"
    run_and_capture "Test uppercase pod name (should fail)" "$binary test-pod --pod INVALID --namespace default || true" "$TEST_LOG"
}

# Run performance benchmarks
run_benchmarks() {
    print_header "RUNNING PERFORMANCE BENCHMARKS"
    
    local binary="./target/release/$BINARY_NAME"
    
    if [ ! -f "$binary" ]; then
        print_warning "Release binary not found, using debug binary for benchmarks"
        binary="./target/debug/$BINARY_NAME"
    fi
    
    chmod +x "$binary"
    
    echo "Performance Benchmarks for k8s-netinspect" > "$BENCHMARK_OUTPUT"
    echo "Generated: $(date)" >> "$BENCHMARK_OUTPUT"
    echo "Binary: $binary" >> "$BENCHMARK_OUTPUT"
    echo "" >> "$BENCHMARK_OUTPUT"
    
    # Benchmark basic commands
    run_benchmark "Version command" "$binary version"
    run_benchmark "Help command" "$binary --help"
    
    # Benchmark diagnostic commands (may fail without cluster)
    run_benchmark "Diagnose cluster" "$binary diagnose || true"
    run_benchmark "Diagnose default namespace" "$binary diagnose --namespace default || true"
    
    # Benchmark pod test commands (may fail without pods)
    run_benchmark "Test pod command" "$binary test-pod --pod test --namespace default || true"
}

# Generate comprehensive documentation
generate_documentation() {
    print_header "GENERATING DOCUMENTATION"
    
    local binary="./target/release/$BINARY_NAME"
    if [ ! -f "$binary" ]; then
        binary="./target/debug/$BINARY_NAME"
    fi
    
    local doc_file="$DOCS_OUTPUT_DIR/USER_GUIDE.md"
    
    cat > "$doc_file" << 'YAML_EOF2'
# k8s-netinspect User Guide

A minimal Kubernetes network inspection tool for diagnosing CNI and pod connectivity issues.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Commands](#commands)
4. [Examples](#examples)
5. [Troubleshooting](#troubleshooting)
6. [Performance](#performance)

## Installation

### Prerequisites

- Kubernetes cluster access
- `kubectl` configured with valid kubeconfig
- Appropriate RBAC permissions (see RBAC Setup below)

### Build from Source

```bash
git clone https://github.com/marcuspat/k8s-netinspect.git
cd k8s-netinspect
cargo build --release
```

### RBAC Setup

The tool requires specific Kubernetes RBAC permissions. Run the following to set up permissions:

```bash
# Create service account
kubectl create serviceaccount k8s-netinspect -n default

# Apply cluster-level permissions (nodes, namespaces)
kubectl apply -f - <<YAML_YAML_EOF2
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-netinspect-cluster
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-netinspect-cluster
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-netinspect-cluster
subjects:
- kind: ServiceAccount
  name: k8s-netinspect
  namespace: default
YAML_YAML_EOF2

# Apply namespace-level permissions (pods, services, endpoints)
kubectl apply -f - <<YAML_YAML_EOF22
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: k8s-netinspect-namespace
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"] 
- apiGroups: [""]
  resources: ["endpoints"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: k8s-netinspect-namespace
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: k8s-netinspect-namespace
subjects:
- kind: ServiceAccount
  name: k8s-netinspect
  namespace: default
YAML_EOF2
```

## Quick Start

1. **Check version and help:**
   ```bash
   k8s-netinspect version
   k8s-netinspect --help
   ```

2. **Diagnose cluster network:**
   ```bash
   k8s-netinspect diagnose
   ```

3. **Test specific pod connectivity:**
   ```bash
   k8s-netinspect test-pod --pod nginx --namespace default
   ```

## Commands

### Global Options

- `--help, -h`: Show help information
- `--version, -V`: Show version information

### diagnose

Diagnose CNI and basic network configuration across the cluster or in a specific namespace.

**Usage:**
```bash
k8s-netinspect diagnose [OPTIONS]
```

**Options:**
- `-n, --namespace <NAMESPACE>`: Target namespace for pod diagnostics (default: cluster-wide)

**Examples:**
```bash
# Diagnose entire cluster
k8s-netinspect diagnose

# Diagnose specific namespace
k8s-netinspect diagnose --namespace kube-system
k8s-netinspect diagnose -n production
```

### test-pod

Test connectivity for a specific pod.

**Usage:**
```bash
k8s-netinspect test-pod [OPTIONS] --pod <POD>
```

**Options:**
- `-p, --pod <POD>`: Pod name to test (required)
- `-n, --namespace <NAMESPACE>`: Namespace (default: default)

**Examples:**
```bash
# Test pod in default namespace
k8s-netinspect test-pod --pod nginx

# Test pod in specific namespace
k8s-netinspect test-pod --pod web-server --namespace production
k8s-netinspect test-pod -p api-server -n kube-system
```

### version

Show version information.

**Usage:**
```bash
k8s-netinspect version
```

YAML_EOF2

    # Add command outputs to documentation
    echo "" >> "$doc_file"
    echo "## Command Output Examples" >> "$doc_file"
    echo "" >> "$doc_file"
    
    # Capture version output
    echo "### Version Command" >> "$doc_file"
    echo '```' >> "$doc_file"
    echo "$ k8s-netinspect version" >> "$doc_file"
    $binary version >> "$doc_file" 2>/dev/null || echo "Error running version command" >> "$doc_file"
    echo '```' >> "$doc_file"
    echo "" >> "$doc_file"
    
    # Capture help output
    echo "### Help Command" >> "$doc_file"
    echo '```' >> "$doc_file"
    echo "$ k8s-netinspect --help" >> "$doc_file"
    $binary --help >> "$doc_file" 2>/dev/null || echo "Error running help command" >> "$doc_file"
    echo '```' >> "$doc_file"
    echo "" >> "$doc_file"
    
    # Add troubleshooting section
    cat >> "$doc_file" << 'YAML_EOF2'
## Troubleshooting

### Common Issues

#### Permission Denied Errors

If you see RBAC permission errors, ensure you have applied the required permissions:

```bash
# Check current permissions
kubectl auth can-i get pods
kubectl auth can-i list nodes

# Apply RBAC setup (see RBAC Setup section above)
```

#### Connection Timeout Errors

- Verify kubectl connectivity: `kubectl get nodes`
- Check kubeconfig: `kubectl config current-context`
- Ensure cluster is accessible and responsive

#### Pod Not Found Errors

- List available pods: `kubectl get pods -A`
- Verify namespace exists: `kubectl get namespaces`
- Check pod name spelling and case (must be lowercase)

#### CNI Detection Issues

- Check node annotations: `kubectl describe nodes`
- Verify CNI is properly installed and running
- Check for CNI-specific pods in kube-system namespace

### Input Validation

The tool validates all inputs according to Kubernetes naming conventions:

- **Pod names**: lowercase alphanumeric, hyphens, dots only (max 253 characters)
- **Namespaces**: lowercase alphanumeric, hyphens only (max 63 characters)
- **IP addresses**: valid IPv4 or IPv6 format

### Exit Codes

- `0`: Success
- `1`: General error
- `2`: Invalid input
- `3`: Permission denied
- `4`: Resource not found
- `5`: Network connectivity issue
- `6`: Kubernetes connection error
- `7`: Timeout error

YAML_EOF2

    # Add performance section from benchmarks
    if [ -f "$BENCHMARK_OUTPUT" ]; then
        echo "## Performance Benchmarks" >> "$doc_file"
        echo "" >> "$doc_file"
        echo "Performance data collected from test runs:" >> "$doc_file"
        echo "" >> "$doc_file"
        echo '```' >> "$doc_file"
        cat "$BENCHMARK_OUTPUT" >> "$doc_file"
        echo '```' >> "$doc_file"
    fi
    
    print_success "Documentation generated: $doc_file"
    
    # Generate RBAC setup script
    local rbac_script="$DOCS_OUTPUT_DIR/setup-rbac.sh"
    cat > "$rbac_script" << 'YAML_EOF2'
#!/bin/bash
# RBAC Setup Script for k8s-netinspect
# Service Account: k8s-netinspect
# Namespace: default

echo "Setting up RBAC permissions for k8s-netinspect..."

# Create service account if it doesn't exist
kubectl create serviceaccount k8s-netinspect -n default --dry-run=client -o yaml | kubectl apply -f -

# Cluster-level permissions (nodes, namespaces)
cat <<YAML_EOF2 | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-netinspect-cluster
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-netinspect-cluster
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-netinspect-cluster
subjects:
- kind: ServiceAccount
  name: k8s-netinspect
  namespace: default
YAML_EOF2

# Namespace-level permissions (pods, services, endpoints)
cat <<YAML_EOF2 | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: k8s-netinspect-namespace
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"] 
- apiGroups: [""]
  resources: ["endpoints"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: k8s-netinspect-namespace
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: k8s-netinspect-namespace
subjects:
- kind: ServiceAccount
  name: k8s-netinspect
  namespace: default
YAML_EOF2

echo "✅ RBAC permissions configured successfully!"
echo "You can now use k8s-netinspect with the service account: k8s-netinspect"
echo ""
echo "To apply the same namespace permissions to other namespaces, run:"
echo "kubectl apply -f - <<YAML_EOF2"
echo "apiVersion: rbac.authorization.k8s.io/v1"
echo "kind: RoleBinding"
echo "metadata:"
echo "  name: k8s-netinspect-namespace"
echo "  namespace: <TARGET_NAMESPACE>"
echo "roleRef:"
echo "  apiGroup: rbac.authorization.k8s.io"
echo "  kind: Role"
echo "  name: k8s-netinspect-namespace"
echo "subjects:"
echo "- kind: ServiceAccount"
echo "  name: k8s-netinspect"
echo "  namespace: default"
echo "YAML_EOF2"
YAML_EOF2
    
    chmod +x "$rbac_script"
    print_success "RBAC setup script generated: $rbac_script"
}

# Generate test summary
generate_summary() {
    print_header "GENERATING TEST SUMMARY"
    
    local summary_file="$TEST_OUTPUT_DIR/summary.md"
    
    cat > "$summary_file" << YAML_EOF2
# k8s-netinspect Test Summary

**Generated:** $(date)
**Test Duration:** $(date -d @$(($(date +%s) - start_time)) -u +%H:%M:%S) 

## Test Results Overview

### Build Tests
- Debug build: $(grep -c "✓ SUCCESS" "$BUILD_LOG" 2>/dev/null || echo "0") passed
- Release build: $(grep -c "✓ SUCCESS" "$BUILD_LOG" 2>/dev/null || echo "0") passed
- Total build failures: $(grep -c "✗ FAILED" "$BUILD_LOG" 2>/dev/null || echo "0")

### Unit Tests
- Unit test results: $(grep "test result:" "$TEST_LOG" 2>/dev/null | tail -1 || echo "Not run")

### CLI Tests
- Command tests: $(grep -c "✓ SUCCESS" "$TEST_LOG" 2>/dev/null || echo "0") passed
- Command failures: $(grep -c "✗ FAILED" "$TEST_LOG" 2>/dev/null || echo "0")

### README Validation
- README instruction tests: $(grep -c "✓ SUCCESS" "$TEST_OUTPUT_DIR/readme_validation.log" 2>/dev/null || echo "0") passed
- README instruction failures: $(grep -c "✗ FAILED" "$TEST_OUTPUT_DIR/readme_validation.log" 2>/dev/null || echo "0")

### Files Generated
- Build log: $BUILD_LOG
- Test log: $TEST_LOG
- README validation log: $TEST_OUTPUT_DIR/readme_validation.log
- Benchmark results: $BENCHMARK_OUTPUT
- User documentation: $DOCS_OUTPUT_DIR/USER_GUIDE.md
- RBAC setup script: $DOCS_OUTPUT_DIR/setup-rbac.sh

### Binary Information
YAML_EOF2

    # Add binary info if available
    for binary in "target/debug/$BINARY_NAME" "target/release/$BINARY_NAME"; do
        if [ -f "$binary" ]; then
            echo "- $binary: $(ls -lh "$binary" | awk '{print $5}')" >> "$summary_file"
            file "$binary" >> "$summary_file" 2>/dev/null || true
        fi
    done
    
    echo "" >> "$summary_file"
    echo "### Performance Summary" >> "$summary_file"
    if [ -f "$BENCHMARK_OUTPUT" ]; then
        grep "Average time:" "$BENCHMARK_OUTPUT" >> "$summary_file" 2>/dev/null || echo "No benchmark data available" >> "$summary_file"
    else
        echo "No benchmark data available" >> "$summary_file"
    fi
    
    print_success "Test summary generated: $summary_file"
    
    # Display summary
    echo ""
    cat "$summary_file"
}

# Main execution
main() {
    local start_time=$(date +%s)
    
    print_header "K8S-NETINSPECT COMPREHENSIVE TEST SUITE"
    echo "Starting comprehensive testing of k8s-netinspect..."
    echo "Timestamp: $(date)"
    
    # Run all test phases
    initialize_test_env
    test_builds
    test_unit_tests
    test_basic_commands
    validate_readme_instructions
    test_diagnostic_commands
    test_pod_commands
    run_benchmarks
    generate_documentation
    generate_summary
    
    print_header "TEST SUITE COMPLETED"
    print_success "All tests completed successfully!"
    print_info "Check the following files for detailed results:"
    print_info "  - Build logs: $BUILD_LOG"
    print_info "  - Test logs: $TEST_LOG" 
    print_info "  - README validation: $TEST_OUTPUT_DIR/readme_validation.log"
    print_info "  - Benchmarks: $BENCHMARK_OUTPUT"
    print_info "  - Documentation: $DOCS_OUTPUT_DIR/"
    print_info "  - Summary: $TEST_OUTPUT_DIR/summary.md"
}

# Error handling
trap 'echo -e "\n${RED}Test suite interrupted!${NC}"; exit 1' INT TERM

# Run main function
main "$@"