#!/usr/bin/env bash
# Read-only smoke run against whatever cluster the current kubeconfig context
# points at. It prints each command's raw output and exit status and draws no
# conclusions of its own: read the output.
#
# It never uses `can-reach --probe`, so it changes nothing in the cluster.
#
# Usage:  scripts/live-smoke.sh [FROM_POD TO_POD PORT]
#   e.g.  scripts/live-smoke.sh production/nginx-web-abc production/redis-cache-xyz 6379
#
# For sample workloads to point it at: kubectl apply -f test-resources.yaml
set -u

BIN="${BIN:-./target/release/k8s-netinspect}"
[ -x "$BIN" ] || BIN=./target/debug/k8s-netinspect
if [ ! -x "$BIN" ]; then
  echo "build first: cargo build --release" >&2
  exit 2
fi

SNAP="$(mktemp -t netinspect-snapshot.XXXXXX.json)"
trap 'rm -f "$SNAP"' EXIT

step() {
  echo
  echo "=== $* ==="
  "$@"
  echo "--- exit status: $? ---"
}

kubectl config current-context 2>/dev/null | sed 's/^/context: /'

step "$BIN" version
step "$BIN" diagnose
step "$BIN" diagnose --output json
step "$BIN" snapshot --file "$SNAP"
step "$BIN" diagnose --from-snapshot "$SNAP"
step "$BIN" diff "$SNAP" "$SNAP"

if [ "$#" -eq 3 ]; then
  step "$BIN" can-reach --from "$1" --to "$2" --port "$3" --suggest
else
  echo
  echo "(skipping can-reach: pass FROM_POD TO_POD PORT to include it)"
fi
