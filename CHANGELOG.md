# Changelog

## 0.2.1 — unreleased

First round of live-cluster feedback (kind v1.37, 2026-10-14). No new
features; one behavioural fix and documentation corrected to match reality.

**Script authors note — probe exit codes and JSON `agrees` changed:**

- Blocked flow with a silent failed connect: was `inconclusive`,
  `agrees: false`, exit 8; now `failed`, `agrees: true`, exit 6.
- Allowed flow, `timed out`: was exit 8, `agrees: false`; now exit 0,
  `agrees: true`.
- Allowed flow, new `failed` observation: exit 0, `agrees: true`.
- `inconclusive`: exit 1 (was 8).
- Exit 8 now means only one thing: the flow is blocked yet the probe
  connected or was refused — the policy is not being enforced.

### Fixed

- `can-reach --probe` classified only *successful* connects. busybox `nc`
  often fails silently (`-w` timeouts print nothing; diagnostics go to
  stderr, which the log read does not always surface), so every failed
  connect landed in `inconclusive` and exited 8 claiming a mismatch it
  could not see — the most valuable case, confirming a block, was the
  broken one. Classification is now exit-code-first: a non-zero exit
  without recognisable output is `failed` (connect failed, flavour
  unknown). Exit 8 is reserved for genuine contradictions (flow blocked,
  yet connected or refused); a failed connect under an allowing verdict is
  reported as consistent — "allowed" never promised the connection would
  succeed — with where to look instead; an inconclusive probe exits 1.

### Documentation

- `cargo install` line was stale: crates.io already serves 0.2.0
  (published 2026-10-09), not 0.1.1.
- "Access it needs" understated the hard requirements: services and
  endpoints are also mandatory (exit 5 without them), and the pre-flight
  probes namespaced access in `default`.
- Verification status reflects the 2026-10-14 live round; the probe
  section documents what each observation means instead of claiming the
  code has never run on a real cluster.

## 0.2.0 — 2026-10-09

Everything below is tested offline against recorded snapshots; the live
path was exercised after release (see 0.2.1 and `docs/SOTA_ROADMAP.md`).

### Changed

- `diagnose` now collects a snapshot once and runs pure analysis over it.
  The legacy lines (`CNI detected`, `Found N nodes`, `Found N pods`) are
  kept; a `Service proxy` line and a findings section are added.
- CNI detection reads the CNI agent DaemonSet (16 plugins, with version and
  rollout health) and falls back to node annotations. It no longer reports
  `Generic CNI (containerd)` for clusters it does not recognise.
- **Minimum Rust version is 1.89** (was 1.70), required by kube 4.x.
- Dependencies: kube 0.87 → 4.2, k8s-openapi 0.20 → 0.28, reqwest
  0.11 → 0.12, colored 2 → 3. `cargo audit` reports no vulnerabilities.
- Lists the tool is not allowed to read (beyond the required nodes, pods
  and namespaces) no longer end the run: the checks that need them are
  reported as skipped.

### Added

- Findings with stable rule ids, severity, evidence and a suggested fix —
  43 rules across CNI, nodes, pod IPAM, NetworkPolicy, Services, DNS,
  service proxy, Ingress and Gateway API. See `docs/RULES.md`.
- `can-reach`: policy reachability for a flow (NetworkPolicy plus
  AdminNetworkPolicy / BaselineAdminNetworkPolicy tiers), naming the policy
  that blocks it. `--suggest` prints the NetworkPolicy that would allow it.
  `--probe` tests it from inside the source pod (modifies that pod).
- `snapshot`, and `--from-snapshot` on `diagnose`, `can-reach` and `mcp`,
  for offline analysis.
- `diff` between two snapshots; `diagnose --watch`.
- `--output json | sarif | junit | prometheus`, `--fail-on`, `--only`,
  `--skip`, and the `rules` and `explain` commands.
- `mcp`: a read-only Model Context Protocol server over stdio.

### Fixed

- `version` no longer requires a kubeconfig.
- Running inside a pod no longer fails the kubeconfig pre-flight check.
- `KUBECONFIG` is treated as a path list, as kubectl does.
- Compressed IPv6 addresses such as `fd00::1` were rejected as invalid.
- `test-pod` built an invalid URL for IPv6 pod IPs.

### Removed

- `live-cluster-test.sh` and `test-comprehensive.sh`. The first wrote a
  report with its conclusions hard-coded; the second wrapped `cargo`
  commands that the test suite now covers. `scripts/live-smoke.sh` replaces
  them: read-only, prints raw output and exit codes, concludes nothing.
- The unused `axum` dependency.

### New exit codes

`6` flow blocked (`can-reach`), `7` `--fail-on` threshold met, `8` probe
result contradicts the policy verdict. Codes `0`–`5` are unchanged.

## 0.1.1

- Demo GIF added to the README.

## 0.1.0

- Initial release: `diagnose`, `test-pod`, `version`.
