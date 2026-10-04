# Changelog

## 0.2.0 — unreleased

Not published to crates.io. Everything below is tested offline against
recorded snapshots; none of it has been run against a live cluster yet.

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
