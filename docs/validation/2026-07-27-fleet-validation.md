# Fleet validation — 2026-07-27

## Verified

- Five trusted development machines completed release-mode scans:
  three Windows x86_64 nodes and two macOS arm64 nodes.
- Fast mode completed in 0.77–1.44 seconds.
- Default mode completed in 0.78–1.31 seconds and summarized 42–109
  application names per node.
- Each snapshot contained 13 fixed CLI entries, 23–28 MCP server-name
  records, and at most 20 sanitized process summaries.
- NVIDIA probes returned typed observations on all three Windows nodes.
- Deterministic rules identified two currently busy GPU nodes without
  attempting to stop or reconfigure their workloads.
- The committed redaction corpus plus a post-scan check found zero matches for
  IP addresses, user-home paths, common token/key prefixes, private-key
  markers, or credential assignments.
- No raw fleet snapshot, hostname, address, process argument, configuration
  body, or authentication material was committed.

## Not verified

- A native Linux release binary was not executed. Two available WSL
  environments were x86_64 Linux but did not have Rust installed; no toolchain
  was installed as part of this read-only validation. A container fallback was
  also attempted, but Docker Desktop's existing credential helper failed
  before the public Rust image could be pulled; no image was added.
- GitHub-hosted CI jobs did not start because the account reported a billing or
  spending-limit problem. GitHub returned `runner_id: 0` and no job steps, so
  this is not a source/test failure.

## Local verification commands

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
pwsh -NoProfile -File scripts/check-read-only-boundary.ps1
```

Claude Code performed a separate read-only review after the final fleet
constraint change and returned `APPROVE` with no blocking findings.
