# rsi-system-analyzer agent rules

The fleet baseline at `~/work/agent-context/AGENTS.MD` applies. This file adds
repository-specific rules only.

## Scope

- Build a fast, cross-platform, read-only system analyzer for Windows, macOS,
  Linux, WSL, Apple Silicon, x86_64, NVIDIA, AMD, and Intel environments.
- Inventory hardware, OS, selected applications, CLI versions, MCP metadata,
  process summaries, and configuration posture without collecting secrets.
- Produce deterministic optimization findings before any optional AI
  explanation.

## Safety

- V1 contains no apply, elevation, cleanup, package install, service mutation,
  remote write, or permission-bypass code path.
- Never collect raw command lines, environment values, configuration bodies,
  command history, auth databases, tokens, cookies, SSH material, IP addresses,
  or raw logs.
- External commands must be declared in a typed probe manifest and executed
  without a shell through one bounded runner.
- Redaction occurs at each collector boundary before data enters the canonical
  snapshot.
- Missing data is explicit: `unsupported`, `timeout`, `denied`, `unreachable`,
  or `stale`.
- Node constraints are enforced before findings reach an AI component.

## Development

- Rust stable is the primary implementation language.
- Add covering tests in the same change as behavior.
- Keep OS adapters isolated behind typed traits and a versioned schema.
- Prefer fixtures and deterministic rules over machine-specific assumptions.
- Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  and `cargo test --all` before reporting implementation complete.
- Do not commit real hostnames, IPs, machine identifiers, process arguments,
  or captured fleet snapshots.
