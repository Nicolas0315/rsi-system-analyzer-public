# Contributing

Thank you for improving RSI System Analyzer.

## Before opening a change

- Discuss broad data-model or trust-boundary changes in an issue.
- Never submit real machine snapshots, raw configuration, logs, credentials,
  addresses, hostnames, usernames, or full paths.
- Add synthetic fixtures for every new behavior.
- Keep collectors read-only and optimization output non-executable.
- Add official documentation evidence under `docs/official-docs/` when changing
  platform, CLI, API, authentication, or dependency behavior.

## Development checks

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
pwsh -NoProfile -File scripts/check-read-only-boundary.ps1
```

Use `scripts/check-read-only-boundary.sh` on macOS or Linux.

## Pull requests

Explain the user-visible behavior, security impact, tests run, and rollback.
Changes to collection, verification, optimization, knowledge sources, or
redaction must receive a review independent from the author.
