# GitHub Actions pinning evidence

- Retrieved: 2026-07-28
- Local workflow: `.github/workflows/ci.yml`
- Local repository Actions posture: enabled; default workflow permissions `read`;
  pull-request approval disabled.
- Official guidance:
  - https://docs.github.com/en/actions/reference/security/secure-use
  - https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/auto-update-actions
- Decision: pin every external Action to a full-length commit SHA and retain the
  release/channel name as an inline comment so Dependabot can update it.
- Resolved upstream references:
  - `actions/checkout@v5`:
    `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09`
  - `dtolnay/rust-toolchain@stable`:
    `4cda84d5c5c54efe2404f9d843567869ab1699d4`
- Toolchain: Rust `1.96.0`, matching workspace `rust-version`.
- Verification:
  - `rg -n 'uses: .*@[0-9a-f]{40}' .github/workflows/ci.yml`
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all`
- Risk: pinned Actions require intentional update PRs.
- Rollback: restore the prior workflow references from Git.
- Next refresh: 2026-08-04 or when Dependabot opens an Actions update.
