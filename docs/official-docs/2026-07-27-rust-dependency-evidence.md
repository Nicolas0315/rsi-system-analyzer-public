# Rust dependency evidence — 2026-07-27

- retrieved_at: 2026-07-27 +09:00
- local_rustc: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- local_cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- target: `x86_64-pc-windows-msvc`

## Sources and decisions

- sysinfo: <https://docs.rs/sysinfo/latest/>
  - registry version observed with `cargo search`: `0.39.6`
  - decision: use one retained `System`, take two process/CPU samples separated
    by `MINIMUM_CPU_UPDATE_INTERVAL`, and use selective refresh APIs.
- clap: <https://docs.rs/clap/latest/clap/_derive/>
  - registry version observed: `4.6.4`
  - decision: derive `Parser`, `Subcommand`, `Args`, and `ValueEnum`; no external
    subcommands.
- serde: <https://serde.rs/enum-representations.html> and
  <https://serde.rs/attributes.html>
  - registry version observed: `1.0.229`
  - decision: adjacently tagged observation enums and
    `deny_unknown_fields` on persisted top-level records.
- regex: <https://docs.rs/regex/latest/>
  - registry version observed: `1.13.1`
  - decision: bounded, precompiled redaction patterns only; no user-provided
    regular expressions.
- thiserror: <https://docs.rs/thiserror/latest/>
  - registry version observed: `2.0.19`
  - decision: stable internal error variants; raw external output is not stored
    in errors.

## Risk and verification

- risk: platform APIs and minimum supported Rust versions may change.
- mitigation: `Cargo.lock`, workspace `rust-version = "1.96"`, Windows/macOS/
  Linux CI, fixture parsers, and warnings denied by clippy.
- verification:
  - `cargo check --workspace`
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all`
- rollback: revert the dependency commit or restore the prior `Cargo.toml` and
  `Cargo.lock`, then rerun the verification commands.
- next_refresh: 2026-10-27, or earlier when a dependency major version changes.
