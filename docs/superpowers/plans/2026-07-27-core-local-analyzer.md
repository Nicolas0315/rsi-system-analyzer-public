# Core Local Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a safe Rust CLI that scans one Windows, macOS, or Linux machine and emits a sanitized, versioned JSON or Markdown snapshot plus deterministic optimization findings.

**Architecture:** A Cargo workspace separates schema, process execution, collection, rules, and CLI concerns. External commands can only run through a typed probe runner; portable facts and process summaries use `sysinfo`; every observation has an explicit availability state.

**Tech Stack:** Rust 1.96 stable, serde/serde_json, clap derive, sysinfo, regex, sha2, uuid, chrono, thiserror, tempfile, assert_cmd, predicates.

---

### Task 1: Workspace and official-doc evidence

**Files:**
- Create: `Cargo.toml`
- Create: `docs/official-docs/2026-07-27-rust-dependency-evidence.md`
- Create: `crates/rsi-schema/Cargo.toml`
- Create: `crates/rsi-schema/src/lib.rs`
- Create: `crates/rsi-probe/Cargo.toml`
- Create: `crates/rsi-probe/src/lib.rs`
- Create: `crates/rsi-collect/Cargo.toml`
- Create: `crates/rsi-collect/src/lib.rs`
- Create: `crates/rsi-optimize/Cargo.toml`
- Create: `crates/rsi-optimize/src/lib.rs`
- Create: `crates/rsi-cli/Cargo.toml`
- Create: `crates/rsi-cli/src/main.rs`

- [ ] **Step 1: Add a workspace manifest**

```toml
[workspace]
resolver = "2"
members = [
  "crates/rsi-schema",
  "crates/rsi-probe",
  "crates/rsi-collect",
  "crates/rsi-optimize",
  "crates/rsi-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
rust-version = "1.96"

[workspace.dependencies]
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive"] }
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
sysinfo = "0.39.6"
thiserror = "2"
uuid = { version = "1", features = ["serde", "v4"] }
```

- [ ] **Step 2: Record dependency decisions**

Write the retrieved documentation URLs, retrieval date, local Rust version,
chosen APIs, risks, rollback (`git revert` or dependency removal), verification
commands, and next review date in the official-doc evidence file.

- [ ] **Step 3: Add compileable crate entry points**

`rsi-schema` starts with:

```rust
pub const SCHEMA_VERSION: &str = "rsi.snapshot.v1";
```

Each other library exports a `pub const CRATE_NAME: &str` matching its package
name. The CLI prints `env!("CARGO_PKG_VERSION")` when invoked with `--version`,
so `cargo check --workspace` has a runnable target without introducing
behavior before its covering tests.

- [ ] **Step 4: Verify the workspace**

Run: `cargo check --workspace`

Expected: all five workspace members compile.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates docs/official-docs
git commit -m "Set up RSI analyzer workspace"
```

### Task 2: Versioned schema and explicit observations

**Files:**
- Modify: `crates/rsi-schema/src/lib.rs`
- Create: `crates/rsi-schema/tests/schema.rs`

- [ ] **Step 1: Write failing schema tests**

```rust
#[test]
fn observation_serializes_with_explicit_status() {
    let value = Observation::Value {
        value: 64_u64,
        captured_at: fixed_time(),
        source: Source::Native,
        confidence: Confidence::High,
        stability: Stability::Stable,
    };
    let json = serde_json::to_value(value).unwrap();
    assert_eq!(json["status"], "value");
    assert_eq!(json["data"]["value"], 64);
}

#[test]
fn unavailable_states_are_not_zero() {
    let unsupported = Observation::<u64>::Unsupported {
        reason: "vendor tool absent".into(),
    };
    assert_ne!(
        serde_json::to_value(unsupported).unwrap(),
        serde_json::json!({"status":"value","data":{"value":0}})
    );
}
```

- [ ] **Step 2: Confirm the tests fail**

Run: `cargo test -p rsi-schema --test schema`

Expected: compile failure because `Observation` and supporting types do not
exist.

- [ ] **Step 3: Implement schema types**

Define:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum Observation<T> {
    Value {
        value: T,
        captured_at: DateTime<Utc>,
        source: Source,
        confidence: Confidence,
        stability: Stability,
    },
    Unsupported { reason: String },
    Timeout { probe_id: String, limit_ms: u64 },
    Denied { capability: Capability },
    Unreachable { transport: String },
    Stale { last_value: T, as_of: DateTime<Utc> },
    Error { code: ErrorCode },
}
```

Add `Snapshot`, `MachineFacts`, `ProcessSummary`, `CliFact`, `McpFact`,
`ApplicationSummary`, `Completeness`, `Finding`, `DisplayOnly<T>`,
`RemediationText`, `VerificationText`, and all closed enums referenced by the
design.

- [ ] **Step 4: Test serialization and strict parsing**

Use `#[serde(deny_unknown_fields)]` on top-level snapshots and findings. Add a
round-trip fixture and reject an unknown top-level field.

- [ ] **Step 5: Run tests**

Run: `cargo test -p rsi-schema`

Expected: all schema tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rsi-schema
git commit -m "Add versioned analyzer schema"
```

### Task 3: Collector-boundary redaction

**Files:**
- Create: `crates/rsi-schema/src/redaction.rs`
- Modify: `crates/rsi-schema/src/lib.rs`
- Create: `crates/rsi-schema/tests/redaction.rs`

- [ ] **Step 1: Write malicious fixture tests**

```rust
#[test]
fn redacts_network_and_secret_material() {
    let raw = "host=workstation 100.64.1.9 token=ghp_FAKEFAKEFAKE \
               --password secret C:\\Users\\person\\tool";
    let sanitized = sanitize_untrusted_text(raw);
    assert!(!sanitized.contains("100.64.1.9"));
    assert!(!sanitized.contains("ghp_"));
    assert!(!sanitized.contains("secret"));
    assert!(!sanitized.contains("C:\\Users\\person"));
}
```

- [ ] **Step 2: Confirm failure**

Run: `cargo test -p rsi-schema --test redaction`

Expected: compile failure because `sanitize_untrusted_text` does not exist.

- [ ] **Step 3: Implement bounded sanitization**

Implement ordered replacements for IP addresses, private-key markers, common
token prefixes, credential assignments, Windows user paths, Unix home paths,
and line-length/output-length caps. Return `[redacted]` markers, never hashes of
secret values.

- [ ] **Step 4: Add property-style test corpus**

Create a fixed array of secret/network/path patterns and assert none survive.
Assert ordinary versions such as `1.96.0` and names such as `rustc` survive.

- [ ] **Step 5: Run tests**

Run: `cargo test -p rsi-schema --test redaction`

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rsi-schema
git commit -m "Add collector boundary redaction"
```

### Task 4: Typed probe runner

**Files:**
- Modify: `crates/rsi-probe/src/lib.rs`
- Create: `crates/rsi-probe/src/manifest.rs`
- Create: `crates/rsi-probe/src/runner.rs`
- Create: `crates/rsi-probe/tests/runner.rs`

- [ ] **Step 1: Write runner tests**

```rust
#[test]
fn rejects_unlisted_executable() {
    let result = Runner::default().run(&Probe::test_only(
        ProbeId::GitVersion,
        PathBuf::from("unknown-program"),
        vec!["--version".into()],
    ));
    assert!(matches!(result, Err(ProbeError::ExecutableDenied)));
}

#[test]
fn times_out_and_returns_bounded_status() {
    let result = Runner::with_allowlist(test_allowlist()).run(&slow_fixture());
    assert!(matches!(result, Err(ProbeError::Timeout { .. })));
}
```

- [ ] **Step 2: Confirm failure**

Run: `cargo test -p rsi-probe --test runner`

Expected: compile failure because the runner is absent.

- [ ] **Step 3: Implement manifest types**

`Probe` contains only `ProbeId`, `ExecutableId`, `&'static [&'static str]`,
timeout, output caps, parser ID, capability, sensitivity, and platform. No
public constructor accepts an arbitrary executable or argument.

- [ ] **Step 4: Implement the only process boundary**

Use `std::process::Command` only in `runner.rs`, set stdin to null, pipe bounded
stdout/stderr, poll `try_wait()` until deadline, kill and wait on timeout, and
sanitize output before returning it. Do not invoke a shell.

- [ ] **Step 5: Add integrity and output-cap tests**

Test an allowed version fixture, a timeout fixture, oversized output, missing
executable, and denied capability.

- [ ] **Step 6: Run tests**

Run: `cargo test -p rsi-probe`

Expected: all probe tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/rsi-probe
git commit -m "Add typed bounded probe runner"
```

### Task 5: Portable hardware and process collector

**Files:**
- Modify: `crates/rsi-collect/src/lib.rs`
- Create: `crates/rsi-collect/src/portable.rs`
- Create: `crates/rsi-collect/tests/portable.rs`

- [ ] **Step 1: Write collector tests**

Test that total memory and CPU count are positive and that every persisted
process record has a basename/category but no path, arguments, environment, or
PID.

- [ ] **Step 2: Confirm failure**

Run: `cargo test -p rsi-collect --test portable`

Expected: compile failure because `collect_portable` is absent.

- [ ] **Step 3: Implement two-sample sysinfo collection**

Keep one `System`, refresh processes/CPU, sleep
`sysinfo::MINIMUM_CPU_UPDATE_INTERVAL`, refresh again, then normalize process
CPU usage by logical CPU count. Store at most the top 20 records.

- [ ] **Step 4: Run tests**

Run: `cargo test -p rsi-collect --test portable`

Expected: tests pass on Windows.

- [ ] **Step 5: Commit**

```bash
git add crates/rsi-collect
git commit -m "Collect portable hardware and processes"
```

### Task 6: Platform, CLI, MCP, application, WSL, and GPU adapters

**Files:**
- Create: `crates/rsi-collect/src/platform/mod.rs`
- Create: `crates/rsi-collect/src/platform/windows.rs`
- Create: `crates/rsi-collect/src/platform/macos.rs`
- Create: `crates/rsi-collect/src/platform/linux.rs`
- Create: `crates/rsi-collect/src/catalog.rs`
- Create: `crates/rsi-collect/src/parsers/mod.rs`
- Create: `crates/rsi-collect/tests/fixtures/*.txt`
- Create: `crates/rsi-collect/tests/parsers.rs`

- [ ] **Step 1: Add parser fixtures**

Fixtures cover sanitized `nvidia-smi` CSV, Windows uninstall entries, macOS
`system_profiler -json`, Linux `os-release`, CLI version lines, Codex TOML
section names, Claude/Gemini JSON MCP names, and WSL kernel output.

- [ ] **Step 2: Write failing parser tests**

Each parser test asserts typed values and ensures raw config values are absent.

- [ ] **Step 3: Implement static probe catalog**

Allowlist only fixed version commands for `codex`, `claude`, `gemini`, `gh`,
`git`, `rustc`, `cargo`, `node`, `python`, `uv`, `bun`, `docker`, `ollama`, and
vendor GPU tools. Fast mode omits application/package probes.

- [ ] **Step 4: Implement platform adapters**

Use direct files/native facts first. Use the fixed PowerShell adapter only for
closed Windows probe enums. Parse MCP files in-process and emit names/enabled
state only.

- [ ] **Step 5: Run parser and collector tests**

Run: `cargo test -p rsi-collect`

Expected: all fixtures pass; unsupported tools produce `Unsupported`.

- [ ] **Step 6: Commit**

```bash
git add crates/rsi-collect
git commit -m "Add platform and tool collectors"
```

### Task 7: Deterministic findings

**Files:**
- Modify: `crates/rsi-optimize/src/lib.rs`
- Create: `crates/rsi-optimize/src/rules.rs`
- Create: `crates/rsi-optimize/tests/rules.rs`

- [ ] **Step 1: Write rule fixtures**

Cover version drift, duplicate CUDA/toolkit versions, GPU contention, storage
pressure, stale evidence, missing required fields, MCP executable absence, and
no-findings input.

- [ ] **Step 2: Confirm failure**

Run: `cargo test -p rsi-optimize`

Expected: compile failure because `analyze` does not exist.

- [ ] **Step 3: Implement pure rules**

`analyze(&Snapshot, &Constraints) -> Vec<Finding>` contains no I/O. Sort by
severity then stable rule ID. Suppress findings forbidden by constraints.

- [ ] **Step 4: Assert empty means empty**

An optimal fixture returns zero findings. No AI or narrative fallback runs.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p rsi-optimize
git add crates/rsi-optimize
git commit -m "Add deterministic optimization rules"
```

### Task 8: CLI scan, analyze, and semantic diff

**Files:**
- Modify: `crates/rsi-cli/src/main.rs`
- Create: `crates/rsi-cli/src/commands.rs`
- Create: `crates/rsi-cli/src/render.rs`
- Create: `crates/rsi-cli/tests/cli.rs`

- [ ] **Step 1: Write CLI tests**

Use `assert_cmd` to test `scan --format json`, `scan --fast`, `analyze
<fixture>`, and `diff <left> <right>`. Assert JSON parses and help contains no
apply/elevate/install/remove/service command.

- [ ] **Step 2: Implement clap commands**

```rust
#[derive(Subcommand)]
enum Commands {
    Scan(ScanArgs),
    Analyze { snapshot: PathBuf, #[arg(long, value_enum, default_value_t = Output::Json)] format: Output },
    Diff { left: PathBuf, right: PathBuf },
}
```

- [ ] **Step 3: Implement JSON and Markdown renderers**

JSON is canonical. Markdown renders sanitized facts/findings without raw probe
output. Stdout is default; file output is absent in V1.

- [ ] **Step 4: Implement semantic diff**

Recursively compare stable typed fields and omit only values marked
`Ephemeral`.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p rsi-cli
git add crates/rsi-cli
git commit -m "Add analyzer CLI commands"
```

### Task 9: Source-boundary lint and repository checks

**Files:**
- Create: `scripts/check-read-only-boundary.ps1`
- Create: `scripts/check-read-only-boundary.sh`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Add failing source-boundary tests**

The scripts fail if process construction exists outside `rsi-probe`, if shell
execution flags occur in probe manifests, or if V1 mutation command variants
exist.

- [ ] **Step 2: Run against an injected fixture**

Create a temporary test fixture containing `std::process::Command` outside the
probe crate, confirm the checker fails, then remove the fixture.

- [ ] **Step 3: Run against the real source**

Run:

```powershell
pwsh -NoProfile -File scripts/check-read-only-boundary.ps1
```

Expected: `READ_ONLY_BOUNDARY_OK`.

- [ ] **Step 4: Add CI**

CI runs format, clippy with warnings denied, all tests, and the boundary script
on Windows, macOS, and Ubuntu.

- [ ] **Step 5: Commit**

```bash
git add scripts .github
git commit -m "Enforce read-only process boundary"
```

### Task 10: Core completion verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the full suite**

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

- [ ] **Step 2: Run local scan twice**

Capture output outside the repository, validate both JSON documents, and run
semantic diff. Expected stable difference count: zero.

- [ ] **Step 3: Run redaction scan**

Scan emitted JSON for IP, hostname, user path, command arguments, environment
assignment, key/token/cookie patterns. Expected matches: zero.

- [ ] **Step 4: Measure fast/default runs**

Run one warm-up and 20 measured runs for each mode. Record p95 and test
conditions in a sanitized local report; do not commit machine identifiers.

- [ ] **Step 5: Update README**

Document commands, output guarantees, unsupported states, and V1 non-goals.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "Document core analyzer usage"
```
