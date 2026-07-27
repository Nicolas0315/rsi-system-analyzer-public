# Fleet Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded SSH fan-out that aggregates sanitized analyzer snapshots while preserving unreachable, stale, and node-constrained states.

**Architecture:** A dedicated `rsi-fleet` crate owns transport and marker parsing. It invokes only the local `ssh` executable through the typed probe runner, accepts aliases from an uncommitted constraints file, and never persists addresses or credentials.

**Tech Stack:** Rust workspace, serde/serde_json, clap, rsi-schema, rsi-probe, tempfile, assert_cmd.

---

### Task 1: Fleet schema and constraints

**Files:**
- Create: `crates/rsi-fleet/Cargo.toml`
- Create: `crates/rsi-fleet/src/lib.rs`
- Create: `crates/rsi-fleet/src/constraints.rs`
- Create: `crates/rsi-fleet/tests/constraints.rs`
- Modify: `Cargo.toml`

- [ ] Define `FleetConstraints`, `NodeConstraint`, duration/resource limits,
forbidden collector/rule IDs, freshness limits, and operating windows:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConstraint {
    pub alias: String,
    pub max_probe_duration_ms: u64,
    pub forbidden_collectors: BTreeSet<String>,
    pub forbidden_rules: BTreeSet<String>,
    pub max_resource_class: ResourceClass,
    pub freshness_limit_secs: u64,
}
```

- [ ] Test that sustained-load constraints and mobile-node
constraints reject unsafe collectors/findings before AI packaging.
- [ ] Add the crate to the workspace and run `cargo test -p rsi-fleet`.
- [ ] Commit with `git commit -m "Add fleet constraint model"`.

### Task 2: Marker-delimited transport parser

**Files:**
- Create: `crates/rsi-fleet/src/markers.rs`
- Create: `crates/rsi-fleet/tests/markers.rs`

- [ ] Write fixtures with shell warnings before/after valid marker lines,
missing close markers, oversized JSON, and invalid schema.
- [ ] Implement extraction of exactly one compact JSON line between fixed
markers; discard all other text:

```rust
pub const START_MARKER: &str = "RSI_SNAPSHOT_BEGIN_V1";
pub const END_MARKER: &str = "RSI_SNAPSHOT_END_V1";

pub fn extract_snapshot(stdout: &str, max_bytes: usize) -> Result<Snapshot, TransportError>;
```

- [ ] Return stable transport errors without raw remote output.
- [ ] Run tests and commit with `git commit -m "Parse bounded fleet transport"`.

### Task 3: SSH fan-out

**Files:**
- Create: `crates/rsi-fleet/src/controller.rs`
- Create: `crates/rsi-fleet/tests/controller.rs`
- Modify: `crates/rsi-probe/src/manifest.rs`

- [ ] Add a closed SSH probe that accepts only a configured alias enum, fixed
BatchMode/connect-timeout flags, and the fixed remote analyzer command.
- [ ] Test success, timeout, unreachable node, noisy stdout, and one-node
failure without bundle failure.
- [ ] Implement bounded concurrency and deterministic alias ordering.
- [ ] Run tests and commit with `git commit -m "Add bounded SSH fleet scan"`.

### Task 4: Fleet CLI

**Files:**
- Modify: `crates/rsi-cli/src/commands.rs`
- Modify: `crates/rsi-cli/src/main.rs`
- Create: `crates/rsi-cli/tests/fleet.rs`

- [ ] Add `fleet scan --constraints <path> --format json|markdown`.
- [ ] Reject constraints files containing addresses, usernames, secrets, or
unknown fields.
- [ ] Emit aliases and completeness only; never emit SSH targets.
- [ ] Run tests and commit with `git commit -m "Expose fleet scan command"`.

### Task 5: Live read-only validation

**Files:**
- Modify: `README.md`

- [ ] Build release binaries for Windows x86_64 and macOS ARM64.
- [ ] Run local scans on four reachable nodes with no remote installation.
- [ ] Represent an offline node as `Unreachable` and merge only explicitly
stale prior facts.
- [ ] Verify schema, redaction, constraints, 10-second local budget, and
partial-bundle behavior.
- [ ] Record only sanitized aggregate results in README and commit with
`git commit -m "Document fleet validation"`.
