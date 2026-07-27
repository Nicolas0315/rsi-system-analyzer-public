# AI and RSI Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a sanitized AI explanation packet and a governed, test-driven rule-promotion workflow without allowing AI-generated execution.

**Architecture:** `rsi-ai` packages deterministic findings into a provider-neutral request and validates a structured response. `rsi-optimize` promotion uses fixtures, regression checks, a different-engine review record, and operator approval metadata; it never modifies a running binary.

**Tech Stack:** Rust workspace, serde/serde_json, rsi-schema, rsi-optimize, JSON fixtures, GitHub Actions.

---

### Task 1: Provider-neutral AI packet

**Files:**
- Create: `crates/rsi-ai/Cargo.toml`
- Create: `crates/rsi-ai/src/lib.rs`
- Create: `crates/rsi-ai/tests/packet.rs`
- Modify: `Cargo.toml`

- [ ] Define `AiRequest` with deterministic findings, sanitized architecture
facts, constraint IDs, and a bounded objective:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRequest {
    pub schema_version: String,
    pub findings: Vec<Finding>,
    pub architecture: SanitizedArchitecture,
    pub constraint_ids: BTreeSet<String>,
    pub objective: BoundedObjective,
}
```

- [ ] Assert raw snapshots, process data, probe output, paths, addresses, config
bodies, and empty-finding requests are rejected.
- [ ] Add the crate and run `cargo test -p rsi-ai`.
- [ ] Commit with `git commit -m "Add sanitized AI explanation packet"`.

### Task 2: Structured AI response validation

**Files:**
- Create: `crates/rsi-ai/src/response.rs`
- Create: `crates/rsi-ai/tests/response.rs`

- [ ] Define rank/explanation/group/validation-plan fields referencing existing
finding IDs only:

```rust
pub fn validate_response(
    request: &AiRequest,
    response: AiResponse,
) -> Result<ValidatedAiResponse, AiValidationError>;
```

- [ ] Reject new findings, commands, weakened constraints, unknown IDs, and
unbounded prose.
- [ ] Run tests and commit with `git commit -m "Validate AI explanations"`.

### Task 3: CLI packet export and response rendering

**Files:**
- Modify: `crates/rsi-cli/src/commands.rs`
- Modify: `crates/rsi-cli/src/render.rs`
- Create: `crates/rsi-cli/tests/ai.rs`

- [ ] Add `ai packet <analysis>` and `ai render <analysis> <response>`.
- [ ] Keep provider invocation outside the binary; stdout carries sanitized
JSON only.
- [ ] Test zero findings produce `AiNotNeeded`.
- [ ] Run tests and commit with `git commit -m "Expose safe AI packet workflow"`.

### Task 4: Governed rule proposal format

**Files:**
- Create: `rules/schema.json`
- Create: `rules/builtin/cli-version-drift.json`
- Create: `rules/builtin/gpu-contention.json`
- Create: `rules/builtin/stale-evidence.json`
- Create: `crates/rsi-optimize/src/catalog.rs`
- Create: `crates/rsi-optimize/tests/catalog.rs`

- [ ] Define versioned rule documents with evidence predicates, findings,
constraints, verification, rollback requirement, and non-executable
remediation text.
- [ ] Reject duplicate IDs, unbounded regex, missing fixtures, and mutation
verbs.
- [ ] Run tests and commit with `git commit -m "Add governed rule catalog"`.

### Task 5: Promotion gate

**Files:**
- Create: `scripts/check-rule-promotion.ps1`
- Create: `scripts/check-rule-promotion.sh`
- Create: `reviews/.gitkeep`
- Modify: `.github/workflows/ci.yml`

- [ ] Require candidate rule fixtures, regression results, redaction results,
different-engine reviewer identity, `APPROVE`, operator approval metadata, and
rule version increment.
- [ ] Reject generator and certifier using the same engine label.
- [ ] Test missing/dissenting review and valid promotion fixtures.
- [ ] Add CI and commit with `git commit -m "Gate RSI rule promotion"`.

### Task 6: End-to-end review

**Files:**
- Modify: `README.md`

- [ ] Run a sanitized local and fleet analysis.
- [ ] Generate an AI packet only when deterministic findings exist.
- [ ] Obtain a read-only explanation from a separate engine and validate it.
- [ ] Propose one fixture-only rule improvement, run promotion checks, and keep
it unpromoted unless operator metadata is present.
- [ ] Run format, clippy, all tests, boundary lint, and promotion lint.
- [ ] Document verified and unverified scope and commit with
`git commit -m "Document governed RSI workflow"`.
