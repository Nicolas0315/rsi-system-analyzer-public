# Layered Public Architecture

Date: 2026-07-27
Status: approved for implementation

## Decision

The analyzer uses four explicit trust boundaries:

1. `rsi-collect` gathers sanitized observations without evaluating them.
2. `rsi-verify` validates schema, freshness, completeness, and privacy
   invariants and issues an opaque `VerifiedSnapshot`.
3. `rsi-optimize` accepts only `VerifiedSnapshot` and emits deterministic,
   non-executable findings.
4. `rsi-knowledge` retrieves only an embedded allowlist of official HTTPS
   documents during an explicit sync. `rsi-journal` classifies sanitized audit
   events without recording raw configuration bodies.

Normal `scan`, `verify`, and `analyze` operations are offline. Network access
exists only in the explicit `knowledge-sync` command. Cached documents are
content-addressed and never overwritten.

## Dependency Direction

```text
rsi-schema
  ├── rsi-collect
  ├── rsi-verify
  │     ├── rsi-optimize
  │     ├── rsi-ai
  │     ├── rsi-fleet
  │     └── rsi-journal
  └── rsi-knowledge

rsi-cli composes the layers but no lower layer depends on rsi-cli.
```

`rsi-optimize::analyze` cannot accept a raw `Snapshot`. A successful
`rsi-verify::verify` call is therefore a compile-time prerequisite for
optimization and AI packet creation.

## Verification Contract

Verification rejects:

- unknown snapshot schema versions;
- blank analyzer or probe-manifest versions;
- snapshots captured beyond the permitted clock skew;
- scans exceeding the configured elapsed-time budget;
- missing required collectors;
- path-like process basenames;
- duplicate CLI identities; and
- inventory fields that exceed public artifact size limits.

Failures are machine-readable reason codes. A failure is reported, not repaired.

## Knowledge Contract

The source registry is compiled into the binary and contains only official
HTTPS origins. Callers select registry IDs, never arbitrary URLs. Fetches use:

- certificate validation;
- disabled redirects;
- connect and total timeouts;
- bounded response bodies; and
- SHA-256 content addressing.

The catalog records source ID, official URL, retrieval time, byte count, hash,
freshness deadline, and per-source failure reason codes. One unavailable source
does not discard successful retrievals. Document bodies remain in an
operator-selected cache and are excluded from Git by default.

## Journal Contract

The journal layer records classifications and reason codes only. It never
records command lines, environment values, configuration bodies, hostnames,
addresses, usernames, tokens, cookies, keys, or raw logs. CLI output is stdout
only unless the operator explicitly redirects it.

## Public Release Gate

Visibility may change to public only after:

1. format, clippy, unit, integration, and read-only boundary checks pass;
2. repository files and full Git history pass secret and machine-identity scans;
3. public governance files and sanitized examples exist;
4. a different-engine Claude review approves the same commit; and
5. the remote PR head matches the reviewed commit.

Any finding in Git history stops publication. History rewriting requires a
separate backup, retention, restore plan, and operator-approved destructive
change.
