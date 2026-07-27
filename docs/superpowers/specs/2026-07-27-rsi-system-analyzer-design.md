# RSI System Analyzer Design

Date: 2026-07-27
Status: approved architecture, implementation pending
Repository visibility: public

## 1. Goal

Build a fast, cross-platform analyzer that gives an AI system a safe,
structured view of a machine and its development environment. It must support
Windows, macOS, Linux, WSL, Apple Silicon, ARM64, x86_64, NVIDIA, AMD, and Intel
systems.

The analyzer inventories:

- hardware and architecture;
- operating system and kernel;
- GPU vendor, driver, memory, and current utilization when available;
- selected applications and package-manager summaries;
- development CLI presence and versions;
- MCP server names and enabled state without configuration values;
- bounded process summaries without raw command lines;
- configuration posture and version drift;
- node-specific constraints and evidence freshness.

The output feeds deterministic optimization rules. An optional AI component
may rank or explain existing findings, but it cannot invent a change when no
deterministic finding exists and cannot apply a change.

## 2. Evidence Behind the Design

A read-only development fleet scan produced live results across Windows,
macOS, and WSL nodes. Offline nodes were represented by explicitly stale
evidence.

Observed differences included:

- Windows 11 and macOS 26 hosts, plus Ubuntu 26.04 under WSL2;
- Apple Silicon and multiple Intel CPU generations;
- multiple NVIDIA GPU generations;
- material Codex, Gemini, Ollama, Docker, Node, Python, CUDA, and application
  version drift;
- nine or ten Codex MCP definitions per reachable node and differing
  Claude/Gemini MCP sets;
- active GPU workloads;
- a hardware safety constraint prohibiting sustained load on a constrained node;
- a mobility constraint prohibiting long work on a mobile node.

The scan also demonstrated why the implementation cannot depend on ad hoc
shell quoting: Windows SSH, PowerShell, Git Bash, and WSL changed argument
interpretation in different ways. The product therefore requires typed probes,
no shell expansion, bounded output, and a versioned schema.

## 3. Alternatives

### A. Rust single binary with native and command adapters — selected

Rust provides a single distributable binary, predictable memory use, strong
schema types, and a direct path to future signed probe manifests. Collection
latency will still be dominated by operating-system commands, so Rust is chosen
for packaging and safety rather than benchmark claims.

### B. Go single binary

Go could deliver a similar product with simpler compilation and networking.
It remains a viable fallback. The adapter and schema boundaries must avoid
Rust-specific assumptions so a future collector could be reimplemented.

### C. Python plugin-first collector

Python would accelerate experimentation but makes the collector dependent on
the exact Python runtime, package environment, and architecture of each node.
The fleet already has materially different Python versions and environments,
so Python is unsuitable for the trusted collection layer. Python may consume
sanitized snapshots for offline research.

## 4. Architecture

The workspace contains six crates:

1. `rsi-schema`
   - versioned snapshot, finding, probe, constraint, and status types;
   - JSON serialization and schema validation;
   - explicit absence states.
2. `rsi-probe`
   - the only external-process execution boundary;
   - typed executable path, fixed arguments, timeout, output cap, parser, and
     required capability;
   - direct process spawning without a shell.
3. `rsi-collect`
   - platform-neutral collector orchestration;
   - bounded parallel directed acyclic graph;
   - collector-boundary redaction.
4. `rsi-optimize`
   - deterministic findings, severity, evidence, constraints, and remediation
     proposals;
   - no model calls.
5. `rsi-fleet`
   - local and SSH fan-out;
   - marker-delimited single-line JSON transport;
   - unreachable and stale-node handling.
6. `rsi-cli`
   - `scan`, `analyze`, `diff`, and `fleet scan`;
   - JSON and Markdown output only.

The first implementation may use a Cargo workspace while keeping these
boundaries as modules if that shortens delivery. Public types and dependency
direction must match the crate boundaries:

`rsi-cli -> rsi-fleet/rsi-optimize/rsi-collect -> rsi-probe/rsi-schema`.

No lower layer depends on the CLI, fleet transport, or an AI provider.

## 5. Canonical Data Model

Every collected field uses a typed observation:

```text
Observation<T> =
  Value { value, captured_at, source, confidence }
  Unsupported { reason }
  Timeout { probe_id, limit_ms }
  Denied { capability }
  Unreachable { transport }
  Stale { last_value, as_of }
  Error { code }
```

Snapshots include:

- `schema_version`;
- `snapshot_id`, generated locally and not derived from a hardware identifier;
- `captured_at`;
- operating-system and architecture family;
- `completeness` by collector;
- sanitized observations;
- applied node constraints;
- analyzer version and probe-manifest version.

Schema fields declare stability as `Stable` or `Ephemeral`. The initial
ephemeral set is:

- snapshot ID and capture timestamps;
- process CPU, memory, and ephemeral process identity;
- GPU utilization, used memory, temperature, power, and performance state;
- free memory and free storage;
- probe elapsed time.

Semantic diff excludes only fields typed `Ephemeral`; it does not maintain a
separate name-based ignore list.

Zero, empty, unsupported, timeout, denied, unreachable, and stale are never
interchangeable.

## 6. Collection Model

### Common

- Rust `sysinfo` supplies portable process and memory primitives where its
  values are reliable.
- Process records contain executable basename, current CPU percentage, private
  or resident memory, process category, and sample time.
- Process IDs are ephemeral and excluded from persisted fleet bundles.
- Raw arguments, executable paths containing user directories, environment
  values, open-file names, network peers, and command history are excluded.

### Windows

- native Windows APIs are preferred for stable system information;
- where CIM/WMI requires PowerShell, the binary may launch only a bundled,
  hash-verified `.ps1` file with `powershell.exe -NoLogo -NoProfile
  -NonInteractive -File <fixed-path> -Probe <enum-value>`;
- the fixed path must resolve inside the analyzer's immutable resource
  directory, the opened file handle is hashed and executed without a second
  path lookup, and a mismatch returns `Error { code: ProbeIntegrityFailed }`;
- the PowerShell adapter accepts only a closed probe enum, contains no dynamic
  script text, and cannot accept a command, path, filter, or expression from
  collected data or user input;
- registry uninstall keys for application names and versions;
- Windows build, CPU topology, memory, storage summaries, GPU adapters;
- WSL distro, kernel, and architecture through fixed `wsl.exe` arguments;
- no registry or WMI writes.

### macOS

- `sysctl` and `system_profiler -json` with fixed data types;
- Homebrew formula/cask counts and selected package versions;
- Apple Silicon model, core counts, Metal support, memory, and storage;
- no `defaults write`, launchctl mutation, or package changes.

### Linux

- `/proc`, `/sys`, `os-release`, package database summaries, and fixed
  capability probes;
- NVIDIA `nvidia-smi`, AMD ROCm tools, Intel tools, or sysfs when available;
- absence of a vendor tool becomes `unsupported`, not a failed snapshot.

### CLI and MCP

- CLI inventory uses an allowlisted executable-name catalog and fixed version
  arguments.
- Each version probe has a short timeout and bounded stdout/stderr.
- MCP parsing extracts server names, enabled state, transport category, and
  source file category only.
- MCP commands, arguments, environment maps, URLs, headers, tokens, and raw
  configuration bodies never enter the snapshot.

### Applications

- V1 reports total application/package counts and allowlisted development,
  GPU, container, agent, and observability tools.
- It does not export a complete personal application inventory by default.

## 7. Probe Manifest

All external commands are declared as typed static data:

```text
Probe {
  id,
  platform,
  executable,
  fixed_arguments,
  timeout_ms,
  max_stdout_bytes,
  max_stderr_bytes,
  parser,
  capability,
  sensitivity,
}
```

Requirements:

- no shell executable;
- no command string;
- no runtime argument concatenation from collected data;
- no redirect operator;
- no input from stdin;
- allowlisted absolute executable resolution;
- one runner implementation;
- cancellation on deadline;
- child-process cleanup;
- output redaction before returning a typed observation.

V1 has no elevated capability. A probe requiring elevation returns `Denied`.

## 8. Performance

Targets:

- local default scan: p95 at or below 10 seconds;
- fast scan: p95 at or below 3 seconds;
- default whole-process CPU overhead below one core-second, excluding
  operating-system tools;
- memory below 100 MiB;
- independent probes run concurrently within platform and resource limits;
- slow package/application probes are optional in fast mode;
- any timed-out probe produces a partial snapshot rather than failing the scan.

The scheduler prevents GPU vendor probes and heavyweight application scans from
running more than once per snapshot.

## 9. Deterministic Optimization Engine

Rules consume only sanitized observations and constraints. Initial rule groups:

- CLI and tool version drift;
- duplicate runtime or toolkit installations;
- incompatible architecture/runtime combinations;
- missing compiler or SDK prerequisites;
- MCP duplication, unavailable executables, and excessive startup surface;
- process/resource contention;
- GPU memory contention;
- storage pressure;
- WSL/host version mismatch;
- unsupported or stale evidence;
- analyzer coverage gaps.

Each finding contains:

- stable rule ID and version;
- severity and confidence;
- evidence references;
- affected component;
- proposed action as a non-executable `DisplayOnly<RemediationText>` value;
- risk and required authority;
- verification guidance as a non-executable `DisplayOnly<VerificationText>`
  value;
- rollback requirement;
- whether AI explanation is permitted.

`DisplayOnly<T>` is serializable text with no conversion into a probe,
executable, argument list, process builder, or operating-system command type.

The engine may recommend inspection or an operator-approved action. It cannot
execute the action.

## 10. AI Boundary

The optional AI adapter receives only:

- deterministic findings;
- sanitized architecture and version facts;
- machine constraint IDs;
- a bounded optimization objective.

It does not receive raw snapshots, secrets, command output, process arguments,
configuration bodies, logs, or network identifiers.

The AI may:

- rank findings;
- explain trade-offs;
- group compatible recommendations;
- propose a measurable validation plan.

The AI may not:

- create a finding when the deterministic finding set is empty;
- weaken a constraint;
- generate an apply command outside a finding's approved remediation template;
- certify its own proposed rule.

## 11. Fleet Transport

V1 supports:

- local scan;
- SSH execution of an already-installed analyzer;
- optional one-shot binary copy in a later, separately approved feature.

Remote stdout uses:

1. a fixed marker;
2. one compact JSON line;
3. a closing marker.

The controller discards all text outside the markers. One failed or offline
node never fails the fleet bundle.

Fleet output uses aliases supplied by a local constraints file. It does not
persist hostnames, IP addresses, SSH configuration, or account names.

## 12. Constraints

The controller loads a local, uncommitted `fleet-constraints` file containing:

- node alias;
- maximum probe duration;
- forbidden collector categories;
- forbidden optimization categories;
- maximum resource class;
- evidence freshness limit;
- optional operating window.

Constraints are applied twice:

1. before collection scheduling;
2. before findings reach the AI adapter.

Example fleet constraints include:

- constrained nodes: no sustained CPU/GPU load or stress recommendations;
- mobile nodes: short diagnostics only while mobile;
- busy GPU nodes: do not recommend additional GPU workloads while training
  occupies the GPU.

Real fleet constraint files and snapshots are excluded from Git.

## 13. Recursive Self-Improvement

RSI operates on rules, parsers, and coverage:

1. collect two comparable sanitized snapshots;
2. generate a candidate incremental rule or parser delta;
3. run schema, fixture, regression, redaction, and stability checks;
4. send the diff to a different engine for read-only refutation;
5. require operator approval before promotion;
6. record rule version and measured impact.

The same evaluator cannot generate and certify a rule. A failed or dissenting
review stops promotion. V1 is report-only and contains no self-modifying binary
or automatic deployment path.

## 14. Security and Privacy

The test suite must demonstrate that output contains no:

- IP addresses;
- real hostnames or hardware serial numbers;
- MAC addresses;
- raw process arguments or environment values;
- user-specific executable paths;
- configuration bodies;
- command history;
- logs;
- auth database content;
- common token, private-key, cookie, or credential formats.

Collector output is redacted before it reaches shared schema types. Sensitive
types are not serializable. Snapshot persistence is opt-in; stdout is default.

## 15. Error Handling

- Probe failure is local to the observation.
- Parser failure records a stable error code without raw output.
- Deadlines cancel child processes.
- Unsupported tools produce `Unsupported`.
- Permission failures produce `Denied`.
- Offline nodes produce `Unreachable`.
- Cached evidence beyond its freshness limit produces `Stale`.
- The CLI exits nonzero only when its own schema or invariant fails; partial
  environmental coverage remains a valid snapshot.

## 16. Testing

Required layers:

- schema serialization and compatibility tests;
- probe-runner allowlist and timeout tests;
- parser fixtures for each OS and vendor;
- redaction property tests;
- malicious-output fixtures;
- deterministic-rule unit tests;
- node-constraint fixtures;
- snapshot stability and semantic-diff tests;
- cross-platform compile checks;
- local smoke tests;
- SSH marker/noise tests;
- live read-only fleet validation with sanitized summaries only.

No test may depend on a real credential, token, host address, or auth state.

CI also runs a source-boundary lint that fails when:

- process construction (`std::process::Command`, Windows process creation, or
  an approved wrapper alias) appears outside `rsi-probe`;
- shell executables, `-Command`, `-EncodedCommand`, `cmd /c`, `sh -c`, or
  `bash -c` appear in probe definitions;
- apply/elevate/install/uninstall/remove/delete/prune/service-start,
  permission-write, package-mutation, or registry-write command variants
  appear in the V1 CLI or probe manifest;
- `DisplayOnly<T>` values flow into `rsi-probe`.

## 17. V1 Acceptance Criteria

1. Each of the four currently reachable nodes completes 20 consecutive warm
   default scans after one unmeasured priming scan. Per-node p95 wall time from
   analyzer entry to final JSON flush is at most ten seconds and every result
   passes schema validation. SSH connection time is measured separately and is
   not included in local analyzer p95.
2. A fleet scan containing an offline node completes successfully and marks it
   `Unreachable` with completeness metadata.
3. Redaction tests find zero IPs, raw arguments, environment values,
   configuration bodies, auth material, and known secret formats.
4. Every external process launch goes through the single typed probe runner,
   proven by the source-boundary lint and probe-runner tests.
5. Two consecutive snapshots produce zero semantic difference after excluding
   only schema fields typed `Ephemeral`.
6. Windows x86_64, macOS ARM64, and Linux/WSL x86_64 return `Value` or `Stale`
   for platform-required hardware, OS, CLI, and MCP fields; those required
   fields may not be `Unsupported` or `Error`.
7. The source-boundary lint confirms that the binary contains no apply,
   elevation, cleanup, install, service, permission, package, registry-write,
   or other mutation command path, and remediation text cannot construct a
   probe or process.
8. Constraint fixtures suppress unsafe recommendations for constrained nodes,
   mobile nodes, and GPUs occupied by training.
9. Elevation-required probes return `Denied`.
10. Time-budget exhaustion returns a valid partial bundle with timed-out probes
    identified.

Fast mode is measured separately: after one unmeasured priming scan, 20 warm
local runs must have p95 at or below three seconds with application and package
inventory probes disabled by the documented fast-mode manifest.

Platform-required fields for criterion 6 are OS family/version, kernel or build,
architecture, CPU model/core count, total memory, primary GPU vendor/model when
present, analyzer version, allowlisted CLI presence/version, and MCP server
name/enabled-state inventory. Vendor-only details such as CUDA, ROCm, Metal,
GPU power, and GPU temperature remain capability-dependent observations.

## 18. Delivery Sequence

1. schema and fixtures;
2. typed probe runner and redaction;
3. portable collectors;
4. Windows, macOS, Linux, WSL, and GPU adapters;
5. deterministic rules;
6. CLI output and semantic diff;
7. SSH fleet fan-out;
8. live read-only validation;
9. optional AI explanation interface;
10. governed RSI rule-promotion workflow.

The repository starts with this specification. Implementation begins only
after the written specification is reviewed.
