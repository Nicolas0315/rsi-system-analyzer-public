use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use rsi_collect::{CollectOptions, collect_snapshot};
use rsi_optimize::analyze;
use rsi_schema::{Constraints, Finding, Snapshot};
use rsi_verify::{VerificationPolicy, VerifiedSnapshot};
use serde::Serialize;
use serde_json::Value;

use crate::render::{render_findings_markdown, render_snapshot_markdown};

const MAX_SNAPSHOT_BYTES: u64 = 4 * 1_048_576;
const MAX_CONSTRAINTS_BYTES: u64 = 1_048_576;

#[derive(Debug, Parser)]
#[command(
    name = "rsi-scan",
    version,
    about = "Fast, read-only cross-platform system analyzer"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Collect a sanitized snapshot from this machine.
    Scan {
        #[arg(long)]
        fast: bool,
        #[arg(long, hide = true)]
        transport_markers: bool,
        #[arg(long, value_enum, default_value_t = Output::Json)]
        format: Output,
    },
    /// Run deterministic optimization rules over a snapshot.
    Analyze {
        snapshot: PathBuf,
        #[arg(long, value_enum, default_value_t = Output::Json)]
        format: Output,
    },
    /// Validate a snapshot without optimizing it.
    Verify { snapshot: PathBuf },
    /// Compare stable snapshot content.
    Diff { left: PathBuf, right: PathBuf },
    /// Export a sanitized packet for optional external AI explanation.
    AiPacket { snapshot: PathBuf },
    /// Scan configured SSH aliases and preserve unreachable node states.
    FleetScan { constraints: PathBuf },
    /// List the embedded allowlist of official documentation sources.
    KnowledgeSources,
    /// Explicitly retrieve allowlisted official documents into a content-addressed cache.
    KnowledgeSync {
        #[arg(long)]
        cache: PathBuf,
        #[arg(long = "source")]
        sources: Vec<String>,
    },
    /// Classify a verified snapshot into a sanitized audit journal.
    Journal { snapshot: PathBuf },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Output {
    Json,
    Markdown,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Analysis<'a> {
    schema_version: &'static str,
    findings: &'a [Finding],
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticDiff {
    schema_version: &'static str,
    equal: bool,
    changed_paths: Vec<String>,
}

pub fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Commands::Scan {
            fast,
            transport_markers,
            format,
        } => {
            let snapshot = rsi_verify::verify(
                collect_snapshot(CollectOptions { fast }),
                &VerificationPolicy::default(),
            )
            .map_err(verification_error)?
            .into_snapshot();
            if transport_markers {
                if !matches!(format, Output::Json) {
                    return Err("transport markers require JSON format".into());
                }
                let payload = serde_json::to_string(&snapshot).map_err(json_error)?;
                return Ok(format!(
                    "{}\n{}\n{}",
                    rsi_fleet::START_MARKER,
                    payload,
                    rsi_fleet::END_MARKER
                ));
            }
            match format {
                Output::Json => serde_json::to_string_pretty(&snapshot).map_err(json_error),
                Output::Markdown => Ok(render_snapshot_markdown(&snapshot)),
            }
        }
        Commands::Analyze { snapshot, format } => {
            let verified = read_verified_snapshot(&snapshot)?;
            let findings = analyze(&verified, &Constraints::default());
            match format {
                Output::Json => serde_json::to_string_pretty(&Analysis {
                    schema_version: "rsi.analysis.v1",
                    findings: &findings,
                })
                .map_err(json_error),
                Output::Markdown => Ok(render_findings_markdown(&findings)),
            }
        }
        Commands::Verify { snapshot } => {
            let snapshot = read_snapshot(&snapshot)?;
            match rsi_verify::verify(snapshot, &VerificationPolicy::default()) {
                Ok(verified) => serde_json::to_string_pretty(verified.report()).map_err(json_error),
                Err(report) => Err(serde_json::to_string(&report)
                    .unwrap_or_else(|_| "snapshot verification failed".into())),
            }
        }
        Commands::Diff { left, right } => {
            let mut left = serde_json::to_value(read_verified_snapshot(&left)?.into_snapshot())
                .map_err(json_error)?;
            let mut right = serde_json::to_value(read_verified_snapshot(&right)?.into_snapshot())
                .map_err(json_error)?;
            remove_ephemeral(&mut left);
            remove_ephemeral(&mut right);
            let mut changed_paths = Vec::new();
            compare("", &left, &right, &mut changed_paths);
            serde_json::to_string_pretty(&SemanticDiff {
                schema_version: "rsi.diff.v1",
                equal: changed_paths.is_empty(),
                changed_paths,
            })
            .map_err(json_error)
        }
        Commands::AiPacket { snapshot } => {
            let verified = read_verified_snapshot(&snapshot)?;
            let findings = analyze(&verified, &Constraints::default());
            let packet = rsi_ai::build_request(&verified, findings, BTreeSet::new())
                .map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&packet).map_err(json_error)
        }
        Commands::FleetScan { constraints } => {
            let content =
                read_utf8_bounded(&constraints, MAX_CONSTRAINTS_BYTES, "fleet constraints")?;
            let constraints: rsi_fleet::FleetConstraints = serde_json::from_str(&content)
                .map_err(|_| "fleet constraints schema invalid".to_string())?;
            constraints.validate().map_err(str::to_string)?;
            serde_json::to_string_pretty(&rsi_fleet::scan(&constraints)).map_err(json_error)
        }
        Commands::KnowledgeSources => {
            serde_json::to_string_pretty(rsi_knowledge::official_sources()).map_err(json_error)
        }
        Commands::KnowledgeSync { cache, sources } => {
            let selected = sources.into_iter().collect::<BTreeSet<_>>();
            let catalog =
                rsi_knowledge::sync(&cache, &selected).map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&catalog).map_err(json_error)
        }
        Commands::Journal { snapshot } => {
            let verified = read_verified_snapshot(&snapshot)?;
            let findings = analyze(&verified, &Constraints::default());
            serde_json::to_string_pretty(&rsi_journal::classify(&verified, &findings))
                .map_err(json_error)
        }
    }
}

fn read_verified_snapshot(path: &Path) -> Result<VerifiedSnapshot, String> {
    let snapshot = read_snapshot(path)?;
    rsi_verify::verify(snapshot, &VerificationPolicy::default()).map_err(verification_error)
}

fn read_snapshot(path: &Path) -> Result<Snapshot, String> {
    let content = read_utf8_bounded(path, MAX_SNAPSHOT_BYTES, "snapshot")?;
    serde_json::from_str(&content).map_err(|_| "snapshot schema invalid".to_string())
}

fn read_utf8_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|_| format!("{label} read failed"))?;
    let mut content = String::new();
    file.take(max_bytes + 1)
        .read_to_string(&mut content)
        .map_err(|_| format!("{label} read failed"))?;
    if content.len() as u64 > max_bytes {
        return Err(format!("{label} exceeded byte limit"));
    }
    Ok(content)
}

fn verification_error(report: rsi_verify::VerificationReport) -> String {
    let reason_codes = report
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!("snapshot verification failed: {reason_codes}")
}

fn remove_ephemeral(value: &mut Value) {
    if value.get("stability") == Some(&Value::String("ephemeral".into())) {
        *value = Value::Null;
        return;
    }
    match value {
        Value::Object(map) => {
            for key in ["snapshot_id", "captured_at", "elapsed_ms"] {
                map.remove(key);
            }
            for child in map.values_mut() {
                if child.get("stability") == Some(&Value::String("ephemeral".into())) {
                    *child = Value::Null;
                } else {
                    remove_ephemeral(child);
                }
            }
            if let Some(Value::Array(processes)) = map.get_mut("processes") {
                processes.sort_by_key(|process| {
                    (
                        process
                            .get("executable_basename")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        process
                            .get("category")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    )
                });
            }
        }
        Value::Array(values) => values.iter_mut().for_each(remove_ephemeral),
        _ => {}
    }
}

fn compare(path: &str, left: &Value, right: &Value, changed: &mut Vec<String>) {
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let keys = left
                .keys()
                .chain(right.keys())
                .collect::<std::collections::BTreeSet<_>>();
            for key in keys {
                let next = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                compare(
                    &next,
                    left.get(key).unwrap_or(&Value::Null),
                    right.get(key).unwrap_or(&Value::Null),
                    changed,
                );
            }
        }
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
            for (index, (left, right)) in left.iter().zip(right).enumerate() {
                compare(&format!("{path}[{index}]"), left, right, changed);
            }
        }
        _ if left != right => changed.push(path.into()),
        _ => {}
    }
}

fn json_error(_: serde_json::Error) -> String {
    "JSON serialization failed".into()
}
