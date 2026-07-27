use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use rsi_schema::redaction::sanitize_untrusted_text;
use rsi_schema::{SCHEMA_VERSION, Snapshot};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERIFICATION_SCHEMA_VERSION: &str = "rsi.verification.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPolicy {
    pub max_clock_skew_secs: u64,
    pub max_elapsed_ms: u64,
    pub max_inventory_items: usize,
    pub required_collectors: BTreeSet<String>,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            max_clock_skew_secs: 300,
            max_elapsed_ms: 120_000,
            max_inventory_items: 10_000,
            required_collectors: ["portable", "cli"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationIssue {
    pub code: String,
    pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    pub schema_version: String,
    pub snapshot_id: String,
    pub valid: bool,
    pub issues: Vec<VerificationIssue>,
}

#[derive(Debug, Clone)]
pub struct VerifiedSnapshot {
    snapshot: Snapshot,
    report: VerificationReport,
}

impl VerifiedSnapshot {
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn report(&self) -> &VerificationReport {
        &self.report
    }

    pub fn into_snapshot(self) -> Snapshot {
        self.snapshot
    }
}

pub fn verify(
    snapshot: Snapshot,
    policy: &VerificationPolicy,
) -> Result<VerifiedSnapshot, VerificationReport> {
    verify_at(snapshot, policy, Utc::now())
}

pub fn verify_at(
    snapshot: Snapshot,
    policy: &VerificationPolicy,
    now: DateTime<Utc>,
) -> Result<VerifiedSnapshot, VerificationReport> {
    let mut issues = Vec::new();
    check(
        snapshot.schema_version == SCHEMA_VERSION,
        "schema.unsupported",
        "schema_version",
        &mut issues,
    );
    check(
        !snapshot.analyzer_version.trim().is_empty(),
        "version.analyzer_blank",
        "analyzer_version",
        &mut issues,
    );
    check(
        !snapshot.probe_manifest_version.trim().is_empty(),
        "version.probe_manifest_blank",
        "probe_manifest_version",
        &mut issues,
    );
    let skew = Duration::seconds(policy.max_clock_skew_secs.try_into().unwrap_or(i64::MAX));
    check(
        snapshot.captured_at <= now + skew,
        "time.future_capture",
        "captured_at",
        &mut issues,
    );
    check(
        snapshot.elapsed_ms <= policy.max_elapsed_ms,
        "budget.elapsed_exceeded",
        "elapsed_ms",
        &mut issues,
    );

    for collector in &policy.required_collectors {
        check(
            snapshot
                .completeness
                .collectors_completed
                .contains(collector),
            "completeness.required_collector_missing",
            &format!("completeness.collectors_completed.{collector}"),
            &mut issues,
        );
    }

    for (index, process) in snapshot.processes.iter().enumerate() {
        check(
            !process.executable_basename.contains(['/', '\\', ':']),
            "privacy.process_path_like",
            &format!("processes[{index}].executable_basename"),
            &mut issues,
        );
    }

    let mut cli_names = BTreeSet::new();
    for (index, cli) in snapshot.cli.iter().enumerate() {
        check(
            cli_names.insert(cli.name.to_ascii_lowercase()),
            "inventory.duplicate_cli",
            &format!("cli[{index}].name"),
            &mut issues,
        );
    }

    let inventory_items = snapshot
        .processes
        .len()
        .saturating_add(snapshot.cli.len())
        .saturating_add(snapshot.mcp.len())
        .saturating_add(snapshot.applications.len());
    check(
        inventory_items <= policy.max_inventory_items,
        "budget.inventory_exceeded",
        "inventory",
        &mut issues,
    );

    match serde_json::to_value(&snapshot) {
        Ok(value) => collect_unsanitized_fields(&value, "", &mut issues),
        Err(_) => issues.push(VerificationIssue {
            code: "privacy.scan_failed".into(),
            field: "snapshot".into(),
        }),
    }

    issues.sort_by(|left, right| (&left.code, &left.field).cmp(&(&right.code, &right.field)));
    let report = VerificationReport {
        schema_version: VERIFICATION_SCHEMA_VERSION.into(),
        snapshot_id: snapshot.snapshot_id.to_string(),
        valid: issues.is_empty(),
        issues,
    };
    if report.valid {
        Ok(VerifiedSnapshot { snapshot, report })
    } else {
        Err(report)
    }
}

fn check(valid: bool, code: &str, field: &str, issues: &mut Vec<VerificationIssue>) {
    if !valid {
        issues.push(VerificationIssue {
            code: code.into(),
            field: field.into(),
        });
    }
}

fn collect_unsanitized_fields(value: &Value, path: &str, issues: &mut Vec<VerificationIssue>) {
    if issues.len() >= 64 {
        return;
    }
    match value {
        Value::String(text) if sanitize_untrusted_text(text) != *text => {
            issues.push(VerificationIssue {
                code: "privacy.unsanitized_text".into(),
                field: if path.is_empty() {
                    "snapshot".into()
                } else {
                    path.into()
                },
            });
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_unsanitized_fields(value, &format!("{path}/{index}"), issues);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                let key = key.replace('~', "~0").replace('/', "~1");
                collect_unsanitized_fields(value, &format!("{path}/{key}"), issues);
            }
        }
        _ => {}
    }
}
