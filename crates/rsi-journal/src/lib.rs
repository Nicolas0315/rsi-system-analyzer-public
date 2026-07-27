use rsi_schema::redaction::sanitize_untrusted_text;
use rsi_schema::{Finding, Observation};
use rsi_verify::VerifiedSnapshot;
use serde::{Deserialize, Serialize};

pub const JOURNAL_SCHEMA_VERSION: &str = "rsi.journal.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalCategory {
    Hardware,
    Process,
    Toolchain,
    Mcp,
    Application,
    Verification,
    Optimization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClassifiedRecord {
    pub category: JournalCategory,
    pub subject: String,
    pub version: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JournalBundle {
    pub schema_version: String,
    pub correlation_id: String,
    pub records: Vec<ClassifiedRecord>,
    pub verification_reason_codes: Vec<String>,
    pub optimization_rule_ids: Vec<String>,
}

pub fn classify(verified: &VerifiedSnapshot, findings: &[Finding]) -> JournalBundle {
    let snapshot = verified.snapshot();
    let mut records = Vec::new();
    if let Observation::Value { value, .. } = &snapshot.machine.cpu {
        records.push(ClassifiedRecord {
            category: JournalCategory::Hardware,
            subject: sanitize_untrusted_text(&value.architecture),
            version: None,
            state: "observed".into(),
        });
    }
    records.extend(snapshot.processes.iter().map(|process| ClassifiedRecord {
        category: JournalCategory::Process,
        subject: sanitize_untrusted_text(&process.category),
        version: None,
        state: "summarized".into(),
    }));
    records.extend(snapshot.cli.iter().map(|cli| ClassifiedRecord {
        category: JournalCategory::Toolchain,
        subject: sanitize_untrusted_text(&cli.name),
        version: cli.version.as_deref().map(sanitize_untrusted_text),
        state: if cli.present { "present" } else { "absent" }.into(),
    }));
    records.extend(snapshot.mcp.iter().map(|mcp| ClassifiedRecord {
        category: JournalCategory::Mcp,
        subject: sanitize_untrusted_text(&format!("{}:{}", mcp.client, mcp.server_name)),
        version: None,
        state: if mcp.enabled { "enabled" } else { "disabled" }.into(),
    }));
    records.extend(
        snapshot
            .applications
            .iter()
            .map(|application| ClassifiedRecord {
                category: JournalCategory::Application,
                subject: sanitize_untrusted_text(&application.name),
                version: application.version.as_deref().map(sanitize_untrusted_text),
                state: "installed".into(),
            }),
    );
    records.sort_by(|left, right| {
        (
            category_key(&left.category),
            &left.subject,
            &left.version,
            &left.state,
        )
            .cmp(&(
                category_key(&right.category),
                &right.subject,
                &right.version,
                &right.state,
            ))
    });
    let mut optimization_rule_ids = findings
        .iter()
        .map(|finding| sanitize_untrusted_text(&finding.rule_id))
        .collect::<Vec<_>>();
    optimization_rule_ids.sort();
    optimization_rule_ids.dedup();
    JournalBundle {
        schema_version: JOURNAL_SCHEMA_VERSION.into(),
        correlation_id: snapshot.snapshot_id.to_string(),
        records,
        verification_reason_codes: verified
            .report()
            .issues
            .iter()
            .map(|issue| sanitize_untrusted_text(&issue.code))
            .collect(),
        optimization_rule_ids,
    }
}

fn category_key(category: &JournalCategory) -> u8 {
    match category {
        JournalCategory::Hardware => 0,
        JournalCategory::Process => 1,
        JournalCategory::Toolchain => 2,
        JournalCategory::Mcp => 3,
        JournalCategory::Application => 4,
        JournalCategory::Verification => 5,
        JournalCategory::Optimization => 6,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use rsi_schema::CliFact;
    use rsi_verify::{VerificationPolicy, verify_at};

    use super::classify;

    #[test]
    fn classifies_without_raw_configuration_content() {
        let mut snapshot = rsi_schema::Snapshot::minimal_for_test(
            Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap(),
        );
        snapshot
            .completeness
            .collectors_completed
            .extend(["portable".into(), "cli".into()]);
        snapshot.cli.push(CliFact {
            name: "rustc".into(),
            present: true,
            version: Some("1.96.0".into()),
        });
        let now = snapshot.captured_at;
        let verified = verify_at(snapshot, &VerificationPolicy::default(), now).unwrap();
        let bundle = classify(&verified, &[]);
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("rustc"));
        assert!(!json.contains("command_line"));
        assert!(!json.contains("environment"));
    }
}
