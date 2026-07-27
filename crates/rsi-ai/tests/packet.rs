use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use rsi_ai::{AiPacketError, build_request};
use rsi_schema::{Constraints, Snapshot};
use rsi_verify::{VerificationPolicy, verify_at};

fn snapshot() -> Snapshot {
    let mut snapshot =
        Snapshot::minimal_for_test(Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap());
    snapshot
        .completeness
        .collectors_completed
        .extend(["portable".into(), "cli".into()]);
    snapshot
}

fn verified(snapshot: Snapshot) -> rsi_verify::VerifiedSnapshot {
    let now = snapshot.captured_at;
    verify_at(snapshot, &VerificationPolicy::default(), now).unwrap()
}

#[test]
fn empty_findings_do_not_create_ai_request() {
    assert_eq!(
        build_request(&verified(snapshot()), Vec::new(), BTreeSet::new()),
        Err(AiPacketError::NotNeeded)
    );
}

#[test]
fn packet_contains_no_raw_snapshot_surfaces() {
    let mut input = snapshot();
    input
        .completeness
        .collectors_partial
        .insert("fixture".into(), "partial".into());
    let input = verified(input);
    let findings = rsi_optimize::analyze(&input, &Constraints::default());
    let packet = build_request(&input, findings, BTreeSet::new()).unwrap();
    let json = serde_json::to_string(&packet).unwrap();
    for forbidden in [
        "processes",
        "applications",
        "mcp",
        "snapshot_id",
        "captured_at",
        "elapsed_ms",
    ] {
        assert!(!json.contains(forbidden));
    }
}

#[test]
fn finding_text_is_redacted_again_at_ai_boundary() {
    let finding = rsi_schema::Finding {
        id: "finding:test".into(),
        rule_id: "test".into(),
        severity: rsi_schema::Severity::Low,
        title: "token=ghp_FAKEFAKEFAKE".into(),
        evidence: vec!["192.168.1.20".into()],
        remediation: rsi_schema::DisplayOnly::new("inspect"),
        verification: rsi_schema::DisplayOnly::new("verify"),
    };
    let packet = build_request(&verified(snapshot()), vec![finding], BTreeSet::new()).unwrap();
    let json = serde_json::to_string(&packet).unwrap();
    assert!(!json.contains("ghp_"));
    assert!(!json.contains("192.168.1.20"));
}
