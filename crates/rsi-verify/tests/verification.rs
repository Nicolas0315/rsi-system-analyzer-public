use chrono::{Duration, TimeZone, Utc};
use rsi_schema::{CliFact, SCHEMA_VERSION, Snapshot};
use rsi_verify::{VerificationPolicy, verify_at};

fn fixture() -> Snapshot {
    let at = Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap();
    let mut snapshot = Snapshot::minimal_for_test(at);
    snapshot.schema_version = SCHEMA_VERSION.into();
    snapshot
        .completeness
        .collectors_completed
        .extend(["portable".into(), "cli".into()]);
    snapshot
}

#[test]
fn valid_snapshot_produces_opaque_verified_value() {
    let snapshot = fixture();
    let now = snapshot.captured_at;
    let verified = verify_at(snapshot, &VerificationPolicy::default(), now).unwrap();
    assert!(verified.report().valid);
}

#[test]
fn invalid_snapshot_returns_stable_reason_codes() {
    let mut snapshot = fixture();
    snapshot.schema_version = "unknown".into();
    snapshot.cli = vec![
        CliFact {
            name: "git".into(),
            present: true,
            version: None,
        },
        CliFact {
            name: "GIT".into(),
            present: true,
            version: None,
        },
    ];
    let now = snapshot.captured_at - Duration::minutes(10);
    let report = verify_at(snapshot, &VerificationPolicy::default(), now).unwrap_err();
    let codes = report
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        codes,
        [
            "inventory.duplicate_cli",
            "schema.unsupported",
            "time.future_capture"
        ]
    );
}

#[test]
fn rejects_schema_valid_unsanitized_inventory_and_architecture() {
    let mut snapshot = fixture();
    snapshot.cli.push(CliFact {
        name: "token=ghp_FAKEFAKEFAKE".into(),
        present: true,
        version: Some("\u{1b}[31m1.0".into()),
    });
    snapshot.machine.os_family = rsi_schema::Observation::stable(
        "host=private-machine".into(),
        snapshot.captured_at,
        rsi_schema::Source::Native,
    );
    let now = snapshot.captured_at;
    let report = verify_at(snapshot, &VerificationPolicy::default(), now).unwrap_err();
    let fields = report
        .issues
        .iter()
        .filter(|issue| issue.code == "privacy.unsanitized_text")
        .map(|issue| issue.field.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        [
            "/cli/0/name",
            "/cli/0/version",
            "/machine/os_family/data/value"
        ]
    );
}
