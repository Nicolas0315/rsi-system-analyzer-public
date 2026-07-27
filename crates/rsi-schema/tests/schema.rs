use chrono::{TimeZone, Utc};
use rsi_schema::{Capability, Confidence, ErrorCode, Observation, Source, Stability};

fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap()
}

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
    let states = [
        Observation::<u64>::Unsupported {
            reason: "vendor tool absent".into(),
        },
        Observation::Timeout {
            probe_id: "gpu.vendor".into(),
            limit_ms: 250,
        },
        Observation::Denied {
            capability: Capability::Elevation,
        },
        Observation::Unreachable {
            transport: "ssh".into(),
        },
        Observation::Error {
            code: ErrorCode::InvalidOutput,
        },
    ];
    let zero = serde_json::json!({"status":"value","data":{"value":0}});
    for state in states {
        assert_ne!(serde_json::to_value(state).unwrap(), zero);
    }
}

#[test]
fn snapshot_round_trips_and_rejects_unknown_top_level_fields() {
    let snapshot = rsi_schema::Snapshot::minimal_for_test(fixed_time());
    assert_eq!(snapshot.schema_version, "rsi.snapshot.v2");
    let json = serde_json::to_string(&snapshot).unwrap();
    assert_eq!(
        serde_json::from_str::<rsi_schema::Snapshot>(&json).unwrap(),
        snapshot
    );

    let mut value = serde_json::to_value(snapshot).unwrap();
    value["secret_extra"] = serde_json::json!("must reject");
    assert!(serde_json::from_value::<rsi_schema::Snapshot>(value).is_err());
}

#[test]
fn display_only_text_has_no_probe_conversion() {
    let text = rsi_schema::DisplayOnly::new("Update after verifying compatibility");
    assert_eq!(text.as_str(), "Update after verifying compatibility");
}
