use chrono::{TimeZone, Utc};
use rsi_optimize::analyze;
use rsi_schema::{CliFact, Constraints, Observation, ProcessSummary, Source};
use rsi_verify::{VerificationPolicy, verify_at};

fn snapshot() -> rsi_schema::Snapshot {
    let mut snapshot =
        rsi_schema::Snapshot::minimal_for_test(Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap());
    snapshot
        .completeness
        .collectors_completed
        .extend(["portable".into(), "cli".into()]);
    snapshot
}

fn verified(snapshot: rsi_schema::Snapshot) -> rsi_verify::VerifiedSnapshot {
    let now = snapshot.captured_at;
    verify_at(snapshot, &VerificationPolicy::default(), now).unwrap()
}

#[test]
fn optimal_snapshot_has_no_findings() {
    assert!(analyze(&verified(snapshot()), &Constraints::default()).is_empty());
}

#[test]
fn detects_pressure_and_cli_coverage_in_stable_order() {
    let mut input = snapshot();
    let at = input.captured_at;
    input.machine.memory_bytes = Observation::stable(100, at, Source::Native);
    input.machine.available_memory_bytes = Observation::stable(5, at, Source::Native);
    input.processes.push(ProcessSummary {
        executable_basename: "worker".into(),
        category: "ai_compute".into(),
        cpu_percent: Observation::Value {
            value: 90.0,
            captured_at: at,
            source: Source::Native,
            confidence: rsi_schema::Confidence::High,
            stability: rsi_schema::Stability::Ephemeral,
        },
        memory_bytes: Observation::Value {
            value: 50,
            captured_at: at,
            source: Source::Native,
            confidence: rsi_schema::Confidence::High,
            stability: rsi_schema::Stability::Ephemeral,
        },
    });
    input.cli.push(CliFact {
        name: "tool".into(),
        present: true,
        version: None,
    });

    let findings = analyze(&verified(input), &Constraints::default());
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].rule_id, "resource.memory-pressure");
    assert_eq!(findings[1].rule_id, "resource.process-contention");
}

#[test]
fn forbidden_rules_are_suppressed_before_ai_boundary() {
    let mut input = snapshot();
    input.cli.push(CliFact {
        name: "tool".into(),
        present: true,
        version: None,
    });
    let mut constraints = Constraints::default();
    constraints
        .forbidden_rules
        .insert("coverage.cli-version.tool".into());
    assert!(analyze(&verified(input), &constraints).is_empty());
}

#[test]
fn high_gpu_utilization_produces_report_only_contention_finding() {
    let mut input = snapshot();
    let at = input.captured_at;
    input.machine.gpus = Observation::stable(
        vec![rsi_schema::GpuFact {
            vendor: "NVIDIA".into(),
            model: "fixture".into(),
            memory_bytes: Some(24 * 1_073_741_824),
            utilization_percent: Observation::Value {
                value: 100,
                captured_at: at,
                source: Source::TypedProbe,
                confidence: rsi_schema::Confidence::High,
                stability: rsi_schema::Stability::Ephemeral,
            },
        }],
        at,
        Source::TypedProbe,
    );
    let findings = analyze(&verified(input), &Constraints::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "resource.gpu-contention");
    assert!(!findings[0].remediation.as_str().contains("kill"));
}
