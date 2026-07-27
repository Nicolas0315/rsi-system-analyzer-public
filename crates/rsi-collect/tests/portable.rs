use chrono::Utc;
use rsi_collect::{collect_cli, collect_portable};
use rsi_schema::Observation;

#[test]
fn portable_facts_have_real_cpu_and_memory() {
    let (machine, _) = collect_portable(Utc::now());
    match machine.cpu {
        Observation::Value { value, .. } => assert!(value.logical_cores > 0),
        other => panic!("expected CPU value, got {other:?}"),
    }
    match machine.memory_bytes {
        Observation::Value { value, .. } => assert!(value > 0),
        other => panic!("expected memory value, got {other:?}"),
    }
}

#[test]
fn persisted_processes_have_only_safe_summary_fields() {
    let (_, processes) = collect_portable(Utc::now());
    assert!(!processes.is_empty());
    assert!(processes.len() <= 20);
    let json = serde_json::to_string(&processes).unwrap();
    for forbidden in ["pid", "command", "args", "environment", "exe_path"] {
        assert!(!json.contains(forbidden));
    }
    assert!(
        processes
            .iter()
            .all(|process| !process.executable_basename.contains('\\'))
    );
}

#[test]
fn cli_catalog_is_sorted_and_fixed() {
    let facts = collect_cli();
    assert_eq!(facts.len(), 13);
    assert!(facts.windows(2).all(|pair| pair[0].name < pair[1].name));
    assert!(
        facts
            .iter()
            .any(|fact| fact.name == "rustc" && fact.present)
    );
}
