use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn scan_fast_emits_valid_snapshot_json() {
    let output = Command::cargo_bin("rsi-scan")
        .unwrap()
        .args(["scan", "--fast", "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "rsi.snapshot.v2");
    assert!(
        value["machine"]["cpu"]["data"]["value"]["logical_cores"]
            .as_u64()
            .unwrap()
            > 0
    );
    let snapshot: rsi_schema::Snapshot = serde_json::from_slice(&output.stdout).unwrap();
    assert!(rsi_verify::verify(snapshot, &rsi_verify::VerificationPolicy::default()).is_ok());
}

#[test]
fn help_exposes_no_mutation_commands() {
    let mut command = Command::cargo_bin("rsi-scan").unwrap();
    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("analyze"))
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("apply").not())
        .stdout(predicate::str::contains("elevate").not())
        .stdout(predicate::str::contains("install").not())
        .stdout(predicate::str::contains("remove").not());
}

#[test]
fn analyze_accepts_a_real_snapshot() {
    let scan = Command::cargo_bin("rsi-scan")
        .unwrap()
        .args(["scan", "--fast"])
        .output()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    std::fs::write(&path, scan.stdout).unwrap();
    let output = Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("analyze")
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "rsi.analysis.v1");
}

#[test]
fn verify_and_journal_accept_a_real_snapshot() {
    let scan = Command::cargo_bin("rsi-scan")
        .unwrap()
        .args(["scan", "--fast"])
        .output()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    std::fs::write(&path, scan.stdout).unwrap();

    let verify = Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert!(verify.status.success());
    let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(report["valid"], true);

    let journal = Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("journal")
        .arg(path)
        .output()
        .unwrap();
    assert!(journal.status.success());
    let text = String::from_utf8(journal.stdout).unwrap();
    assert!(text.contains("rsi.journal.v1"));
    assert!(!text.contains("command_line"));
    assert!(!text.contains("environment"));
}

#[test]
fn invalid_snapshot_fails_verification_and_analysis() {
    let scan = Command::cargo_bin("rsi-scan")
        .unwrap()
        .args(["scan", "--fast"])
        .output()
        .unwrap();
    let mut invalid: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    invalid["schema_version"] = serde_json::json!("unknown");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.json");
    std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();

    for command in ["verify", "analyze", "ai-packet", "journal"] {
        Command::cargo_bin("rsi-scan")
            .unwrap()
            .arg(command)
            .arg(&path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("schema.unsupported"));
    }
}

#[test]
fn oversized_snapshot_and_constraints_are_rejected_before_parsing() {
    let directory = tempfile::tempdir().unwrap();
    let snapshot = directory.path().join("oversized-snapshot.json");
    std::fs::write(&snapshot, vec![b'x'; 4 * 1_048_576 + 1]).unwrap();
    Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("verify")
        .arg(snapshot)
        .assert()
        .failure()
        .stderr(predicate::str::contains("snapshot exceeded byte limit"));

    let constraints = directory.path().join("oversized-constraints.json");
    std::fs::write(&constraints, vec![b'x'; 1_048_576 + 1]).unwrap();
    Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("fleet-scan")
        .arg(constraints)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "fleet constraints exceeded byte limit",
        ));
}

#[test]
fn knowledge_sources_exposes_only_embedded_https_urls() {
    let output = Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("knowledge-sources")
        .output()
        .unwrap();
    assert!(output.status.success());
    let sources: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert!(sources.len() >= 8);
    assert!(sources.iter().all(|source| {
        source["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("https://"))
    }));
}

#[test]
fn semantic_diff_ignores_ephemeral_runtime_samples() {
    let directory = tempfile::tempdir().unwrap();
    let left = directory.path().join("left.json");
    let right = directory.path().join("right.json");
    let scan = Command::cargo_bin("rsi-scan")
        .unwrap()
        .args(["scan", "--fast"])
        .output()
        .unwrap();
    assert!(scan.status.success());
    let mut changed: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    changed["machine"]["available_memory_bytes"]["data"]["value"] = serde_json::json!(1);
    if let Some(processes) = changed["processes"].as_array_mut() {
        for process in processes {
            process["cpu_percent"]["data"]["value"] = serde_json::json!(99.0);
            process["memory_bytes"]["data"]["value"] = serde_json::json!(1);
        }
    }
    std::fs::write(&left, scan.stdout).unwrap();
    std::fs::write(&right, serde_json::to_vec(&changed).unwrap()).unwrap();
    let output = Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("diff")
        .arg(left)
        .arg(right)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["equal"], true);
    assert_eq!(value["changed_paths"].as_array().unwrap().len(), 0);
}

#[test]
fn transport_markers_contain_exactly_one_compact_snapshot_line() {
    let output = Command::cargo_bin("rsi-scan")
        .unwrap()
        .args(["scan", "--fast", "--transport-markers"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let snapshot = rsi_fleet::extract_snapshot(&text, 1_048_576).unwrap();
    assert_eq!(snapshot.schema_version, "rsi.snapshot.v2");
}

#[test]
fn semantic_diff_detects_stable_os_change() {
    let scan = Command::cargo_bin("rsi-scan")
        .unwrap()
        .args(["scan", "--fast"])
        .output()
        .unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    changed["machine"]["os_family"]["data"]["value"] = serde_json::json!("FixtureOS");
    let directory = tempfile::tempdir().unwrap();
    let left = directory.path().join("left.json");
    let right = directory.path().join("right.json");
    std::fs::write(&left, scan.stdout).unwrap();
    std::fs::write(&right, serde_json::to_vec(&changed).unwrap()).unwrap();
    let output = Command::cargo_bin("rsi-scan")
        .unwrap()
        .arg("diff")
        .arg(left)
        .arg(right)
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["equal"], false);
    assert!(
        value["changed_paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path == "machine.os_family.data.value")
    );
}
