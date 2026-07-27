use rsi_schema::{Finding, Observation, Snapshot};

pub fn render_snapshot_markdown(snapshot: &Snapshot) -> String {
    let os = match &snapshot.machine.os_family {
        Observation::Value { value, .. } => value.as_str(),
        _ => "unavailable",
    };
    format!(
        "# RSI System Snapshot\n\n- Schema: `{}`\n- OS: `{}`\n- Processes summarized: {}\n- CLI entries: {}\n- Elapsed: {} ms\n",
        snapshot.schema_version,
        os,
        snapshot.processes.len(),
        snapshot.cli.len(),
        snapshot.elapsed_ms
    )
}

pub fn render_findings_markdown(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "# RSI Analysis\n\nNo deterministic findings.\n".into();
    }
    let mut output = String::from("# RSI Analysis\n");
    for finding in findings {
        output.push_str(&format!(
            "\n## {}\n\n- Severity: `{:?}`\n- Rule: `{}`\n- Recommendation: {}\n- Verify: {}\n",
            finding.title,
            finding.severity,
            finding.rule_id,
            finding.remediation.as_str(),
            finding.verification.as_str()
        ));
    }
    output
}
