use rsi_schema::redaction::sanitize_untrusted_text;
use rsi_schema::{Constraints, DisplayOnly, Finding, Observation, Severity};
use rsi_verify::VerifiedSnapshot;

pub fn analyze(verified: &VerifiedSnapshot, constraints: &Constraints) -> Vec<Finding> {
    let snapshot = verified.snapshot();
    let mut findings = Vec::new();

    if let (
        Observation::Value { value: total, .. },
        Observation::Value {
            value: available, ..
        },
    ) = (
        &snapshot.machine.memory_bytes,
        &snapshot.machine.available_memory_bytes,
    ) && *total > 0
        && available.saturating_mul(100) / total < 10
    {
        push(
            &mut findings,
            constraints,
            finding(
                "resource.memory-pressure",
                Severity::High,
                "Available memory is below 10%",
                vec!["memory.available_ratio<0.10".into()],
                "Reduce concurrent memory-heavy workloads after identifying their owners.",
                "Repeat a fast scan and confirm available memory is at least 10%.",
            ),
        );
    }

    if snapshot.processes.iter().any(|process| {
        matches!(
            process.cpu_percent,
            Observation::Value { value, .. } if value >= 80.0
        )
    }) {
        push(
            &mut findings,
            constraints,
            finding(
                "resource.process-contention",
                Severity::Medium,
                "A process is consuming sustained CPU capacity",
                vec!["process.cpu_percent>=80".into()],
                "Schedule competing development workloads outside the observed busy window.",
                "Repeat two scans and confirm the contention no longer overlaps.",
            ),
        );
    }

    if let Observation::Value { value: gpus, .. } = &snapshot.machine.gpus
        && gpus.iter().any(|gpu| {
            matches!(
                gpu.utilization_percent,
                Observation::Value { value, .. } if value >= 90
            )
        })
    {
        push(
            &mut findings,
            constraints,
            finding(
                "resource.gpu-contention",
                Severity::Medium,
                "GPU utilization is at or above 90%",
                vec!["gpu.utilization_percent>=90".into()],
                "Preserve the active workload and schedule additional GPU tasks for a separate window.",
                "Repeat a scan outside the active workload and compare utilization.",
            ),
        );
    }

    for cli in &snapshot.cli {
        if cli.present && cli.version.is_none() {
            let cli_name = sanitize_untrusted_text(&cli.name);
            push(
                &mut findings,
                constraints,
                finding(
                    &format!("coverage.cli-version.{cli_name}"),
                    Severity::Low,
                    &format!("{cli_name} is present but its version was not captured"),
                    vec![format!("cli.{cli_name}.version=missing")],
                    "Inspect the fixed version probe compatibility before changing the tool.",
                    "Run a fast scan and confirm a sanitized version is present.",
                ),
            );
        }
    }

    for (collector, reason) in &snapshot.completeness.collectors_partial {
        if collector == "applications" && reason == "disabled in fast mode" {
            continue;
        }
        let collector = sanitize_untrusted_text(collector);
        push(
            &mut findings,
            constraints,
            finding(
                &format!("coverage.partial.{collector}"),
                Severity::Info,
                &format!("Collector {collector} returned partial evidence"),
                vec![format!("collector.{collector}=partial")],
                "Review collector compatibility without broadening permissions.",
                "Repeat the collector within its existing read-only capability.",
            ),
        );
    }

    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    findings
}

fn push(findings: &mut Vec<Finding>, constraints: &Constraints, finding: Finding) {
    if !constraints.forbidden_rules.contains(&finding.rule_id) {
        findings.push(finding);
    }
}

fn finding(
    rule_id: &str,
    severity: Severity,
    title: &str,
    evidence: Vec<String>,
    remediation: &str,
    verification: &str,
) -> Finding {
    Finding {
        id: format!("finding:{rule_id}"),
        rule_id: rule_id.into(),
        severity,
        title: title.into(),
        evidence,
        remediation: DisplayOnly::new(remediation),
        verification: DisplayOnly::new(verification),
    }
}
