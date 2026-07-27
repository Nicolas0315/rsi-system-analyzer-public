use std::collections::BTreeSet;

use rsi_schema::redaction::sanitize_untrusted_text;
use rsi_schema::{DisplayOnly, Finding, Observation};
use rsi_verify::VerifiedSnapshot;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const AI_SCHEMA_VERSION: &str = "rsi.ai-request.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SanitizedArchitecture {
    pub os_family: Option<String>,
    pub cpu_architecture: Option<String>,
    pub logical_cores: Option<usize>,
    pub gpu_vendors: BTreeSet<String>,
    pub gpu_models: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BoundedObjective {
    RankAndExplainExistingFindings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AiRequest {
    pub schema_version: String,
    pub findings: Vec<Finding>,
    pub architecture: SanitizedArchitecture,
    pub constraint_ids: BTreeSet<String>,
    pub objective: BoundedObjective,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AiPacketError {
    #[error("AI explanation is not needed when deterministic findings are empty")]
    NotNeeded,
}

pub fn build_request(
    verified: &VerifiedSnapshot,
    findings: Vec<Finding>,
    constraint_ids: BTreeSet<String>,
) -> Result<AiRequest, AiPacketError> {
    if findings.is_empty() {
        return Err(AiPacketError::NotNeeded);
    }
    let snapshot = verified.snapshot();
    let findings = findings.into_iter().map(sanitize_finding).collect();
    let (cpu_architecture, logical_cores) = match &snapshot.machine.cpu {
        Observation::Value { value, .. } => (
            Some(sanitize_untrusted_text(&value.architecture)),
            Some(value.logical_cores),
        ),
        _ => (None, None),
    };
    let os_family = match &snapshot.machine.os_family {
        Observation::Value { value, .. } => Some(sanitize_untrusted_text(value)),
        _ => None,
    };
    let mut gpu_vendors = BTreeSet::new();
    let mut gpu_models = BTreeSet::new();
    if let Observation::Value { value, .. } = &snapshot.machine.gpus {
        for gpu in value {
            gpu_vendors.insert(sanitize_untrusted_text(&gpu.vendor));
            gpu_models.insert(sanitize_untrusted_text(&gpu.model));
        }
    }
    Ok(AiRequest {
        schema_version: AI_SCHEMA_VERSION.into(),
        findings,
        architecture: SanitizedArchitecture {
            os_family,
            cpu_architecture,
            logical_cores,
            gpu_vendors,
            gpu_models,
        },
        constraint_ids,
        objective: BoundedObjective::RankAndExplainExistingFindings,
    })
}

fn sanitize_finding(finding: Finding) -> Finding {
    Finding {
        id: sanitize_untrusted_text(&finding.id),
        rule_id: sanitize_untrusted_text(&finding.rule_id),
        severity: finding.severity,
        title: sanitize_untrusted_text(&finding.title),
        evidence: finding
            .evidence
            .into_iter()
            .map(|value| sanitize_untrusted_text(&value))
            .collect(),
        remediation: DisplayOnly::new(sanitize_untrusted_text(finding.remediation.as_str())),
        verification: DisplayOnly::new(sanitize_untrusted_text(finding.verification.as_str())),
    }
}
