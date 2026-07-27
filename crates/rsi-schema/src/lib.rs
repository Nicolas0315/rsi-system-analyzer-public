pub mod redaction;

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SCHEMA_VERSION: &str = "rsi.snapshot.v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Native,
    File,
    TypedProbe,
    Derived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    Stable,
    Ephemeral,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Elevation,
    ExternalExecutable,
    FileRead,
    RemoteTransport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidOutput,
    Io,
    Schema,
    BudgetExhausted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum Observation<T> {
    Value {
        value: T,
        captured_at: DateTime<Utc>,
        source: Source,
        confidence: Confidence,
        stability: Stability,
    },
    Unsupported {
        reason: String,
    },
    Timeout {
        probe_id: String,
        limit_ms: u64,
    },
    Denied {
        capability: Capability,
    },
    Unreachable {
        transport: String,
    },
    Stale {
        last_value: T,
        as_of: DateTime<Utc>,
    },
    Error {
        code: ErrorCode,
    },
}

impl<T> Observation<T> {
    pub fn stable(value: T, captured_at: DateTime<Utc>, source: Source) -> Self {
        Self::Value {
            value,
            captured_at,
            source,
            confidence: Confidence::High,
            stability: Stability::Stable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct DisplayOnly<T>(T);

impl DisplayOnly<String> {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type RemediationText = DisplayOnly<String>;
pub type VerificationText = DisplayOnly<String>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct CpuFacts {
    pub architecture: String,
    pub logical_cores: usize,
    pub vendor: Option<String>,
    pub brand: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GpuFact {
    pub vendor: String,
    pub model: String,
    pub memory_bytes: Option<u64>,
    pub utilization_percent: Observation<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct MachineFacts {
    pub os_family: Observation<String>,
    pub os_version: Observation<String>,
    pub kernel_version: Observation<String>,
    pub cpu: Observation<CpuFacts>,
    pub memory_bytes: Observation<u64>,
    pub available_memory_bytes: Observation<u64>,
    pub gpus: Observation<Vec<GpuFact>>,
}

impl Default for Observation<String> {
    fn default() -> Self {
        Self::Unsupported {
            reason: "not collected".into(),
        }
    }
}

impl Default for Observation<u64> {
    fn default() -> Self {
        Self::Unsupported {
            reason: "not collected".into(),
        }
    }
}

impl Default for Observation<CpuFacts> {
    fn default() -> Self {
        Self::Unsupported {
            reason: "not collected".into(),
        }
    }
}

impl Default for Observation<Vec<GpuFact>> {
    fn default() -> Self {
        Self::Unsupported {
            reason: "not collected".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProcessSummary {
    pub executable_basename: String,
    pub category: String,
    pub cpu_percent: Observation<f32>,
    pub memory_bytes: Observation<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CliFact {
    pub name: String,
    pub present: bool,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpFact {
    pub client: String,
    pub server_name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationSummary {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    pub collectors_completed: BTreeSet<String>,
    pub collectors_partial: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: String,
    pub analyzer_version: String,
    pub probe_manifest_version: String,
    pub snapshot_id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub elapsed_ms: u64,
    pub machine: MachineFacts,
    pub processes: Vec<ProcessSummary>,
    pub cli: Vec<CliFact>,
    pub mcp: Vec<McpFact>,
    pub applications: Vec<ApplicationSummary>,
    pub completeness: Completeness,
}

impl Snapshot {
    pub fn minimal_for_test(captured_at: DateTime<Utc>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            analyzer_version: "0.1.0-test".into(),
            probe_manifest_version: "rsi.probes.v1".into(),
            snapshot_id: Uuid::nil(),
            captured_at,
            elapsed_ms: 0,
            machine: MachineFacts::default(),
            processes: Vec::new(),
            cli: Vec::new(),
            mcp: Vec::new(),
            applications: Vec::new(),
            completeness: Completeness::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub evidence: Vec<String>,
    pub remediation: RemediationText,
    pub verification: VerificationText,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    pub forbidden_collectors: BTreeSet<String>,
    pub forbidden_rules: BTreeSet<String>,
    pub max_probe_duration_ms: Option<u64>,
}
