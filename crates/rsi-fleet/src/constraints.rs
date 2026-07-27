use std::collections::BTreeSet;

use rsi_probe::SshAlias;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    Minimal,
    Standard,
    Heavy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeConstraint {
    pub alias: String,
    pub max_probe_duration_ms: u64,
    pub forbidden_collectors: BTreeSet<String>,
    pub forbidden_rules: BTreeSet<String>,
    pub max_resource_class: ResourceClass,
    pub freshness_limit_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetConstraints {
    pub nodes: Vec<NodeConstraint>,
}

impl FleetConstraints {
    pub fn validate(&self) -> Result<(), &'static str> {
        for node in &self.nodes {
            if SshAlias::parse(node.alias.clone()).is_err() {
                return Err("fleet alias must be an SSH config alias, not an address or target");
            }
            if !(100..=30_000).contains(&node.max_probe_duration_ms) {
                return Err("probe duration is outside the bounded range");
            }
            if node.freshness_limit_secs == 0 {
                return Err("freshness limit must be positive");
            }
            if node
                .forbidden_collectors
                .iter()
                .any(|collector| !known_collector(collector))
            {
                return Err("unknown forbidden collector ID");
            }
            if node.forbidden_rules.iter().any(|rule| !known_rule(rule)) {
                return Err("unknown forbidden rule ID");
            }
        }
        Ok(())
    }
}

fn known_collector(collector: &str) -> bool {
    matches!(
        collector,
        "portable" | "cli" | "mcp" | "gpu" | "applications"
    )
}

fn known_rule(rule: &str) -> bool {
    matches!(
        rule,
        "resource.memory-pressure" | "resource.process-contention" | "resource.gpu-contention"
    ) || rule.starts_with("coverage.cli-version.")
        || rule.starts_with("coverage.partial.")
}
