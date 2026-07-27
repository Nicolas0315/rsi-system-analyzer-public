mod inventory;
mod portable;
mod tools;

use std::time::Instant;

use chrono::Utc;
use rsi_probe::PROBE_MANIFEST_VERSION;
use rsi_schema::redaction::sanitize_snapshot;
use rsi_schema::{Completeness, Snapshot};
use uuid::Uuid;

pub use portable::collect_portable;
pub use tools::collect_cli;

#[derive(Debug, Clone, Copy, Default)]
pub struct CollectOptions {
    pub fast: bool,
}

pub fn collect_snapshot(options: CollectOptions) -> Snapshot {
    let started = Instant::now();
    let captured_at = Utc::now();
    let (mut machine, processes) = collect_portable(captured_at);
    let cli = collect_cli();
    let mcp = inventory::collect_mcp_metadata();
    let applications = if options.fast {
        Vec::new()
    } else {
        inventory::collect_application_names()
    };
    machine.gpus = inventory::collect_gpu(captured_at);
    let mut completeness = Completeness::default();
    completeness.collectors_completed.extend(
        ["portable", "cli"]
            .into_iter()
            .map(std::string::ToString::to_string),
    );
    if options.fast {
        completeness
            .collectors_partial
            .insert("applications".into(), "disabled in fast mode".into());
    }

    let mut snapshot = Snapshot {
        schema_version: rsi_schema::SCHEMA_VERSION.into(),
        analyzer_version: env!("CARGO_PKG_VERSION").into(),
        probe_manifest_version: PROBE_MANIFEST_VERSION.into(),
        snapshot_id: Uuid::new_v4(),
        captured_at,
        elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        machine,
        processes,
        cli,
        mcp,
        applications,
        completeness,
    };
    sanitize_snapshot(&mut snapshot);
    snapshot
}
