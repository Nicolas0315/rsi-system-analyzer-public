use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

use regex::Regex;

use crate::{
    ApplicationSummary, CpuFacts, GpuFact, McpFact, Observation, ProcessSummary, Snapshot,
};

const MAX_INPUT_BYTES: usize = 65_536;
const MAX_OUTPUT_BYTES: usize = 16_384;
const MAX_METADATA_BYTES: usize = 256;

fn patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            (r"\x1B\[[0-?]*[ -/]*[@-~]", ""),
            (
                r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
                "[redacted-key]",
            ),
            (
                r"(?i)\b(?:ghp_|github_pat_|glpat-|sk-proj-|sk-|xox[baprs]-|AIza)[A-Za-z0-9_\-]{6,}",
                "[redacted-token]",
            ),
            (r"\bAKIA[0-9A-Z]{16}\b", "[redacted-token]"),
            (
                r"\b[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
                "[redacted-token]",
            ),
            (
                r"(?i)\b(?:token|password|passwd|secret|cookie|authorization)\s*[:=]\s*(?:Bearer\s+)?[^\s]+",
                "[redacted-credential]",
            ),
            (
                r"(?i)--(?:password|token|secret)(?:=|\s+)[^\s]+",
                "[redacted-credential]",
            ),
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[redacted-ip]"),
            (
                r"(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b",
                "[redacted-ip]",
            ),
            (
                r"(?i)(^|[^0-9a-f:])((?:[0-9a-f]{0,4}:){1,7}:[0-9a-f]{0,4})([^0-9a-f:]|$)",
                "$1[redacted-ip]$3",
            ),
            (
                r"(?i)\bC:\\Users\\[^\\\s]+(?:\\[^\s]*)?",
                "[redacted-user-path]",
            ),
            (
                r"(?i)(?:/Users|/home)/[^/\s]+(?:/[^\s]*)?",
                "[redacted-user-path]",
            ),
            (
                r"(?i)\bhost(?:name)?\s*=\s*[A-Za-z0-9_.-]+",
                "host=[redacted]",
            ),
            (
                r"(?i)\bhost(?:name)?\s*:\s*[A-Za-z0-9_.-]+",
                "host:[redacted]",
            ),
            (
                r"(?i)\bhttps?://[^/\s:@]+:[^@\s/]+@",
                "https://[redacted]@",
            ),
            (
                r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b",
                "[redacted-mac]",
            ),
            (
                r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?($|[^a-z0-9.-])",
                "[redacted-hostname]$1",
            ),
        ]
        .into_iter()
        .map(|(pattern, replacement)| {
            (
                Regex::new(pattern).expect("static redaction regex must compile"),
                replacement,
            )
        })
        .collect()
    })
}

pub fn sanitize_untrusted_text(input: &str) -> String {
    let input = &input[..input.floor_char_boundary(input.len().min(MAX_INPUT_BYTES))];
    let mut sanitized = input.to_string();
    for (pattern, replacement) in patterns() {
        sanitized = pattern.replace_all(&sanitized, *replacement).into_owned();
    }
    sanitized = redact_ip_literals(&sanitized);
    sanitized.retain(|character| !character.is_control() || matches!(character, '\n' | '\t'));

    let mut bounded = String::with_capacity(sanitized.len().min(MAX_OUTPUT_BYTES));
    for line in sanitized.lines().take(256) {
        let line = if line.len() > 1_024 {
            &line[..line.floor_char_boundary(1_024)]
        } else {
            line
        };
        if !bounded.is_empty() {
            bounded.push('\n');
        }
        if bounded.len() + line.len() > MAX_OUTPUT_BYTES {
            let remaining = MAX_OUTPUT_BYTES.saturating_sub(bounded.len());
            bounded.push_str(&line[..line.floor_char_boundary(remaining)]);
            break;
        }
        bounded.push_str(line);
    }
    bounded
}

fn redact_ip_literals(input: &str) -> String {
    static CANDIDATES: OnceLock<Regex> = OnceLock::new();
    let candidates = CANDIDATES.get_or_init(|| {
        Regex::new(r"[0-9A-Za-z:.%]{2,}").expect("static IP candidate regex must compile")
    });
    candidates
        .replace_all(input, |capture: &regex::Captures<'_>| {
            let candidate = capture.get(0).map_or("", |value| value.as_str());
            let address = candidate.split('%').next().unwrap_or(candidate);
            if address.contains(':') && IpAddr::from_str(address).is_ok() {
                "[redacted-ip]".to_string()
            } else {
                candidate.to_string()
            }
        })
        .into_owned()
}

pub fn sanitize_metadata_text(input: &str) -> String {
    let sanitized = sanitize_untrusted_text(input);
    let single_line = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
    let end = single_line.floor_char_boundary(single_line.len().min(MAX_METADATA_BYTES));
    single_line[..end].to_string()
}

pub fn sanitize_snapshot(snapshot: &mut Snapshot) {
    snapshot.schema_version = sanitize_metadata_text(&snapshot.schema_version);
    snapshot.analyzer_version = sanitize_metadata_text(&snapshot.analyzer_version);
    snapshot.probe_manifest_version = sanitize_metadata_text(&snapshot.probe_manifest_version);
    sanitize_machine(snapshot);
    for process in &mut snapshot.processes {
        sanitize_process(process);
    }
    for cli in &mut snapshot.cli {
        cli.name = sanitize_metadata_text(&cli.name);
        cli.version = cli.version.as_deref().map(sanitize_metadata_text);
    }
    for mcp in &mut snapshot.mcp {
        sanitize_mcp(mcp);
    }
    for application in &mut snapshot.applications {
        sanitize_application(application);
    }
    snapshot.completeness.collectors_completed =
        std::mem::take(&mut snapshot.completeness.collectors_completed)
            .into_iter()
            .map(|value| sanitize_metadata_text(&value))
            .collect();
    snapshot.completeness.collectors_partial =
        std::mem::take(&mut snapshot.completeness.collectors_partial)
            .into_iter()
            .map(|(key, value)| (sanitize_metadata_text(&key), sanitize_metadata_text(&value)))
            .collect();
}

fn sanitize_machine(snapshot: &mut Snapshot) {
    sanitize_string_observation(&mut snapshot.machine.os_family);
    sanitize_string_observation(&mut snapshot.machine.os_version);
    sanitize_string_observation(&mut snapshot.machine.kernel_version);
    sanitize_observation_envelope(&mut snapshot.machine.memory_bytes);
    sanitize_observation_envelope(&mut snapshot.machine.available_memory_bytes);
    sanitize_observation_envelope(&mut snapshot.machine.cpu);
    match &mut snapshot.machine.cpu {
        Observation::Value { value, .. } => sanitize_cpu(value),
        Observation::Stale { last_value, .. } => sanitize_cpu(last_value),
        _ => {}
    }
    sanitize_observation_envelope(&mut snapshot.machine.gpus);
    match &mut snapshot.machine.gpus {
        Observation::Value { value, .. } => value.iter_mut().for_each(sanitize_gpu),
        Observation::Stale { last_value, .. } => last_value.iter_mut().for_each(sanitize_gpu),
        _ => {}
    }
}

fn sanitize_string_observation(observation: &mut Observation<String>) {
    sanitize_observation_envelope(observation);
    match observation {
        Observation::Value { value, .. } => *value = sanitize_metadata_text(value),
        Observation::Stale { last_value, .. } => {
            *last_value = sanitize_metadata_text(last_value);
        }
        _ => {}
    }
}

fn sanitize_observation_envelope<T>(observation: &mut Observation<T>) {
    match observation {
        Observation::Unsupported { reason } => *reason = sanitize_metadata_text(reason),
        Observation::Timeout { probe_id, .. } => *probe_id = sanitize_metadata_text(probe_id),
        Observation::Unreachable { transport } => {
            *transport = sanitize_metadata_text(transport);
        }
        _ => {}
    }
}

fn sanitize_cpu(cpu: &mut CpuFacts) {
    cpu.architecture = sanitize_metadata_text(&cpu.architecture);
    cpu.vendor = cpu.vendor.as_deref().map(sanitize_metadata_text);
    cpu.brand = cpu.brand.as_deref().map(sanitize_metadata_text);
}

fn sanitize_gpu(gpu: &mut GpuFact) {
    gpu.vendor = sanitize_metadata_text(&gpu.vendor);
    gpu.model = sanitize_metadata_text(&gpu.model);
    sanitize_observation_envelope(&mut gpu.utilization_percent);
}

fn sanitize_process(process: &mut ProcessSummary) {
    process.executable_basename = sanitize_metadata_text(&process.executable_basename);
    process.category = sanitize_metadata_text(&process.category);
    sanitize_observation_envelope(&mut process.cpu_percent);
    sanitize_observation_envelope(&mut process.memory_bytes);
}

fn sanitize_mcp(mcp: &mut McpFact) {
    mcp.client = sanitize_metadata_text(&mcp.client);
    mcp.server_name = sanitize_metadata_text(&mcp.server_name);
}

fn sanitize_application(application: &mut ApplicationSummary) {
    application.name = sanitize_metadata_text(&application.name);
    application.version = application.version.as_deref().map(sanitize_metadata_text);
}
