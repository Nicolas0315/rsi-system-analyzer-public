use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use regex::Regex;
use rsi_probe::{ProbeId, Runner};
use rsi_schema::redaction::sanitize_metadata_text;
use rsi_schema::{
    ApplicationSummary, Confidence, GpuFact, McpFact, Observation, Source, Stability,
};

const MAX_MCP_CONFIG_BYTES: u64 = 1_048_576;

pub fn collect_gpu(captured_at: DateTime<Utc>) -> Observation<Vec<GpuFact>> {
    let output = match Runner.run(ProbeId::NvidiaSummary) {
        Ok(output) if output.success => output.stdout,
        _ => {
            return Observation::Unsupported {
                reason: "supported GPU vendor tool unavailable".into(),
            };
        }
    };
    let gpus = output
        .lines()
        .filter_map(|line| parse_nvidia_line(line, captured_at))
        .collect::<Vec<_>>();
    if gpus.is_empty() {
        Observation::Unsupported {
            reason: "GPU vendor output was not recognized".into(),
        }
    } else {
        Observation::Value {
            value: gpus,
            captured_at,
            source: Source::TypedProbe,
            confidence: Confidence::High,
            stability: Stability::Stable,
        }
    }
}

fn parse_nvidia_line(line: &str, captured_at: DateTime<Utc>) -> Option<GpuFact> {
    let mut fields = line.split(',').map(str::trim);
    let model = safe_name(fields.next()?)?;
    let memory_mib = fields.next()?.parse::<u64>().ok();
    let utilization_percent = fields.next()?.parse::<u8>().ok()?;
    Some(GpuFact {
        vendor: "NVIDIA".into(),
        model,
        memory_bytes: memory_mib.map(|value| value.saturating_mul(1_048_576)),
        utilization_percent: Observation::Value {
            value: utilization_percent,
            captured_at,
            source: Source::TypedProbe,
            confidence: Confidence::High,
            stability: Stability::Ephemeral,
        },
    })
}

pub fn collect_mcp_metadata() -> Vec<McpFact> {
    let Some(home) = home_directory() else {
        return Vec::new();
    };
    let mut facts = Vec::new();
    parse_codex_mcp(&home.join(".codex").join("config.toml"), &mut facts);
    parse_json_mcp(&home.join(".claude.json"), "claude", &mut facts);
    parse_json_mcp(
        &home.join(".gemini").join("settings.json"),
        "gemini",
        &mut facts,
    );
    facts.sort_by(|left, right| {
        left.client
            .cmp(&right.client)
            .then_with(|| left.server_name.cmp(&right.server_name))
    });
    facts.dedup_by(|left, right| {
        left.client == right.client && left.server_name == right.server_name
    });
    facts
}

fn parse_codex_mcp(path: &Path, output: &mut Vec<McpFact>) {
    let Some(content) = read_bounded_config(path) else {
        return;
    };
    let section = Regex::new(r"(?m)^\[mcp_servers\.([A-Za-z0-9_.-]{1,80})\]$")
        .expect("static MCP section regex");
    output.extend(section.captures_iter(&content).filter_map(|capture| {
        safe_name(capture.get(1)?.as_str()).map(|server_name| McpFact {
            client: "codex".into(),
            server_name,
            enabled: true,
        })
    }));
}

fn parse_json_mcp(path: &Path, client: &str, output: &mut Vec<McpFact>) {
    let Some(content) = read_bounded_config(path) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return;
    };
    let servers = value
        .get("mcpServers")
        .or_else(|| value.get("mcp_servers"))
        .and_then(serde_json::Value::as_object);
    let Some(servers) = servers else {
        return;
    };
    output.extend(servers.keys().filter_map(|name| {
        safe_name(name).map(|server_name| McpFact {
            client: client.into(),
            server_name,
            enabled: true,
        })
    }));
}

pub fn collect_application_names() -> Vec<ApplicationSummary> {
    let roots = application_roots();
    let mut names = BTreeSet::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten().take(500) {
            let path = entry.path();
            if let Some(name) = application_name(&path) {
                names.insert(name);
            }
        }
    }
    names
        .into_iter()
        .take(200)
        .map(|name| ApplicationSummary {
            name,
            version: None,
        })
        .collect()
}

fn home_directory() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

fn application_roots() -> Vec<PathBuf> {
    if cfg!(target_os = "windows") {
        ["ProgramFiles", "ProgramFiles(x86)"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect()
    } else if cfg!(target_os = "macos") {
        vec![PathBuf::from("/Applications")]
    } else {
        vec![
            PathBuf::from("/usr/share/applications"),
            PathBuf::from("/usr/local/share/applications"),
        ]
    }
}

fn application_name(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_string_lossy();
    let trimmed = file_name
        .strip_suffix(".app")
        .or_else(|| file_name.strip_suffix(".desktop"))
        .unwrap_or(&file_name);
    safe_name(trimmed)
}

fn safe_name(value: &str) -> Option<String> {
    let sanitized = sanitize_metadata_text(value);
    let trimmed = sanitized.trim();
    if trimmed.is_empty()
        || trimmed.len() > 160
        || !trimmed
            .chars()
            .all(|character| character.is_alphanumeric() || " ._()+-".contains(character))
    {
        None
    } else {
        Some(trimmed.into())
    }
}

fn read_bounded_config(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut content = String::new();
    file.take(MAX_MCP_CONFIG_BYTES + 1)
        .read_to_string(&mut content)
        .ok()?;
    (content.len() as u64 <= MAX_MCP_CONFIG_BYTES).then_some(content)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use rsi_schema::Observation;

    use super::{parse_nvidia_line, safe_name};

    #[test]
    fn parses_sanitized_nvidia_csv() {
        let gpu = parse_nvidia_line("NVIDIA Test GPU, 24564, 87", Utc::now()).unwrap();
        assert_eq!(gpu.model, "NVIDIA Test GPU");
        assert!(matches!(
            gpu.utilization_percent,
            Observation::Value { value: 87, .. }
        ));
        assert_eq!(gpu.memory_bytes, Some(25_757_220_864));
    }

    #[test]
    fn rejects_secret_shaped_inventory_names() {
        assert!(safe_name("github_pat_abcdefghijklmnopqrstuvwxyz").is_none());
        assert_eq!(safe_name("safe-tool").as_deref(), Some("safe-tool"));
    }
}
