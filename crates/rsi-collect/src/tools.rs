use rsi_probe::{ProbeError, ProbeId, Runner};
use rsi_schema::CliFact;

const CATALOG: &[(&str, ProbeId)] = &[
    ("git", ProbeId::GitVersion),
    ("gh", ProbeId::GhVersion),
    ("rustc", ProbeId::RustcVersion),
    ("cargo", ProbeId::CargoVersion),
    ("node", ProbeId::NodeVersion),
    ("python", ProbeId::PythonVersion),
    ("uv", ProbeId::UvVersion),
    ("bun", ProbeId::BunVersion),
    ("docker", ProbeId::DockerVersion),
    ("ollama", ProbeId::OllamaVersion),
    ("codex", ProbeId::CodexVersion),
    ("claude", ProbeId::ClaudeVersion),
    ("gemini", ProbeId::GeminiVersion),
];

pub fn collect_cli() -> Vec<CliFact> {
    let mut handles = CATALOG
        .iter()
        .map(|&(name, probe)| {
            std::thread::spawn(move || {
                let result = Runner.run(probe);
                let present = !matches!(result, Err(ProbeError::Unavailable));
                let version = result.ok().and_then(|output| {
                    let combined = if output.stdout.trim().is_empty() {
                        output.stderr
                    } else {
                        output.stdout
                    };
                    combined.lines().next().map(normalize_version)
                });
                CliFact {
                    name: name.into(),
                    present,
                    version,
                }
            })
        })
        .collect::<Vec<_>>();
    let mut facts = handles
        .drain(..)
        .filter_map(|handle| handle.join().ok())
        .collect::<Vec<_>>();
    facts.sort_by(|left, right| left.name.cmp(&right.name));
    facts
}

fn normalize_version(line: &str) -> String {
    line.trim().chars().take(160).collect()
}
