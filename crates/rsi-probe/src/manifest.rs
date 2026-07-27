use rsi_schema::Capability;
use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("SSH alias is not a safe config alias")]
pub struct SshAliasError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAlias(String);

impl SshAlias {
    pub fn parse(alias: impl Into<String>) -> Result<Self, SshAliasError> {
        let alias = alias.into();
        if alias.is_empty()
            || alias.len() > 64
            || alias.starts_with('-')
            || !alias
                .chars()
                .any(|character| character.is_ascii_alphabetic())
            || !alias
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
            || alias.contains("..")
        {
            Err(SshAliasError)
        } else {
            Ok(Self(alias))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeId {
    GitVersion,
    GhVersion,
    RustcVersion,
    CargoVersion,
    NodeVersion,
    PythonVersion,
    UvVersion,
    BunVersion,
    DockerVersion,
    OllamaVersion,
    CodexVersion,
    ClaudeVersion,
    GeminiVersion,
    NvidiaSummary,
    ElevationRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableId {
    Git,
    Gh,
    Rustc,
    Cargo,
    Node,
    Python,
    Uv,
    Bun,
    Docker,
    Ollama,
    Codex,
    Claude,
    Gemini,
    NvidiaSmi,
}

impl ExecutableId {
    pub fn program(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Gh => "gh",
            Self::Rustc => "rustc",
            Self::Cargo => "cargo",
            Self::Node => "node",
            Self::Python => "python",
            Self::Uv => "uv",
            Self::Bun => "bun",
            Self::Docker => "docker",
            Self::Ollama => "ollama",
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::NvidiaSmi => "nvidia-smi",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityPolicy {
    Allowed,
    Denied(Capability),
}

#[derive(Debug, Clone, Copy)]
pub struct ProbeSpec {
    pub id: ProbeId,
    pub executable: ExecutableId,
    pub args: &'static [&'static str],
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub capability: CapabilityPolicy,
}

impl ProbeSpec {
    pub fn from_id(id: ProbeId) -> Self {
        const VERSION: &[&str] = &["--version"];
        match id {
            ProbeId::GitVersion => Self::version(id, ExecutableId::Git, VERSION),
            ProbeId::GhVersion => Self::version(id, ExecutableId::Gh, VERSION),
            ProbeId::RustcVersion => Self::version(id, ExecutableId::Rustc, VERSION),
            ProbeId::CargoVersion => Self::version(id, ExecutableId::Cargo, VERSION),
            ProbeId::NodeVersion => Self::version(id, ExecutableId::Node, VERSION),
            ProbeId::PythonVersion => Self::version(id, ExecutableId::Python, VERSION),
            ProbeId::UvVersion => Self::version(id, ExecutableId::Uv, VERSION),
            ProbeId::BunVersion => Self::version(id, ExecutableId::Bun, VERSION),
            ProbeId::DockerVersion => Self::version(id, ExecutableId::Docker, VERSION),
            ProbeId::OllamaVersion => Self::version(id, ExecutableId::Ollama, VERSION),
            ProbeId::CodexVersion => Self::version(id, ExecutableId::Codex, VERSION),
            ProbeId::ClaudeVersion => Self::version(id, ExecutableId::Claude, VERSION),
            ProbeId::GeminiVersion => Self::version(id, ExecutableId::Gemini, VERSION),
            ProbeId::NvidiaSummary => Self {
                id,
                executable: ExecutableId::NvidiaSmi,
                args: &[
                    "--query-gpu=name,memory.total,utilization.gpu",
                    "--format=csv,noheader,nounits",
                ],
                timeout_ms: 1_500,
                max_output_bytes: 8_192,
                capability: CapabilityPolicy::Allowed,
            },
            ProbeId::ElevationRequired => Self {
                id,
                executable: ExecutableId::Git,
                args: VERSION,
                timeout_ms: 100,
                max_output_bytes: 128,
                capability: CapabilityPolicy::Denied(Capability::Elevation),
            },
        }
    }

    fn version(id: ProbeId, executable: ExecutableId, args: &'static [&'static str]) -> Self {
        Self {
            id,
            executable,
            args,
            timeout_ms: 1_000,
            max_output_bytes: 4_096,
            capability: CapabilityPolicy::Allowed,
        }
    }
}
