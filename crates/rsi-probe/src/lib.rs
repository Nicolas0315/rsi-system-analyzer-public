mod manifest;
mod runner;

pub use manifest::{CapabilityPolicy, ExecutableId, ProbeId, ProbeSpec, SshAlias, SshAliasError};
pub use runner::{ProbeError, ProbeOutput, Runner, SshScanOutput};

pub const PROBE_MANIFEST_VERSION: &str = "rsi.probes.v1";
