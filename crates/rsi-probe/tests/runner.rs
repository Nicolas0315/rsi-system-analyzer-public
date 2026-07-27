use rsi_probe::{ProbeError, ProbeId, Runner, SshAlias};
use rsi_schema::Capability;

#[test]
fn allowed_fixed_version_probe_runs_without_shell() {
    let output = Runner.run(ProbeId::RustcVersion).unwrap();
    assert!(output.success);
    assert!(output.stdout.starts_with("rustc "));
}

#[test]
fn elevation_required_probe_is_denied_before_launch() {
    assert_eq!(
        Runner.run(ProbeId::ElevationRequired),
        Err(ProbeError::CapabilityDenied(Capability::Elevation))
    );
}

#[test]
fn unavailable_tool_has_stable_error_without_os_details() {
    let result = Runner.run(ProbeId::OllamaVersion);
    if let Err(error) = result {
        assert!(matches!(
            error,
            ProbeError::Unavailable | ProbeError::Execution
        ));
        assert!(!error.to_string().contains("C:\\"));
    }
}

#[test]
fn ssh_alias_rejects_option_like_and_address_targets() {
    for denied in ["-N", "-oProxyCommand", "user@node", "100.64.1.2", "node:22"] {
        assert!(SshAlias::parse(denied).is_err());
    }
    assert_eq!(
        SshAlias::parse("fixture-node").unwrap().as_str(),
        "fixture-node"
    );
}
