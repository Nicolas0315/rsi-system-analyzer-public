use chrono::{TimeZone, Utc};
use rsi_schema::redaction::{sanitize_metadata_text, sanitize_snapshot, sanitize_untrusted_text};
use rsi_schema::{
    ApplicationSummary, CliFact, Confidence, CpuFacts, GpuFact, McpFact, Observation,
    ProcessSummary, Source, Stability,
};

#[test]
fn redacts_network_and_secret_material() {
    let raw = "host=workstation 100.64.1.9 token=ghp_FAKEFAKEFAKE \
               --password secret C:\\Users\\person\\tool /home/person/.ssh/id_ed25519";
    let sanitized = sanitize_untrusted_text(raw);
    for forbidden in [
        "workstation",
        "100.64.1.9",
        "ghp_",
        "secret",
        "C:\\Users\\person",
        "/home/person",
    ] {
        assert!(!sanitized.contains(forbidden), "{forbidden} survived");
    }
}

#[test]
fn sanitization_preserves_safe_versions_and_bounds_output() {
    let safe = sanitize_untrusted_text("rustc 1.96.0\ncargo 1.96.0");
    assert!(safe.contains("rustc 1.96.0"));
    assert!(safe.contains("cargo 1.96.0"));

    let huge = "x".repeat(100_000);
    assert!(sanitize_untrusted_text(&huge).len() <= 16_400);
}

#[test]
fn fixed_secret_corpus_never_survives() {
    let corpus = [
        ("-----BEGIN PRIVATE KEY-----", "PRIVATE KEY"),
        ("sk-proj-abcdefghijklmnopqrstuvwxyz", "sk-proj-"),
        ("github_pat_abcdefghijklmnopqrstuvwxyz", "github_pat_"),
        ("cookie=session-value", "session-value"),
        ("Authorization: Bearer abcdef", "abcdef"),
        ("192.168.10.20", "192.168.10.20"),
    ];
    for (raw, forbidden) in corpus {
        assert!(!sanitize_untrusted_text(raw).contains(forbidden));
    }
}

#[test]
fn redacts_complete_private_keys_and_additional_token_formats() {
    let aws = ["AK", "IAABCDEFGHIJKLMNOP"].concat();
    let gitlab = ["gl", "pat-abcdefghijklmnopqrstuvwxyz"].concat();
    let jwt = [
        "eyJhbGciOiJIUzI1NiJ9",
        "abcdefghijklmnop",
        "qrstuvwxyzABCDEF",
    ]
    .join(".");
    let raw = format!(
        "-----BEGIN PRIVATE KEY-----\nTOPSECRETBODY\n-----END PRIVATE KEY-----\n\
         {aws}\n{gitlab}\n{jwt}\nhttps://alice:password@example.test\n00:11:22:33:44:55"
    );
    let sanitized = sanitize_untrusted_text(&raw);
    for forbidden in [
        "TOPSECRETBODY",
        &aws,
        &gitlab,
        "eyJhbGciOiJIUzI1NiJ9",
        "alice:password",
        "00:11:22:33:44:55",
    ] {
        assert!(!sanitized.contains(forbidden), "{forbidden} survived");
    }
}

#[test]
fn metadata_is_single_line_bounded_and_control_free() {
    let raw = format!("name\u{1b}[31m\n{}", "a".repeat(1_000));
    let sanitized = sanitize_metadata_text(&raw);
    assert!(!sanitized.contains('\u{1b}'));
    assert!(!sanitized.contains("[31m"));
    assert!(!sanitized.contains('\n'));
    assert!(sanitized.len() <= 256);
}

#[test]
fn redacts_ipv6_and_windows_mac_addresses() {
    for raw in [
        "address=2001:db8:85a3::8a2e:370:7334",
        "loopback=::1",
        "physical=00-11-22-33-44-55",
    ] {
        let sanitized = sanitize_untrusted_text(raw);
        assert!(!sanitized.contains("2001:db8"));
        assert!(!sanitized.contains("::1"));
        assert!(!sanitized.contains("00-11-22-33-44-55"));
    }
    assert_eq!(
        sanitize_untrusted_text("2026-07-28T00:00:00Z"),
        "2026-07-28T00:00:00Z"
    );
}

#[test]
fn redacts_ipv6_fqdn_and_all_hostname_key_forms() {
    let raw = "2001:db8::1 ::1 build.internal.example build.internal.example. \
               host=alpha hostname=beta host:gamma hostname:delta";
    let sanitized = sanitize_untrusted_text(raw);
    for forbidden in [
        "2001:db8::1",
        "::1",
        "build.internal.example",
        "alpha",
        "beta",
        "gamma",
        "delta",
    ] {
        assert!(!sanitized.contains(forbidden), "{forbidden} survived");
    }
}

#[test]
fn snapshot_sanitizer_covers_every_string_surface() {
    let at = Utc.with_ymd_and_hms(2026, 7, 28, 0, 0, 0).unwrap();
    let secret = "host=private-node";
    let mut snapshot = rsi_schema::Snapshot::minimal_for_test(at);
    snapshot.analyzer_version = secret.into();
    snapshot.probe_manifest_version = secret.into();
    snapshot.machine.os_family = Observation::stable(secret.into(), at, Source::Native);
    snapshot.machine.os_version = Observation::Unsupported {
        reason: secret.into(),
    };
    snapshot.machine.kernel_version = Observation::Unreachable {
        transport: secret.into(),
    };
    snapshot.machine.cpu = Observation::stable(
        CpuFacts {
            architecture: secret.into(),
            logical_cores: 1,
            vendor: Some(secret.into()),
            brand: Some(secret.into()),
        },
        at,
        Source::Native,
    );
    snapshot.machine.gpus = Observation::stable(
        vec![GpuFact {
            vendor: secret.into(),
            model: secret.into(),
            memory_bytes: None,
            utilization_percent: Observation::Value {
                value: 0,
                captured_at: at,
                source: Source::Native,
                confidence: Confidence::High,
                stability: Stability::Ephemeral,
            },
        }],
        at,
        Source::Native,
    );
    snapshot.processes.push(ProcessSummary {
        executable_basename: secret.into(),
        category: secret.into(),
        cpu_percent: Observation::Timeout {
            probe_id: secret.into(),
            limit_ms: 1,
        },
        memory_bytes: Observation::Unsupported {
            reason: secret.into(),
        },
    });
    snapshot.cli.push(CliFact {
        name: secret.into(),
        present: true,
        version: Some(secret.into()),
    });
    snapshot.mcp.push(McpFact {
        client: secret.into(),
        server_name: secret.into(),
        enabled: true,
    });
    snapshot.applications.push(ApplicationSummary {
        name: secret.into(),
        version: Some(secret.into()),
    });
    snapshot
        .completeness
        .collectors_completed
        .insert(secret.into());
    snapshot
        .completeness
        .collectors_partial
        .insert(secret.into(), secret.into());

    sanitize_snapshot(&mut snapshot);
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("private-node"));
}

#[test]
fn strips_terminal_control_sequences() {
    let sanitized = sanitize_untrusted_text("safe\u{1b}[31mred\u{7}");
    assert_eq!(sanitized, "safered");
}
