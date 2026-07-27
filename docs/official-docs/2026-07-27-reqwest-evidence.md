# Reqwest dependency evidence — 2026-07-27

- retrieval date: 2026-07-27
- local dependency: `reqwest 0.13.4`
- source:
  <https://github.com/seanmonstar/reqwest/blob/master/_autodocs/api-reference/blocking.md>
- upstream manifest:
  <https://github.com/seanmonstar/reqwest/blob/master/Cargo.toml>

## Decision

`rsi-knowledge` uses the blocking client with default features disabled and the
`blocking` and `rustls` features enabled. The client sets connect and total
timeouts, disables redirects, validates TLS certificates, and bounds every
response body before writing it to a content-addressed cache. System proxies
and referrer headers are disabled.

The installed `0.13.4` blocking builder does not expose `read_timeout`; local
compilation is authoritative, so the implementation uses `timeout` for the
complete request and a separate connect timeout.

## Risk and rollback

- risk: the TLS stack adds build time and supply-chain surface;
- mitigation: exact lockfile, allowlisted HTTPS sources, bounded bodies,
redirects disabled, no cookies, and no arbitrary URL input;
- verification: workspace tests, clippy, live one-source sync, and dependency
  source inspection;
- rollback: remove `rsi-knowledge`, the `knowledge-*` CLI commands, and the
  workspace `reqwest` dependency in one revert;
- next refresh: 2026-08-27.
