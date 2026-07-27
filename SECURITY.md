# Security Policy

## Reporting a vulnerability

Do not open a public issue containing a vulnerability, raw snapshot, machine
identifier, configuration body, credential, token, key, cookie, address, or
private log. Use the repository's private GitHub Security Advisory reporting
flow instead.

Include the affected commit, platform, minimal sanitized reproduction, and
expected security boundary. Remove usernames, hostnames, paths, addresses, and
authentication material before submission.

## Supported version

Until the first stable release, only the current default branch is supported.
Security fixes are not backported to older commits.

## Security boundaries

- Collection is read-only and uses fixed typed probes.
- Raw snapshots must not be committed or attached to issues.
- Optimization accepts only snapshots approved by `rsi-verify`.
- AI packets contain deterministic findings and sanitized architecture only.
- Documentation sync accepts embedded source IDs, not arbitrary URLs.
- The analyzer never applies optimization suggestions or changes permissions.

These boundaries are enforced by tests and
`scripts/check-read-only-boundary.*`. A bypass is a security defect.
