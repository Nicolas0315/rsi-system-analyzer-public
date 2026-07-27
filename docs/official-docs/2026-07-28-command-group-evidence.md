# command-group process containment evidence

- Retrieved: 2026-07-28
- Local versions: Rust 1.96.0; `command-group` 5.0.1
- Official documentation:
  - https://docs.rs/command-group/5.0.1/command_group/stdlib/trait.CommandGroup.html
  - https://docs.rs/command-group/5.0.1/command_group/struct.GroupChild.html
  - https://crates.io/crates/command-group/5.0.1
- Decision: spawn every typed probe with `CommandGroup::group_spawn`.
  `GroupChild::kill` targets the POSIX process group on Unix and the Job Object
  created by the crate on Windows.
- License: Apache-2.0 OR MIT.
- Verification:
  - `cargo test -p rsi-probe runner::tests::timeout_terminates_descendant_process_tree`
  - `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- Risk: platform process containment depends on the operating system primitives
  exposed by the crate. Keep the real descendant-survival test enabled on every
  CI operating system.
- Rollback: revert `command-group` from the workspace and restore the prior
  runner only if an equivalent POSIX process-group and Windows Job Object
  implementation replaces it.
- Next refresh: 2026-08-28 or when `command-group` changes major version.
