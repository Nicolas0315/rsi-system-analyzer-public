#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
violations=0

while IFS= read -r line; do
  case "$line" in
    *rsi-probe/src/runner.rs*) ;;
    *) printf 'process boundary: %s\n' "$line" >&2; violations=1 ;;
  esac
done < <(rg -n 'Command::new' "$repo_root/crates" -g '*.rs' || true)

if rg -n '"(-c|/C|-Command|--command)"' \
  "$repo_root/crates/rsi-probe/src/manifest.rs"; then
  violations=1
fi

if rg -n '^[[:space:]]*(Apply|Elevate|Install|Remove|Uninstall|Cleanup|Service)\b' \
  "$repo_root/crates/rsi-cli/src" -g '*.rs'; then
  violations=1
fi

if rg -n 'rsi[-_]rules' "$repo_root/crates" -g '*.rs' -g 'Cargo.toml'; then
  violations=1
fi

if rg -n 'analyze\(&snapshot' "$repo_root/crates" -g '*.rs'; then
  violations=1
fi

if ! rg -q 'pub fn analyze\(verified: &VerifiedSnapshot' \
  "$repo_root/crates/rsi-optimize/src/lib.rs"; then
  printf '%s\n' \
    'verification type gate: rsi-optimize::analyze must require VerifiedSnapshot' >&2
  violations=1
fi

if [[ "$violations" -ne 0 ]]; then
  exit 1
fi
printf 'READ_ONLY_AND_LAYER_BOUNDARIES_OK\n'
