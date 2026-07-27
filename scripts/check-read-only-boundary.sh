#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
violations=0

while IFS= read -r line; do
  case "$line" in
    *rsi-probe/src/runner.rs*) ;;
    *) printf 'process boundary: %s\n' "$line" >&2; violations=1 ;;
  esac
done < <(
  git -C "$repo_root" grep -n -E 'Command::new' -- \
    ':(glob)crates/**/*.rs' || true
)

if git -C "$repo_root" grep -n -E '"(-c|/C|-Command|--command)"' -- \
  'crates/rsi-probe/src/manifest.rs'; then
  violations=1
fi

if git -C "$repo_root" grep -n -E \
  '^[[:space:]]*(Apply|Elevate|Install|Remove|Uninstall|Cleanup|Service)([[:space:]]|$)' -- \
  ':(glob)crates/rsi-cli/src/**/*.rs'; then
  violations=1
fi

if git -C "$repo_root" grep -n -E 'rsi[-_]rules' -- \
  ':(glob)crates/**/*.rs' ':(glob)crates/**/Cargo.toml'; then
  violations=1
fi

if git -C "$repo_root" grep -n -E 'analyze\(&snapshot' -- \
  ':(glob)crates/**/*.rs'; then
  violations=1
fi

if ! git -C "$repo_root" grep -q -E \
  'pub fn analyze\(verified: &VerifiedSnapshot' -- \
  'crates/rsi-optimize/src/lib.rs'; then
  printf '%s\n' \
    'verification type gate: rsi-optimize::analyze must require VerifiedSnapshot' >&2
  violations=1
fi

if [[ "$violations" -ne 0 ]]; then
  exit 1
fi
printf 'READ_ONLY_AND_LAYER_BOUNDARIES_OK\n'
