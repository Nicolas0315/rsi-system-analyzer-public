$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$violations = [System.Collections.Generic.List[string]]::new()

$processLaunches = & git -C $repoRoot grep -n -E 'Command::new' -- ':(glob)crates/**/*.rs'
foreach ($line in $processLaunches) {
    if ($line -notmatch 'rsi-probe[\\/]+src[\\/]+runner\.rs') {
        $violations.Add("process boundary: $line")
    }
}

$shellFlags = & git -C $repoRoot grep -n -E '"(-c|/C|-Command|--command)"' -- 'crates/rsi-probe/src/manifest.rs'
foreach ($line in $shellFlags) {
    $violations.Add("shell flag: $line")
}

$mutationCommands = & git -C $repoRoot grep -n -E '^[[:space:]]*(Apply|Elevate|Install|Remove|Uninstall|Cleanup|Service)([[:space:]]|$)' -- ':(glob)crates/rsi-cli/src/**/*.rs'
foreach ($line in $mutationCommands) {
    $violations.Add("mutation command: $line")
}

$legacyLayer = & git -C $repoRoot grep -n -E 'rsi[-_]rules' -- ':(glob)crates/**/*.rs' ':(glob)crates/**/Cargo.toml'
foreach ($line in $legacyLayer) {
    $violations.Add("legacy optimization layer: $line")
}

$rawAnalysis = & git -C $repoRoot grep -n -E 'analyze\(&snapshot' -- ':(glob)crates/**/*.rs'
foreach ($line in $rawAnalysis) {
    $violations.Add("unverified analysis input: $line")
}

$optimizeSource = Get-Content -Raw (Join-Path $repoRoot 'crates/rsi-optimize/src/lib.rs')
if ($optimizeSource -notmatch 'pub fn analyze\(verified: &VerifiedSnapshot') {
    $violations.Add('verification type gate: rsi-optimize::analyze must require VerifiedSnapshot')
}

if ($violations.Count -gt 0) {
    $violations | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'READ_ONLY_AND_LAYER_BOUNDARIES_OK'
