$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $repoRoot 'crates'
$violations = [System.Collections.Generic.List[string]]::new()

$processLaunches = & rg -n 'Command::new' $sourceRoot -g '*.rs'
foreach ($line in $processLaunches) {
    if ($line -notmatch 'rsi-probe[\\/]+src[\\/]+runner\.rs') {
        $violations.Add("process boundary: $line")
    }
}

$manifest = Join-Path $repoRoot 'crates/rsi-probe/src/manifest.rs'
$shellFlags = & rg -n '"(?:-c|/C|-Command|--command)"' $manifest
foreach ($line in $shellFlags) {
    $violations.Add("shell flag: $line")
}

$cliSource = Join-Path $repoRoot 'crates/rsi-cli/src'
$mutationCommands = & rg -n '^\s*(Apply|Elevate|Install|Remove|Uninstall|Cleanup|Service)\b' $cliSource -g '*.rs'
foreach ($line in $mutationCommands) {
    $violations.Add("mutation command: $line")
}

$legacyLayer = & rg -n 'rsi[-_]rules' $sourceRoot -g '*.rs' -g 'Cargo.toml'
foreach ($line in $legacyLayer) {
    $violations.Add("legacy optimization layer: $line")
}

$rawAnalysis = & rg -n 'analyze\(&snapshot' $sourceRoot -g '*.rs'
foreach ($line in $rawAnalysis) {
    $violations.Add("unverified analysis input: $line")
}

$optimizeSource = Get-Content -Raw (Join-Path $sourceRoot 'rsi-optimize/src/lib.rs')
if ($optimizeSource -notmatch 'pub fn analyze\(verified: &VerifiedSnapshot') {
    $violations.Add('verification type gate: rsi-optimize::analyze must require VerifiedSnapshot')
}

if ($violations.Count -gt 0) {
    $violations | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'READ_ONLY_AND_LAYER_BOUNDARIES_OK'
