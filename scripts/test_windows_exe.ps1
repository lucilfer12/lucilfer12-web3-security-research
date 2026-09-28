$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Gui = Join-Path $Root "dist\ATLAS.exe"
$Cli = Join-Path $Root "dist\atlas-cli.exe"
if (-not (Test-Path $Gui)) { throw "Missing $Gui" }
if (-not (Test-Path $Cli)) { throw "Missing $Cli" }

Write-Host "== ATLAS CLI =="
& $Cli --version
if ($LASTEXITCODE -ne 0) { throw "CLI version failed" }

Write-Host "== CLI validation =="
& $Cli validate $Root
if ($LASTEXITCODE -ne 0) { throw "CLI validation failed" }

Write-Host "== CLI quality constitution =="
$quality = & $Cli quality $Root --json | ConvertFrom-Json
if (-not $quality.ok) { throw "CLI quality constitution is not green" }
Write-Host "quality.ok=$($quality.ok)"

Write-Host "== CLI evidence gate =="
$gate = & $Cli gate $Root --json | ConvertFrom-Json
Write-Host "gate.findings=$($gate.finding_count) validated=$($gate.validated_count)"

Write-Host "== CLI audit =="
$audit = & $Cli audit $Root --json | ConvertFrom-Json
if (-not $audit.ok) { throw "CLI audit is not green" }
Write-Host "audit.ok=$($audit.ok)"
Write-Host "nodes=$($audit.graph.node_count) edges=$($audit.graph.edge_count)"
Write-Host "federation_candidates=$($audit.federation.candidate_record_count)"
Write-Host "== CLI intake smoke test =="
$Sample = Join-Path $env:TEMP "w3sec-intake-smoke.sol"
Set-Content $Sample 'pragma solidity ^0.8.20; contract Smoke { function ping() external {} }' -Encoding utf8
$intake = & $Cli intake $Sample --os-root $Root --json | ConvertFrom-Json
if ($intake.target.kind -ne "file") { throw "CLI intake did not classify the target as a file" }
if ($intake.summary.contract_count -ne 1) { throw "CLI intake did not detect the sample contract" }

Write-Host "== GUI packaged self-test =="
$log = Join-Path $env:APPDATA "ATLAS\self-test.log"
Remove-Item $log -Force -ErrorAction SilentlyContinue
$self = Start-Process -FilePath $Gui -WorkingDirectory $Root -ArgumentList "--self-test" -PassThru
$deadline = (Get-Date).AddSeconds(120)
while ((-not $self.HasExited) -and ((Get-Date) -lt $deadline)) {
    if (Test-Path $log) {
        $selfText = Get-Content $log -Raw -ErrorAction SilentlyContinue
        if ($selfText -match "SELF-TEST: OK") { break }
    }
    Start-Sleep -Milliseconds 500
}
$selfText = if (Test-Path $log) { Get-Content $log -Raw -ErrorAction SilentlyContinue } else { "" }
if ($selfText -notmatch "SELF-TEST: OK") {
    Stop-Process -Id $self.Id -Force -ErrorAction SilentlyContinue
    throw "GUI self-test did not report OK within 120 seconds"
}
Get-Process ATLAS -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Gui } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "== GUI packaged live-process smoke test =="
$CrashLog = Join-Path $env:APPDATA "ATLAS\crash.log"
Remove-Item $CrashLog -Force -ErrorAction SilentlyContinue
$live = Start-Process -FilePath $Gui -WorkingDirectory $Root -PassThru
Start-Sleep -Seconds 5
$running = Get-Process -Id $live.Id -ErrorAction SilentlyContinue
$pathRunning = Get-Process ATLAS -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Gui }
if (-not $running -and -not $pathRunning) {
    throw "GUI exited early and no ATLAS process remains"
}
Get-Process ATLAS -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Gui } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
if (Test-Path $CrashLog) {
    $crashText = Get-Content $CrashLog -Raw -ErrorAction SilentlyContinue
    if ($crashText.Trim()) { throw "GUI crash log is non-empty after live-process smoke test: $crashText" }
}

$log = Join-Path $env:APPDATA "ATLAS\self-test.log"
if (-not (Test-Path $log)) { throw "GUI self-test log missing: $log" }
$logText = Get-Content $log -Raw
if ($logText -notmatch "SELF-TEST: OK") { throw "GUI self-test log does not report OK" }
Write-Host $logText

$guiHash=(Get-FileHash $Gui -Algorithm SHA256).Hash
$cliHash=(Get-FileHash $Cli -Algorithm SHA256).Hash
Write-Host "GUI SHA256=$guiHash"
Write-Host "CLI SHA256=$cliHash"
