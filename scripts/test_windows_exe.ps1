$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Root "dist\w3sec.exe"
if (-not (Test-Path $Exe)) { throw "Missing $Exe. Run build_windows_exe.ps1 first." }

Write-Host "== EXE version =="
& $Exe --version

Write-Host "== EXE help =="
& $Exe --help | Select-Object -First 20

Write-Host "== EXE validation against repository =="
& $Exe validate $Root

if ($LASTEXITCODE -ne 0) { throw "w3sec.exe validation failed with exit code $LASTEXITCODE" }

Write-Host "== EXE audit smoke test =="
$audit = & $Exe audit $Root --json | ConvertFrom-Json
if (-not $audit.ok) { throw "w3sec.exe audit is not green" }
Write-Host "audit.ok=$($audit.ok)"
Write-Host "nodes=$($audit.graph.node_count) edges=$($audit.graph.edge_count)"
Write-Host "federation_candidates=$($audit.federation.candidate_record_count)"
