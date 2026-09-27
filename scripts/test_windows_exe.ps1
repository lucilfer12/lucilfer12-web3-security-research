$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Gui = Join-Path $Root "dist\w3sec.exe"
$Cli = Join-Path $Root "dist\w3sec-cli.exe"
if (-not (Test-Path $Gui)) { throw "Missing $Gui" }
if (-not (Test-Path $Cli)) { throw "Missing $Cli" }

Write-Host "== CLI version =="
& $Cli --version
if ($LASTEXITCODE -ne 0) { throw "CLI version failed" }

Write-Host "== CLI validation =="
& $Cli validate $Root
if ($LASTEXITCODE -ne 0) { throw "CLI validation failed" }

Write-Host "== CLI audit =="
$audit = & $Cli audit $Root --json | ConvertFrom-Json
if (-not $audit.ok) { throw "CLI audit is not green" }
Write-Host "audit.ok=$($audit.ok)"
Write-Host "nodes=$($audit.graph.node_count) edges=$($audit.graph.edge_count)"
Write-Host "federation_candidates=$($audit.federation.candidate_record_count)"
Write-Host "== GUI packaged self-test =="
$self = Start-Process -FilePath $Gui -WorkingDirectory $Root -ArgumentList "--self-test" -Wait -PassThru
if ($self.ExitCode -ne 0) { throw "GUI self-test failed with exit code $($self.ExitCode)" }

$log = Join-Path $env:APPDATA "W3Sec\self-test.log"
if (-not (Test-Path $log)) { throw "GUI self-test log missing: $log" }
$logText = Get-Content $log -Raw
if ($logText -notmatch "SELF-TEST: OK") { throw "GUI self-test log does not report OK" }
Write-Host $logText

$guiHash=(Get-FileHash $Gui -Algorithm SHA256).Hash
$cliHash=(Get-FileHash $Cli -Algorithm SHA256).Hash
Write-Host "GUI SHA256=$guiHash"
Write-Host "CLI SHA256=$cliHash"
