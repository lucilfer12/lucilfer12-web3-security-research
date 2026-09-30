$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

Write-Host "== ATLAS Windows build (active repository) =="
python --version
python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt

Get-Process | Where-Object { $_.ProcessName -in @("ATLAS", "atlas-cli") } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300

$Commit = (git -C $Root rev-parse HEAD).Trim()
$BranchRaw = git -C $Root branch --show-current
$Branch = if ($null -ne $BranchRaw) { $BranchRaw.Trim() } else { "" }
if ([string]::IsNullOrWhiteSpace($Branch)) {
    $Branch = "detached:$((git -C $Root rev-parse --short HEAD).Trim())"
}
$changed = @(git -C $Root status --porcelain=v1 --untracked-files=all)
Write-Host "Build source: $Root"
Write-Host "Branch: $Branch"
Write-Host "Commit: $Commit"
Write-Host "Working-tree changes: $($changed.Count)"

# Build directly from the active repository tree.
# No staging clone and no copy-back step.
Set-Location $Root
$env:PYTHONPATH = Join-Path $Root "src"
$env:ATLAS_FEDERATION_BASE = $Root
python -m py_compile src\w3sec\audit.py src\w3sec\atlas_ui.py src\w3sec\finding_gate.py
if ($LASTEXITCODE -ne 0) { throw "Python compile preflight failed" }

python -c "import w3sec.audit, w3sec.finding_gate; print('imports=OK')"
if ($LASTEXITCODE -ne 0) { throw "Package import preflight failed" }

python -m w3sec validate
if ($LASTEXITCODE -ne 0) { throw "Repository validation failed in active repository tree" }

python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw "Unit test suite failed in active repository tree" }

python -m PyInstaller --clean --noconfirm w3sec-gui.spec
if ($LASTEXITCODE -ne 0) { throw "GUI PyInstaller build failed" }

python -m PyInstaller --clean --noconfirm w3sec-cli.spec
if ($LASTEXITCODE -ne 0) { throw "CLI PyInstaller build failed" }

if (-not (Test-Path "dist\ATLAS.exe")) { throw "GUI output missing" }
if (-not (Test-Path "dist\atlas-cli.exe")) { throw "CLI output missing" }

Write-Host "== Packaged smoke tests =="
& ".\dist\atlas-cli.exe" --version
if ($LASTEXITCODE -ne 0) { throw "Packaged CLI --version failed" }

# Real packaged audit smoke test: a UTF-8-BOM Solidity file inside ZIP must be
# extracted, parsed, scanned, and serialized without encoding corruption.
$SmokeWork = Join-Path $env:TEMP ("ATLAS-packaged-smoke-" + [guid]::NewGuid().ToString("N"))
$SmokeDir = Join-Path $SmokeWork "fixture"
$SmokeZip = Join-Path $SmokeWork "packaged-smoke.zip"
$SmokeJson = Join-Path $SmokeWork "packaged-smoke.json"
New-Item -ItemType Directory -Force $SmokeWork | Out-Null
$SmokeDirPosix = $SmokeDir -replace '\\','/'
$SmokeZipPosix = $SmokeZip -replace '\\','/'
$SmokeJsonPosix = $SmokeJson -replace '\\','/'
New-Item -ItemType Directory -Force $SmokeDir | Out-Null
$SmokePy = Join-Path $SmokeWork "make_smoke.py"
@'
from pathlib import Path
import zipfile

root = Path(r"__SMOKE_DIR__")
source = root / "Risky.sol"
source.write_text(
    "pragma solidity ^0.8.20;\n"
    "contract Risky { function f() public { require(tx.origin == msg.sender); } }\n",
    encoding="utf-8-sig",
)
with zipfile.ZipFile(r"__SMOKE_ZIP__", "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.write(source, "Risky.sol")
'@.Replace("__SMOKE_DIR__", $SmokeDirPosix).Replace("__SMOKE_ZIP__", $SmokeZipPosix) | Set-Content $SmokePy -Encoding utf8
python $SmokePy
if ($LASTEXITCODE -ne 0) { throw "Packaged audit smoke fixture creation failed" }
$AuditPy = Join-Path $SmokeWork "run_smoke_audit.py"
@'
import subprocess
import sys

exe = sys.argv[1]
archive = sys.argv[2]
repo = sys.argv[3]
out_path = sys.argv[4]
proc = subprocess.run(
    [exe, "audit-contract", archive, "--os-root", repo, "--json"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
)
if proc.returncode != 0:
    sys.stderr.buffer.write(proc.stderr)
    raise SystemExit(proc.returncode or 1)
with open(out_path, "wb") as handle:
    handle.write(proc.stdout)
'@ | Set-Content $AuditPy -Encoding utf8
python $AuditPy (Join-Path $Root "dist\atlas-cli.exe") $SmokeZip $Root $SmokeJson
if ($LASTEXITCODE -ne 0) { throw "Packaged CLI audit smoke test failed" }
$SmokeCheck = @'
import json
from pathlib import Path

path = Path(r"__SMOKE_JSON__")
raw = path.read_text(encoding="utf-8")
if "\ufeff" in raw:
    raise SystemExit("BOM leaked into packaged audit JSON")
report = json.loads(raw)
summary = report["summary"]
assert report["target"]["archive_format"] == "zip", report["target"]
assert summary["file_count"] == 1, summary
assert summary["source_file_count"] == 1, summary
assert summary["contract_count"] == 1, summary
assert summary["function_count"] == 1, summary
assert summary["finding_count"] == 1, summary
assert summary["engine_finding_count"] == 1, summary
assert any(
    item.get("engine") == "atlas-rules"
    and item.get("signal") == "tx_origin"
    for item in report["engine_scan"]["engine_findings"]
), report["engine_scan"]
print("PACKAGED AUDIT SMOKE: OK")
'@.Replace("__SMOKE_JSON__", $SmokeJsonPosix) | Set-Content (Join-Path $SmokeWork "check_smoke.py") -Encoding utf8
python (Join-Path $SmokeWork "check_smoke.py")
if ($LASTEXITCODE -ne 0) { throw "Packaged audit smoke assertions failed" }
Remove-Item $SmokeWork -Recurse -Force -ErrorAction SilentlyContinue

$selfTest = Start-Process -FilePath ".\dist\ATLAS.exe" -WorkingDirectory $Root -ArgumentList "--self-test" -PassThru
if (-not $selfTest.WaitForExit(120000)) {
    Stop-Process -Id $selfTest.Id -Force -ErrorAction SilentlyContinue
    throw "Packaged GUI self-test timed out after 120 seconds"
}
if ($selfTest.ExitCode -ne 0) { throw "Packaged GUI self-test failed with exit code $($selfTest.ExitCode)" }

Set-Location $Root
$Out = Join-Path $Root "dist"
New-Item -ItemType Directory -Force $Out | Out-Null

$Gui = Get-Item (Join-Path $Out "ATLAS.exe")
$Cli = Get-Item (Join-Path $Out "atlas-cli.exe")
$GuiHash = (Get-FileHash $Gui.FullName -Algorithm SHA256).Hash
$CliHash = (Get-FileHash $Cli.FullName -Algorithm SHA256).Hash
$BuiltAt = (Get-Date).ToUniversalTime().ToString("o")

Set-Content (Join-Path $Out "ATLAS.exe.sha256") "$GuiHash  ATLAS.exe" -Encoding ascii
Set-Content (Join-Path $Out "atlas-cli.exe.sha256") "$CliHash  atlas-cli.exe" -Encoding ascii
@(
    "product=ATLAS"
    "lifecycle=continuous-development"
    "commit=$Commit"
    "built_at_utc=$BuiltAt"
    "platform=windows-x64"
    "python=$(& python --version)"
    "pyinstaller=$(& python -m PyInstaller --version)"
    "gui_sha256=$GuiHash"
    "cli_sha256=$CliHash"
    "build_source=active-repository"
    "working_tree_changes=$($changed.Count)"
) | Set-Content (Join-Path $Out "BUILD-MANIFEST.txt") -Encoding utf8

$Bundle = Join-Path $Out "ATLAS-windows-x64.zip"
if (Test-Path $Bundle) { Remove-Item $Bundle -Force }
Compress-Archive -Path @(
    (Join-Path $Out "ATLAS.exe"),
    (Join-Path $Out "atlas-cli.exe"),
    (Join-Path $Out "ATLAS.exe.sha256"),
    (Join-Path $Out "atlas-cli.exe.sha256"),
    (Join-Path $Out "BUILD-MANIFEST.txt")
) -DestinationPath $Bundle -Force

Write-Host "Built GUI: $($Gui.FullName)"
Write-Host "GUI bytes: $($Gui.Length)"
Write-Host "GUI SHA256: $GuiHash"
Write-Host "Built CLI: $($Cli.FullName)"
Write-Host "CLI bytes: $($Cli.Length)"
Write-Host "CLI SHA256: $CliHash"
Write-Host "Build source: $Root"
Write-Host "== ATLAS Windows build complete =="
