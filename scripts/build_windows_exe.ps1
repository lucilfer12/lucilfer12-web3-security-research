$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "== ATLAS Windows build =="
python --version
python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt

Get-Process | Where-Object { $_.ProcessName -in @("ATLAS", "atlas-cli") } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
if (Test-Path build) { Remove-Item build -Recurse -Force }
foreach ($legacy in @(
    "dist\ATLAS.exe", "dist\atlas-cli.exe", "dist\ATLAS-windows-x64.zip",
    "dist\ATLAS.exe.sha256", "dist\atlas-cli.exe.sha256",
    "dist\w3sec.exe", "dist\w3sec-cli.exe", "dist\w3sec-windows-x64.zip",
    "dist\w3sec.exe.sha256", "dist\w3sec-cli.exe.sha256"
)) {
    if (Test-Path $legacy) { Remove-Item $legacy -Force }
}

python -m compileall -q src
python -m PyInstaller --clean --noconfirm w3sec-gui.spec
python -m PyInstaller --clean --noconfirm w3sec-cli.spec

if (-not (Test-Path dist\ATLAS.exe)) { throw "GUI build completed without dist\ATLAS.exe" }
if (-not (Test-Path dist\atlas-cli.exe)) { throw "CLI build completed without dist\atlas-cli.exe" }

$Gui = Get-Item "dist\ATLAS.exe"
$Cli = Get-Item "dist\atlas-cli.exe"
$GuiHash = (Get-FileHash $Gui.FullName -Algorithm SHA256).Hash
$CliHash = (Get-FileHash $Cli.FullName -Algorithm SHA256).Hash
$Lifecycle = "continuous-development"
$Commit = (git rev-parse HEAD).Trim()
$BuiltAt = (Get-Date).ToUniversalTime().ToString("o")

Set-Content "dist\ATLAS.exe.sha256" "$GuiHash  ATLAS.exe" -Encoding ascii
Set-Content "dist\atlas-cli.exe.sha256" "$CliHash  atlas-cli.exe" -Encoding ascii
@(
    "product=ATLAS"
    "lifecycle=$Lifecycle"
    "commit=$Commit"
    "built_at_utc=$BuiltAt"
    "platform=windows-x64"
    "python=$(& python --version)"
    "pyinstaller=$(& python -m PyInstaller --version)"
    "gui_sha256=$GuiHash"
    "cli_sha256=$CliHash"
) | Set-Content "dist\BUILD-MANIFEST.txt" -Encoding utf8

Write-Host "Built GUI: $($Gui.FullName)"
Write-Host "GUI bytes: $($Gui.Length)"
Write-Host "GUI SHA256: $GuiHash"
Write-Host "Built CLI: $($Cli.FullName)"
Write-Host "CLI bytes: $($Cli.Length)"
Write-Host "CLI SHA256: $CliHash"
Write-Host "Lifecycle: $Lifecycle"

$Bundle = Join-Path $Root "ATLAS-windows-x64.zip"
if (Test-Path $Bundle) { Remove-Item $Bundle -Force }
Compress-Archive -Path @("dist\ATLAS.exe","dist\atlas-cli.exe","dist\ATLAS.exe.sha256","dist\atlas-cli.exe.sha256","dist\BUILD-MANIFEST.txt") -DestinationPath $Bundle -Force
Move-Item $Bundle "dist\ATLAS-windows-x64.zip" -Force
Write-Host "Bundle: $((Get-Item 'dist\ATLAS-windows-x64.zip').FullName)"
