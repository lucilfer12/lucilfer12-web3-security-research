$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "== w3sec Windows build =="
python --version
python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt

if (Test-Path build) { Remove-Item build -Recurse -Force }
if (Test-Path dist\w3sec.exe) { Remove-Item dist\w3sec.exe -Force }
if (Test-Path dist\w3sec-cli.exe) { Remove-Item dist\w3sec-cli.exe -Force }
if (Test-Path dist\w3sec-windows-x64.zip) { Remove-Item dist\w3sec-windows-x64.zip -Force }

python -m compileall -q src
python -m PyInstaller --clean --noconfirm w3sec-gui.spec
python -m PyInstaller --clean --noconfirm w3sec-cli.spec

if (-not (Test-Path dist\w3sec.exe)) { throw "GUI build completed without dist\w3sec.exe" }
if (-not (Test-Path dist\w3sec-cli.exe)) { throw "CLI build completed without dist\w3sec-cli.exe" }

$Gui = Get-Item "dist\w3sec.exe"
$Cli = Get-Item "dist\w3sec-cli.exe"
$GuiHash = (Get-FileHash $Gui.FullName -Algorithm SHA256).Hash
$CliHash = (Get-FileHash $Cli.FullName -Algorithm SHA256).Hash
$Version = (& python -c "import sys; sys.path.insert(0, 'src'); from w3sec.gui import APP_VERSION; print(APP_VERSION)").Trim()
$Commit = (git rev-parse HEAD).Trim()
$BuiltAt = (Get-Date).ToUniversalTime().ToString("o")

Set-Content "dist\w3sec.exe.sha256" "$GuiHash  w3sec.exe" -Encoding ascii
Set-Content "dist\w3sec-cli.exe.sha256" "$CliHash  w3sec-cli.exe" -Encoding ascii
@(
    "product=W3Sec Research OS"
    "version=$Version"
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
Write-Host "Version: $Version"

$Bundle = Join-Path $Root "w3sec-windows-x64.zip"
if (Test-Path $Bundle) { Remove-Item $Bundle -Force }
Compress-Archive -Path @("dist\w3sec.exe","dist\w3sec-cli.exe","dist\w3sec.exe.sha256","dist\w3sec-cli.exe.sha256","dist\BUILD-MANIFEST.txt") -DestinationPath $Bundle -Force
Move-Item $Bundle "dist\w3sec-windows-x64.zip" -Force
Write-Host "Bundle: $((Get-Item 'dist\w3sec-windows-x64.zip').FullName)"
