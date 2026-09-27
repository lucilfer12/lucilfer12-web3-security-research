$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "== w3sec Windows build =="
python --version
python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt

if (Test-Path build) { Remove-Item build -Recurse -Force }
if (Test-Path dist\w3sec.exe) { Remove-Item dist\w3sec.exe -Force }

python -m compileall -q src
python -m PyInstaller --clean --noconfirm w3sec.spec

if (-not (Test-Path dist\w3sec.exe)) {
    throw "Build completed without dist\w3sec.exe"
}

$Exe = Get-Item "dist\w3sec.exe"
$Hash = (Get-FileHash $Exe.FullName -Algorithm SHA256).Hash
$Version = (& $Exe --version).Trim()
$Commit = (git rev-parse HEAD).Trim()
$BuiltAt = (Get-Date).ToUniversalTime().ToString("o")

Set-Content "dist\w3sec.exe.sha256" "$Hash  w3sec.exe" -Encoding ascii
@(
    "product=$Version"
    "commit=$Commit"
    "built_at_utc=$BuiltAt"
    "platform=windows-x64"
    "python=$(& python --version)"
    "pyinstaller=$(& python -m PyInstaller --version)"
    "sha256=$Hash"
) | Set-Content "dist\BUILD-MANIFEST.txt" -Encoding utf8

Write-Host "Built: $($Exe.FullName)"
Write-Host "Bytes: $($Exe.Length)"
Write-Host "SHA256: $Hash"
Write-Host "Version: $Version"
