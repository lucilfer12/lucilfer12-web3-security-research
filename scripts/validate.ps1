$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m w3sec validate
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m w3sec inventory --json
