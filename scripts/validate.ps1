$env:PYTHONPATH = Join-Path $PSScriptRoot "..\\src"
python -m unittest discover -s (Join-Path $PSScriptRoot "..\\tests") -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m w3sec validate (Join-Path $PSScriptRoot "..")