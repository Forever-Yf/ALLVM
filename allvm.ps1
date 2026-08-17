$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "tools/allvm.py"

$py = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $py) {
    & $py.Source -3 $scriptPath @args
    exit $LASTEXITCODE
}

$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -ne $python) {
    & $python.Source $scriptPath @args
    exit $LASTEXITCODE
}

Write-Error "ALLVM: 未找到 Python 3.9 或更高版本。"
exit 2
