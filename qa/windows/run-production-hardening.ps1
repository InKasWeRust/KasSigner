[CmdletBinding()]
param(
    [int]$FuzzPasses = 100000,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$RemainingArgs
)
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Write-Host 'NOTE: production hardening is now an alias for the authoritative make qa catalog.'
Write-Host '      Physical/HIL tests remain explicit make test-hardware/workflow-* commands.'
$python = if (Get-Command python -ErrorAction SilentlyContinue) { 'python' } else { 'python3' }
& $python (Join-Path $root 'qa/windows/runner/run_all.py') --profile full --fuzz-passes $FuzzPasses @RemainingArgs
exit $LASTEXITCODE
