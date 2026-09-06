# Native Windows facade for real-node-integration. This gate accepts no arguments.
if (@($args).Count -ne 0) {
    [Console]::Error.WriteLine('Usage: real-node-integration')
    exit 2
}
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/run-real-node-integration.ps1'
exit $LASTEXITCODE
