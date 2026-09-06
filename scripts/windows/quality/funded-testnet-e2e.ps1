# Native Windows facade for funded-testnet-e2e. This gate accepts no arguments.
if (@($args).Count -ne 0) {
    [Console]::Error.WriteLine('Usage: funded-testnet-e2e')
    exit 2
}
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/run-funded-testnet-e2e.ps1'
exit $LASTEXITCODE
