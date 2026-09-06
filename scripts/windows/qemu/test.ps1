$runScript = Join-Path $PSScriptRoot 'run.ps1'
# Do not splat an empty $args collection: Windows PowerShell 5.1 can bind it as a phantom null positional argument.
if (@($args).Count -eq 0) {
    & $runScript -TestOnly
} else {
    & $runScript -TestOnly @args
}
exit $LASTEXITCODE
