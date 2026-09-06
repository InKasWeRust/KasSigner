# Native Windows facade for run-all.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/run-all.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
