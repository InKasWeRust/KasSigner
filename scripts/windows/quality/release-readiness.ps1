# Native Windows facade for release-readiness.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/run-release-readiness.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
