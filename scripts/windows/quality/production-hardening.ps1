# Native Windows facade for production-hardening.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/run-production-hardening.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
