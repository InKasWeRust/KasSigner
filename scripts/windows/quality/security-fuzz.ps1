# Native Windows facade for security-fuzz.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/run-security-fuzz.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
