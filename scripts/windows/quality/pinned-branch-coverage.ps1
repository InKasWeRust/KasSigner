# Native Windows facade for pinned-branch-coverage.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'qa/windows/run-pinned-branch-coverage.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
