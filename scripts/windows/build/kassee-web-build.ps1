# Native Windows facade for kassee-web-build.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'apps/kassee-web/build.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
