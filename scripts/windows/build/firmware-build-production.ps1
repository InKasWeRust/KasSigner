# Native Windows facade for firmware-build-production.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'tools/build/firmware/build_production.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
