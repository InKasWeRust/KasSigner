# Native Windows facade for firmware-build.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'tools/build/firmware/build_with_hash.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
