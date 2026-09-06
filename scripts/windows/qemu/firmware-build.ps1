# Native Windows facade for firmware-build.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'tools/firmware/qemu/build.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
