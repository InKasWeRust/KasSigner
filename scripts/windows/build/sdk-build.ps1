# Native Windows facade for standalone SDK WASM build.
& (Join-Path $PSScriptRoot '../lib/_invoke.ps1') -Target 'crates/kassigner-sdk/build.ps1' -CommandArguments ([string[]]$args)
exit $LASTEXITCODE
