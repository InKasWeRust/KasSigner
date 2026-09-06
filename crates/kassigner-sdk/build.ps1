$Dir = $PSScriptRoot
$Root = [IO.Path]::GetFullPath((Join-Path $Dir '../..'))
$OutputRoot = if ($env:KASSIGNER_SDK_OUTPUT_ROOT) { $env:KASSIGNER_SDK_OUTPUT_ROOT } else { Join-Path $Root 'target/sdk' }
$PkgDir = Join-Path $OutputRoot 'kassigner-sdk/pkg'
& (Join-Path $Dir '../../scripts/windows/lib/rust-wasm-sdk.ps1') -Package 'kassigner-sdk' -WasmStem 'kassigner_sdk' -PkgDir $PkgDir -Label 'KasSigner SDK Rust/WASM' -NpmName '@kassigner/sdk'
if ($LASTEXITCODE) { exit $LASTEXITCODE }
