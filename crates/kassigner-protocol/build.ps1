$Dir = $PSScriptRoot
$Root = [IO.Path]::GetFullPath((Join-Path $Dir '../..'))
$OutputRoot = if ($env:KASSIGNER_SDK_OUTPUT_ROOT) { $env:KASSIGNER_SDK_OUTPUT_ROOT } else { Join-Path $Root 'target/sdk' }
$PkgDir = Join-Path $OutputRoot 'kassigner-protocol/pkg'
& (Join-Path $Dir '../../scripts/windows/lib/rust-wasm-sdk.ps1') -Package 'kassigner-protocol' -WasmStem 'kassigner_protocol' -PkgDir $PkgDir -Label 'KasSigner protocol Rust/WASM' -NpmName '@kassigner/protocol'
if ($LASTEXITCODE) { exit $LASTEXITCODE }
