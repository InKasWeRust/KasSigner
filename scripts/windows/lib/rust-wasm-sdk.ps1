[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Package,
    [Parameter(Mandatory=$true)][string]$WasmStem,
    [Parameter(Mandatory=$true)][string]$PkgDir,
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$NpmName
)
$ScriptDir = $PSScriptRoot
$Root = [IO.Path]::GetFullPath((Join-Path $ScriptDir '../../..'))
. (Join-Path $Root 'scripts/windows/lib/common.ps1')
. (Join-Path $Root 'scripts/windows/lib/cargo_locks.ps1')
Import-KasSignerToolchains $Root
Require-KasSignerCommand rustup 'Install rustup for Windows and reopen PowerShell.' | Out-Null
Repair-KasSignerOneHostLock $Root 'Root workspace' 'Cargo.toml' 'Cargo.lock'

$WasmTarget = 'wasm32-unknown-unknown'
$CacheBase = if ($env:KASSIGNER_TOOL_CACHE_DIR) { $env:KASSIGNER_TOOL_CACHE_DIR } elseif ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'KasSigner/tools' } else { Join-Path $HOME '.cache/kassigner/tools' }
$WasmToolRoot = Join-Path $CacheBase "wasm-bindgen-cli-$($env:KASSIGNER_WASM_BINDGEN_CLI_VERSION)"
$WasmBindgen = Join-Path $WasmToolRoot 'bin/wasm-bindgen.exe'
$TargetDir = Join-Path $Root "target/$Package-wasm"

$targets = Invoke-KasSignerCapture -Command 'rustup' -Arguments @('target','list','--toolchain',$env:KASSIGNER_STABLE_RUST,'--installed')
if ($targets.ExitCode -ne 0) { throw $targets.Output }
if (($targets.Output -split "`r?`n") -notcontains $WasmTarget) {
    Invoke-KasSignerCommand -Command 'rustup' -Arguments @('target','add',$WasmTarget,'--toolchain',$env:KASSIGNER_STABLE_RUST) | Out-Null
}

$expected = "wasm-bindgen $($env:KASSIGNER_WASM_BINDGEN_CLI_VERSION)"
$actual = ''
if (Test-Path -LiteralPath $WasmBindgen -PathType Leaf) {
    $version = Invoke-KasSignerCapture -Command $WasmBindgen -Arguments @('--version')
    if ($version.ExitCode -eq 0) { $actual = $version.Output.Trim() }
}
if ($actual -ne $expected) {
    Remove-KasSignerPath $WasmToolRoot
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $environment = @{ 'PATH' = (Join-Path $cargoHome 'bin') + [IO.Path]::PathSeparator + $env:PATH; 'RUSTUP_TOOLCHAIN' = $env:KASSIGNER_STABLE_RUST }
    foreach ($name in @('RUSTC','RUSTDOC','CARGO_BUILD_TARGET','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS')) { $environment[$name] = $null }
    Invoke-KasSignerCommand -Command 'rustup' -Arguments @('run',$env:KASSIGNER_STABLE_RUST,'cargo','install','wasm-bindgen-cli','--version',$env:KASSIGNER_WASM_BINDGEN_CLI_VERSION,'--locked','--root',$WasmToolRoot) -WorkingDirectory $Root -Environment $environment | Out-Null
}

$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
$buildEnvironment = @{
    'PATH' = (Join-Path $cargoHome 'bin') + [IO.Path]::PathSeparator + $env:PATH
    'RUSTUP_TOOLCHAIN' = $env:KASSIGNER_STABLE_RUST
    'CARGO_TARGET_DIR' = $TargetDir
    'RUSTC' = $null; 'RUSTDOC' = $null; 'CARGO_BUILD_TARGET' = $null; 'RUSTFLAGS' = $null; 'CARGO_ENCODED_RUSTFLAGS' = $null
}
Invoke-KasSignerCommand -Command 'rustup' -Arguments @('run',$env:KASSIGNER_STABLE_RUST,'cargo','rustc','--manifest-path',(Join-Path $Root 'Cargo.toml'),'--locked','--package',$Package,'--target',$WasmTarget,'--release','--no-default-features','--features','wasm','--crate-type=cdylib') -WorkingDirectory $Root -Environment $buildEnvironment | Out-Null

$WasmInput = Join-Path $TargetDir "$WasmTarget/release/$WasmStem.wasm"
if (-not (Test-Path -LiteralPath $WasmInput -PathType Leaf)) { throw "missing $WasmInput" }
Remove-KasSignerPath $PkgDir
New-Item -ItemType Directory -Force -Path $PkgDir | Out-Null
Copy-Item -LiteralPath (Join-Path $Root "crates/$Package/LICENSE-MIT") -Destination (Join-Path $PkgDir 'LICENSE-MIT')
Copy-Item -LiteralPath (Join-Path $Root "crates/$Package/LICENSE-APACHE") -Destination (Join-Path $PkgDir 'LICENSE-APACHE')
Invoke-KasSignerCommand -Command $WasmBindgen -Arguments @('--target','web','--out-dir',$PkgDir,'--out-name',$WasmStem,$WasmInput) -WorkingDirectory $Root | Out-Null
foreach ($name in @("$WasmStem.js","${WasmStem}_bg.wasm")) {
    $path = Join-Path $PkgDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item $path).Length -eq 0) { throw "missing $path" }
}
$packageJson = @{ name = $NpmName; version = '2.0.0'; type = 'module'; module = "./$WasmStem.js"; types = "./$WasmStem.d.ts"; license = 'MIT OR Apache-2.0'; files = @("$WasmStem.js", "$WasmStem.d.ts", "${WasmStem}_bg.wasm", "${WasmStem}_bg.wasm.d.ts", 'LICENSE-MIT', 'LICENSE-APACHE') } | ConvertTo-Json -Depth 3
Set-Content -LiteralPath (Join-Path $PkgDir 'package.json') -Value $packageJson -Encoding UTF8
Write-Host "$Label built: $(Join-Path $PkgDir "${WasmStem}_bg.wasm")"
