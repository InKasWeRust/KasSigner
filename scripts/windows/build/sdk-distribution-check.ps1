[CmdletBinding()]
param([switch]$RegistryDryRun)

$ScriptDir = $PSScriptRoot
$Root = [IO.Path]::GetFullPath((Join-Path $ScriptDir '../../..'))
. (Join-Path $Root 'scripts/windows/lib/common.ps1')
Import-KasSignerToolchains $Root
foreach ($command in @('rustup', 'tar', 'npm')) {
    Require-KasSignerCommand $command "Install $command and reopen PowerShell." | Out-Null
}

$Stage = Join-Path $Root 'target/sdk-distribution-check'
$CrateStage = Join-Path $Stage 'crates'
$Unpacked = Join-Path $Stage 'unpacked'
$Consumer = Join-Path $Stage 'consumer'
Remove-KasSignerPath $Stage
New-Item -ItemType Directory -Force -Path $CrateStage, $Unpacked, (Join-Path $Consumer 'src') | Out-Null

function Invoke-StableCargo {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $environment = @{
        'PATH' = (Join-Path $cargoHome 'bin') + [IO.Path]::PathSeparator + $env:PATH
        'RUSTUP_TOOLCHAIN' = $env:KASSIGNER_STABLE_RUST
        'RUSTC' = $null; 'RUSTDOC' = $null; 'CARGO_BUILD_TARGET' = $null
        'RUSTFLAGS' = $null; 'CARGO_ENCODED_RUSTFLAGS' = $null
    }
    Invoke-KasSignerCommand -Command 'rustup' -Arguments (@('run', $env:KASSIGNER_STABLE_RUST, 'cargo') + $Arguments) -WorkingDirectory $Root -Environment $environment | Out-Null
}

foreach ($name in @('shared-signer', 'kassigner-protocol', 'kassigner-sdk')) {
    Invoke-StableCargo @('package', '--manifest-path', (Join-Path $Root 'Cargo.toml'), '--locked', '--package', $name, '--allow-dirty', '--no-verify')
    $archive = Join-Path $Root "target/package/$name-2.0.0.crate"
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw "missing packaged crate $archive" }
    Copy-Item -LiteralPath $archive -Destination $CrateStage
    & tar -xzf $archive -C $Unpacked
    if ($LASTEXITCODE) { throw "failed to unpack $archive" }
}

Invoke-StableCargo @('check', '--manifest-path', (Join-Path $Root 'Cargo.toml'), '--locked', '--package', 'offline-signer')
Write-Host 'PASS: offline-signer consumes the no_std kassigner-protocol wire core'

$nativeTree = (& rustup run $env:KASSIGNER_STABLE_RUST cargo tree --manifest-path (Join-Path $Root 'Cargo.toml') --locked --package kassigner-sdk --edges normal --no-default-features --features native | Out-String)
if ($LASTEXITCODE) { throw 'failed to inspect native kassigner-sdk dependency graph' }
if ($nativeTree -match '(?m)^.*(?:wasm-bindgen|js-sys) v') { throw 'native kassigner-sdk dependency graph pulled WASM-only dependencies' }
Write-Host 'PASS: native SDK dependency graph excludes wasm-bindgen/js-sys'

$expected = @{
    'shared-signer' = $null
    'kassigner-protocol' = @('shared-signer', '=2.0.0')
    'kassigner-sdk' = @('kassigner-protocol', '=2.0.0')
}
foreach ($name in $expected.Keys) {
    $manifest = Join-Path $Unpacked "$name-2.0.0/Cargo.toml"
    $text = Get-Content -LiteralPath $manifest -Raw
    if ($text -match '(?m)^path\s*=') { throw "packaged dependency retained a path: $manifest" }
    if ($text -notmatch "(?m)^name\s*=\s*`"$([regex]::Escape($name))`"" -or $text -notmatch '(?m)^version\s*=\s*"2\.0\.0"') {
        throw "normalized package identity mismatch: $manifest"
    }
    if ($text -notmatch '(?m)^license\s*=\s*"MIT OR Apache-2\.0"') { throw "public SDK crate is not dual MIT/Apache: $manifest" }
    foreach ($licenseName in @('LICENSE-MIT', 'LICENSE-APACHE')) {
        if (-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $manifest) $licenseName) -PathType Leaf)) {
            throw "packaged crate is missing ${licenseName}: $manifest"
        }
    }
    $dependency = $expected[$name]
    if ($dependency) {
        $depName = [regex]::Escape($dependency[0])
        if ($text -notmatch "(?ms)\[dependencies\.$depName\].*?version\s*=\s*`"=2\.0\.0`"") {
            throw "$name packaged dependency metadata is not pinned to =2.0.0 for $($dependency[0])"
        }
    }
}
Write-Host 'PASS: normalized crates contain registry-ready dependency metadata'

function Toml-Path([string]$Path) { return ([IO.Path]::GetFullPath($Path)).Replace('\', '/') }
$sharedPath = Toml-Path (Join-Path $Unpacked 'shared-signer-2.0.0')
$protocolPath = Toml-Path (Join-Path $Unpacked 'kassigner-protocol-2.0.0')
$sdkPath = Toml-Path (Join-Path $Unpacked 'kassigner-sdk-2.0.0')
$consumerToml = @"
[package]
name = "kassigner-sdk-package-consumer"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
kassigner-sdk = "=2.0.0"
kassigner-protocol = "=2.0.0"

[patch.crates-io]
shared-signer = { path = "$sharedPath" }
kassigner-protocol = { path = "$protocolPath" }
kassigner-sdk = { path = "$sdkPath" }
"@
Set-Content -LiteralPath (Join-Path $Consumer 'Cargo.toml') -Value $consumerToml -Encoding UTF8
Set-Content -LiteralPath (Join-Path $Consumer 'src/main.rs') -Value @'
use kassigner_sdk::Network;
fn main() {
    let _network = Network::Mainnet;
}
'@ -Encoding UTF8
Invoke-StableCargo @('check', '--manifest-path', (Join-Path $Consumer 'Cargo.toml'))
Write-Host 'PASS: packaged crates compile as an external consumer graph'

& (Join-Path $Root 'crates/kassigner-protocol/build.ps1')
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& (Join-Path $Root 'crates/kassigner-sdk/build.ps1')
if ($LASTEXITCODE) { exit $LASTEXITCODE }
foreach ($packageDir in @((Join-Path $Root 'target/sdk/kassigner-protocol/pkg'), (Join-Path $Root 'target/sdk/kassigner-sdk/pkg'))) {
    Push-Location $packageDir
    try {
        & npm pack --dry-run | Out-Null
        if ($LASTEXITCODE) { throw "npm pack dry-run failed in $packageDir" }
    } finally { Pop-Location }
}
Write-Host 'PASS: generated WASM/npm packages pass npm pack dry-run'

if ($RegistryDryRun) {
    foreach ($name in @('shared-signer', 'kassigner-protocol', 'kassigner-sdk')) {
        Invoke-StableCargo @('publish', '--manifest-path', (Join-Path $Root 'Cargo.toml'), '--locked', '--package', $name, '--allow-dirty', '--dry-run')
    }
    Write-Host 'PASS: Cargo registry dry-runs completed'
}
Write-Host 'PASS: KasSigner SDK distribution verification completed'
