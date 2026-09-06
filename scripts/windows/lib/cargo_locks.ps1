# Transactional host Cargo.lock reconciliation under the repository-pinned stable Cargo.
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-KasSignerLockSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-KasSignerLockPackageCount {
    param([Parameter(Mandatory = $true)][string]$Path)
    # Cargo.lock writes every package as an array-of-tables entry. Counting
    # those headers avoids imposing the QA Python parser requirement on
    # standalone Rust commands such as `make sdk`.
    return @(Select-String -LiteralPath $Path -Pattern '^\s*\[\[package\]\]\s*$').Count
}

function Invoke-KasSignerHostCargoMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Manifest,
        [string[]]$ExtraArguments = @(),
        [switch]$Capture
    )
    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
    $environment = @{
        'RUSTUP_TOOLCHAIN' = $env:KASSIGNER_STABLE_RUST
        'CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS' = 'fallback'
        'PATH' = (Join-Path $cargoHome 'bin') + [IO.Path]::PathSeparator + $env:PATH
    }
    foreach ($name in @('RUSTC','RUSTDOC','CARGO_BUILD_TARGET','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS')) {
        $environment[$name] = $null
    }
    $arguments = @('run', $env:KASSIGNER_STABLE_RUST, 'cargo', 'metadata', '--manifest-path', (Join-Path $Root $Manifest), '--format-version', '1') + $ExtraArguments
    if ($Capture) { return Invoke-KasSignerCapture -Command 'rustup' -Arguments $arguments -WorkingDirectory $Root -Environment $environment }
    Invoke-KasSignerCommand -Command 'rustup' -Arguments $arguments -WorkingDirectory $Root -Environment $environment | Out-Null
}

function Repair-KasSignerOneHostLock {
    param([string]$Root,[string]$Label,[string]$Manifest,[string]$Lock)
    $lockPath = Join-Path $Root $Lock
    $verify = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest $Manifest -ExtraArguments @('--locked') -Capture
    if ($verify.ExitCode -eq 0) { return }
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw "Expected workspace lockfile is missing: $Lock" }
    $backup = [IO.Path]::GetTempFileName()
    Copy-Item -LiteralPath $lockPath -Destination $backup -Force
    try {
        $oldHash = Get-KasSignerLockSha256 $lockPath
        $oldCount = Get-KasSignerLockPackageCount $lockPath
        Write-Host "$Label Cargo.lock is stale under pinned Cargo $($env:KASSIGNER_STABLE_RUST); reconciling transactionally."
        Write-Host "  Existing: sha256=$oldHash packages=$oldCount"
        $offline = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest $Manifest -ExtraArguments @('--offline') -Capture
        if ($offline.ExitCode -ne 0) {
            Copy-Item -LiteralPath $backup -Destination $lockPath -Force
            Write-Host '  Offline reconciliation was insufficient; retrying with registry access.'
            $online = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest $Manifest -Capture
            if ($online.ExitCode -ne 0) {
                Copy-Item -LiteralPath $backup -Destination $lockPath -Force
                throw "Cargo could not reconcile $Lock.`n$($online.Output)"
            }
        }
        $final = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest $Manifest -ExtraArguments @('--locked') -Capture
        if ($final.ExitCode -ne 0) {
            Copy-Item -LiteralPath $backup -Destination $lockPath -Force
            throw "Reconciled $Lock still fails Cargo --locked verification.`n$($final.Output)"
        }
        Write-Host "  Reconciled: sha256=$(Get-KasSignerLockSha256 $lockPath) packages=$(Get-KasSignerLockPackageCount $lockPath)"
    } finally { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
}

function Test-KasSignerMetadataRustCompatibility {
    param([Parameter(Mandatory = $true)][string]$Json,[Parameter(Mandatory = $true)][string]$MaxRust)
    # Windows PowerShell 5.1 ConvertFrom-Json rejects valid JSON objects whose
    # keys differ only by case (for example Cargo package metadata containing
    # both "Default" and "default"). Parse Cargo's case-sensitive JSON with
    # Python instead and inspect only package rust_version fields.
    $python = Get-KasSignerPython
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
    $checker = Join-Path $root 'scripts/common/lib/cargo_metadata_compat.py'
    if (-not (Test-Path -LiteralPath $checker -PathType Leaf)) { throw "Missing Cargo metadata compatibility checker: $checker" }
    $metadataPath = [IO.Path]::GetTempFileName()
    try {
        Write-KasSignerUtf8NoBom -Path $metadataPath -Text $Json
        $result = Invoke-KasSignerCapture -Command $python -Arguments @($checker,'--metadata',$metadataPath,'--max-rust',$MaxRust) -WorkingDirectory $root
        if ($result.ExitCode -eq 0) { return $true }
        if ($result.ExitCode -eq 1) {
            @($result.Output -split '\r?\n') | Where-Object { $_ } | ForEach-Object { Write-Warning $_ }
            return $false
        }
        throw "Cargo metadata compatibility check failed with exit code $($result.ExitCode).`n$($result.Output)"
    } finally {
        Remove-Item -LiteralPath $metadataPath -Force -ErrorAction SilentlyContinue
    }
}

function Repair-KasSignerKasseeMsrvLock {
    param([Parameter(Mandatory = $true)][string]$Root)
    $lock = Join-Path $Root 'apps/kassee-web/Cargo.lock'
    $metadata = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest 'apps/kassee-web/Cargo.toml' -ExtraArguments @('--filter-platform','wasm32-unknown-unknown','--locked') -Capture
    if ($metadata.ExitCode -eq 0 -and (Test-KasSignerMetadataRustCompatibility -Json $metadata.Output -MaxRust $env:KASSIGNER_REPRO_HOST_RUST)) { return }
    $backup = [IO.Path]::GetTempFileName()
    Copy-Item -LiteralPath $lock -Destination $backup -Force
    try {
        Write-Host "KasSee Web Cargo.lock is not compatible with reproducible Rust $($env:KASSIGNER_REPRO_HOST_RUST); resolving an MSRV-compatible lock transactionally."
        Write-Host "  Existing: sha256=$(Get-KasSignerLockSha256 $lock) packages=$(Get-KasSignerLockPackageCount $lock)"
        Remove-Item -LiteralPath $lock -Force
        $offline = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest 'apps/kassee-web/Cargo.toml' -ExtraArguments @('--offline') -Capture
        if ($offline.ExitCode -ne 0) {
            Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue
            Write-Host '  Offline MSRV reconciliation was insufficient; retrying with registry access.'
            $online = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest 'apps/kassee-web/Cargo.toml' -Capture
            if ($online.ExitCode -ne 0) { Copy-Item $backup $lock -Force; throw "Cargo could not resolve an MSRV-compatible KasSee lock.`n$($online.Output)" }
        }
        $final = Invoke-KasSignerHostCargoMetadata -Root $Root -Manifest 'apps/kassee-web/Cargo.toml' -ExtraArguments @('--filter-platform','wasm32-unknown-unknown','--locked') -Capture
        if ($final.ExitCode -ne 0 -or -not (Test-KasSignerMetadataRustCompatibility -Json $final.Output -MaxRust $env:KASSIGNER_REPRO_HOST_RUST)) {
            Copy-Item $backup $lock -Force
            throw "MSRV-reconciled KasSee lock is not valid under reproducible Rust $($env:KASSIGNER_REPRO_HOST_RUST)."
        }
        Write-Host "  MSRV-compatible: sha256=$(Get-KasSignerLockSha256 $lock) packages=$(Get-KasSignerLockPackageCount $lock)"
    } finally { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
}

function Repair-KasSignerHostLocks {
    param([Parameter(Mandatory = $true)][string]$Root)
    Require-KasSignerCommand rustup 'Install rustup for Windows and reopen PowerShell.' | Out-Null
    Get-KasSignerPython | Out-Null
    $probe = Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run',$env:KASSIGNER_STABLE_RUST,'cargo','--version')
    if ($probe.ExitCode -ne 0) {
        Write-Host "==> Installing pinned host Rust $($env:KASSIGNER_STABLE_RUST) for lock verification"
        Invoke-KasSignerCommand -Command 'rustup' -Arguments @('toolchain','install',$env:KASSIGNER_STABLE_RUST,'--profile','minimal') | Out-Null
    }
    Repair-KasSignerOneHostLock $Root 'Root workspace' 'Cargo.toml' 'Cargo.lock'
    Repair-KasSignerOneHostLock $Root 'Signer firmware workspace' 'apps/signer-firmware/Cargo.toml' 'apps/signer-firmware/Cargo.lock'
    Repair-KasSignerOneHostLock $Root 'KasSee Web' 'apps/kassee-web/Cargo.toml' 'apps/kassee-web/Cargo.lock'
    Repair-KasSignerKasseeMsrvLock $Root
    Repair-KasSignerOneHostLock $Root 'External rqrr workspace' 'external/rqrr-nostd/Cargo.toml' 'external/rqrr-nostd/Cargo.lock'
    Repair-KasSignerOneHostLock $Root 'Funded/tools workspace' 'tools/Cargo.toml' 'tools/Cargo.lock'
    Repair-KasSignerOneHostLock $Root 'QA workspace' 'qa/Cargo.toml' 'qa/Cargo.lock'
}
