[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputDir,
    [switch]$OwnerOnly
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$mode = if ($OwnerOnly) { 'owner-only' } else { 'dual' }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$trustPolicy = Join-Path $OutputDir 'TRUST-POLICY'
if (Test-Path -LiteralPath $trustPolicy -PathType Leaf) {
    $existing = (Get-Content -LiteralPath $trustPolicy -Raw).Trim()
    if ($existing -ne $mode) {
        throw "refusing to mix secure trust policies in $OutputDir (existing=$existing requested=$mode). Use a clean output directory."
    }
}
$authorityMarker = Join-Path $OutputDir 'AUTHORITY-MODE'
if (Test-Path -LiteralPath $authorityMarker -PathType Leaf) {
    $existingAuthority = (Get-Content -LiteralPath $authorityMarker -Raw).Trim()
    if ($existingAuthority -ne $mode) {
        throw "refusing to mix secure authority modes in $OutputDir (existing=$existingAuthority requested=$mode). Use a clean output directory."
    }
}
$staleNames = if ($OwnerOnly) {
    @('kassigner-m5stack-secure-provisioning.bin', 'kassigner-m5stack-app-secureboot-signed.bin', 'kassigner-m5stack-update.ksfu')
} else {
    @('kassigner-m5stack-secure-owner-only.bin', 'kassigner-m5stack-owner-only-app-secureboot-signed.bin')
}
foreach ($name in $staleNames) {
    if (Test-Path -LiteralPath (Join-Path $OutputDir $name)) {
        $policyName = if ($OwnerOnly) { 'owner-only' } else { 'dual-authority' }
        throw "$policyName output contains a stale opposite-policy artifact $name. Use a clean output directory."
    }
}

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) { $pythonCmd = Get-Command python3 -ErrorAction Stop }
$python = $pythonCmd.Source
$packageText = Get-Content -LiteralPath (Join-Path $root 'apps/signer-firmware/Cargo.toml') -Raw
$packagePart = ($packageText -split '\[package\]', 2)[1]
$versionMatch = [regex]::Match($packagePart, '(?m)^version\s*=\s*"([^"]+)"')
if (-not $versionMatch.Success) { throw 'signer-firmware package version not found.' }
$packageVersion = $versionMatch.Groups[1].Value
$policy = @{}
foreach ($line in Get-Content -LiteralPath (Join-Path $root 'apps/signer-firmware/release-policy.env')) {
    if ($line -match '^([A-Z0-9_]+)=(.+)$') { $policy[$matches[1]] = $matches[2].Trim() }
}
foreach ($name in @('KASSIGNER_UPDATE_SEQUENCE','KASSIGNER_SECURITY_VERSION')) {
    if (-not $policy.ContainsKey($name) -or $policy[$name] -notmatch '^\d+$') { throw "invalid $name in release-policy.env" }
}
if ([int]$policy['KASSIGNER_UPDATE_SEQUENCE'] -lt 1) { throw 'KASSIGNER_UPDATE_SEQUENCE must be positive.' }
if ([int]$policy['KASSIGNER_SECURITY_VERSION'] -lt 1 -or [int]$policy['KASSIGNER_SECURITY_VERSION'] -gt 16) { throw 'KASSIGNER_SECURITY_VERSION must be 1..16 for ESP32-S3.' }

$oldFinal = $env:KASSIGNER_FINAL_IMAGE_OUT
$oldSecure = $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY
$oldMode = $env:KASSIGNER_SECURE_BOOT_AUTHORITY_MODE
$oldSigning = $env:KASSIGNER_SIGNING_KEY
try {
    if ($OwnerOnly) {
        $ownerKey = $env:KASSIGNER_OWNER_SECURE_BOOT_KEY
        if (-not $ownerKey -or -not (Test-Path -LiteralPath $ownerKey -PathType Leaf)) {
            throw 'KASSIGNER_OWNER_SECURE_BOOT_KEY must point to the owner RSA-3072 Secure Boot v2 private key.'
        }
        $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY = [IO.Path]::GetFullPath($ownerKey)
        $env:KASSIGNER_SECURE_BOOT_AUTHORITY_MODE = 'owner-only'
        Remove-Item Env:KASSIGNER_SIGNING_KEY -ErrorAction SilentlyContinue
        $app = Join-Path $OutputDir 'kassigner-m5stack-secure-owner-only.bin'
        $signedApp = Join-Path $OutputDir 'kassigner-m5stack-owner-only-app-secureboot-signed.bin'
        $env:KASSIGNER_FINAL_IMAGE_OUT = $app
        & (Join-Path $PSScriptRoot 'build_production.ps1') '--secure-owner-only'
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & (Join-Path $PSScriptRoot 'secure_bootloader/m5stack/build.ps1') $OutputDir
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & $python (Join-Path $PSScriptRoot 'secure_bootloader/m5stack/sign_app.py') $app $signedApp
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & $python (Join-Path $PSScriptRoot 'owner_authority.py') --key $ownerKey --output (Join-Path $OutputDir 'OWNERKEY.KAS')
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Set-Content -LiteralPath $trustPolicy -Value 'owner-only' -Encoding ascii
    } else {
        $secureKey = $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY
        if (-not $secureKey -or -not (Test-Path -LiteralPath $secureKey -PathType Leaf)) {
            throw 'KASSIGNER_SECURE_BOOT_SIGNING_KEY must point to the offline vendor RSA-3072 Secure Boot v2 key.'
        }
        $schnorr = $env:KASSIGNER_SIGNING_KEY
        if (-not $schnorr -or -not (Test-Path -LiteralPath $schnorr -PathType Leaf)) {
            throw 'KASSIGNER_SIGNING_KEY must point to the 32-byte Schnorr release key.'
        }
        if ((Get-Item -LiteralPath $schnorr).Length -ne 32) { throw 'Schnorr release key must be exactly 32 bytes.' }
        $env:KASSIGNER_SECURE_BOOT_AUTHORITY_MODE = 'dual'
        $app = Join-Path $OutputDir 'kassigner-m5stack-secure-provisioning.bin'
        $signedApp = Join-Path $OutputDir 'kassigner-m5stack-app-secureboot-signed.bin'
        $env:KASSIGNER_FINAL_IMAGE_OUT = $app
        & (Join-Path $PSScriptRoot 'build_production.ps1') '--secure-provisioning'
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & (Join-Path $PSScriptRoot 'secure_bootloader/m5stack/build.ps1') $OutputDir
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & $python (Join-Path $PSScriptRoot 'secure_bootloader/m5stack/sign_app.py') $app $signedApp
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & cargo run --offline --locked --manifest-path (Join-Path $root 'tools/Cargo.toml') `
            --bin gen-update-manifest --release -- `
            $signedApp $schnorr m5stack $packageVersion `
            $policy['KASSIGNER_UPDATE_SEQUENCE'] $policy['KASSIGNER_SECURITY_VERSION'] `
            (Join-Path $root 'apps/signer-firmware/partitions/m5stack-cores3.csv') `
            (Join-Path $OutputDir 'kassigner-m5stack-update.ksfu')
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Set-Content -LiteralPath $trustPolicy -Value 'dual' -Encoding ascii
    }

    $names = Get-ChildItem -LiteralPath $OutputDir -File | Where-Object {
        $_.Name -like 'kassigner-m5stack-*' -or $_.Name -in @('TRUST-POLICY','AUTHORITY-MODE') -or ($OwnerOnly -and $_.Name -eq 'OWNERKEY.KAS')
    } | Sort-Object Name
    $sumLines = foreach ($file in $names) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        "$hash  $($file.Name)"
    }
    Set-Content -LiteralPath (Join-Path $OutputDir 'SECURE-BOOT-SHA256SUMS') -Value $sumLines -Encoding ascii
    Write-Host "Prepared non-flashing CoreS3 secure release artifacts ($mode): $OutputDir"
} finally {
    if ($null -eq $oldFinal) { Remove-Item Env:KASSIGNER_FINAL_IMAGE_OUT -ErrorAction SilentlyContinue } else { $env:KASSIGNER_FINAL_IMAGE_OUT = $oldFinal }
    if ($null -eq $oldSecure) { Remove-Item Env:KASSIGNER_SECURE_BOOT_SIGNING_KEY -ErrorAction SilentlyContinue } else { $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY = $oldSecure }
    if ($null -eq $oldMode) { Remove-Item Env:KASSIGNER_SECURE_BOOT_AUTHORITY_MODE -ErrorAction SilentlyContinue } else { $env:KASSIGNER_SECURE_BOOT_AUTHORITY_MODE = $oldMode }
    if ($null -eq $oldSigning) { Remove-Item Env:KASSIGNER_SIGNING_KEY -ErrorAction SilentlyContinue } else { $env:KASSIGNER_SIGNING_KEY = $oldSigning }
}
