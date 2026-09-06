[CmdletBinding()]
param([Parameter(Position=0)][string]$OutputDir = '')
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$key = $env:KASSIGNER_OWNER_SECURE_BOOT_KEY
if (-not $key -or -not (Test-Path -LiteralPath $key -PathType Leaf)) {
    throw 'KASSIGNER_OWNER_SECURE_BOOT_KEY must point to the owner RSA-3072 Secure Boot v2 private key.'
}
if (-not $OutputDir) { $OutputDir = Join-Path $root 'target/owner-firmware' }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('kassigner-owner-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$oldFinal = $env:KASSIGNER_FINAL_IMAGE_OUT
$oldSecure = $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY
$oldSigning = $env:KASSIGNER_SIGNING_KEY
try {
    $unsigned = Join-Path $tmp 'owner-firmware-unsigned.bin'
    $env:KASSIGNER_FINAL_IMAGE_OUT = $unsigned
    # Owner firmware is authorized by the enrolled Secure Boot RSA owner key.
    # Never inherit a vendor/development Schnorr identity from the caller.
    Remove-Item Env:KASSIGNER_SIGNING_KEY -ErrorAction SilentlyContinue
    & (Join-Path $PSScriptRoot 'build_with_hash.ps1') -Board m5stack owner-firmware --no-default-features --features m5stack,owner-firmware
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY = $key
    $python = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $python) { $python = (Get-Command python3 -ErrorAction Stop).Source }
    & $python (Join-Path $root 'tools/build/firmware/secure_bootloader/m5stack/sign_app.py') $unsigned (Join-Path $OutputDir 'OWNERFW.BIN')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $python (Join-Path $root 'tools/build/firmware/owner_authority.py') --key $key --output (Join-Path $OutputDir 'OWNERKEY.KAS')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $lines = @()
    foreach ($name in @('OWNERFW.BIN','OWNERKEY.KAS')) {
        $path = Join-Path $OutputDir $name
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        $lines += "$hash  $name"
    }
    Set-Content -LiteralPath (Join-Path $OutputDir 'SHA256SUMS') -Value $lines -Encoding ascii
    Write-Host "Owner-authority media prepared in: $OutputDir"
} finally {
    if ($null -eq $oldFinal) { Remove-Item Env:KASSIGNER_FINAL_IMAGE_OUT -ErrorAction SilentlyContinue } else { $env:KASSIGNER_FINAL_IMAGE_OUT = $oldFinal }
    if ($null -eq $oldSecure) { Remove-Item Env:KASSIGNER_SECURE_BOOT_SIGNING_KEY -ErrorAction SilentlyContinue } else { $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY = $oldSecure }
    if ($null -eq $oldSigning) { Remove-Item Env:KASSIGNER_SIGNING_KEY -ErrorAction SilentlyContinue } else { $env:KASSIGNER_SIGNING_KEY = $oldSigning }
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
