[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$CargoArgs = @())

$features = 'm5stack,production'
$label = 'm5stack-production'
$requireSchnorr = $true
if ($CargoArgs.Count -gt 0) {
    if ($CargoArgs[0] -eq '--secure-provisioning') {
        $features = 'm5stack,secure-provisioning'
        $label = 'm5stack-secure-provisioning'
        if ($CargoArgs.Count -eq 1) { $CargoArgs = @() } else { $CargoArgs = $CargoArgs[1..($CargoArgs.Count - 1)] }
    } elseif ($CargoArgs[0] -eq '--secure-owner-only') {
        $features = 'm5stack,secure-owner-only'
        $label = 'm5stack-secure-owner-only'
        $requireSchnorr = $false
        if ($CargoArgs.Count -eq 1) { $CargoArgs = @() } else { $CargoArgs = $CargoArgs[1..($CargoArgs.Count - 1)] }
    }
}

if ($requireSchnorr -and (-not $env:KASSIGNER_SIGNING_KEY -or -not (Test-Path -LiteralPath $env:KASSIGNER_SIGNING_KEY -PathType Leaf))) {
    throw 'KASSIGNER_SIGNING_KEY must point to the 32-byte Schnorr firmware release key.'
}

$oldSigningKey = $env:KASSIGNER_SIGNING_KEY
try {
    if (-not $requireSchnorr) {
        Remove-Item Env:KASSIGNER_SIGNING_KEY -ErrorAction SilentlyContinue
    }
    & (Join-Path $PSScriptRoot 'build_with_hash.ps1') -Board m5stack -Label $label '--no-default-features' '--features' $features @CargoArgs
    exit $LASTEXITCODE
} finally {
    if ($null -eq $oldSigningKey) {
        Remove-Item Env:KASSIGNER_SIGNING_KEY -ErrorAction SilentlyContinue
    } else {
        $env:KASSIGNER_SIGNING_KEY = $oldSigningKey
    }
}
