[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$SkipAndroidEmulator
)
# KasSigner native Windows developer bootstrap façade.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
try {
    & (Join-Path $root 'scripts/windows/install/install.ps1') @PSBoundParameters
    exit 0
} catch {
    Write-Error $_
    exit 1
}
