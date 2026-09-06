# Shared native Windows wrapper dispatcher. No WSL, Bash, or path translation is used.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Target,
    [Parameter()][string[]]$CommandArguments = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([System.IO.Path]::IsPathRooted($Target) -or $Target -match '(^|[\\/])\.\.([\\/]|$)') {
    throw "Invalid wrapper target: $Target"
}
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$targetPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Target))
if (-not $targetPath.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Wrapper target escapes repository root: $Target"
}
if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
    throw "Native Windows canonical script not found: $Target"
}
$powerShellHost = (Get-Process -Id $PID).Path
if (@($CommandArguments).Count -eq 0) {
    & $powerShellHost -NoProfile -ExecutionPolicy Bypass -File $targetPath
} else {
    & $powerShellHost -NoProfile -ExecutionPolicy Bypass -File $targetPath @CommandArguments
}
exit $LASTEXITCODE
