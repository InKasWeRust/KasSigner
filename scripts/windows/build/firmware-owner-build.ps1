[CmdletBinding()]
param([Parameter(Position=0)][string]$OutputDir = '')
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
& (Join-Path $root 'tools/build/firmware/build_owner_firmware.ps1') $OutputDir
exit $LASTEXITCODE
