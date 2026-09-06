[CmdletBinding()]
param([ValidateSet('release','dev')][string]$Mode = 'release')
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
$python = Get-KasSignerPython
& $python (Join-Path $root 'tools/build/web/build_kassee_runtime.py') --mode $Mode
exit $LASTEXITCODE
