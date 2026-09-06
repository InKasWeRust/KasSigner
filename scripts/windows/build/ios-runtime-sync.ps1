$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
$python = Get-KasSignerPython
& $python (Join-Path $root 'tools/build/web/build_kassee_runtime.py') --mode release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $python (Join-Path $root 'tools/build/ios/sync_runtime.py')
exit $LASTEXITCODE
