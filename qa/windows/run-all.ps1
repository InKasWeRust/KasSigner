$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
$python = Get-KasSignerPython
& $python (Join-Path $root 'qa/windows/runner/run_all.py') @args
exit $LASTEXITCODE
