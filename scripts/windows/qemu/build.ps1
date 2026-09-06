$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $PSScriptRoot '../lib/qemu-common.ps1')
Initialize-KasSignerQemuEnvironment
& (Join-Path $root 'tools/firmware/qemu/build.ps1')
exit $LASTEXITCODE
