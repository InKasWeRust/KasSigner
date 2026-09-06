[CmdletBinding()]
param([switch]$TestOnly,[Parameter(ValueFromRemainingArguments=$true)][string[]]$RemainingArgs)
# Windows PowerShell 5.1 can bind a phantom null/empty element for ValueFromRemainingArguments.
# Normalize those binder artifacts before rejecting genuine unsupported arguments.
$unsupportedArgs = @($RemainingArgs | Where-Object { -not [string]::IsNullOrEmpty($_) })
if ($unsupportedArgs.Count -gt 0) { [Console]::Error.WriteLine("ERROR: unsupported QEMU run argument: $($unsupportedArgs[0])"); exit 2 }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $PSScriptRoot '../lib/qemu-common.ps1')
Initialize-KasSignerQemuEnvironment
& (Join-Path $root 'tools/firmware/qemu/build.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$python = Get-KasSignerPython
$arguments = @((Join-Path $root 'qa/checks/firmware/qemu/run.py'),'--qemu',$env:QEMU_SYSTEM_XTENSA,'--image',(Join-Path $root 'target/qemu/kassigner-qemu-flash.bin'))
if (-not $TestOnly) { $arguments += '--keep-running' }
Invoke-KasSignerCommand -Command $python -Arguments $arguments -WorkingDirectory $root | Out-Null
