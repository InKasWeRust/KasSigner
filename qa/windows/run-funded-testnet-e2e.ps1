# This gate intentionally accepts no parameters. Use PowerShell's automatic $args
# collection so a zero-argument invocation cannot be turned into a phantom
# positional value by parameter binding on Windows PowerShell 5.1.
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
Import-KasSignerToolchains $root
if (@($args).Count -ne 0) {
    [Console]::Error.WriteLine("Usage: $($MyInvocation.MyCommand.Path)")
    [Console]::Error.WriteLine('The funded E2E asks for the public Kaspa testnet interactively before creating/loading a wallet.')
    exit 2
}
Require-KasSignerCommand rustup 'Install rustup for Windows and reopen PowerShell.' | Out-Null
$python = Get-KasSignerPython
# Run the interactive E2E directly so its prompts remain attached to the
# maintainer terminal. Do not pipe through Invoke-KasSignerCommand/Out-Null:
# native stdout would become function output, making an assigned status an
# Object[] instead of the one integer exit code we need to propagate.
Push-Location -LiteralPath $root
try {
    & $python 'qa/checks/integration/funded_testnet_e2e.py'
    $status = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
} finally {
    Pop-Location
}
if (@(0,77) -notcontains $status) { exit $status }
exit $status
