# This gate intentionally accepts no parameters. Use PowerShell's automatic $args
# collection so a zero-argument invocation cannot be turned into a phantom
# positional value by parameter binding on Windows PowerShell 5.1.
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
. (Join-Path $root 'scripts/windows/lib/cargo_locks.ps1')
Import-KasSignerToolchains $root
if (@($args).Count -ne 0) {
    [Console]::Error.WriteLine("Usage: $($MyInvocation.MyCommand.Path)")
    [Console]::Error.WriteLine("This gate uses Kaspa's public-node resolver only; no local-node mode exists.")
    exit 2
}
Write-Host "==> Reconciling/verifying host Cargo.lock files under pinned Cargo $($env:KASSIGNER_STABLE_RUST)"
Repair-KasSignerHostLocks $root
Write-Host '==> Building the real KasSee WebAssembly package'
$python = Get-KasSignerPython
& (Join-Path $root 'scripts/windows/build/kassee-web-build.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host '==> Real Kaspa public-node integration (official resolver pool)'
$evidence = 'target/qa/security/real-node-integration.json'
Invoke-KasSignerCommand -Command $python -Arguments @('qa/checks/integration/real_node_browser.py','--evidence',$evidence) -WorkingDirectory $root | Out-Null
if (-not $env:KASSIGNER_SECURITY_RUN_DIR -and -not $env:KASSIGNER_QA_CATALOG_ACTIVE) {
    Invoke-KasSignerCommand -Command $python -Arguments @('qa/checks/security/complete_hardening.py','--real-node-evidence',$evidence) -WorkingDirectory $root | Out-Null
}
