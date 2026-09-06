$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
Import-KasSignerToolchains $root
$toolchain = $env:KASSIGNER_BRANCH_RUST
$llvmVersion = $env:KASSIGNER_CARGO_LLVM_COV_VERSION
$crapVersion = $env:KASSIGNER_CARGO_CRAP_VERSION
$crapDir = Join-Path $root 'target/qa/crap'
$targetBundle = Join-Path $root 'target/qa/kassigner-branch-coverage.zip'
$shaPath = "$targetBundle.sha256"
$python = Get-KasSignerPython
foreach ($cmd in @('cargo','make','rustup')) { Require-KasSignerCommand $cmd | Out-Null }
function Step([string]$Text) { Write-Host "`n================================================================================"; Write-Host $Text; Write-Host '================================================================================' }
function Verify-Version([string]$Label,[string]$Actual,[string]$Expected) { if ($Actual.Trim() -ne "$Label $Expected") { throw "expected $Label $Expected, found: $Actual" }; Write-Host ("  {0,-19}{1}" -f ($Label+':'),$Actual.Trim()) }

Push-Location $root
try {
    Step '1/6 Provisioning the pinned nightly and analysis tools'
    $old1=$env:CRAP_BRANCH_TOOLCHAIN; $old2=$env:CRAP_LLVM_COV_VERSION; $old3=$env:CRAP_CARGO_CRAP_VERSION
    $env:CRAP_BRANCH_TOOLCHAIN=$toolchain; $env:CRAP_LLVM_COV_VERSION=$llvmVersion; $env:CRAP_CARGO_CRAP_VERSION=$crapVersion
    & (Join-Path $root 'scripts/windows/quality/branch-coverage-setup.ps1'); if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $env:CRAP_BRANCH_TOOLCHAIN=$old1; $env:CRAP_LLVM_COV_VERSION=$old2; $env:CRAP_CARGO_CRAP_VERSION=$old3

    Step '2/6 Verifying exact analysis-tool versions'
    $a=(& rustup run $toolchain cargo llvm-cov --version | Out-String).Trim(); if ($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    $b=(& rustup run $toolchain cargo crap --version | Out-String).Trim(); if ($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    Verify-Version 'cargo-llvm-cov' $a $llvmVersion; Verify-Version 'cargo-crap' $b $crapVersion

    Step '3/6 Clearing stale coverage state'
    & rustup run $toolchain cargo llvm-cov clean --workspace; if ($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    Remove-KasSignerPath $crapDir; foreach($p in @($targetBundle,$shaPath)){Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue}

    Step '4/6 Running pinned-nightly branch coverage'
    $env:CRAP_COVERAGE_TOOLCHAIN=$toolchain; $env:CRAP_ENABLE_BRANCH='1'; $env:CRAP_BRANCH_TOOLCHAIN=$toolchain
    & (Join-Path $root 'scripts/windows/quality/crap.ps1') --strict; if ($LASTEXITCODE -ne 0){exit $LASTEXITCODE}

    Step '5/6 Validating persisted branch records and critical-domain ratchets'
    & $python qa/checks/quality/crap/package_branch_artifacts.py --validate-only --input-dir $crapDir; if ($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    & $python qa/checks/security/branch_ratchets.py; if ($LASTEXITCODE -ne 0){exit $LASTEXITCODE}

    Step '6/6 Packaging the ephemeral upload bundle under target/qa'
    & $python qa/checks/quality/crap/package_branch_artifacts.py --input-dir $crapDir --output $targetBundle; if ($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    if (-not (Test-Path $targetBundle) -or (Get-Item $targetBundle).Length -eq 0){throw "bundle target did not create: $targetBundle"}
    $hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $targetBundle).Hash.ToLowerInvariant(); Set-Content -LiteralPath $shaPath -Value "$hash  $(Split-Path -Leaf $targetBundle)" -Encoding ascii
    Write-Host "`nSHA-256:"; Get-Content $shaPath | Write-Host; Write-Host "`nBranch-coverage job completed successfully."; Write-Host "Fresh evidence is retained only under target/qa/crap/."; Write-Host "Optional upload ZIP (ephemeral):`n  $targetBundle"
} finally { Pop-Location }
