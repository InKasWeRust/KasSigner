$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
$evidence = $env:KASSIGNER_RELEASE_EVIDENCE_DIR
$source = $env:KASSIGNER_SOURCE_SHA256
$release = $env:KASSIGNER_RELEASE_ARTIFACT_SHA256
$releaseManifest = $env:KASSIGNER_RELEASE_MANIFEST
$trustPolicy = $env:KASSIGNER_RELEASE_TRUST_POLICY
$trustPolicySha = $env:KASSIGNER_RELEASE_TRUST_POLICY_SHA256
if (-not $evidence -or -not $source -or -not $release -or -not $releaseManifest -or -not $trustPolicy -or -not $trustPolicySha) {
    [Console]::Error.WriteLine('ERROR: release readiness requires a concrete release artifact and signed evidence.')
    [Console]::Error.WriteLine('Set KASSIGNER_RELEASE_EVIDENCE_DIR, KASSIGNER_SOURCE_SHA256, KASSIGNER_RELEASE_ARTIFACT_SHA256, KASSIGNER_RELEASE_MANIFEST, KASSIGNER_RELEASE_TRUST_POLICY, and KASSIGNER_RELEASE_TRUST_POLICY_SHA256.')
    [Console]::Error.WriteLine('See qa/release/README.md; these values cannot be synthesized safely by the launcher.')
    exit 2
}
Require-KasSignerCommand 'openssl' | Out-Null
$python = Get-KasSignerPython
Invoke-KasSignerCommand -Command $python -Arguments @(
    (Join-Path $root 'qa/checks/release/release_readiness.py'),
    '--evidence-dir',$evidence,
    '--source-sha256',$source,
    '--release-artifact-sha256',$release,
    '--release-manifest',$releaseManifest,
    '--trust-policy',$trustPolicy,
    '--trust-policy-sha256',$trustPolicySha
) -WorkingDirectory $root | Out-Null
