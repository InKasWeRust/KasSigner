[CmdletBinding()]
param([string]$OutputDir)
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
if (-not $OutputDir) {
    $OutputDir = if ($env:KASSIGNER_RELEASE_EVIDENCE_DIR) { $env:KASSIGNER_RELEASE_EVIDENCE_DIR } else { Join-Path $root 'target/qa/release/evidence' }
}
$source = $env:KASSIGNER_SOURCE_SHA256
$release = $env:KASSIGNER_RELEASE_ARTIFACT_SHA256
$signerKeyId = $env:KASSIGNER_RELEASE_EVIDENCE_SIGNER_KEY_ID
$signingKey = $env:KASSIGNER_RELEASE_EVIDENCE_SIGNING_KEY
if (-not $source -or -not $release -or -not $signerKeyId -or -not $signingKey) {
    [Console]::Error.WriteLine('ERROR: set KASSIGNER_SOURCE_SHA256, KASSIGNER_RELEASE_ARTIFACT_SHA256, KASSIGNER_RELEASE_EVIDENCE_SIGNER_KEY_ID, and KASSIGNER_RELEASE_EVIDENCE_SIGNING_KEY.')
    exit 2
}
New-Item -ItemType Directory -Force -Path (Join-Path $OutputDir 'software') | Out-Null
foreach ($tool in @('cargo-deny','syft','osv-scanner','openssl')) { Require-KasSignerCommand $tool | Out-Null }
Push-Location $root
try {
    & cargo deny check advisories licenses 2>&1 | Tee-Object -FilePath (Join-Path $OutputDir 'software/cargo-deny.txt')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & syft 'dir:.' '-o' "cyclonedx-json=$(Join-Path $OutputDir 'software/sbom.cdx.json')"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $osvJson = (& osv-scanner scan source -r . --format json | Out-String)
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-KasSignerUtf8NoBom -Path (Join-Path $OutputDir 'software/osv.json') -Text $osvJson
} finally { Pop-Location }
$python = Get-KasSignerPython
Invoke-KasSignerCommand -Command $python -Arguments @(
    (Join-Path $root 'qa/checks/release/generate_software_assurance.py'),
    '--evidence-dir',$OutputDir,
    '--source-sha256',$source,
    '--release-artifact-sha256',$release,
    '--signer-key-id',$signerKeyId,
    '--signing-key',$signingKey
) -WorkingDirectory $root | Out-Null
