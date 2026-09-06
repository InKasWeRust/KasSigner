[CmdletBinding()]
param([Parameter(Position=0)][string]$OutputDir = '')

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../../..'))
$profile = $PSScriptRoot
$partitions = Join-Path $root 'apps/signer-firmware/partitions/m5stack-cores3.csv'
$signingKey = $env:KASSIGNER_SECURE_BOOT_SIGNING_KEY
$authorityMode = if ($env:KASSIGNER_SECURE_BOOT_AUTHORITY_MODE) { $env:KASSIGNER_SECURE_BOOT_AUTHORITY_MODE } else { 'dual' }
if ($authorityMode -notin @('dual', 'owner-only')) {
    throw 'KASSIGNER_SECURE_BOOT_AUTHORITY_MODE must be dual or owner-only.'
}
if (-not $OutputDir) { $OutputDir = Join-Path $root 'target/qa/state/m5stack-secure-bootloader' }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
if (-not $env:IDF_PATH -or -not (Test-Path -LiteralPath $env:IDF_PATH -PathType Container)) {
    throw 'IDF_PATH must point to an ESP-IDF checkout/tool environment.'
}
if (-not $signingKey -or -not (Test-Path -LiteralPath $signingKey -PathType Leaf)) {
    throw 'KASSIGNER_SECURE_BOOT_SIGNING_KEY must point to the offline RSA-3072 Secure Boot v2 private key.'
}
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) { $pythonCmd = Get-Command python3 -ErrorAction Stop }
$python = $pythonCmd.Source
$idf = (Get-Command idf.py -ErrorAction Stop).Source
$espsecure = (Get-Command espsecure -ErrorAction Stop).Source

function Invoke-Tool([string]$Tool, [string[]]$Arguments) {
    if ([IO.Path]::GetExtension($Tool) -ieq '.py') {
        & $python $Tool @Arguments
    } else {
        & $Tool @Arguments
    }
    if ($LASTEXITCODE -ne 0) { throw "command failed ($LASTEXITCODE): $Tool $($Arguments -join ' ')" }
}

$policy = Get-Content -LiteralPath (Join-Path $root 'apps/signer-firmware/release-policy.env')
$securityLine = $policy | Where-Object { $_ -match '^KASSIGNER_SECURITY_VERSION=' } | Select-Object -First 1
if (-not $securityLine) { throw 'KASSIGNER_SECURITY_VERSION is missing from release-policy.env.' }
$securityVersion = ($securityLine -split '=', 2)[1].Trim()
if ($securityVersion -notmatch '^\d+$' -or [int]$securityVersion -le 0) { throw 'KASSIGNER_SECURITY_VERSION must be a positive integer.' }

New-Item -ItemType Directory -Force -Path (Join-Path $root 'target/qa/state'), $OutputDir | Out-Null
$work = Join-Path (Join-Path $root 'target/qa/state') ('m5-secure-bootloader.' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    Copy-Item -Path (Join-Path $profile '*') -Destination $work -Recurse -Force
    Copy-Item -LiteralPath $partitions -Destination (Join-Path $work 'partitions.csv') -Force
    $components = Join-Path $work 'bootloader_components'
    New-Item -ItemType Directory -Force -Path $components | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:IDF_PATH 'components/bootloader_support') -Destination (Join-Path $components 'bootloader_support') -Recurse -Force

    $key = [IO.Path]::GetFullPath($signingKey)
    $expectedDigest = Join-Path $work 'kassigner-sbv2-authority-key-digest.bin'
    Invoke-Tool $espsecure @('digest-sbv2-public-key', '--keyfile', $key, '--output', $expectedDigest)
    if ((Get-Item -LiteralPath $expectedDigest).Length -ne 32) {
        throw 'espsecure did not produce a 32-byte Secure Boot v2 public-key digest.'
    }
    & $python (Join-Path $profile 'patch_pop_it_bootloader.py') `
        (Join-Path $components 'bootloader_support') `
        --expected-key-digest $expectedDigest --authority-mode $authorityMode
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $keyForConfig = $key -replace '\\', '/'
    $configAppend = "`nCONFIG_SECURE_BOOT_SIGNING_KEY=`"$keyForConfig`"`nCONFIG_BOOTLOADER_APP_SECURE_VERSION=$securityVersion`n"
    [IO.File]::AppendAllText(
        (Join-Path $work 'sdkconfig.defaults'),
        $configAppend,
        (New-Object Text.UTF8Encoding($false))
    )

    Push-Location $work
    try {
        Invoke-Tool $idf @('set-target', 'esp32s3')
        Invoke-Tool $idf @('bootloader')
    } finally {
        Pop-Location
    }

    $bootloader = Join-Path $work 'build/bootloader/bootloader.bin'
    if (-not (Test-Path -LiteralPath $bootloader -PathType Leaf) -or (Get-Item $bootloader).Length -eq 0) {
        throw 'signed bootloader.bin was not produced.'
    }
    $bootOut = Join-Path $OutputDir 'kassigner-m5stack-secure-bootloader.bin'
    $digestOut = Join-Path $OutputDir 'kassigner-m5stack-secure-boot-key-digest.bin'
    $partitionOut = Join-Path $OutputDir 'kassigner-m5stack-partition-table.bin'
    $partitionCsvOut = Join-Path $OutputDir 'kassigner-m5stack-partitions.csv'
    Copy-Item -LiteralPath $bootloader -Destination $bootOut -Force
    Copy-Item -LiteralPath $expectedDigest -Destination $digestOut -Force
    & $python (Join-Path $env:IDF_PATH 'components/partition_table/gen_esp32part.py') $partitions $partitionOut
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Copy-Item -LiteralPath $partitions -Destination $partitionCsvOut -Force
    Set-Content -LiteralPath (Join-Path $OutputDir 'AUTHORITY-MODE') -Value $authorityMode -Encoding ascii

    $lines = foreach ($name in @(
        'kassigner-m5stack-secure-bootloader.bin',
        'kassigner-m5stack-secure-boot-key-digest.bin',
        'kassigner-m5stack-partition-table.bin',
        'kassigner-m5stack-partitions.csv',
        'AUTHORITY-MODE'
    )) {
        $path = Join-Path $OutputDir $name
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    Set-Content -LiteralPath (Join-Path $OutputDir 'SHA256SUMS') -Value $lines -Encoding ascii
    Write-Host "Built signed CoreS3 secure bootloader profile ($authorityMode): $OutputDir"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
