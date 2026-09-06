$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$env:CARGO_TARGET_DIR = Join-Path $root 'target/qa'
. (Join-Path $root 'scripts/windows/lib/common.ps1')
Import-KasSignerToolchains $root
$version = $env:KASSIGNER_CARGO_FUZZ_VERSION
$installer = $env:KASSIGNER_STABLE_RUST
$execution = $env:KASSIGNER_BRANCH_RUST
$secondsPerTarget = if ($env:FUZZ_SECONDS) { [int]$env:FUZZ_SECONDS } else { 300 }
$output = Join-Path $root 'target/qa/fuzz'
$statusFile = Join-Path $output 'statuses.tsv'
$artifactRoot = Join-Path $output 'artifacts'
$corpusRoot = Join-Path $output 'corpus'
$seedRoot = Join-Path $root 'qa/fuzz/seeds'
$python = Get-KasSignerPython
foreach ($cmd in @('rustup','cargo')) { Require-KasSignerCommand $cmd | Out-Null }
foreach ($toolchain in @($installer,$execution)) {
    $probe = Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run',$toolchain,'rustc','--version')
    if ($probe.ExitCode -ne 0) { Invoke-KasSignerCommand -Command 'rustup' -Arguments @('toolchain','install',$toolchain,'--profile','minimal') | Out-Null }
}
$actualProbe = Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run',$execution,'cargo','fuzz','--version')
$actual = $actualProbe.Output
if ($actualProbe.ExitCode -ne 0 -or $actual -notlike "*cargo-fuzz $version*") {
    Invoke-KasSignerCommand -Command 'rustup' -Arguments @('run',$installer,'cargo','install','cargo-fuzz','--version',$version,'--locked','--force') | Out-Null
    $actualProbe = Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run',$execution,'cargo','fuzz','--version'); $actual = $actualProbe.Output
}
if ($actual -notlike "*cargo-fuzz $version*") { throw "expected cargo-fuzz $version, received: $actual" }
$targetResult = Invoke-KasSignerCapture -Command $python -Arguments @('qa/checks/security/fuzz_targets.py','--validate') -WorkingDirectory $root
if ($targetResult.ExitCode -ne 0) { throw $targetResult.Output }
$targets = @($targetResult.Output -split "`r?`n" | Where-Object { $_ })
if ($targets.Count -eq 0) { throw 'no fuzz targets are registered' }
Remove-KasSignerPath $output
New-Item -ItemType Directory -Force -Path $output,$artifactRoot,$corpusRoot | Out-Null
Set-Content -LiteralPath $statusFile -Value '' -NoNewline -Encoding ascii
$started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
foreach ($target in $targets) {
    Write-Host "=== fuzz: $target ($($secondsPerTarget)s) ==="
    $seed = Join-Path $seedRoot $target; $corpus = Join-Path $corpusRoot $target; $artifact = Join-Path $artifactRoot $target
    if (-not (Test-Path -LiteralPath $seed -PathType Container)) {
        [Console]::Error.WriteLine("ERROR: authored fuzz seeds are missing for $target`: $seed")
        Add-Content -LiteralPath $statusFile -Value "$target`t2" -Encoding ascii
        continue
    }
    New-Item -ItemType Directory -Force -Path $corpus,$artifact | Out-Null
    Copy-KasSignerDirectoryContents $seed $corpus
    Push-Location (Join-Path $root 'qa/fuzz')
    try {
        & rustup run $execution cargo fuzz run $target --no-include-main-msvc -- "-max_total_time=$secondsPerTarget" '-print_final_stats=1' "-artifact_prefix=$artifact\" $corpus 2>&1 | Tee-Object -FilePath (Join-Path $output "$target.log")
        $status = $LASTEXITCODE
    } finally { Pop-Location }
    Add-Content -LiteralPath $statusFile -Value "$target`t$status" -Encoding ascii
    if ($status -ne 0) { [Console]::Error.WriteLine("FAIL: fuzz target $target (exit $status)") }
}
$completed = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
Invoke-KasSignerCommand -Command $python -Arguments @('qa/checks/security/fuzz_results.py','--statuses',$statusFile,'--tool',$actual.Trim(),'--started',$started,'--completed',$completed,'--seconds',[string]$secondsPerTarget) -WorkingDirectory $root | Out-Null
