[CmdletBinding()]
param(
    [string]$OutputDir,
    [string]$SigningKey = $env:KASSIGNER_SIGNING_KEY,
    [switch]$RefreshInputs
)
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
. (Join-Path $root 'scripts/windows/lib/cargo_locks.ps1')
Import-KasSignerToolchains $root
$python=Get-KasSignerPython
if(-not$OutputDir){$OutputDir=Join-Path $root 'release'}
$toolchainImage='kassigner-toolchain:v3';$ubuntuImage='kassigner-ubuntu-rootfs:v1';$platform='linux/amd64';$prefetch=Join-Path $root 'target/qa/state/reproducible-build-inputs'
foreach($c in @('docker','rustup','cargo')){Require-KasSignerCommand $c|Out-Null}

function Ensure-Docker {
    $p=Invoke-KasSignerCapture -Command 'docker' -Arguments @('info')
    if($p.ExitCode -eq 0){return}
    $desktop=Join-Path $env:ProgramFiles 'Docker/Docker/Docker Desktop.exe'
    if(Test-Path $desktop){Write-Host 'Docker Desktop is installed but its engine is unavailable. Starting Docker Desktop...';Start-Process -FilePath $desktop|Out-Null;for($i=0;$i -lt 120;$i++){Start-Sleep -Seconds 1;$p=Invoke-KasSignerCapture -Command 'docker' -Arguments @('info');if($p.ExitCode -eq 0){return}}}
    throw "Docker Desktop/Linux containers are required for the reproducible build.`n$($p.Output)"
}
Ensure-Docker

# Native Windows inter-process lock: FileShare.None is the Windows equivalent of flock for this workflow.
$state=Join-Path $root 'target/qa/state';New-Item -ItemType Directory -Force -Path $state|Out-Null;$lockPath=Join-Path $state 'release-workflow.lock';$lock=$null
while(-not$lock){try{$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch [IO.IOException]{Write-Host 'Another KasSigner QA/reproducible-release workflow is active; waiting for it to finish.';Start-Sleep -Milliseconds 500}}
try {
    Write-Host "==> Reconciling/verifying host Cargo.lock files under pinned Cargo $($env:KASSIGNER_STABLE_RUST)"
    Repair-KasSignerHostLocks $root
    if($SigningKey){$SigningKey=[IO.Path]::GetFullPath($SigningKey);if(-not(Test-Path $SigningKey)){throw "signing key not found: $SigningKey"};if((Get-Item $SigningKey).Length -ne 32){throw "signing key must be exactly 32 bytes; got $((Get-Item $SigningKey).Length)"}}
    $commit=$env:KASSIGNER_GIT_COMMIT
    if(-not$commit -and (Get-Command git -ErrorAction SilentlyContinue)){ $g=Invoke-KasSignerCapture -Command 'git' -Arguments @('-C',$root,'rev-parse','--verify','HEAD');if($g.ExitCode -eq 0){$commit=$g.Output.Trim()} }
    if($commit -and $commit -notmatch '^[0-9A-Fa-f]{7,40}$'){throw 'KASSIGNER_GIT_COMMIT must be 7-40 hexadecimal characters.'}
    $OutputDir=[IO.Path]::GetFullPath($OutputDir);New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputDir)|Out-Null

    # The reproducible Docker context contains Linux/amd64 toolchains by design.
    # On a Windows host, perform that Linux-specific prefetch inside a pinned
    # Linux container instead of executing Bash/Linux binaries on Windows.
    # This requires only the native Docker CLI/engine; WSL and host Bash are not used.
    $prefetchParent = Split-Path -Parent $prefetch
    New-Item -ItemType Directory -Force -Path $prefetchParent | Out-Null
    $prefetchImage = "ubuntu@$($env:KASSIGNER_UBUNTU_BASE_DIGEST)"
    Write-Host "==> Preparing pinned Linux/amd64 helper container $prefetchImage"
    Invoke-KasSignerCommand -Command 'docker' -Arguments @('pull','--platform',$platform,$prefetchImage) -WorkingDirectory $root | Out-Null

    function Invoke-ReproPrefetch([switch]$Finalize) {
        $inner = @('python3','/workspace/scripts/linux/build/reproducible/prefetch.py','--root','/workspace','--output','/state/reproducible-build-inputs')
        if ($Finalize) { $inner += '--finalize-context-manifests' } elseif ($RefreshInputs) { $inner += '--refresh' }
        $bootstrap = 'export DEBIAN_FRONTEND=noninteractive; apt-get update >/dev/null; apt-get install -y --no-install-recommends python3 ca-certificates git curl build-essential pkg-config unzip xz-utils >/dev/null; exec "$@"'
        $dockerArgs = @(
            'run','--rm','--platform',$platform,
            '--mount',"type=bind,source=$root,target=/workspace",
            '--mount',"type=bind,source=$prefetchParent,target=/state",
            $prefetchImage,'/bin/sh','-c',$bootstrap,'kassigner-prefetch'
        ) + $inner
        Invoke-KasSignerCommand -Command 'docker' -Arguments $dockerArgs -WorkingDirectory $root | Out-Null
    }

    Write-Host '==> Prefetching/verifying every external build input through the pinned Linux helper container'
    Invoke-ReproPrefetch

    # Use native Windows rustup/cargo for the MSRV preflight while pointing Cargo at
    # the prefetched portable registry/source cache. No Linux executable is launched.
    $repro=$env:KASSIGNER_REPRO_HOST_RUST
    $probe=Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run',$repro,'rustc','--version')
    if($probe.ExitCode -ne 0){Invoke-KasSignerCommand -Command 'rustup' -Arguments @('toolchain','install',$repro,'--profile','minimal')|Out-Null}
    $targets=Invoke-KasSignerCapture -Command 'rustup' -Arguments @('target','list','--toolchain',$repro,'--installed')
    if(($targets.Output -split "`r?`n") -notcontains 'wasm32-unknown-unknown'){Invoke-KasSignerCommand -Command 'rustup' -Arguments @('target','add','wasm32-unknown-unknown','--toolchain',$repro)|Out-Null}
    $cargoHome=Join-Path $prefetch 'root-home/.cargo';$reproEnv=@{'CARGO_HOME'=$cargoHome;'RUSTUP_TOOLCHAIN'=$repro;'CARGO_NET_OFFLINE'='true'}
    Write-Host "==> Verifying KasSee lock with frozen reproducible Rust $repro"
    Invoke-KasSignerCommand -Command 'cargo' -Arguments @('metadata','--manifest-path',(Join-Path $root 'apps/kassee-web/Cargo.toml'),'--format-version','1','--filter-platform','wasm32-unknown-unknown','--locked','--offline') -WorkingDirectory $root -Environment $reproEnv|Out-Null
    Write-Host "==> Preflighting KasSee WASM release with frozen reproducible Rust $repro"
    $msrvTarget=Join-Path $prefetch 'kassee-msrv-target';Remove-KasSignerPath $msrvTarget;$reproEnv['CARGO_TARGET_DIR']=$msrvTarget
    Invoke-KasSignerCommand -Command 'cargo' -Arguments @('build','--manifest-path',(Join-Path $root 'apps/kassee-web/Cargo.toml'),'--target','wasm32-unknown-unknown','--release','--locked','--offline') -WorkingDirectory $root -Environment $reproEnv|Out-Null
    Write-Host '==> Finalizing post-preflight Docker input manifests'
    Invoke-ReproPrefetch -Finalize

    Write-Host "`n==> Host network phase complete; all Docker operations are networkless";$env:DOCKER_BUILDKIT='1'
    & docker image rm --force $ubuntuImage *> $null
    & docker import --platform $platform (Join-Path $prefetch 'ubuntu-rootfs-layer.tar.gz') $ubuntuImage *> $null;if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
    Write-Host '==> Building pinned KasSigner toolchain image with Docker networking disabled'
    Invoke-KasSignerCommand -Command 'docker' -Arguments @('build','--network=none','--pull=false','--platform',$platform,'--file',(Join-Path $root 'Dockerfile.base'),'--tag',$toolchainImage,(Join-Path $prefetch 'context')) -WorkingDirectory $root|Out-Null
    $stage=if($OutputDir.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){Join-Path $root ('target/qa/state/reproducible-release-stage.'+$PID)}else{$OutputDir+'.tmp.'+$PID};Remove-KasSignerPath $stage;New-Item -ItemType Directory -Force -Path $stage|Out-Null
    try{
        Write-Host "`n==> Building and exporting release artifacts with Docker networking disabled"
        $build=@('build','--network=none','--pull=false','--platform',$platform,'--file',(Join-Path $root 'Dockerfile'),'--target','artifacts','--output',"type=local,dest=$stage")
        if($commit){$build+=@('--build-arg',"KASSIGNER_GIT_COMMIT=$commit")};if($SigningKey){$build+=@('--secret',"id=signkey,src=$SigningKey")};$build+=$root
        Invoke-KasSignerCommand -Command 'docker' -Arguments $build -WorkingDirectory $root|Out-Null
        $required=@('SHA256SUMS','SOURCE-SHA256SUMS','BUILD-MANIFEST.txt','ARTIFACT-MANIFEST.json','MANIFEST-SHA256SUMS','BUILD-INPUT-SHA256SUMS','BUILD-INPUT-MANIFEST.json','kassigner-waveshare-unsigned.bin','kassigner-waveshare-unsigned-full.bin','kassigner-waveshare-unsigned.codehash','kassigner-waveshare-af-unsigned.bin','kassigner-waveshare-af-unsigned-full.bin','kassigner-waveshare-af-unsigned.codehash','kassigner-m5stack-unsigned.bin','kassigner-m5stack-unsigned-full.bin','kassigner-m5stack-unsigned.codehash','kassigner-m5stack-partitions.csv')
        if($SigningKey){$required+=@('kassigner-waveshare.bin','kassigner-waveshare-full.bin','kassigner-waveshare.codehash','kassigner-waveshare-af.bin','kassigner-waveshare-af-full.bin','kassigner-waveshare-af.codehash','kassigner-m5stack.bin','kassigner-m5stack-full.bin','kassigner-m5stack.codehash','kassigner-waveshare-update.ksfu','kassigner-waveshare-af-update.ksfu')}
        foreach($name in $required){if(-not(Test-Path (Join-Path $stage $name))){throw "Docker build did not export required artifact: $name"}}
        $verify = @'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
for manifest_name in ("MANIFEST-SHA256SUMS", "SHA256SUMS"):
    for line in (root / manifest_name).read_text().splitlines():
        if not line.strip():
            continue
        expected, name = line.split(None, 1)
        name = name.lstrip(" *")
        candidate = root / name
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"ERROR: {manifest_name}: hash mismatch for {name}")
print("SHA-256 manifests verified")
'@
        & $python -c $verify $stage;if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
        Remove-KasSignerPath $OutputDir;Move-Item -LiteralPath $stage -Destination $OutputDir
    }finally{Remove-KasSignerPath $stage}
    $count=(Get-ChildItem -LiteralPath $OutputDir -File -Filter '*.bin').Count
    Write-Host "`nKasSigner reproducible Docker build complete.`nArtifacts: $OutputDir`nFirmware images: $count`nDocker networking: disabled for every build step.`nNo device was flashed or contacted."
} finally { if($lock){$lock.Dispose()} }
