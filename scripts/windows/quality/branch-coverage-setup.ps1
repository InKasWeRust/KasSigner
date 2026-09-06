$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
Import-KasSignerToolchains $root
$toolchain=if($env:CRAP_BRANCH_TOOLCHAIN){$env:CRAP_BRANCH_TOOLCHAIN}else{$env:KASSIGNER_BRANCH_RUST}
$llvm=if($env:CRAP_LLVM_COV_VERSION){$env:CRAP_LLVM_COV_VERSION}else{$env:KASSIGNER_CARGO_LLVM_COV_VERSION}
$crap=if($env:CRAP_CARGO_CRAP_VERSION){$env:CRAP_CARGO_CRAP_VERSION}else{$env:KASSIGNER_CARGO_CRAP_VERSION}
foreach($c in @('rustup','cargo')){Require-KasSignerCommand $c|Out-Null}

# Keep QA-owned Cargo subcommands out of the developer's global ~/.cargo/bin.
# Windows can hold an executable open long enough for `cargo install --force` to
# fail while replacing it (Access denied / os error 5). A pin-qualified local
# root also means changing either tool version naturally provisions a fresh
# directory instead of mutating an executable that another process may use.
$toolRoot=Join-Path $root ("target/development-tools/branch-coverage-{0}-llvm-{1}-crap-{2}" -f $toolchain,$llvm,$crap)
$toolBin=Join-Path $toolRoot 'bin'
New-Item -ItemType Directory -Force -Path $toolBin|Out-Null
$pathEntries=@($env:PATH -split ';'|Where-Object{$_})
if($pathEntries -notcontains $toolBin){$env:PATH=$toolBin+';'+$env:PATH}

Write-Host "Provisioning pinned branch-coverage tools:`n  Toolchain:       $toolchain`n  Local tool root: $toolRoot"
$p=Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run',$toolchain,'rustc','--version')
if($p.ExitCode -eq 0){Write-Host '  Rust toolchain:  already installed'}else{Invoke-KasSignerCommand -Command 'rustup' -Arguments @('toolchain','install',$toolchain,'--profile','minimal','--component','llvm-tools-preview')|Out-Null}
$components=Invoke-KasSignerCapture -Command 'rustup' -Arguments @('component','list','--toolchain',$toolchain,'--installed')
if($components.Output -match '(?m)^llvm-tools'){Write-Host '  LLVM tools:      already installed'}else{Invoke-KasSignerCommand -Command 'rustup' -Arguments @('component','add','llvm-tools-preview','--toolchain',$toolchain)|Out-Null;Write-Host '  LLVM tools:      installed'}
function Ensure-Plugin([string]$sub,[string]$package,[string]$expected){
 $exe=Join-Path $toolBin ($package+'.exe')
 # Cargo subcommand executables receive their subcommand name as argv[1] when
 # Cargo dispatches `cargo <subcommand> ...`. Invoking cargo-llvm-cov.exe or
 # cargo-crap.exe directly therefore must preserve that argv shape. A bare
 # `--version` probe is rejected by cargo-llvm-cov as an unknown subcommand.
 $probeArgs=@($sub,'--version')
 $probe=if(Test-Path -LiteralPath $exe -PathType Leaf){Invoke-KasSignerCapture -Command $exe -Arguments $probeArgs}else{[pscustomobject]@{ExitCode=1;Output=''}}
 if($probe.ExitCode -eq 0 -and $probe.Output.Trim().EndsWith(" $expected")){Write-Host ("  {0,-17}{1}" -f ($package+':'),$probe.Output.Trim());return}
 $args=@("+$toolchain",'install',$package,'--version',$expected,'--locked','--root',$toolRoot);if(Test-Path -LiteralPath $exe -PathType Leaf){$args+='--force'}
 Write-Host "Installing $package $expected for $toolchain into repository-local tooling...";Invoke-KasSignerCommand -Command 'cargo' -Arguments $args|Out-Null
 $final=Invoke-KasSignerCapture -Command $exe -Arguments $probeArgs;if($final.ExitCode -ne 0 -or -not$final.Output.Trim().EndsWith(" $expected")){throw "expected $package $expected, found: $($final.Output)"}
 Write-Host ("  {0,-17}{1}" -f ($package+':'),$final.Output.Trim())
}
Ensure-Plugin 'llvm-cov' 'cargo-llvm-cov' $llvm
Ensure-Plugin 'crap' 'cargo-crap' $crap
Write-Host 'Pinned branch-coverage tools are ready.'
