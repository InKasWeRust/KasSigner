# Native Windows QEMU setup helpers.
$script:QemuScriptDir = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../qemu'))
$script:RootDir = [IO.Path]::GetFullPath((Join-Path $script:QemuScriptDir '../../..'))
. (Join-Path $script:RootDir 'scripts/windows/lib/common.ps1')
Import-KasSignerToolchains $script:RootDir
$script:QemuStateDir = if ($env:KASSIGNER_QEMU_HOME) { $env:KASSIGNER_QEMU_HOME } elseif ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'KasSigner/qemu' } else { Join-Path $HOME '.kassigner/qemu' }
$script:ManagedIdfPath = Join-Path $script:QemuStateDir "esp-idf-$($env:KASSIGNER_ESP_IDF_VERSION)"

function Install-KasSignerRustupIfMissing {
    if ((Get-Command cargo -ErrorAction SilentlyContinue) -and (Get-Command rustup -ErrorAction SilentlyContinue)) { return }
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { throw 'Rustup is required. Install Rust for Windows from rustup.rs, then reopen PowerShell.' }
    Write-Host 'Rustup is missing; installing Rustup natively with winget.'
    & $winget.Source install --id Rustlang.Rustup --exact --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $cargoBin = Join-Path $HOME '.cargo/bin'
    if ($env:PATH -notlike "*$cargoBin*") { $env:PATH = $cargoBin + [IO.Path]::PathSeparator + $env:PATH }
    Require-KasSignerCommand rustup 'Restart PowerShell if winget installed Rustup but PATH has not refreshed.' | Out-Null
    Require-KasSignerCommand cargo 'Restart PowerShell if winget installed Rustup but PATH has not refreshed.' | Out-Null
}

function Install-KasSignerEspRustToolchain {
    Require-KasSignerCommand cargo | Out-Null; Require-KasSignerCommand rustup | Out-Null
    $probe = Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run','esp','rustc','--version')
    if ($probe.ExitCode -ne 0) {
        $espup = Invoke-KasSignerCapture -Command 'espup' -Arguments @('--version')
        if ($espup.ExitCode -ne 0 -or $espup.Output -notlike "*$($env:KASSIGNER_ESPUP_VERSION)*") {
            Invoke-KasSignerCommand -Command 'cargo' -Arguments @('install','espup','--version',$env:KASSIGNER_ESPUP_VERSION,'--locked','--force') | Out-Null
        }
        # espup installs a rustup toolchain named `esp` on Windows. Its POSIX export
        # file is intentionally not sourced; Cargo/rustup selection is native.
        Invoke-KasSignerCommand -Command 'espup' -Arguments @('install','--toolchain-version',$env:KASSIGNER_ESP_RUST) | Out-Null
        $probe = Invoke-KasSignerCapture -Command 'rustup' -Arguments @('run','esp','rustc','--version')
        if ($probe.ExitCode -ne 0) { throw 'espup completed, but no usable ESP Rust toolchain named esp was found.' }
    }
    $cargoProbe = Invoke-KasSignerCapture -Command 'cargo' -Arguments @('--version') -WorkingDirectory (Join-Path $script:RootDir 'apps/signer-firmware')
    if ($cargoProbe.ExitCode -ne 0) { throw "Cargo cannot activate the ESP toolchain selected by apps/signer-firmware/rust-toolchain.toml.`n$($cargoProbe.Output)" }
    Write-Host "ESP Rust toolchain ready: $($probe.Output.Trim())"
}

function Install-KasSignerEspflash {
    $actual = Invoke-KasSignerCapture -Command 'espflash' -Arguments @('--version')
    if ($actual.ExitCode -ne 0 -or $actual.Output -notlike "*$($env:KASSIGNER_ESPFLASH_VERSION)*") {
        Invoke-KasSignerCommand -Command 'cargo' -Arguments @('install','espflash','--version',$env:KASSIGNER_ESPFLASH_VERSION,'--locked','--force') | Out-Null
    }
    Require-KasSignerCommand espflash | Out-Null
}

function Resolve-KasSignerIdfPath {
    if ($env:KASSIGNER_IDF_PATH) {
        $candidate = [IO.Path]::GetFullPath($env:KASSIGNER_IDF_PATH)
        if (-not (Test-Path -LiteralPath (Join-Path $candidate 'tools/idf_tools.py') -PathType Leaf)) { throw "invalid KASSIGNER_IDF_PATH: $candidate" }
        return $candidate
    }
    New-Item -ItemType Directory -Force -Path $script:QemuStateDir | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $script:ManagedIdfPath '.git') -PathType Container)) {
        Remove-KasSignerPath $script:ManagedIdfPath
        Require-KasSignerCommand git 'Git for Windows is required for QEMU setup.' | Out-Null
        Invoke-KasSignerCommand -Command 'git' -Arguments @('clone','--filter=blob:none','--depth','1','--branch',$env:KASSIGNER_ESP_IDF_VERSION,'https://github.com/espressif/esp-idf.git',$script:ManagedIdfPath) | Out-Null
    }
    return $script:ManagedIdfPath
}

function Find-KasSignerQemuBinary {
    $toolsRoot = if ($env:IDF_TOOLS_PATH) { $env:IDF_TOOLS_PATH } else { Join-Path $HOME '.espressif' }
    $search = Join-Path $toolsRoot 'tools/qemu-xtensa'
    if (Test-Path -LiteralPath $search) {
        $candidate = Get-ChildItem -LiteralPath $search -Recurse -File -Filter 'qemu-system-xtensa.exe' -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
        if ($candidate) { return $candidate.FullName }
    }
    $cmd = Get-Command qemu-system-xtensa.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Install-KasSignerEspressifQemu {
    $python = Get-KasSignerPython
    $idf = Resolve-KasSignerIdfPath
    $env:IDF_TOOLS_PATH = if ($env:IDF_TOOLS_PATH) { $env:IDF_TOOLS_PATH } else { Join-Path $HOME '.espressif' }
    Invoke-KasSignerCommand -Command $python -Arguments @((Join-Path $idf 'tools/idf_tools.py'),'install','qemu-xtensa') -WorkingDirectory $script:RootDir | Out-Null
    $qemu = Find-KasSignerQemuBinary
    if (-not $qemu) { throw "Espressif QEMU was installed, but qemu-system-xtensa.exe could not be located under $($env:IDF_TOOLS_PATH)." }
    $env:IDF_PATH = $idf
    $env:QEMU_SYSTEM_XTENSA = $qemu
    $qemuDir = Split-Path -Parent $qemu
    if ($env:PATH -notlike "*$qemuDir*") { $env:PATH = $qemuDir + [IO.Path]::PathSeparator + $env:PATH }
    Write-Host "Espressif QEMU ready: $qemu"
}

function Initialize-KasSignerQemuEnvironment {
    Get-KasSignerPython | Out-Null
    Require-KasSignerCommand git 'Install Git for Windows and ensure git.exe is on PATH.' | Out-Null
    Install-KasSignerRustupIfMissing
    Install-KasSignerEspRustToolchain
    Install-KasSignerEspflash
    Install-KasSignerEspressifQemu
    Write-Host "QEMU environment ready: $($env:QEMU_SYSTEM_XTENSA)"
}
