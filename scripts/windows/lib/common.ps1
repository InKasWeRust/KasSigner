# Shared native PowerShell helpers for KasSigner Windows entrypoints.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-KasSignerRepoRoot {
    param([Parameter(Mandatory = $true)][string]$FromPath)
    $current = [System.IO.Path]::GetFullPath($FromPath)
    if (Test-Path -LiteralPath $current -PathType Leaf) { $current = Split-Path -Parent $current }
    while ($true) {
        if ((Test-Path -LiteralPath (Join-Path $current 'Cargo.toml') -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $current 'qa/config/toolchains.env') -PathType Leaf)) {
            return $current
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { throw "Unable to locate KasSigner repository root from $FromPath" }
        $current = $parent
    }
}

function Import-KasSignerToolchains {
    param([Parameter(Mandatory = $true)][string]$Root)
    $path = Join-Path $Root 'qa/config/toolchains.env'
    foreach ($line in Get-Content -LiteralPath $path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $parts = $trimmed.Split('=', 2)
        if ($parts.Count -ne 2) { throw "Invalid toolchain environment line: $line" }
        [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
    }
}

function Get-KasSignerPython {
    # QA uses the stdlib tomllib module, which requires Python 3.11+. Prefer
    # the Windows py launcher so an older python.exe earlier on PATH cannot
    # shadow a newer supported installation.
    $launcher = Get-Command 'py.exe' -ErrorAction SilentlyContinue
    if ($launcher) {
        foreach ($version in @('3.13','3.12','3.11')) {
            $savedPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'SilentlyContinue'
                $resolved = (& $launcher.Source "-$version" -c 'import sys; print(sys.executable)' 2>$null | Select-Object -First 1)
                $code = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
            } finally {
                $ErrorActionPreference = $savedPreference
            }
            if ($code -eq 0 -and $resolved) {
                $path = ([string]$resolved).Trim()
                if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
            }
        }
    }

    foreach ($candidate in @('python3.13.exe','python3.12.exe','python3.11.exe','python.exe','python3.exe','python','python3')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $savedPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'SilentlyContinue'
            & $cmd.Source -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
            $code = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
        } finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($code -eq 0) { return $cmd.Source }
    }
    throw 'Python 3.11 or newer is required for KasSigner QA (Python 3.12 recommended). Run make install to install/select a supported Python.'
}

function Require-KasSignerCommand {
    param([Parameter(Mandatory = $true)][string]$Name, [string]$Guidance = '')
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        if ($Guidance) { throw "Required command not found: $Name. $Guidance" }
        throw "Required command not found: $Name"
    }
    return $cmd.Source
}

function Invoke-KasSignerCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = '',
        [hashtable]$Environment = @{},
        [int[]]$AllowedExitCodes = @(0),
        [switch]$Quiet
    )
    $old = @{}
    foreach ($key in $Environment.Keys) {
        $old[$key] = [Environment]::GetEnvironmentVariable([string]$key, 'Process')
        $value = $Environment[$key]
        $effectiveValue = if ($null -eq $value) { $null } else { [string]$value }
        [Environment]::SetEnvironmentVariable([string]$key, $effectiveValue, 'Process')
    }
    if ($WorkingDirectory) { Push-Location -LiteralPath $WorkingDirectory }
    try {
        if (-not $Quiet) {
            $display = @($Command) + $Arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"','\"') + '"' } else { $_ } }
            Write-Host ('  + ' + ($display -join ' '))
        }
        & $Command @Arguments
        $code = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
    } finally {
        if ($WorkingDirectory) { Pop-Location }
        foreach ($key in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable([string]$key, $old[$key], 'Process')
        }
    }
    if ($AllowedExitCodes -notcontains $code) { throw "Command failed with exit code ${code}: $Command" }
    return $code
}

function Invoke-KasSignerCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = '',
        [hashtable]$Environment = @{}
    )
    $old = @{}
    foreach ($key in $Environment.Keys) {
        $old[$key] = [Environment]::GetEnvironmentVariable([string]$key, 'Process')
        $value = $Environment[$key]
        $effectiveValue = if ($null -eq $value) { $null } else { [string]$value }
        [Environment]::SetEnvironmentVariable([string]$key, $effectiveValue, 'Process')
    }
    if ($WorkingDirectory) { Push-Location -LiteralPath $WorkingDirectory }
    $savedPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 turns native stderr redirected through 2>&1
        # into NativeCommandError records. With the repository-wide Stop
        # policy those records become terminating exceptions before callers
        # can inspect LASTEXITCODE. Capture probes must therefore temporarily
        # use Continue and return the native process exit code explicitly.
        # A missing optional native command is still a terminating
        # CommandNotFoundException, so normalize that probe result to 127.
        $ErrorActionPreference = 'Continue'
        try {
            $output = & $Command @Arguments 2>&1 | Out-String
            $code = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        } catch [System.Management.Automation.CommandNotFoundException] {
            $output = $_.Exception.Message
            $code = 127
        }
    } finally {
        $ErrorActionPreference = $savedPreference
        if ($WorkingDirectory) { Pop-Location }
        foreach ($key in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable([string]$key, $old[$key], 'Process')
        }
    }
    return [pscustomobject]@{ ExitCode = $code; Output = $output.TrimEnd() }
}

function Remove-KasSignerPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
}

function Copy-KasSignerDirectoryContents {
    param([Parameter(Mandatory = $true)][string]$Source, [Parameter(Mandatory = $true)][string]$Destination)
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $Destination -Recurse -Force
    }
}

function Write-KasSignerUtf8NoBom {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}
