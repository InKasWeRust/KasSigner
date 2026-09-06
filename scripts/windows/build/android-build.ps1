param([ValidateSet('debug','release','test')][string]$Mode='debug')
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
$android = Join-Path $root 'apps/kassee-android'
$wrapperProperties = Join-Path $android 'gradle/wrapper/gradle-wrapper.properties'
$daemonJvmProperties = Join-Path $android 'gradle/gradle-daemon-jvm.properties'

Import-KasSignerToolchains $root
if (-not (Test-Path -LiteralPath $daemonJvmProperties -PathType Leaf)) { throw "Missing canonical Gradle Daemon JVM criteria: $daemonJvmProperties" }
$daemonJvm = @{}
foreach ($line in Get-Content -LiteralPath $daemonJvmProperties) {
    if ($line -match '^([^=]+)=(.*)$') { $daemonJvm[$Matches[1].Trim()] = $Matches[2].Trim() }
}
$centralJavaText = [string]$env:KASSIGNER_ANDROID_JDK
$daemonJavaText = [string]$daemonJvm['toolchainVersion']
if ($centralJavaText -notmatch '^\d+$') { throw 'KASSIGNER_ANDROID_JDK is missing or invalid in qa/config/toolchains.env.' }
if ($daemonJavaText -notmatch '^\d+$') { throw 'toolchainVersion is missing or invalid in gradle-daemon-jvm.properties.' }
$requiredJava = [int]$centralJavaText
if ([int]$daemonJavaText -ne $requiredJava) { throw "Gradle Daemon JVM criteria ($daemonJavaText) does not match central Android JDK pin ($requiredJava)." }

function Get-JavaMajor([string]$Java) {
    if (-not $Java) { return 0 }
    if (-not (Test-Path -LiteralPath $Java -PathType Leaf)) { return 0 }
    try {
        $probe = Invoke-KasSignerCapture -Command $Java -Arguments @('-version')
    } catch {
        # A stale or partially prepared managed JDK must be treated as absent
        # so Install-ManagedJava can replace it. Do not let a broken java.exe
        # candidate abort Android QA before the repair path runs.
        return 0
    }
    if ($probe.ExitCode -ne 0) { return 0 }
    if ($probe.Output -match 'version\s+"(?:(?:1\.)?)(\d+)') { return [int]$Matches[1] }
    return 0
}
function Add-JavaCandidate([Collections.Generic.List[string]]$Candidates, [string]$Java) {
    if (-not $Java) { return }
    if (-not (Test-Path -LiteralPath $Java -PathType Leaf)) { return }
    $full = [IO.Path]::GetFullPath($Java)
    foreach ($existing in $Candidates) {
        if ([string]::Equals($existing, $full, [StringComparison]::OrdinalIgnoreCase)) { return }
    }
    $Candidates.Add($full)
}
function Install-ManagedJava([int]$RequiredMajor) {
    $target = Join-Path $HOME ".kassigner/tools/jdk-$RequiredMajor"
    $targetJava = Join-Path $target 'bin/java.exe'
    if ((Get-JavaMajor $targetJava) -eq $RequiredMajor) { return $targetJava }

    $arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'ARM64' { 'aarch64' } default { 'x64' } }
    $metaUri = "https://api.adoptium.net/v3/assets/latest/$RequiredMajor/hotspot?architecture=$arch&image_type=jdk&os=windows&vendor=eclipse"
    Write-Host "==> Pinned JDK $RequiredMajor is not installed; downloading and verifying it under $target"
    $assets = Invoke-RestMethod -Uri $metaUri -UseBasicParsing
    if (-not $assets -or -not $assets[0].binary.package) { throw "Adoptium did not return a Windows JDK $RequiredMajor package for $arch." }
    $package = $assets[0].binary.package
    $link = [string]$package.link
    $checksum = [string]$package.checksum
    if (-not $link -or $checksum -notmatch '^[0-9A-Fa-f]{64}$') { throw "Adoptium JDK $RequiredMajor metadata is incomplete." }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('kassigner-android-jdk-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        $archive = Join-Path $tmp 'jdk.zip'
        Invoke-WebRequest -UseBasicParsing -Uri $link -OutFile $archive
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $checksum.ToLowerInvariant()) { throw "JDK SHA-256 mismatch: expected $checksum, got $actual" }
        $unpack = Join-Path $tmp 'unpack'
        Expand-Archive -LiteralPath $archive -DestinationPath $unpack -Force
        $source = Get-ChildItem -LiteralPath $unpack -Directory | Select-Object -First 1
        if (-not $source) { throw 'JDK archive did not contain a top-level directory.' }
        Remove-KasSignerPath $target
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Move-Item -LiteralPath $source.FullName -Destination $target
    } finally {
        Remove-KasSignerPath $tmp
    }
    if ((Get-JavaMajor $targetJava) -ne $RequiredMajor) { throw "Prepared JDK does not report required major ${RequiredMajor}: $targetJava" }
    return $targetJava
}

function Resolve-Java([int]$RequiredMajor) {
    $candidates = [Collections.Generic.List[string]]::new()
    if ($env:KASSIGNER_ANDROID_JDK) {
        Add-JavaCandidate $candidates (Join-Path $HOME ".kassigner/tools/jdk-$($env:KASSIGNER_ANDROID_JDK)/bin/java.exe")
    }
    if ($env:JAVA_HOME) { Add-JavaCandidate $candidates (Join-Path $env:JAVA_HOME 'bin/java.exe') }
    if ($env:ProgramFiles) { Add-JavaCandidate $candidates (Join-Path $env:ProgramFiles 'Android/Android Studio/jbr/bin/java.exe') }
    if ($env:LOCALAPPDATA) { Add-JavaCandidate $candidates (Join-Path $env:LOCALAPPDATA 'Programs/Android Studio/jbr/bin/java.exe') }
    $pathJava = Get-Command java.exe -ErrorAction SilentlyContinue
    if (-not $pathJava) { $pathJava = Get-Command java -ErrorAction SilentlyContinue }
    if ($pathJava) { Add-JavaCandidate $candidates $pathJava.Source }

    foreach ($candidate in $candidates) {
        $major = Get-JavaMajor $candidate
        if ($major -eq $RequiredMajor) {
            return [pscustomobject]@{ Path = $candidate; Major = $major }
        }
    }

    $managed = Install-ManagedJava $RequiredMajor
    return [pscustomobject]@{ Path = $managed; Major = $RequiredMajor }
}

$java = Resolve-Java $requiredJava
$javaBin = Split-Path -Parent $java.Path
$env:JAVA_HOME = Split-Path -Parent $javaBin
$env:PATH = $javaBin + [IO.Path]::PathSeparator + $env:PATH

function Read-LocalSdk {
    $properties = Join-Path $android 'local.properties'
    if (-not (Test-Path -LiteralPath $properties -PathType Leaf)) { return $null }
    foreach ($line in Get-Content -LiteralPath $properties) {
        if ($line -match '^\s*sdk\.dir\s*=\s*(.+?)\s*$') {
            return ($Matches[1] -replace '\\\\','\' -replace '\\:',':' -replace '\\ ',' ').Trim()
        }
    }
    return $null
}
function Looks-LikeAndroidSdk([string]$Path) {
    return $Path -and (Test-Path -LiteralPath $Path -PathType Container) -and (
        (Test-Path -LiteralPath (Join-Path $Path 'platforms') -PathType Container) -or
        (Test-Path -LiteralPath (Join-Path $Path 'platform-tools') -PathType Container) -or
        (Test-Path -LiteralPath (Join-Path $Path 'cmdline-tools') -PathType Container)
    )
}
function Find-AndroidSdk {
    $candidates = [Collections.Generic.List[string]]::new()
    foreach ($candidate in @($env:KASSIGNER_ANDROID_SDK_ROOT, (Read-LocalSdk), $env:ANDROID_SDK_ROOT, $env:ANDROID_HOME)) {
        if ($candidate) { $candidates.Add($candidate) }
    }
    if ($env:LOCALAPPDATA) { $candidates.Add((Join-Path $env:LOCALAPPDATA 'Android/Sdk')) }
    $candidates.Add((Join-Path $HOME 'AppData/Local/Android/Sdk'))
    $candidates.Add((Join-Path $HOME 'Android/Sdk'))
    foreach ($candidate in $candidates) {
        if (Looks-LikeAndroidSdk $candidate) { return [IO.Path]::GetFullPath($candidate) }
    }
    return $null
}
function Find-Api37Jar([string]$Sdk) {
    $platforms = Join-Path $Sdk 'platforms'
    if (-not (Test-Path -LiteralPath $platforms -PathType Container)) { return $null }
    foreach ($directory in Get-ChildItem -LiteralPath $platforms -Directory -ErrorAction SilentlyContinue | Sort-Object Name) {
        $jar = Join-Path $directory.FullName 'android.jar'
        if (-not (Test-Path -LiteralPath $jar -PathType Leaf)) { continue }
        $api = $null
        $source = Join-Path $directory.FullName 'source.properties'
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            $text = Get-Content -LiteralPath $source -Raw
            if ($text -match '(?m)^AndroidVersion\.ApiLevel\s*=\s*(\d+)\s*$') { $api = [int]$Matches[1] }
        }
        if ($null -eq $api -and $directory.Name -match '^android-(\d+)(?:\.\d+)?$') { $api = [int]$Matches[1] }
        if ($api -eq 37) { return $jar }
    }
    return $null
}

$sdk = Find-AndroidSdk
if (-not $sdk) { throw 'Android SDK was not found. Configure apps/kassee-android/local.properties sdk.dir, ANDROID_SDK_ROOT/ANDROID_HOME, or KASSIGNER_ANDROID_SDK_ROOT.' }
$env:ANDROID_SDK_ROOT = $sdk
$env:ANDROID_HOME = $sdk
$api37 = Find-Api37Jar $sdk
if (-not $api37) { throw "Android SDK platform API 37 (CINNAMON_BUN / Android 17) is required under $sdk\platforms." }

if (-not (Test-Path -LiteralPath $wrapperProperties -PathType Leaf)) { throw "Missing Gradle wrapper metadata: $wrapperProperties" }
$wrapper = @{}
foreach ($line in Get-Content -LiteralPath $wrapperProperties) {
    if ($line -match '^([^=]+)=(.*)$') { $wrapper[$Matches[1].Trim()] = ($Matches[2].Trim() -replace '\\:', ':') }
}
$url = [string]$wrapper['distributionUrl']
$sha = [string]$wrapper['distributionSha256Sum']
if ($url -notmatch '/gradle-([0-9]+(?:\.[0-9]+)*)-(?:bin|all)\.zip(?:[?#].*)?$') { throw 'Could not determine the pinned Gradle version from distributionUrl.' }
$version = $Matches[1]
if ($sha -notmatch '^[0-9A-Fa-f]{64}$') { throw 'distributionSha256Sum is missing or invalid in Gradle wrapper metadata.' }

function Gradle-Version([string]$Command) {
    if (-not $Command) { return $null }
    $probe = Invoke-KasSignerCapture -Command $Command -Arguments @('--version')
    if ($probe.ExitCode -ne 0) { return $null }
    if ($probe.Output -match '(?m)^Gradle\s+([^\s]+)') { return $Matches[1] }
    return $null
}

$gradle = $null
if ($env:GRADLE_BIN) {
    $command = Get-Command $env:GRADLE_BIN -ErrorAction SilentlyContinue
    if (-not $command -and (Test-Path -LiteralPath $env:GRADLE_BIN -PathType Leaf)) { $gradle = $env:GRADLE_BIN }
    elseif ($command) { $gradle = $command.Source }
    if (-not $gradle) { throw "GRADLE_BIN=$($env:GRADLE_BIN) was requested but is not executable or on PATH." }
    $foundVersion = Gradle-Version $gradle
    if ($foundVersion -ne $version) { throw "Pinned Gradle $version is required; GRADLE_BIN provides $foundVersion." }
} else {
    $command = Get-Command gradle.exe -ErrorAction SilentlyContinue
    if (-not $command) { $command = Get-Command gradle.bat -ErrorAction SilentlyContinue }
    if ($command -and (Gradle-Version $command.Source) -eq $version) { $gradle = $command.Source }
}

$gradleHome = if ($env:GRADLE_USER_HOME) { $env:GRADLE_USER_HOME } else { Join-Path $HOME '.gradle' }
$env:GRADLE_USER_HOME = $gradleHome
if (-not $gradle) {
    $distRoot = Join-Path $gradleHome 'kassigner/distributions'
    $zip = Join-Path $distRoot "gradle-$version-distribution.zip"
    $extracted = Join-Path $distRoot "gradle-$version"
    $gradle = Join-Path $extracted 'bin/gradle.bat'
    New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
    $archiveValid = (Test-Path -LiteralPath $zip -PathType Leaf) -and ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -eq $sha.ToLowerInvariant())
    if (-not $archiveValid) {
        Write-Host "==> Pinned Gradle $version is not installed; downloading and verifying it under $distRoot"
        $temporary = "$zip.tmp"
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        try { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $temporary }
        catch { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue; throw "Unable to download pinned Gradle from $url`: $($_.Exception.Message)" }
        $actual = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $sha.ToLowerInvariant()) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
            throw "Gradle SHA-256 mismatch: expected $sha, got $actual"
        }
        Move-Item -LiteralPath $temporary -Destination $zip -Force
    }
    if (-not (Test-Path -LiteralPath $gradle -PathType Leaf)) {
        Remove-KasSignerPath $extracted
        Expand-Archive -LiteralPath $zip -DestinationPath $distRoot -Force
    }
}
if (-not (Test-Path -LiteralPath $gradle -PathType Leaf)) { throw "Pinned Gradle $version could not be prepared." }
$foundVersion = Gradle-Version $gradle
if ($foundVersion -ne $version) { throw "Pinned Gradle $version is required; prepared $foundVersion." }

$task = switch ($Mode) { 'debug' {'assembleDebug'} 'release' {'assembleRelease'} 'test' {'testDebugUnitTest'} }
Write-Host "==> KasSee Android - $Mode (API 37)"
Write-Host "==> Android SDK: $sdk"
Write-Host "==> Java: $($java.Path) (major $($java.Major))"
Write-Host "==> Gradle: $gradle"
Invoke-KasSignerCommand -Command $gradle -Arguments @('--project-dir',$android,'--no-daemon',$task) -WorkingDirectory $root | Out-Null
Write-Host "KasSee Android - $Mode complete."

if ($Mode -in @('debug','release')) {
    $variantDir = Join-Path $android "app/build/outputs/apk/$Mode"
    $artifacts = @(Get-ChildItem -LiteralPath $variantDir -Filter '*.apk' -File -ErrorAction SilentlyContinue | Sort-Object FullName)
    if ($artifacts.Count -eq 0) { throw "Android $Mode build completed but no APK was found under $variantDir." }
    Write-Host $(if ($artifacts.Count -eq 1) { 'Built artifact:' } else { 'Built artifacts:' })
    foreach ($artifact in $artifacts) { Write-Host "  $($artifact.FullName)" }
} elseif ($Mode -eq 'test') {
    $report = Join-Path $android 'app/build/reports/tests/testDebugUnitTest/index.html'
    if (Test-Path -LiteralPath $report -PathType Leaf) {
        Write-Host 'Test report:'
        Write-Host "  $report"
    }
}
