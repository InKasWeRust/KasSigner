$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$android = Join-Path $root 'apps/kassee-android'
. (Join-Path $root 'scripts/windows/lib/common.ps1')
Import-KasSignerToolchains $root
$python = Get-KasSignerPython
Require-KasSignerCommand rustup 'Install Rustup for Windows and reopen PowerShell.' | Out-Null

function Find-AndroidStudio {
    $candidates = [Collections.Generic.List[string]]::new()
    if ($env:ANDROID_STUDIO_BIN) { $candidates.Add($env:ANDROID_STUDIO_BIN) }
    if ($env:ANDROID_STUDIO_HOME) { $candidates.Add((Join-Path $env:ANDROID_STUDIO_HOME 'bin/studio64.exe')); $candidates.Add((Join-Path $env:ANDROID_STUDIO_HOME 'bin/studio.exe')) }
    foreach($name in @('studio64.exe','studio.exe','android-studio.exe')) { $cmd=Get-Command $name -ErrorAction SilentlyContinue; if($cmd){$candidates.Add($cmd.Source)} }
    foreach($base in @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:LOCALAPPDATA)) {
        if(-not $base){continue}
        foreach($rel in @('Android/Android Studio/bin/studio64.exe','Android/Android Studio/bin/studio.exe','Google/Android Studio/bin/studio64.exe','Programs/Android Studio/bin/studio64.exe')) { $candidates.Add((Join-Path $base $rel)) }
    }
    if($env:LOCALAPPDATA){
        foreach($toolbox in @((Join-Path $env:LOCALAPPDATA 'JetBrains/Toolbox/apps/AndroidStudio'),(Join-Path $env:LOCALAPPDATA 'JetBrains/Toolbox/apps/AndroidStudioPreview'))){
            if(Test-Path $toolbox){$hit=Get-ChildItem $toolbox -Recurse -File -Filter studio64.exe -ErrorAction SilentlyContinue|Select-Object -First 1;if($hit){$candidates.Add($hit.FullName)}}
        }
    }
    return $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
}
function Read-LocalSdk {
    $p=Join-Path $android 'local.properties'; if(-not(Test-Path $p)){return $null}
    foreach($line in Get-Content $p){if($line -match '^\s*sdk\.dir\s*=\s*(.+?)\s*$'){return ($Matches[1] -replace '\\\\','\' -replace '\\:',':' -replace '\\ ',' ').Trim()}}
    return $null
}
function Looks-LikeSdk([string]$p){return $p -and (Test-Path $p) -and ((Test-Path (Join-Path $p 'platforms')) -or (Test-Path (Join-Path $p 'platform-tools')) -or (Test-Path (Join-Path $p 'cmdline-tools')))}
function Find-Sdk {
    $list=@($env:KASSIGNER_ANDROID_SDK_ROOT,(Read-LocalSdk),$env:ANDROID_SDK_ROOT,$env:ANDROID_HOME)
    if($env:LOCALAPPDATA){$list += (Join-Path $env:LOCALAPPDATA 'Android/Sdk')}
    $list += @((Join-Path $HOME 'AppData/Local/Android/Sdk'),(Join-Path $HOME 'Android/Sdk'))
    return $list|Where-Object{Looks-LikeSdk $_}|Select-Object -First 1
}
function Java-Major([string]$java){$probe=Invoke-KasSignerCapture -Command $java -Arguments @('-version');if($probe.ExitCode -eq 0 -and $probe.Output -match 'version\s+"(?:(?:1\.)?)(\d+)'){return [int]$Matches[1]};return 0}
function Gradle-VersionFromUrl([string]$url){if($url -match '/gradle-([0-9]+(?:\.[0-9]+)*)-(?:bin|all)\.zip'){return $Matches[1]};throw 'Could not determine pinned Gradle version from distributionUrl.'}

$studio=Find-AndroidStudio; if(-not$studio){throw 'Android Studio was not found. Set ANDROID_STUDIO_BIN/ANDROID_STUDIO_HOME or install Android Studio for Windows.'}
$sdk=Find-Sdk; if(-not$sdk){throw 'Android SDK was not found. Configure sdk.dir, ANDROID_SDK_ROOT/ANDROID_HOME, or KASSIGNER_ANDROID_SDK_ROOT.'}
$env:ANDROID_SDK_ROOT=$sdk;$env:ANDROID_HOME=$sdk
Write-Host "==> Android Studio: $studio";Write-Host "==> Android SDK: $sdk"
$gradleText=Get-Content (Join-Path $android 'app/build.gradle.kts') -Raw
$api=if($env:KASSIGNER_COMPILE_SDK){$env:KASSIGNER_COMPILE_SDK}elseif($gradleText -match '\bcompileSdk\s*=\s*([0-9]+)'){$Matches[1]}else{''}
if($api -match '^api:'){ $api=$api.Substring(4) }
if($api -match '^\d+$'){$jar=Join-Path $sdk "platforms/android-$api/android.jar";if(-not(Test-Path $jar)){throw "The project requires compileSdk $api, but $jar is not installed."};Write-Host "==> compileSdk $api resolved to: $(Split-Path -Parent $jar)"}

$required=[int]$env:KASSIGNER_ANDROID_JDK
$studioHome=[IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $studio) '..'))
$jbr=Join-Path $studioHome 'jbr';$java=Join-Path $jbr 'bin/java.exe'
if((Test-Path $java) -and (Java-Major $java) -eq $required){$env:JAVA_HOME=$jbr}
elseif($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME 'bin/java.exe')) -and (Java-Major (Join-Path $env:JAVA_HOME 'bin/java.exe')) -eq $required){}
else{throw "KasSee Android requires JDK $required for the Gradle daemon. Use Android Studio with JBR $required or set JAVA_HOME to JDK $required."}
$env:PATH=(Join-Path $env:JAVA_HOME 'bin')+[IO.Path]::PathSeparator+$env:PATH
Write-Host "==> Java: $env:JAVA_HOME (major $required)"

$props=Join-Path $android 'gradle/wrapper/gradle-wrapper.properties';$lines=Get-Content $props
$url=(($lines|Where-Object{$_ -match '^distributionUrl='}|Select-Object -Last 1) -replace '^distributionUrl=','' -replace '\\:',':')
$sha=(($lines|Where-Object{$_ -match '^distributionSha256Sum='}|Select-Object -Last 1) -replace '^distributionSha256Sum=','').Trim()
$version=Gradle-VersionFromUrl $url
$gradle=$null;$cmd=Get-Command gradle.exe -ErrorAction SilentlyContinue
if($cmd){$probe=Invoke-KasSignerCapture -Command $cmd.Source -Arguments @('--version');if($probe.ExitCode -eq 0 -and $probe.Output -match '(?m)^Gradle\s+([^\s]+)' -and $Matches[1] -eq $version){$gradle=$cmd.Source}}
$gradleHome=if($env:GRADLE_USER_HOME){$env:GRADLE_USER_HOME}else{Join-Path $HOME '.gradle'};$env:GRADLE_USER_HOME=$gradleHome
if(-not$gradle){
    $distRoot=Join-Path $gradleHome 'kassigner/distributions';$zip=Join-Path $distRoot "gradle-$version-distribution.zip";$extracted=Join-Path $distRoot "gradle-$version";$gradle=Join-Path $extracted 'bin/gradle.bat'
    New-Item -ItemType Directory -Force -Path $distRoot|Out-Null
    if(-not(Test-Path $zip) -or (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sha.ToLowerInvariant()){
        Write-Host "==> Downloading and verifying pinned Gradle $version";$tmp="$zip.tmp";Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp
        $actual=(Get-FileHash $tmp -Algorithm SHA256).Hash.ToLowerInvariant();if($actual -ne $sha.ToLowerInvariant()){Remove-Item $tmp -Force;throw "Gradle SHA-256 mismatch: expected $sha, got $actual"};Move-Item $tmp $zip -Force
    }
    if(-not(Test-Path $gradle)){Remove-KasSignerPath $extracted;Expand-Archive -LiteralPath $zip -DestinationPath $distRoot -Force}
}
if(-not(Test-Path $gradle)){throw "Pinned Gradle $version could not be prepared."}
Write-Host "==> Gradle: $gradle"
Write-Host '==> Building KasSee Android (KasSee runtime is built automatically)'
& (Join-Path $root 'scripts/windows/build/android-runtime-sync.ps1');if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
Invoke-KasSignerCommand -Command $gradle -Arguments @('--project-dir',$android,'--no-daemon',':app:assembleDebug') -WorkingDirectory $root|Out-Null
$apk=Join-Path $android 'app/build/outputs/apk/debug/app-debug.apk';if(-not(Test-Path $apk)-or(Get-Item $apk).Length -eq 0){throw "Gradle reported success but debug APK is missing: $apk"}
$verify='import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); req={"assets/kassee/index.html","assets/kassee/css/app.css","assets/kassee/js/main.js","assets/kassee/pkg/kassee_web.js","assets/kassee/pkg/kassee_web_bg.wasm"}; m=sorted(req-set(z.namelist())); assert not m, "debug APK is missing KasSee assets: "+", ".join(m); print("==> APK KasSee asset verification: PASS")'
& $python -c $verify $apk;if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
Write-Host "==> Debug APK ready: $apk";$env:STUDIO_GRADLE_JDK=$env:JAVA_HOME;Write-Host "==> Android Studio Gradle JDK: $env:STUDIO_GRADLE_JDK";Write-Host '==> Opening Android Studio'
Start-Process -FilePath $studio -ArgumentList @($android)
Write-Host 'KasSee Android is built and Android Studio is starting.'
