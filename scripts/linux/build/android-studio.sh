#!/usr/bin/env bash
# One-command KasSee Android bootstrap: discover host tools, verify the
# project SDK, build the complete debug APK (including KasSee), then open Studio.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
ANDROID_DIR="$REPO_ROOT/apps/kassee-android"
TOOLCHAINS_ENV="$REPO_ROOT/qa/config/toolchains.env"
WRAPPER_PROPERTIES="$ANDROID_DIR/gradle/wrapper/gradle-wrapper.properties"
DAEMON_JVM_PROPERTIES="$ANDROID_DIR/gradle/gradle-daemon-jvm.properties"
LOCAL_PROPERTIES="$ANDROID_DIR/local.properties"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

command -v python3 >/dev/null 2>&1 || fail "python3 is required."
if ! command -v rustup >/dev/null 2>&1 && [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
fi
command -v rustup >/dev/null 2>&1 || fail "rustup is required."

find_android_studio() {
    local candidate root
    local -a candidates=()
    [[ -n "${ANDROID_STUDIO_BIN:-}" ]] && candidates+=("$ANDROID_STUDIO_BIN")
    if [[ -n "${ANDROID_STUDIO_HOME:-}" ]]; then
        candidates+=("$ANDROID_STUDIO_HOME/bin/studio" "$ANDROID_STUDIO_HOME/bin/studio.sh")
    fi
    for candidate in android-studio studio studio.sh; do
        command -v "$candidate" >/dev/null 2>&1 && candidates+=("$(command -v "$candidate")")
    done
    candidates+=(
        "/opt/android-studio/bin/studio" "/opt/android-studio/bin/studio.sh"
        "/usr/local/android-studio/bin/studio" "/usr/local/android-studio/bin/studio.sh"
        "$HOME/android-studio/bin/studio" "$HOME/android-studio/bin/studio.sh"
        "$HOME/.local/opt/android-studio/bin/studio" "$HOME/.local/opt/android-studio/bin/studio.sh"
        "/mnt/Extra/android-dev/android-studio/bin/studio" "/mnt/Extra/android-dev/android-studio/bin/studio.sh"
    )
    for candidate in "${candidates[@]}"; do
        [[ -n "$candidate" && -x "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
    done
    for root in "$HOME/.local/share/JetBrains/Toolbox/apps/AndroidStudio" "$HOME/.local/share/JetBrains/Toolbox/apps/AndroidStudioPreview"; do
        [[ -d "$root" ]] || continue
        candidate="$(find "$root" -type f \( -name studio -o -name studio.sh \) -path '*/bin/*' -perm -u+x -print -quit 2>/dev/null || true)"
        [[ -n "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
    done
    return 1
}

read_local_sdk_dir() {
    [[ -f "$LOCAL_PROPERTIES" ]] || return 1
    python3 - "$LOCAL_PROPERTIES" <<'PY'
from pathlib import Path
import os, sys
value = None
for raw in Path(sys.argv[1]).read_text(errors="replace").splitlines():
    line = raw.strip()
    if not line or line.startswith(("#", "!")): continue
    key, sep, rhs = line.partition("=")
    if sep and key.strip() == "sdk.dir": value = rhs.strip()
if value is None: raise SystemExit(1)
print(os.path.expanduser(value.replace(r"\ ", " ").replace(r"\:", ":").replace(r"\\", "\\")))
PY
}

looks_like_android_sdk() {
    [[ -d "$1" ]] && [[ -d "$1/platforms" || -d "$1/platform-tools" || -d "$1/cmdline-tools" ]]
}

find_android_sdk() {
    local candidate local_sdk
    local -a candidates=()
    [[ -n "${KASSIGNER_ANDROID_SDK_ROOT:-}" ]] && candidates+=("$KASSIGNER_ANDROID_SDK_ROOT")
    local_sdk="$(read_local_sdk_dir 2>/dev/null || true)"
    [[ -n "$local_sdk" ]] && candidates+=("$local_sdk")
    [[ -n "${ANDROID_SDK_ROOT:-}" ]] && candidates+=("$ANDROID_SDK_ROOT")
    [[ -n "${ANDROID_HOME:-}" ]] && candidates+=("$ANDROID_HOME")
    candidates+=(
        "$HOME/Android/Sdk" "$HOME/Android/sdk" "$HOME/.android/sdk"
        "/mnt/Extra/android-dev/sdk" "/opt/android-sdk" "/usr/local/android-sdk"
        "/usr/local/lib/android/sdk" "/usr/lib/android-sdk"
    )
    for candidate in "${candidates[@]}"; do
        [[ -n "$candidate" ]] || continue
        if looks_like_android_sdk "$candidate"; then (cd "$candidate" && pwd -P); return 0; fi
    done
    return 1
}

detect_compile_sdk() {
    python3 - "$ANDROID_DIR" <<'PY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
for path in (root / "app/build.gradle.kts", root / "app/build.gradle"):
    if not path.is_file(): continue
    text = path.read_text(errors="replace")
    m = re.search(r"\bcompileSdk(?:Version)?\s*(?:=\s*)?([0-9]+)\b", text)
    if m: print(f"api:{m.group(1)}"); raise SystemExit(0)
    m = re.search(r"\bcompileSdkPreview\s*(?:=\s*)?[\"']([^\"']+)[\"']", text)
    if m: print(f"preview:{m.group(1)}"); raise SystemExit(0)
raise SystemExit(1)
PY
}

find_platform_jar_for_api() {
    local api="$1" dir props declared_api base
    local -a dirs=()
    [[ -d "$SDK_ROOT/platforms" ]] || return 1
    shopt -s nullglob; dirs=("$SDK_ROOT"/platforms/android-*); shopt -u nullglob
    for dir in "${dirs[@]}"; do
        [[ -d "$dir" && -f "$dir/android.jar" ]] || continue
        props="$dir/source.properties"
        if [[ -f "$props" ]]; then
            declared_api="$(awk -F= '$1 == "AndroidVersion.ApiLevel" { gsub(/\r/, "", $2); print $2; exit }' "$props")"
            [[ "$declared_api" == "$api" ]] && { printf '%s\n' "$dir/android.jar"; return 0; }
        fi
        base="$(basename "$dir")"
        [[ "$base" == "android-$api" || "$base" == "android-$api."* ]] && { printf '%s\n' "$dir/android.jar"; return 0; }
    done
    return 1
}

find_platform_jar_for_preview() {
    local preview="$1" dir props codename base
    local -a dirs=()
    [[ -d "$SDK_ROOT/platforms" ]] || return 1
    shopt -s nullglob; dirs=("$SDK_ROOT"/platforms/android-*); shopt -u nullglob
    for dir in "${dirs[@]}"; do
        [[ -d "$dir" && -f "$dir/android.jar" ]] || continue
        props="$dir/source.properties"
        if [[ -f "$props" ]]; then
            codename="$(awk -F= '$1 == "AndroidVersion.CodeName" { gsub(/\r/, "", $2); print $2; exit }' "$props")"
            [[ "$codename" == "$preview" ]] && { printf '%s\n' "$dir/android.jar"; return 0; }
        fi
        base="$(basename "$dir")"
        [[ "$base" == "android-$preview" ]] && { printf '%s\n' "$dir/android.jar"; return 0; }
    done
    return 1
}

list_installed_platforms() {
    [[ -d "$SDK_ROOT/platforms" ]] || { printf '  (no platforms directory)\n' >&2; return; }
    find "$SDK_ROOT/platforms" -mindepth 1 -maxdepth 1 -type d -name 'android-*' -printf '  %f\n' 2>/dev/null | sort -V >&2
}

find_studio_jbr() {
    local resolved home candidate root
    resolved="$(readlink -f "$STUDIO_BIN" 2>/dev/null || printf '%s' "$STUDIO_BIN")"
    home="$(cd "$(dirname "$resolved")/.." 2>/dev/null && pwd -P || true)"
    [[ -n "$home" && -x "$home/jbr/bin/java" ]] && { printf '%s\n' "$home/jbr"; return 0; }
    for root in "$HOME/.local/share/JetBrains/Toolbox/apps/AndroidStudio" "$HOME/.local/share/JetBrains/Toolbox/apps/AndroidStudioPreview"; do
        [[ -d "$root" ]] || continue
        candidate="$(find "$root" -type f -path '*/jbr/bin/java' -perm -u+x -print -quit 2>/dev/null || true)"
        [[ -n "$candidate" ]] && { dirname "$(dirname "$candidate")"; return 0; }
    done
    return 1
}

java_major_of() {
    "$1" -version 2>&1 | awk -F'[".]' '/version/ { if ($2 == "1") print $3; else print $2; exit }'
}

required_java_major() {
    [[ -f "$TOOLCHAINS_ENV" ]] || fail "Missing central toolchain policy: $TOOLCHAINS_ENV"
    [[ -f "$DAEMON_JVM_PROPERTIES" ]] || fail "Missing canonical Gradle Daemon JVM criteria: $DAEMON_JVM_PROPERTIES"
    # shellcheck disable=SC1090
    source "$TOOLCHAINS_ENV"
    local criteria_major pin_major="${KASSIGNER_ANDROID_JDK:-}"
    criteria_major="$(sed -n 's/^toolchainVersion=//p' "$DAEMON_JVM_PROPERTIES" | tail -n1 | tr -d '\r')"
    [[ "$pin_major" =~ ^[0-9]+$ ]] || fail "KASSIGNER_ANDROID_JDK is missing or invalid in $TOOLCHAINS_ENV"
    [[ "$criteria_major" == "$pin_major" ]] || fail "Gradle Daemon JVM criteria ($criteria_major) does not match central Android JDK pin ($pin_major)."
    printf '%s\n' "$pin_major"
}

configure_java() {
    local required_major="$1" java_bin major jbr

    # Prefer Android Studio's embedded JBR when it exactly matches the
    # repository-owned Daemon JVM criteria. The command-line build and Studio
    # then use the same runtime without persisting a machine-local JDK path.
    jbr="$(find_studio_jbr || true)"
    if [[ -n "$jbr" && -x "$jbr/bin/java" ]]; then
        major="$(java_major_of "$jbr/bin/java")"
        if [[ "$major" == "$required_major" ]]; then
            export JAVA_HOME="$jbr"
            export PATH="$JAVA_HOME/bin:$PATH"
            return 0
        fi
    fi

    if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
        major="$(java_major_of "$JAVA_HOME/bin/java")"
        if [[ "$major" == "$required_major" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; return 0; fi
    fi
    java_bin="$(command -v java 2>/dev/null || true)"
    if [[ -n "$java_bin" ]]; then
        major="$(java_major_of "$java_bin")"
        if [[ "$major" == "$required_major" ]]; then
            java_bin="$(readlink -f "$java_bin" 2>/dev/null || printf '%s' "$java_bin")"
            export JAVA_HOME="$(cd "$(dirname "$java_bin")/.." && pwd -P)"
            export PATH="$JAVA_HOME/bin:$PATH"
            return 0
        fi
    fi
    fail "KasSee Android requires JDK $required_major for the Gradle daemon. Install/use an Android Studio whose embedded JBR is JDK $required_major, or set JAVA_HOME to a JDK $required_major installation."
}

STUDIO_BIN="$(find_android_studio || true)"
[[ -n "$STUDIO_BIN" ]] || fail "Android Studio was not found. Put its launcher on PATH, set ANDROID_STUDIO_BIN, or set ANDROID_STUDIO_HOME."
SDK_ROOT="$(find_android_sdk || true)"
[[ -n "$SDK_ROOT" ]] || fail "Android SDK was not found. Configure sdk.dir in local.properties, ANDROID_HOME/ANDROID_SDK_ROOT, or KASSIGNER_ANDROID_SDK_ROOT."
export ANDROID_SDK_ROOT="$SDK_ROOT" ANDROID_HOME="$SDK_ROOT"
info "Android Studio: $STUDIO_BIN"
info "Android SDK: $SDK_ROOT"

COMPILE_SDK="${KASSIGNER_COMPILE_SDK:-}"
[[ -n "$COMPILE_SDK" ]] || COMPILE_SDK="$(detect_compile_sdk 2>/dev/null || true)"
if [[ "$COMPILE_SDK" == api:* ]]; then
    REQUIRED_API="${COMPILE_SDK#api:}"
    PLATFORM_JAR="$(find_platform_jar_for_api "$REQUIRED_API" || true)"
    if [[ -z "$PLATFORM_JAR" ]]; then
        printf 'Installed SDK platform directories under %s/platforms:\n' "$SDK_ROOT" >&2; list_installed_platforms
        fail "The project requires compileSdk $REQUIRED_API, but no installed SDK platform advertising API $REQUIRED_API was found. Platform directory names may include a minor suffix such as android-${REQUIRED_API}.0; this check uses SDK metadata and does not require an exact directory name."
    fi
    info "compileSdk $REQUIRED_API resolved to: $(dirname "$PLATFORM_JAR")"
elif [[ "$COMPILE_SDK" == preview:* ]]; then
    REQUIRED_PREVIEW="${COMPILE_SDK#preview:}"
    PLATFORM_JAR="$(find_platform_jar_for_preview "$REQUIRED_PREVIEW" || true)"
    if [[ -z "$PLATFORM_JAR" ]]; then
        printf 'Installed SDK platform directories under %s/platforms:\n' "$SDK_ROOT" >&2; list_installed_platforms
        fail "The project requires compileSdkPreview '$REQUIRED_PREVIEW', but no matching installed SDK platform was found."
    fi
    info "compileSdkPreview $REQUIRED_PREVIEW resolved to: $(dirname "$PLATFORM_JAR")"
elif [[ "$COMPILE_SDK" =~ ^[0-9]+$ ]]; then
    PLATFORM_JAR="$(find_platform_jar_for_api "$COMPILE_SDK" || true)"
    [[ -n "$PLATFORM_JAR" ]] || fail "KASSIGNER_COMPILE_SDK=$COMPILE_SDK was requested, but no matching installed SDK platform was found under $SDK_ROOT/platforms."
    info "compileSdk $COMPILE_SDK resolved to: $(dirname "$PLATFORM_JAR")"
elif [[ -n "$COMPILE_SDK" ]]; then
    warn "Could not interpret KASSIGNER_COMPILE_SDK='$COMPILE_SDK'; exact SDK-platform validation will be left to Gradle."
else
    warn "compileSdk is not a literal value in app/build.gradle(.kts); exact SDK-platform validation will be left to Gradle. Set KASSIGNER_COMPILE_SDK=<api> if an explicit preflight check is desired."
fi

REQUIRED_JAVA_MAJOR="$(required_java_major)"
configure_java "$REQUIRED_JAVA_MAJOR"
java_major="$(java_major_of "$JAVA_HOME/bin/java")"
info "Java: $JAVA_HOME/bin/java (major $java_major; daemon criteria $REQUIRED_JAVA_MAJOR)"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$HOME/.gradle}"
mkdir -p "$GRADLE_USER_HOME"
[[ -f "$WRAPPER_PROPERTIES" ]] || fail "Missing Gradle wrapper metadata: $WRAPPER_PROPERTIES"
GRADLE_URL="$(sed -n 's#^distributionUrl=##p' "$WRAPPER_PROPERTIES" | tail -n1 | sed 's#\\:#:#g')"
GRADLE_SHA="$(sed -n 's#^distributionSha256Sum=##p' "$WRAPPER_PROPERTIES" | tail -n1 | tr -d '\r')"
[[ -n "$GRADLE_URL" ]] || fail "distributionUrl is missing from $WRAPPER_PROPERTIES."
[[ "$GRADLE_SHA" =~ ^[0-9A-Fa-f]{64}$ ]] || fail "distributionSha256Sum is missing or invalid in $WRAPPER_PROPERTIES."
GRADLE_VERSION="$(python3 - "$GRADLE_URL" <<'PY'
import re, sys
m = re.search(r"/gradle-([0-9]+(?:\.[0-9]+)*)-(?:bin|all)\.zip(?:[?#].*)?$", sys.argv[1])
if not m: raise SystemExit(1)
print(m.group(1))
PY
)" || fail "Could not determine the pinned Gradle version from distributionUrl."

find_pinned_gradle() {
    local system_gradle cached version
    system_gradle="$(command -v gradle 2>/dev/null || true)"
    if [[ -n "$system_gradle" ]]; then
        version="$("$system_gradle" --version 2>/dev/null | awk '/^Gradle / { print $2; exit }')"
        [[ "$version" == "$GRADLE_VERSION" ]] && { printf '%s\n' "$system_gradle"; return 0; }
    fi
    cached="$(find "$GRADLE_USER_HOME" -type f -path "*/gradle-$GRADLE_VERSION/bin/gradle" -perm -u+x -print -quit 2>/dev/null || true)"
    [[ -n "$cached" ]] && { printf '%s\n' "$cached"; return 0; }
    return 1
}

GRADLE_BIN="$(find_pinned_gradle || true)"
if [[ -z "$GRADLE_BIN" ]]; then
    DIST_ROOT="$GRADLE_USER_HOME/kassigner/distributions"
    DIST_ZIP="$DIST_ROOT/gradle-$GRADLE_VERSION-distribution.zip"
    mkdir -p "$DIST_ROOT"
    info "Downloading and verifying pinned Gradle $GRADLE_VERSION"
    python3 - "$GRADLE_URL" "$DIST_ZIP" "$GRADLE_SHA" "$DIST_ROOT" "$GRADLE_VERSION" <<'PY'
from hashlib import sha256
from pathlib import Path
import shutil, sys, urllib.request, zipfile
url, archive_name, expected, destination, version = sys.argv[1:]
archive, destination = Path(archive_name), Path(destination)
extracted = destination / f"gradle-{version}"
def digest(path):
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
    return h.hexdigest()
def valid(path): return path.is_file() and digest(path) == expected.lower()
if not valid(archive):
    tmp = archive.with_suffix(archive.suffix + ".tmp"); tmp.unlink(missing_ok=True)
    with urllib.request.urlopen(url) as response, tmp.open("wb") as out: shutil.copyfileobj(response, out)
    actual = digest(tmp)
    if actual != expected.lower(): tmp.unlink(missing_ok=True); raise SystemExit(f"ERROR: Gradle SHA-256 mismatch: expected {expected}, got {actual}")
    tmp.replace(archive)
launcher = extracted / "bin/gradle"
with zipfile.ZipFile(archive) as zf:
    if not launcher.is_file():
        if extracted.exists(): shutil.rmtree(extracted)
        zf.extractall(destination)
    # zipfile extraction may drop Unix execute bits. Reapply the verified
    # archive modes even for an existing cache so failed prior bootstraps heal.
    for member in zf.infolist():
        mode = (member.external_attr >> 16) & 0o777
        if mode:
            target = destination / member.filename
            if target.exists(): target.chmod(mode)
if launcher.is_file() and not launcher.stat().st_mode & 0o100:
    launcher.chmod(launcher.stat().st_mode | 0o100)
PY
    GRADLE_BIN="$DIST_ROOT/gradle-$GRADLE_VERSION/bin/gradle"
fi
[[ -x "$GRADLE_BIN" ]] || fail "Pinned Gradle $GRADLE_VERSION could not be prepared."
info "Gradle: $GRADLE_BIN"
info "Building KasSee Android (KasSee runtime is built automatically)"
"$GRADLE_BIN" --project-dir "$ANDROID_DIR" --no-daemon :app:assembleDebug
APK="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
[[ -s "$APK" ]] || fail "Gradle reported success but the debug APK is missing: $APK"
python3 - "$APK" <<'PYAPK'
import sys
import zipfile

apk = sys.argv[1]
required = {
    "assets/kassee/index.html",
    "assets/kassee/css/app.css",
    "assets/kassee/js/main.js",
    "assets/kassee/pkg/kassee_web.js",
    "assets/kassee/pkg/kassee_web_bg.wasm",
}
with zipfile.ZipFile(apk) as archive:
    names = set(archive.namelist())
missing = sorted(required - names)
if missing:
    raise SystemExit("ERROR: debug APK is missing KasSee assets: " + ", ".join(missing))
print("==> APK KasSee asset verification: PASS")
PYAPK
info "Debug APK ready: $APK"
info "The APK is already built; the first Android Studio Play build may complete almost instantly because Gradle can reuse these outputs."
# Android Studio uses STUDIO_GRADLE_JDK before its saved project Gradle-JDK
# selection. Pass the same JDK that just completed the command-line build so
# Studio cannot reopen this project with a stale or invalid Gradle JDK entry.
export STUDIO_GRADLE_JDK="$JAVA_HOME"
info "Android Studio Gradle JDK: $STUDIO_GRADLE_JDK"
info "Opening Android Studio"
"$STUDIO_BIN" "$ANDROID_DIR" >/dev/null 2>&1 &
disown || true
printf 'KasSee Android is built and Android Studio is starting.\n'
