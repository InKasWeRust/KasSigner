#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ANDROID_APP="$ROOT/apps/kassee-android"
WRAPPER_PROPERTIES="$ANDROID_APP/gradle/wrapper/gradle-wrapper.properties"
DAEMON_JVM_PROPERTIES="$ANDROID_APP/gradle/gradle-daemon-jvm.properties"
TOOLCHAINS_ENV="$ROOT/qa/config/toolchains.env"
SDK_ROOT="${KASSIGNER_ANDROID_SDK_ROOT:-${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}}"
MODE="${1:-debug}"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }
command -v python3 >/dev/null 2>&1 || fail "python3 is required to prepare the pinned Android build toolchain."
[[ -f "$TOOLCHAINS_ENV" ]] || fail "Missing central toolchain policy: $TOOLCHAINS_ENV"
[[ -f "$DAEMON_JVM_PROPERTIES" ]] || fail "Missing canonical Gradle Daemon JVM criteria: $DAEMON_JVM_PROPERTIES"
# shellcheck disable=SC1090
source "$TOOLCHAINS_ENV"
required_java="${KASSIGNER_ANDROID_JDK:-}"
daemon_java="$(sed -n 's/^toolchainVersion=//p' "$DAEMON_JVM_PROPERTIES" | tail -n1 | tr -d '\r')"
[[ "$required_java" =~ ^[0-9]+$ ]] || fail "KASSIGNER_ANDROID_JDK is missing or invalid in $TOOLCHAINS_ENV"
[[ "$daemon_java" == "$required_java" ]] || fail "Gradle Daemon JVM criteria ($daemon_java) does not match central Android JDK pin ($required_java)."

java_major_of() {
    "$1" -version 2>&1 | awk -F'[".]' '/version/ { if ($2 == "1") print $3; else print $2; exit }'
}
install_managed_java() {
    local target="$HOME/.local/share/kassigner/jdk-$required_java"
    local target_java="$target/bin/java"
    local arch api_arch
    if [[ -x "$target_java" && "$(java_major_of "$target_java")" == "$required_java" ]]; then
        printf '%s\n' "$target_java"
        return 0
    fi
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) api_arch="x64" ;;
        aarch64|arm64) api_arch="aarch64" ;;
        *) fail "Unsupported Linux architecture for managed JDK $required_java: $arch" ;;
    esac
    info "Pinned JDK $required_java is not installed; downloading and verifying it under $target" >&2
    python3 - "$required_java" "$api_arch" "$target" <<'PYJDK'
from hashlib import sha256
from pathlib import Path
import json, shutil, sys, tarfile, tempfile, urllib.request

major, arch, target_name = sys.argv[1:]
target = Path(target_name)
meta = f"https://api.adoptium.net/v3/assets/latest/{major}/hotspot?architecture={arch}&image_type=jdk&os=linux&vendor=eclipse"

def open_url(url: str, accept: str = "*/*"):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "KasSigner-build/2.0 (+https://github.com/InKasWeRust/KasSigner)",
            "Accept": accept,
        },
    )
    return urllib.request.urlopen(request)

with open_url(meta, "application/json") as response:
    assets = json.load(response)
if not assets:
    raise SystemExit(f"ERROR: Adoptium did not return a Linux JDK {major} package for {arch}.")
package = assets[0].get("binary", {}).get("package", {})
url = package.get("link", "")
expected = str(package.get("checksum", "")).lower()
if not url or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
    raise SystemExit(f"ERROR: Adoptium JDK {major} metadata is incomplete.")

def digest(path: Path) -> str:
    h = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

with tempfile.TemporaryDirectory(prefix="kassigner-android-jdk-") as temp_name:
    temp = Path(temp_name)
    archive = temp / "jdk.tar.gz"
    with open_url(url) as response, archive.open("wb") as output:
        shutil.copyfileobj(response, output)
    actual = digest(archive)
    if actual != expected:
        raise SystemExit(f"ERROR: JDK SHA-256 mismatch: expected {expected}, got {actual}")
    unpack = temp / "unpack"
    unpack.mkdir()
    with tarfile.open(archive, "r:*") as bundle:
        bundle.extractall(unpack, filter="data")
    roots = [path for path in unpack.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise SystemExit("ERROR: JDK archive did not contain exactly one top-level directory.")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(target, ignore_errors=True)
    shutil.move(str(roots[0]), str(target))
PYJDK
    [[ -x "$target_java" && "$(java_major_of "$target_java")" == "$required_java" ]] \
        || fail "Prepared JDK does not report required major $required_java: $target_java"
    printf '%s\n' "$target_java"
}

select_java() {
    local candidate major java_bin
    for candidate in \
        "$HOME/.local/share/kassigner/jdk-$required_java/bin/java" \
        "${JAVA_HOME:+$JAVA_HOME/bin/java}"; do
        [[ -n "$candidate" && -x "$candidate" ]] || continue
        major="$(java_major_of "$candidate")"
        if [[ "$major" == "$required_java" ]]; then
            java_bin="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
            export JAVA_HOME="$(cd "$(dirname "$java_bin")/.." && pwd -P)"
            export PATH="$JAVA_HOME/bin:$PATH"
            return 0
        fi
    done
    java_bin="$(command -v java 2>/dev/null || true)"
    if [[ -n "$java_bin" ]]; then
        major="$(java_major_of "$java_bin")"
        if [[ "$major" == "$required_java" ]]; then
            java_bin="$(readlink -f "$java_bin" 2>/dev/null || printf '%s' "$java_bin")"
            export JAVA_HOME="$(cd "$(dirname "$java_bin")/.." && pwd -P)"
            export PATH="$JAVA_HOME/bin:$PATH"
            return 0
        fi
    fi
    java_bin="$(install_managed_java)"
    export JAVA_HOME="$(cd "$(dirname "$java_bin")/.." && pwd -P)"
    export PATH="$JAVA_HOME/bin:$PATH"
}
select_java
java_major="$(java_major_of "$JAVA_HOME/bin/java")"


read_local_sdk_dir() {
    local properties="$ANDROID_APP/local.properties"
    [[ -f "$properties" ]] || return 1
    python3 - "$properties" <<'PY'
from pathlib import Path
import os, sys
for raw in Path(sys.argv[1]).read_text(errors="replace").splitlines():
    line = raw.strip()
    if not line or line.startswith(("#", "!")):
        continue
    key, sep, value = line.partition("=")
    if sep and key.strip() == "sdk.dir":
        print(os.path.expanduser(value.strip().replace(r"\ ", " ").replace(r"\:", ":").replace(r"\\", "\\")))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

looks_like_android_sdk() {
    [[ -d "$1" ]] && [[ -d "$1/platforms" || -d "$1/platform-tools" || -d "$1/cmdline-tools" ]]
}

if ! looks_like_android_sdk "$SDK_ROOT"; then
    local_sdk="$(read_local_sdk_dir 2>/dev/null || true)"
    for candidate in \
        "$local_sdk" \
        "$HOME/Android/Sdk" "$HOME/Android/sdk" "$HOME/.android/sdk" \
        "/mnt/Extra/android-dev/sdk" "/opt/android-sdk" "/usr/local/android-sdk" \
        "/usr/local/lib/android/sdk" "/usr/lib/android-sdk"; do
        if [[ -n "$candidate" ]] && looks_like_android_sdk "$candidate"; then
            SDK_ROOT="$(cd "$candidate" && pwd -P)"
            break
        fi
    done
fi
[[ -n "$SDK_ROOT" ]] && looks_like_android_sdk "$SDK_ROOT" || fail "Android SDK was not found. Configure apps/kassee-android/local.properties sdk.dir, ANDROID_SDK_ROOT/ANDROID_HOME, or KASSIGNER_ANDROID_SDK_ROOT."
export ANDROID_SDK_ROOT="$SDK_ROOT"
export ANDROID_HOME="$SDK_ROOT"

platform_37="$(python3 - "$SDK_ROOT" <<'PY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1]) / "platforms"
for candidate in sorted(root.glob("android-*")) if root.is_dir() else []:
    jar = candidate / "android.jar"
    if not jar.is_file():
        continue
    api = None
    props = candidate / "source.properties"
    if props.is_file():
        text = props.read_text(errors="replace")
        match = re.search(r"(?m)^AndroidVersion\.ApiLevel\s*=\s*(\d+)\s*$", text)
        if match:
            api = int(match.group(1))
    if api is None:
        match = re.fullmatch(r"android-(\d+)(?:\.\d+)?", candidate.name)
        if match:
            api = int(match.group(1))
    if api == 37:
        print(jar)
        raise SystemExit(0)
raise SystemExit(1)
PY
)" || true
[[ -n "$platform_37" ]] || fail "Android SDK platform API 37 (CINNAMON_BUN / Android 17) is required under $SDK_ROOT/platforms."

[[ -f "$WRAPPER_PROPERTIES" ]] || fail "Missing Gradle wrapper metadata: $WRAPPER_PROPERTIES"
gradle_meta_text="$(python3 - "$WRAPPER_PROPERTIES" <<'PY'
from pathlib import Path
import re, sys
values = {}
for raw in Path(sys.argv[1]).read_text(errors="replace").splitlines():
    key, sep, value = raw.partition("=")
    if sep:
        values[key.strip()] = value.strip().replace(r"\:", ":")
url = values.get("distributionUrl", "")
sha = values.get("distributionSha256Sum", "")
match = re.search(r"/gradle-([0-9]+(?:\.[0-9]+)*)-(?:bin|all)\.zip(?:[?#].*)?$", url)
if not match or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
    raise SystemExit(1)
print(url)
print(sha.lower())
print(match.group(1))
PY
)" || fail "Gradle wrapper distribution URL/SHA-256 metadata is invalid."
readarray -t gradle_meta <<<"$gradle_meta_text"
[[ ${#gradle_meta[@]} -eq 3 ]] || fail "Gradle wrapper distribution metadata is incomplete."
GRADLE_URL="${gradle_meta[0]}"
GRADLE_SHA="${gradle_meta[1]}"
GRADLE_VERSION="${gradle_meta[2]}"

find_compatible_gradle() {
    local requested="${GRADLE_BIN:-}" candidate version
    if [[ -n "$requested" ]]; then
        if [[ -x "$requested" ]]; then
            candidate="$requested"
        else
            candidate="$(command -v "$requested" 2>/dev/null || true)"
        fi
        [[ -n "$candidate" ]] || fail "GRADLE_BIN=$requested was requested but is not executable or on PATH."
        version="$("$candidate" --version 2>/dev/null | awk '/^Gradle / { print $2; exit }')"
        [[ "$version" == "$GRADLE_VERSION" ]] || fail "Pinned Gradle $GRADLE_VERSION is required; GRADLE_BIN provides ${version:-unknown}."
        printf '%s\n' "$candidate"
        return 0
    fi
    candidate="$(command -v gradle 2>/dev/null || true)"
    if [[ -n "$candidate" ]]; then
        version="$("$candidate" --version 2>/dev/null | awk '/^Gradle / { print $2; exit }')"
        [[ "$version" == "$GRADLE_VERSION" ]] && { printf '%s\n' "$candidate"; return 0; }
    fi
    candidate="${GRADLE_USER_HOME:-$HOME/.gradle}/kassigner/distributions/gradle-$GRADLE_VERSION/bin/gradle"
    [[ -x "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
    return 1
}

prepare_pinned_gradle() {
    local gradle dist_root dist_zip extracted
    if [[ -n "${GRADLE_BIN:-}" ]]; then
        gradle="$(find_compatible_gradle)"
    else
        gradle="$(find_compatible_gradle || true)"
    fi
    if [[ -n "$gradle" ]]; then
        printf '%s\n' "$gradle"
        return 0
    fi
    export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$HOME/.gradle}"
    dist_root="$GRADLE_USER_HOME/kassigner/distributions"
    dist_zip="$dist_root/gradle-$GRADLE_VERSION-distribution.zip"
    extracted="$dist_root/gradle-$GRADLE_VERSION"
    mkdir -p "$dist_root"
    info "Pinned Gradle $GRADLE_VERSION is not installed; downloading and verifying it under $dist_root" >&2
    python3 - "$GRADLE_URL" "$dist_zip" "$GRADLE_SHA" "$dist_root" "$GRADLE_VERSION" <<'PY'
from hashlib import sha256
from pathlib import Path
import shutil, sys, urllib.request, zipfile
url, archive_name, expected, destination_name, version = sys.argv[1:]
archive = Path(archive_name)
destination = Path(destination_name)
extracted = destination / f"gradle-{version}"

def digest(path: Path) -> str:
    h = sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def valid(path: Path) -> bool:
    return path.is_file() and digest(path) == expected.lower()

if not valid(archive):
    temporary = archive.with_suffix(archive.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with urllib.request.urlopen(url) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        raise SystemExit(f"ERROR: unable to download pinned Gradle from {url}: {exc}")
    actual = digest(temporary)
    if actual != expected.lower():
        temporary.unlink(missing_ok=True)
        raise SystemExit(f"ERROR: Gradle SHA-256 mismatch: expected {expected}, got {actual}")
    temporary.replace(archive)
launcher = extracted / "bin/gradle"
with zipfile.ZipFile(archive) as package:
    if not launcher.is_file():
        if extracted.exists():
            shutil.rmtree(extracted)
        package.extractall(destination)
    # Python's zipfile extraction does not reliably preserve Unix execute bits.
    # Restore the verified archive's recorded modes every time so an already
    # extracted, non-executable Gradle cache repairs itself on the next run.
    for member in package.infolist():
        mode = (member.external_attr >> 16) & 0o777
        if not mode:
            continue
        target = destination / member.filename
        if target.exists():
            target.chmod(mode)
if launcher.is_file() and not launcher.stat().st_mode & 0o100:
    launcher.chmod(launcher.stat().st_mode | 0o100)
PY
    gradle="$extracted/bin/gradle"
    [[ -x "$gradle" ]] || fail "Pinned Gradle $GRADLE_VERSION could not be prepared under $dist_root."
    printf '%s\n' "$gradle"
}

GRADLE_BIN="$(prepare_pinned_gradle)"
gradle_version="$("$GRADLE_BIN" --version | awk '/^Gradle / { print $2; exit }')"
[[ "$gradle_version" == "$GRADLE_VERSION" ]] || fail "Pinned Gradle $GRADLE_VERSION is required; prepared ${gradle_version:-unknown}."

case "$MODE" in
  debug) tasks=(assembleDebug); label="Debug build" ;;
  release) tasks=(assembleRelease); label="Release build" ;;
  test) tasks=(testDebugUnitTest); label="Debug unit tests" ;;
  *) fail "unknown Android build mode: $MODE (expected debug, release, or test)" ;;
esac

info "KasSee Android — $label (API 37)"
info "Android SDK: $SDK_ROOT"
info "Java: $JAVA_HOME/bin/java (major $java_major)"
info "Gradle: $GRADLE_BIN"
"$GRADLE_BIN" --project-dir "$ANDROID_APP" --no-daemon "${tasks[@]}"
printf 'KasSee Android — %s complete.\n' "$label"

case "$MODE" in
  debug|release)
    variant_dir="$ANDROID_APP/app/build/outputs/apk/$MODE"
    artifacts="$(find "$variant_dir" -maxdepth 1 -type f -name '*.apk' -print 2>/dev/null | sort)"
    [[ -n "$artifacts" ]] || fail "Android $MODE build completed but no APK was found under $variant_dir."
    printf 'Built artifact%s:\n' "$(printf '%s\n' "$artifacts" | awk 'END { if (NR == 1) print ""; else print "s" }')"
    while IFS= read -r artifact; do
      [[ -n "$artifact" ]] && printf '  %s\n' "$artifact"
    done <<<"$artifacts"
    ;;
  test)
    report="$ANDROID_APP/app/build/reports/tests/testDebugUnitTest/index.html"
    if [[ -f "$report" ]]; then
      printf 'Test report:\n  %s\n' "$report"
    fi
    ;;
esac
