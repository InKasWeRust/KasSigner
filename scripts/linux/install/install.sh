#!/usr/bin/env bash
# KasSigner native Linux developer bootstrap.
# After this completes, a new developer should be able to run qa/linux/run-all.sh.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
# shellcheck source=qa/config/toolchains.env
source "${ROOT_DIR}/qa/config/toolchains.env"
# shellcheck source=scripts/linux/lib/admin.sh
source "${ROOT_DIR}/scripts/linux/lib/admin.sh"

CHECK_ONLY=false
SKIP_ANDROID_EMULATOR=false
for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=true ;;
        --skip-android-emulator) SKIP_ANDROID_EMULATOR=true ;;
        -h|--help)
            cat <<'USAGE'
Usage: ./install.sh [--check] [--skip-android-emulator]

Installs the native Linux development environment required by KasSigner QA:
GNU Make, Python, Git, Node/npm, Chromium, Rust toolchains and QA cargo tools,
ESP32-S3 Rust/espflash/QEMU tooling, JDK/Kotlin/Gradle, and Android SDK API 37.

--check                  Verify the environment without installing anything.
--skip-android-emulator  Install Android build tooling but omit emulator/system image.
USAGE
            exit 0 ;;
        *) printf 'ERROR: unknown option: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || { echo 'ERROR: use this installer on native Linux only.' >&2; exit 2; }

LOCAL_BIN="${HOME}/.local/bin"
TOOL_ROOT="${HOME}/.local/share/kassigner"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${HOME}/Android/Sdk}"
export ANDROID_SDK_ROOT ANDROID_HOME="$ANDROID_SDK_ROOT"
mkdir -p "$LOCAL_BIN" "$TOOL_ROOT"
export PATH="$LOCAL_BIN:${HOME}/.cargo/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:$PATH"

have_browser() {
    command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 \
        || command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1
}

version_contains() {
    local command_name="$1" expected="$2"
    shift 2
    command -v "$command_name" >/dev/null 2>&1 || return 1
    "$command_name" "$@" 2>&1 | grep -Fq "$expected"
}

check_environment() {
    local missing=0 command_name actual
    printf 'KasSigner native Linux environment check:\n'
    for command_name in make python3 git curl node npm rustup cargo java kotlinc gradle espup espflash; do
        if command -v "$command_name" >/dev/null 2>&1; then
            printf '  OK   %s\n' "$command_name"
        else
            printf '  MISS %s\n' "$command_name"
            missing=1
        fi
    done
    if have_browser; then printf '  OK   Chromium/Chrome\n'; else printf '  MISS Chromium/Chrome\n'; missing=1; fi

    if command -v java >/dev/null 2>&1; then
        actual="$(java -version 2>&1 | awk -F'[\".]' '/version/ {if ($2=="1") print $3; else print $2; exit}')"
        [[ "$actual" == "$KASSIGNER_ANDROID_JDK" ]] \
            && printf '  OK   JDK %s\n' "$KASSIGNER_ANDROID_JDK" \
            || { printf '  MISS JDK %s (found %s)\n' "$KASSIGNER_ANDROID_JDK" "${actual:-unknown}"; missing=1; }
    fi
    version_contains gradle "$KASSIGNER_GRADLE_VERSION" --version \
        && printf '  OK   Gradle %s\n' "$KASSIGNER_GRADLE_VERSION" \
        || { printf '  MISS Gradle %s\n' "$KASSIGNER_GRADLE_VERSION"; missing=1; }
    version_contains kotlinc "$KASSIGNER_KOTLIN_CLI_VERSION" -version \
        && printf '  OK   Kotlin %s\n' "$KASSIGNER_KOTLIN_CLI_VERSION" \
        || { printf '  MISS Kotlin %s\n' "$KASSIGNER_KOTLIN_CLI_VERSION"; missing=1; }

    [[ -f "$ANDROID_SDK_ROOT/platforms/android-${KASSIGNER_ANDROID_API}/android.jar" ]] \
        && printf '  OK   Android SDK API %s\n' "$KASSIGNER_ANDROID_API" \
        || { printf '  MISS Android SDK API %s\n' "$KASSIGNER_ANDROID_API"; missing=1; }
    [[ -d "$ANDROID_SDK_ROOT/build-tools/${KASSIGNER_ANDROID_BUILD_TOOLS}" ]] \
        && printf '  OK   Android build-tools %s\n' "$KASSIGNER_ANDROID_BUILD_TOOLS" \
        || { printf '  MISS Android build-tools %s\n' "$KASSIGNER_ANDROID_BUILD_TOOLS"; missing=1; }

    if command -v rustup >/dev/null 2>&1; then
        rustup run "$KASSIGNER_STABLE_RUST" rustc --version >/dev/null 2>&1 \
            && printf '  OK   Rust %s\n' "$KASSIGNER_STABLE_RUST" \
            || { printf '  MISS Rust %s\n' "$KASSIGNER_STABLE_RUST"; missing=1; }
        rustup run "$KASSIGNER_BRANCH_RUST" rustc --version >/dev/null 2>&1 \
            && printf '  OK   Rust %s\n' "$KASSIGNER_BRANCH_RUST" \
            || { printf '  MISS Rust %s\n' "$KASSIGNER_BRANCH_RUST"; missing=1; }
        rustup run esp rustc --version >/dev/null 2>&1 \
            && printf '  OK   ESP Rust %s\n' "$KASSIGNER_ESP_RUST" \
            || { printf '  MISS ESP Rust %s\n' "$KASSIGNER_ESP_RUST"; missing=1; }
    fi

    if command -v cargo >/dev/null 2>&1; then
        actual="$(rustup run "$KASSIGNER_STABLE_RUST" cargo mutants --version 2>/dev/null || true)"
        [[ "$actual" == *"$KASSIGNER_CARGO_MUTANTS_VERSION"* ]] \
            && printf '  OK   cargo-mutants %s\n' "$KASSIGNER_CARGO_MUTANTS_VERSION" \
            || { printf '  MISS cargo-mutants %s\n' "$KASSIGNER_CARGO_MUTANTS_VERSION"; missing=1; }
        actual="$(rustup run "$KASSIGNER_BRANCH_RUST" cargo fuzz --version 2>/dev/null || true)"
        [[ "$actual" == *"$KASSIGNER_CARGO_FUZZ_VERSION"* ]] \
            && printf '  OK   cargo-fuzz %s\n' "$KASSIGNER_CARGO_FUZZ_VERSION" \
            || { printf '  MISS cargo-fuzz %s\n' "$KASSIGNER_CARGO_FUZZ_VERSION"; missing=1; }
        actual="$(rustup run "$KASSIGNER_BRANCH_RUST" cargo llvm-cov --version 2>/dev/null || true)"
        [[ "$actual" == *"$KASSIGNER_CARGO_LLVM_COV_VERSION"* ]] \
            && printf '  OK   cargo-llvm-cov %s\n' "$KASSIGNER_CARGO_LLVM_COV_VERSION" \
            || { printf '  MISS cargo-llvm-cov %s\n' "$KASSIGNER_CARGO_LLVM_COV_VERSION"; missing=1; }
        actual="$(rustup run "$KASSIGNER_BRANCH_RUST" cargo crap --version 2>/dev/null || true)"
        [[ "$actual" == *"$KASSIGNER_CARGO_CRAP_VERSION"* ]] \
            && printf '  OK   cargo-crap %s\n' "$KASSIGNER_CARGO_CRAP_VERSION" \
            || { printf '  MISS cargo-crap %s\n' "$KASSIGNER_CARGO_CRAP_VERSION"; missing=1; }
    fi

    if find "${HOME}/.espressif/tools/qemu-xtensa" -type f -name qemu-system-xtensa -perm -u+x -print -quit 2>/dev/null | grep -q . \
        || command -v qemu-system-xtensa >/dev/null 2>&1; then
        printf '  OK   Espressif QEMU\n'
    else
        printf '  MISS Espressif QEMU\n'; missing=1
    fi

    if ((missing)); then return 2; fi
    printf 'PASS: native Linux prerequisites are installed.\n'
}

$CHECK_ONLY && { check_environment; exit $?; }

install_host_packages() {
    local reason='Install KasSigner native Linux development prerequisites.'
    if command -v apt-get >/dev/null 2>&1; then
        run_as_root "$reason" apt-get update
        local -a packages=(
            build-essential ca-certificates clang cmake curl git libgcrypt20 libglib2.0-0
            libpixman-1-0 libsdl2-2.0-0 libslirp0 libssl-dev libudev-dev
            libusb-1.0-0-dev make ninja-build nodejs npm pkg-config python3 python3-pip
            python3-venv unzip util-linux xz-utils zip
        )
        if apt-cache show chromium >/dev/null 2>&1; then packages+=(chromium); else packages+=(chromium-browser); fi
        run_as_root "$reason" apt-get install -y "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        run_as_root "$reason" dnf install -y \
            ca-certificates clang cmake curl gcc gcc-c++ git glib2 libgcrypt libslirp make \
            ninja-build nodejs npm openssl-devel pixman pkgconf-pkg-config python3 python3-pip \
            SDL2 systemd-devel unzip util-linux xz zip libusb1-devel chromium
    elif command -v pacman >/dev/null 2>&1; then
        run_as_root "$reason" pacman -Sy --needed --noconfirm \
            base-devel ca-certificates clang cmake curl git glib2 libgcrypt libslirp make \
            ninja nodejs npm openssl pixman pkgconf python python-pip sdl2 systemd-libs \
            unzip util-linux xz zip libusb chromium
    else
        echo 'ERROR: unsupported Linux package manager; expected apt-get, dnf, or pacman.' >&2
        exit 2
    fi
}

install_rust() {
    if ! command -v rustup >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck disable=SC1090
        source "${HOME}/.cargo/env"
    fi
    rustup toolchain install "$KASSIGNER_STABLE_RUST" --profile minimal
    rustup toolchain install "$KASSIGNER_BRANCH_RUST" --profile minimal --component llvm-tools-preview
    rustup target add wasm32-unknown-unknown --toolchain "$KASSIGNER_STABLE_RUST"
}

ensure_cargo_tool() {
    local probe="$1" package="$2" version="$3" toolchain="${4:-$KASSIGNER_STABLE_RUST}"
    local actual
    actual="$(rustup run "$toolchain" cargo "$probe" --version 2>/dev/null || true)"
    [[ "$actual" == *"$version"* ]] || rustup run "$KASSIGNER_STABLE_RUST" cargo install "$package" --version "$version" --locked --force
}

install_rust_tools() {
    ensure_cargo_tool mutants cargo-mutants "$KASSIGNER_CARGO_MUTANTS_VERSION"
    ensure_cargo_tool fuzz cargo-fuzz "$KASSIGNER_CARGO_FUZZ_VERSION" "$KASSIGNER_BRANCH_RUST"
    "${ROOT_DIR}/scripts/linux/quality/branch-coverage-setup.sh"
    if ! version_contains espup "$KASSIGNER_ESPUP_VERSION" --version; then
        rustup run "$KASSIGNER_STABLE_RUST" cargo install espup --version "$KASSIGNER_ESPUP_VERSION" --locked --force
    fi
    if ! rustup run esp rustc --version >/dev/null 2>&1; then
        espup install --toolchain-version "$KASSIGNER_ESP_RUST"
    fi
    if [[ -r "${HOME}/export-esp.sh" ]]; then source "${HOME}/export-esp.sh"; fi
    if [[ -r "${HOME}/.espup/export-esp.sh" ]]; then source "${HOME}/.espup/export-esp.sh"; fi
    if ! version_contains espflash "$KASSIGNER_ESPFLASH_VERSION" --version; then
        rustup run "$KASSIGNER_STABLE_RUST" cargo install espflash --version "$KASSIGNER_ESPFLASH_VERSION" --locked --force
    fi

    local wasm_root="${XDG_CACHE_HOME:-${HOME}/.cache}/kassigner/tools/wasm-bindgen-cli-${KASSIGNER_WASM_BINDGEN_CLI_VERSION}"
    if [[ ! -x "$wasm_root/bin/wasm-bindgen" ]] \
        || [[ "$($wasm_root/bin/wasm-bindgen --version 2>/dev/null || true)" != "wasm-bindgen ${KASSIGNER_WASM_BINDGEN_CLI_VERSION}" ]]; then
        rm -rf "$wasm_root"
        rustup run "$KASSIGNER_STABLE_RUST" cargo install wasm-bindgen-cli \
            --version "$KASSIGNER_WASM_BINDGEN_CLI_VERSION" --locked --root "$wasm_root"
    fi
}

install_jdk25() {
    local target="$TOOL_ROOT/jdk-${KASSIGNER_ANDROID_JDK}"
    local managed_java="$target/bin/java"
    if [[ -x "$managed_java" ]]; then
        local managed_major
        managed_major="$($managed_java -version 2>&1 | awk -F'[".]' '/version/ {if ($2=="1") print $3; else print $2; exit}')"
        if [[ "$managed_major" == "$KASSIGNER_ANDROID_JDK" ]]; then
            export JAVA_HOME="$target" PATH="$target/bin:$PATH"
            for name in java javac jar keytool; do ln -sfn "$target/bin/$name" "$LOCAL_BIN/$name"; done
            return 0
        fi
    fi

    local arch api_arch tmp metadata link checksum archive extracted
    arch="$(uname -m)"
    case "$arch" in x86_64|amd64) api_arch=x64 ;; aarch64|arm64) api_arch=aarch64 ;; *) echo "ERROR: unsupported JDK architecture: $arch" >&2; exit 2 ;; esac
    tmp="$(mktemp -d)"
    metadata="$tmp/adoptium.json"
    curl -fL "https://api.adoptium.net/v3/assets/latest/${KASSIGNER_ANDROID_JDK}/hotspot?architecture=${api_arch}&image_type=jdk&os=linux&vendor=eclipse" -o "$metadata"
    read -r link checksum < <(python3 - "$metadata" <<'PYJDK'
import json,sys
x=json.load(open(sys.argv[1],encoding='utf-8'))[0]['binary']['package']
print(x['link'], x['checksum'])
PYJDK
)
    archive="$tmp/jdk.tar.gz"
    curl -fL "$link" -o "$archive"
    printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
    mkdir -p "$tmp/unpack"; tar -xzf "$archive" -C "$tmp/unpack"
    extracted="$(find "$tmp/unpack" -mindepth 1 -maxdepth 1 -type d | head -n1)"
    [[ -n "$extracted" ]] || { rm -rf "$tmp"; echo 'ERROR: JDK archive did not contain a top-level directory.' >&2; exit 2; }
    rm -rf "$target"; mv "$extracted" "$target"
    rm -rf "$tmp"
    export JAVA_HOME="$target" PATH="$target/bin:$PATH"
    for name in java javac jar keytool; do ln -sfn "$target/bin/$name" "$LOCAL_BIN/$name"; done
}

install_gradle() {
    local target="$TOOL_ROOT/gradle-${KASSIGNER_GRADLE_VERSION}" archive checksum expected tmp
    if version_contains gradle "$KASSIGNER_GRADLE_VERSION" --version; then return 0; fi
    tmp="$(mktemp -d)"; archive="$tmp/gradle.zip"
    curl -fL "https://services.gradle.org/distributions/gradle-${KASSIGNER_GRADLE_VERSION}-bin.zip" -o "$archive"
    expected="$(curl -fsSL "https://services.gradle.org/distributions/gradle-${KASSIGNER_GRADLE_VERSION}-bin.zip.sha256" | tr -d '[:space:]')"
    checksum="$(sha256sum "$archive" | awk '{print $1}')"
    [[ "$checksum" == "$expected" ]] || { echo 'ERROR: Gradle checksum mismatch.' >&2; rm -rf "$tmp"; exit 2; }
    rm -rf "$target"; unzip -q "$archive" -d "$tmp/unpack"
    mv "$tmp/unpack/gradle-${KASSIGNER_GRADLE_VERSION}" "$target"
    ln -sfn "$target/bin/gradle" "$LOCAL_BIN/gradle"
    rm -rf "$tmp"
}

install_kotlin() {
    local target="$TOOL_ROOT/kotlin-${KASSIGNER_KOTLIN_CLI_VERSION}" tmp archive
    if version_contains kotlinc "$KASSIGNER_KOTLIN_CLI_VERSION" -version; then return 0; fi
    tmp="$(mktemp -d)"; archive="$tmp/kotlin.zip"
    curl -fL "https://github.com/JetBrains/kotlin/releases/download/v${KASSIGNER_KOTLIN_CLI_VERSION}/kotlin-compiler-${KASSIGNER_KOTLIN_CLI_VERSION}.zip" -o "$archive"
    unzip -q "$archive" -d "$tmp/unpack"
    rm -rf "$target"; mv "$tmp/unpack/kotlinc" "$target"
    ln -sfn "$target/bin/kotlinc" "$LOCAL_BIN/kotlinc"
    rm -rf "$tmp"
}

install_android_sdk() {
    local tools_dir="$ANDROID_SDK_ROOT/cmdline-tools/latest" tmp archive sdkmanager image_arch
    sdkmanager="$tools_dir/bin/sdkmanager"
    if [[ ! -x "$sdkmanager" ]]; then
        tmp="$(mktemp -d)"; archive="$tmp/cmdline-tools.zip"
        curl -fL "https://dl.google.com/android/repository/commandlinetools-linux-${KASSIGNER_ANDROID_CMDLINE_TOOLS}_latest.zip" -o "$archive"
        printf '%s  %s\n' "$KASSIGNER_ANDROID_CMDLINE_TOOLS_LINUX_SHA256" "$archive" | sha256sum -c -
        unzip -q "$archive" -d "$tmp/unpack"
        rm -rf "$tools_dir"; mkdir -p "$(dirname "$tools_dir")"
        mv "$tmp/unpack/cmdline-tools" "$tools_dir"
        rm -rf "$tmp"
    fi
    yes | "$sdkmanager" --sdk_root="$ANDROID_SDK_ROOT" --licenses >/dev/null || true
    "$sdkmanager" --sdk_root="$ANDROID_SDK_ROOT" \
        'platform-tools' \
        "platforms;android-${KASSIGNER_ANDROID_API}" \
        "build-tools;${KASSIGNER_ANDROID_BUILD_TOOLS}"
    if ! $SKIP_ANDROID_EMULATOR && [[ "$(uname -m)" == "x86_64" ]]; then
        image_arch=x86_64
        "$sdkmanager" --sdk_root="$ANDROID_SDK_ROOT" 'emulator' \
            "system-images;android-${KASSIGNER_ANDROID_API};google_apis;${image_arch}"
    fi
}

persist_environment() {
    local profile="${HOME}/.profile" start='# >>> KasSigner dev environment >>>' end='# <<< KasSigner dev environment <<<'
    touch "$profile"
    python3 - "$profile" "$start" "$end" "$ANDROID_SDK_ROOT" "$TOOL_ROOT/jdk-${KASSIGNER_ANDROID_JDK}" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); start,end,sdk,jdk=sys.argv[2:]
text=path.read_text()
block=f'''{start}\nexport JAVA_HOME="{jdk}"\nexport ANDROID_SDK_ROOT="{sdk}"\nexport ANDROID_HOME="$ANDROID_SDK_ROOT"\nexport PATH="$HOME/.local/bin:$HOME/.cargo/bin:$JAVA_HOME/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"\n[ -r "$HOME/export-esp.sh" ] && . "$HOME/export-esp.sh"\n[ -r "$HOME/.espup/export-esp.sh" ] && . "$HOME/.espup/export-esp.sh"\n{end}\n'''
if start in text and end in text:
    before=text.split(start,1)[0]
    after=text.split(end,1)[1]
    text=before+block+after.lstrip('\n')
else:
    text=text.rstrip()+"\n\n"+block
path.write_text(text)
PY
}

printf '==> Installing native Linux host packages\n'
install_host_packages
printf '==> Installing pinned Rust and QA toolchains\n'
install_rust
install_rust_tools
printf '==> Installing JDK %s, Kotlin %s, and Gradle %s\n' "$KASSIGNER_ANDROID_JDK" "$KASSIGNER_KOTLIN_CLI_VERSION" "$KASSIGNER_GRADLE_VERSION"
install_jdk25
install_kotlin
install_gradle
printf '==> Installing Android SDK API %s\n' "$KASSIGNER_ANDROID_API"
install_android_sdk
printf '==> Installing Espressif QEMU\n'
"${ROOT_DIR}/scripts/linux/qemu/setup.sh"
printf '==> Priming pinned TypeScript compiler\n'
python3 "${ROOT_DIR}/qa/checks/web/typescript_toolchain.py" >/dev/null
persist_environment
hash -r
check_environment
printf '\nPASS: KasSigner native Linux developer environment is ready.\n'
printf 'Next: cd %q && ./qa/linux/run-all.sh\n' "$ROOT_DIR"
