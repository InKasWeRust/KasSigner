#!/bin/bash
# KasSigner iOS developer bootstrap for macOS.
# Double-click this file in Finder or run it from Terminal.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAINS="${ROOT_DIR}/qa/config/toolchains.env"
CHECK_ONLY=false
PAUSE_ON_EXIT=true

for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=true ;;
        --no-pause) PAUSE_ON_EXIT=false ;;
        -h|--help)
            cat <<'USAGE'
KasSigner iOS macOS developer setup

Usage:
  ./apps/kassee-ios/setup-macos.command
  ./apps/kassee-ios/setup-macos.command --check

Options:
  --check      Verify prerequisites without installing or changing anything.
  --no-pause   Do not wait for Return before closing the terminal window.

The default setup selects the installed full Xcode application, completes
Xcode first-launch setup, installs the repository-pinned Rust toolchain and
WASM target, installs the pinned wasm-bindgen CLI into KasSigner's isolated
cache, and verifies the iOS Simulator destination used by `make ios-qa`.
USAGE
            exit 0
            ;;
        *)
            printf 'ERROR: unknown option: %s\n' "$arg" >&2
            exit 2
            ;;
    esac
done

finish() {
    local rc=$?
    trap - EXIT
    echo
    if (( rc == 0 )); then
        echo "KasSigner iOS setup finished successfully."
    else
        echo "KasSigner iOS setup stopped with an error (exit ${rc})."
    fi
    if $PAUSE_ON_EXIT && [[ -t 0 ]]; then
        echo
        read -r -p "Press Return to close this window..." _ || true
    fi
    exit "$rc"
}
trap finish EXIT

[[ "$(uname -s)" == "Darwin" ]] || {
    echo "ERROR: this setup is for macOS only." >&2
    exit 2
}
[[ -f "$TOOLCHAINS" ]] || {
    echo "ERROR: run this script from an extracted KasSigner source tree; missing $TOOLCHAINS" >&2
    exit 2
}
# shellcheck disable=SC1090
source "$TOOLCHAINS"

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
mkdir -p "$HOME/.local/bin"

echo
printf 'KasSigner iOS developer setup\n'
printf 'Repository: %s\n\n' "$ROOT_DIR"

find_xcode_app() {
    if [[ -n "${KASSIGNER_XCODE_APP:-}" && -d "${KASSIGNER_XCODE_APP}/Contents/Developer" ]]; then
        printf '%s\n' "$KASSIGNER_XCODE_APP"
        return 0
    fi
    if [[ -d "/Applications/Xcode.app/Contents/Developer" ]]; then
        printf '%s\n' "/Applications/Xcode.app"
        return 0
    fi
    local candidate
    while IFS= read -r candidate; do
        [[ -d "$candidate/Contents/Developer" ]] && { printf '%s\n' "$candidate"; return 0; }
    done < <(find /Applications "$HOME/Applications" -maxdepth 1 -type d -name 'Xcode*.app' 2>/dev/null | sort)
    return 1
}

XCODE_APP="$(find_xcode_app || true)"
if [[ -z "$XCODE_APP" ]]; then
    echo "ERROR: full Xcode was not found. Install Xcode, normally at /Applications/Xcode.app." >&2
    exit 2
fi
XCODE_DEVELOPER_DIR="$XCODE_APP/Contents/Developer"

if $CHECK_ONLY; then
    echo "Checking iOS development environment..."
else
    ACTIVE_DEVELOPER="$(xcode-select --print-path 2>/dev/null || true)"
    if [[ "$ACTIVE_DEVELOPER" != "$XCODE_DEVELOPER_DIR" ]]; then
        echo "Selecting full Xcode command-line tools: $XCODE_APP"
        echo "macOS may ask for your administrator password."
        sudo xcode-select --switch "$XCODE_DEVELOPER_DIR"
    fi

    echo "Completing Xcode first-launch component setup..."
    sudo xcodebuild -runFirstLaunch
fi

# Always use the selected Xcode while this script is running, even in --check mode.
export DEVELOPER_DIR="$XCODE_DEVELOPER_DIR"

ensure_xcrun_tool() {
    local name="$1" resolved
    if command -v "$name" >/dev/null 2>&1; then
        return 0
    fi
    resolved="$(xcrun --find "$name" 2>/dev/null || true)"
    if [[ -n "$resolved" && -x "$resolved" ]]; then
        if $CHECK_ONLY; then
            printf 'MISS %-16s (available through xcrun at %s)\n' "$name" "$resolved"
            return 1
        fi
        ln -sfn "$resolved" "$HOME/.local/bin/$name"
        hash -r
        return 0
    fi
    printf 'MISS %-16s\n' "$name"
    return 1
}

missing=0
for tool in xcodebuild xcrun make python3 curl; do
    if ensure_xcrun_tool "$tool"; then
        printf 'OK   %-16s %s\n' "$tool" "$(command -v "$tool" || true)"
    else
        missing=1
    fi
done

if (( missing != 0 )); then
    echo
    echo "ERROR: required Apple command-line tools are missing." >&2
    echo "Open Xcode once and allow it to install required components, then rerun this setup." >&2
    exit 2
fi

XCODE_VERSION="$(xcodebuild -version | head -n 1)"
printf 'OK   %-16s %s\n' "Xcode" "$XCODE_VERSION"
PYTHON_VERSION="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
if python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
    printf 'OK   %-16s %s\n' "Python" "$PYTHON_VERSION"
else
    printf 'MISS %-16s Python 3.10+ required (found %s)\n' "Python" "$PYTHON_VERSION"
    missing=1
fi

if $CHECK_ONLY; then
    if command -v rustup >/dev/null 2>&1; then
        printf 'OK   %-16s %s\n' rustup "$(rustup --version 2>/dev/null | head -n 1)"
    else
        printf 'MISS %-16s\n' rustup
        missing=1
    fi
else
    if ! command -v rustup >/dev/null 2>&1; then
        echo
        echo "Installing rustup (user-local under ~/.cargo)..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
        # shellcheck disable=SC1090
        source "$HOME/.cargo/env"
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    echo
    echo "Installing/verifying pinned Rust ${KASSIGNER_STABLE_RUST}..."
    rustup toolchain install "$KASSIGNER_STABLE_RUST" --profile minimal
    rustup target add wasm32-unknown-unknown --toolchain "$KASSIGNER_STABLE_RUST"
fi

if command -v rustup >/dev/null 2>&1; then
    if rustup run "$KASSIGNER_STABLE_RUST" rustc --version >/dev/null 2>&1; then
        printf 'OK   %-16s %s\n' "Rust" "$(rustup run "$KASSIGNER_STABLE_RUST" rustc --version)"
    else
        printf 'MISS %-16s Rust %s\n' "Rust" "$KASSIGNER_STABLE_RUST"
        missing=1
    fi

    if rustup target list --toolchain "$KASSIGNER_STABLE_RUST" --installed 2>/dev/null | grep -qx 'wasm32-unknown-unknown'; then
        printf 'OK   %-16s %s\n' "WASM target" "wasm32-unknown-unknown"
    else
        printf 'MISS %-16s %s\n' "WASM target" "wasm32-unknown-unknown"
        missing=1
    fi
fi

WASM_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/kassigner/tools/wasm-bindgen-cli-${KASSIGNER_WASM_BINDGEN_CLI_VERSION}"
WASM_BIN="$WASM_ROOT/bin/wasm-bindgen"
EXPECTED_WASM="wasm-bindgen ${KASSIGNER_WASM_BINDGEN_CLI_VERSION}"
ACTUAL_WASM="$($WASM_BIN --version 2>/dev/null || true)"
if [[ "$ACTUAL_WASM" != "$EXPECTED_WASM" ]]; then
    if $CHECK_ONLY; then
        printf 'MISS %-16s %s\n' "wasm-bindgen" "$EXPECTED_WASM"
        missing=1
    else
        echo
        echo "Installing pinned ${EXPECTED_WASM} into KasSigner's isolated tool cache..."
        rm -rf "$WASM_ROOT"
        rustup run "$KASSIGNER_STABLE_RUST" cargo install wasm-bindgen-cli \
            --version "$KASSIGNER_WASM_BINDGEN_CLI_VERSION" --locked --root "$WASM_ROOT"
        ACTUAL_WASM="$($WASM_BIN --version 2>/dev/null || true)"
    fi
fi
if [[ "$ACTUAL_WASM" == "$EXPECTED_WASM" ]]; then
    printf 'OK   %-16s %s\n' "wasm-bindgen" "$ACTUAL_WASM"
elif ! $CHECK_ONLY; then
    echo "ERROR: expected $EXPECTED_WASM after installation; found ${ACTUAL_WASM:-nothing}." >&2
    exit 2
fi

# Persist only the user-local paths the iOS build needs. Do not install or
# configure Android, ESP32, Homebrew, or unrelated KasSigner toolchains here.
if ! $CHECK_ONLY; then
    PROFILE="$HOME/.zprofile"
    START='# >>> KasSigner iOS dev environment >>>'
    END='# <<< KasSigner iOS dev environment <<<'
    touch "$PROFILE"
    python3 - "$PROFILE" "$START" "$END" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
start, end = sys.argv[2:]
text = path.read_text(encoding="utf-8")
block = f'''{start}\nexport PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"\n[ -r "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"\n{end}\n'''
if start in text and end in text:
    before = text.split(start, 1)[0]
    after = text.split(end, 1)[1]
    text = before.rstrip() + "\n\n" + block + after.lstrip("\n")
else:
    text = text.rstrip() + ("\n\n" if text.strip() else "") + block
path.write_text(text, encoding="utf-8")
PY
fi

# `make ios-qa` defaults to an iPhone 16 Pro simulator. Xcode 16.2 normally
# includes that destination; create one only when the device type/runtime exist
# but no matching simulator instance is present.
SIM_NAME="iPhone 16 Pro"
if ! xcrun simctl list devices available 2>/dev/null | grep -Fq "$SIM_NAME"; then
    if $CHECK_ONLY; then
        printf 'MISS %-16s %s\n' "Simulator" "$SIM_NAME"
        missing=1
    else
        echo
        echo "$SIM_NAME simulator is not currently available."
        if ! xcrun simctl list runtimes available 2>/dev/null | grep -Eq '^iOS '; then
            echo "Downloading the iOS Simulator runtime required by Xcode..."
            xcodebuild -downloadPlatform iOS
        fi
        RUNTIME_ID="$(xcrun simctl list runtimes available | awk '/^iOS / { if (match($0, /com\.apple\.CoreSimulator\.SimRuntime\.iOS-[0-9-]+/)) id=substr($0,RSTART,RLENGTH) } END { print id }')"
        DEVICE_TYPE="com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro"
        if [[ -n "$RUNTIME_ID" ]] && xcrun simctl list devicetypes | grep -Fq "$DEVICE_TYPE"; then
            xcrun simctl create "$SIM_NAME" "$DEVICE_TYPE" "$RUNTIME_ID" >/dev/null
        fi
    fi
fi

if xcrun simctl list devices available 2>/dev/null | grep -Fq "$SIM_NAME"; then
    printf 'OK   %-16s %s\n' "Simulator" "$SIM_NAME"
else
    printf 'MISS %-16s %s\n' "Simulator" "$SIM_NAME"
    missing=1
fi

if (( missing != 0 )); then
    echo
    echo "ERROR: the iOS developer environment is not complete." >&2
    if $CHECK_ONLY; then
        echo "Run this setup again without --check to install the missing user-local prerequisites." >&2
    fi
    exit 2
fi

echo
if $CHECK_ONLY; then
    echo "PASS: KasSigner iOS development environment is ready."
else
    echo "PASS: KasSigner iOS development environment is ready."
    echo
    echo "Next commands:"
    printf '  cd %q\n' "$ROOT_DIR"
    echo "  make ios"
    echo "  make ios-qa"
    echo "  ./scripts/mac/run-ios.command"
fi
