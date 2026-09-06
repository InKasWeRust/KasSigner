#!/bin/bash
# Build, install, and launch KasSigner in an Xcode iOS Simulator on macOS.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PROJECT="${ROOT_DIR}/apps/kassee-ios/KasSigner.xcodeproj"
DERIVED_DATA="${ROOT_DIR}/target/ios-simulator"
BUNDLE_ID="org.kassigner.KasSigner"
SIMULATOR_NAME="${KASSIGNER_IOS_SIMULATOR_NAME:-iPhone 16 Pro}"
BUILD_APP=true

usage() {
    cat <<'USAGE'
KasSigner iOS Simulator launcher

Usage:
  ./scripts/mac/run-ios.command
  ./scripts/mac/run-ios.command --simulator "iPhone 16 Pro"
  ./scripts/mac/run-ios.command --no-build

Options:
  --simulator NAME  Use an available simulator with this exact device name.
                    Defaults to KASSIGNER_IOS_SIMULATOR_NAME or iPhone 16 Pro.
  --no-build        Reinstall/relaunch the last simulator build without rebuilding.
  -h, --help        Show this help text.

The launcher uses Xcode's supported xcrun/simctl tooling. It boots the selected
simulator, opens Simulator.app, builds KasSigner into target/ios-simulator,
installs the app, and launches it.
USAGE
}

while (($#)); do
    case "$1" in
        --simulator)
            [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR: --simulator requires a device name." >&2; exit 2; }
            SIMULATOR_NAME="$2"
            shift 2
            ;;
        --no-build)
            BUILD_APP=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'ERROR: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[[ "$(uname -s)" == "Darwin" ]] || {
    echo "ERROR: the iOS Simulator launcher requires macOS with full Xcode." >&2
    exit 2
}

for tool in xcode-select xcrun xcodebuild python3 open sw_vers; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: required macOS/Xcode tool is missing: $tool" >&2
        echo "Run ./scripts/mac/install.sh first." >&2
        exit 2
    }
done

DEVELOPER_DIR="$(xcode-select --print-path 2>/dev/null || true)"
if [[ ! -d "$DEVELOPER_DIR/Applications/Simulator.app" ]]; then
    echo "ERROR: full Xcode is not selected (current developer dir: ${DEVELOPER_DIR:-none})." >&2
    echo "Run ./scripts/mac/install.sh to select and initialize Xcode." >&2
    exit 2
fi
export DEVELOPER_DIR

echo
printf 'KasSigner iOS Simulator launcher\n'
printf 'macOS:     %s\n' "$(sw_vers -productVersion)"
printf 'Xcode:     %s\n' "$(xcodebuild -version | head -n 1)"
printf 'Simulator: %s\n\n' "$SIMULATOR_NAME"

SIMULATOR_UDID="$(python3 - "$SIMULATOR_NAME" <<'PY'
import json
import re
import subprocess
import sys

name = sys.argv[1]
payload = subprocess.check_output(
    ["xcrun", "simctl", "list", "devices", "available", "--json"],
    text=True,
)
data = json.loads(payload)

def version(runtime: str) -> tuple[int, ...]:
    match = re.search(r"\.iOS-([0-9-]+)$", runtime)
    return tuple(int(part) for part in match.group(1).split("-")) if match else ()

matches = []
for runtime, devices in data.get("devices", {}).items():
    for device in devices:
        if device.get("name") == name and device.get("isAvailable", True):
            matches.append((device.get("state") == "Booted", version(runtime), device.get("udid", "")))

if not matches:
    raise SystemExit(1)
matches.sort(reverse=True)
print(matches[0][2])
PY
)" || {
    echo "ERROR: no available '$SIMULATOR_NAME' iOS Simulator was found." >&2
    echo "Run ./scripts/mac/install.sh to verify/create the default iPhone 16 Pro simulator," >&2
    echo "or pass --simulator with a name from: xcrun simctl list devices available" >&2
    exit 2
}

SIMULATOR_APP="$DEVELOPER_DIR/Applications/Simulator.app"
open "$SIMULATOR_APP"

STATE="$(python3 - "$SIMULATOR_UDID" <<'PY'
import json
import subprocess
import sys

udid = sys.argv[1]
data = json.loads(subprocess.check_output(["xcrun", "simctl", "list", "devices", "--json"], text=True))
for devices in data.get("devices", {}).values():
    for device in devices:
        if device.get("udid") == udid:
            print(device.get("state", ""))
            raise SystemExit(0)
raise SystemExit(1)
PY
)" || STATE=""

if [[ "$STATE" != "Booted" ]]; then
    echo "Booting $SIMULATOR_NAME ($SIMULATOR_UDID)..."
    xcrun simctl boot "$SIMULATOR_UDID"
fi
xcrun simctl bootstatus "$SIMULATOR_UDID" -b

if $BUILD_APP; then
    echo
    echo "Synchronizing the shared KasSee runtime..."
    "$ROOT_DIR/scripts/mac/build/ios-runtime-sync.sh"

    echo
    echo "Building KasSigner for $SIMULATOR_NAME..."
    xcodebuild \
        -project "$PROJECT" \
        -scheme KasSigner \
        -configuration Debug \
        -destination "platform=iOS Simulator,id=$SIMULATOR_UDID" \
        -derivedDataPath "$DERIVED_DATA" \
        KASSIGNER_IOS_RUNTIME_SYNCED=1 \
        build
fi

APP_PATH="$DERIVED_DATA/Build/Products/Debug-iphonesimulator/KasSigner.app"
[[ -d "$APP_PATH" ]] || {
    echo "ERROR: simulator app bundle was not found at:" >&2
    echo "  $APP_PATH" >&2
    if ! $BUILD_APP; then
        echo "Run this script once without --no-build." >&2
    fi
    exit 2
}

echo
echo "Installing KasSigner..."
xcrun simctl terminate "$SIMULATOR_UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true
xcrun simctl install "$SIMULATOR_UDID" "$APP_PATH"

echo "Launching KasSigner..."
LAUNCH_RESULT="$(xcrun simctl launch "$SIMULATOR_UDID" "$BUNDLE_ID")"
printf '%s\n' "$LAUNCH_RESULT"

echo
echo "PASS: KasSigner is running on $SIMULATOR_NAME."
echo "Simulator remains open so you can interact with the app normally."
