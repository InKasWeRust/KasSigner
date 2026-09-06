#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROJECT="$ROOT/apps/kassee-ios/KasSigner.xcodeproj"
MODE="${1:-build}"
DERIVED_DATA="$ROOT/target/ios/DerivedData"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: KasSee iOS requires macOS with Xcode. Run this target on a macOS/Xcode host." >&2
  exit 2
fi
command -v xcodebuild >/dev/null 2>&1 || { echo "ERROR: xcodebuild is required for KasSee iOS." >&2; exit 2; }
"$ROOT/scripts/linux/build/ios-runtime-sync.sh"

case "$MODE" in
  build)
    mkdir -p "$DERIVED_DATA"
    xcodebuild -project "$PROJECT" -scheme KasSigner -configuration Debug \
      -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
      -derivedDataPath "$DERIVED_DATA" CODE_SIGNING_ALLOWED=NO build
    artifact="$DERIVED_DATA/Build/Products/Debug-iphonesimulator/KasSigner.app"
    [[ -d "$artifact" ]] || { echo "ERROR: iOS Debug build completed but $artifact was not produced." >&2; exit 1; }
    echo "KasSee iOS — Debug build complete."
    printf 'Built artifact:\n  %s\n' "$artifact"
    ;;
  release)
    mkdir -p "$ROOT/target/ios"
    archive="$ROOT/target/ios/KasSigner.xcarchive"
    rm -rf "$archive"
    xcodebuild archive -project "$PROJECT" -scheme KasSigner -configuration Release \
      -destination 'generic/platform=iOS' -archivePath "$archive"
    [[ -d "$archive" ]] || { echo "ERROR: iOS Release archive completed but $archive was not produced." >&2; exit 1; }
    echo "KasSee iOS — Release archive complete."
    printf 'Built archive:\n  %s\n' "$archive"
    ;;
  test)
    destination="${KASSIGNER_IOS_TEST_DESTINATION:-platform=iOS Simulator,name=iPhone 16 Pro}"
    result_bundle="$ROOT/target/ios/KasSignerTests.xcresult"
    mkdir -p "$DERIVED_DATA" "$(dirname "$result_bundle")"
    rm -rf "$result_bundle"
    xcodebuild -project "$PROJECT" -scheme KasSigner -configuration Debug -destination "$destination" \
      -derivedDataPath "$DERIVED_DATA" -resultBundlePath "$result_bundle" test
    [[ -d "$result_bundle" ]] || { echo "ERROR: iOS tests completed but $result_bundle was not produced." >&2; exit 1; }
    echo "KasSee iOS — Tests complete."
    printf 'Test result bundle:\n  %s\n' "$result_bundle"
    ;;
  *)
    echo "ERROR: unknown iOS build mode: $MODE (expected build, release, or test)" >&2
    exit 2
    ;;
esac
