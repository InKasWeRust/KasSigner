#!/usr/bin/env bash
# Shared release policy loader for firmware tooling. Source this file.
set -euo pipefail

KASSIGNER_FIRMWARE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
KASSIGNER_RELEASE_POLICY="$KASSIGNER_FIRMWARE_ROOT/apps/signer-firmware/release-policy.env"
[[ -f "$KASSIGNER_RELEASE_POLICY" ]] || { echo "ERROR: missing release policy: $KASSIGNER_RELEASE_POLICY" >&2; return 2; }
# shellcheck disable=SC1090
source "$KASSIGNER_RELEASE_POLICY"

for value in KASSIGNER_UPDATE_SEQUENCE KASSIGNER_SECURITY_VERSION; do
  [[ "${!value:-}" =~ ^[0-9]+$ ]] || { echo "ERROR: invalid $value in release-policy.env" >&2; return 2; }
done
(( KASSIGNER_UPDATE_SEQUENCE >= 1 )) || {
  echo "ERROR: KASSIGNER_UPDATE_SEQUENCE must be positive" >&2; return 2;
}
(( KASSIGNER_SECURITY_VERSION >= 1 && KASSIGNER_SECURITY_VERSION <= 16 )) || {
  echo "ERROR: KASSIGNER_SECURITY_VERSION must be 1..16 for ESP32-S3" >&2; return 2;
}
[[ "${KASSIGNER_ESPTOOL_VERSION:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "ERROR: invalid KASSIGNER_ESPTOOL_VERSION in release-policy.env" >&2; return 2;
}

kassigner_package_version() {
  python3 - "$KASSIGNER_FIRMWARE_ROOT/apps/signer-firmware/Cargo.toml" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
package = text.split("[package]", 1)[1]
match = re.search(r'^version\s*=\s*"([^"]+)"', package, re.M)
if not match:
    raise SystemExit("ERROR: signer-firmware package version not found")
print(match.group(1))
PY
}
