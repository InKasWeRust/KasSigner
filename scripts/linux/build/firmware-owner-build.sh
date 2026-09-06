#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
exec "$ROOT/tools/build/firmware/build_owner_firmware.sh" "${1:-$ROOT/target/owner-firmware}"
