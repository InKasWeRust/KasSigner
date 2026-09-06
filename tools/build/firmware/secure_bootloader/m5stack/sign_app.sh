#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: $(basename "$0") <unsigned-app.bin> <signed-app.bin>" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
exec python3 "$ROOT/tools/build/firmware/secure_bootloader/m5stack/sign_app.py" "$1" "$2"
