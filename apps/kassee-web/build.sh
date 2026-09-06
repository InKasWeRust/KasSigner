#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${APP_DIR}/../.." && pwd)"
MODE="${1:-release}"
exec python3 "${ROOT_DIR}/tools/build/web/build_kassee_runtime.py" --mode "${MODE}"
