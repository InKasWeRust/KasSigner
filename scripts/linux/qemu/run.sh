#!/usr/bin/env bash
# Provision, build, validate, and optionally keep the ESP32-S3 QEMU runtime open.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Setup is sourced so its exported Rust/ESP/QEMU environment remains active.
# shellcheck source=scripts/linux/qemu/setup.sh
source "${SCRIPT_DIR}/setup.sh"

keep_running=true
if [[ "${1:-}" == "--test-only" ]]; then
    keep_running=false
    shift
fi
(($# == 0)) || {
    printf 'ERROR: unsupported QEMU run argument: %s\n' "$1" >&2
    exit 2
}

"${ROOT_DIR}/tools/firmware/qemu/build.sh"
command=(
    python3 "${ROOT_DIR}/qa/checks/firmware/qemu/run.py"
    --qemu "${QEMU_SYSTEM_XTENSA}"
    --image "${ROOT_DIR}/target/qemu/kassigner-qemu-flash.bin"
)
$keep_running && command+=(--keep-running)
exec "${command[@]}"
