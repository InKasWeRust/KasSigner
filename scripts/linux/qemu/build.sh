#!/usr/bin/env bash
# Provision all QEMU dependencies, then build the complete ESP32-S3 flash image.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Setup is sourced so its exported Rust/ESP/QEMU environment remains active.
# shellcheck source=scripts/linux/qemu/setup.sh
source "${SCRIPT_DIR}/setup.sh"
exec "${ROOT_DIR}/tools/firmware/qemu/build.sh"
