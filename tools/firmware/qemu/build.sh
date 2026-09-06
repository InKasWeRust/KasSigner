#!/usr/bin/env bash
# Build the QEMU-only firmware and create a complete ESP32-S3 flash image.
set -Eeuo pipefail

# shellcheck source=tools/firmware/qemu/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command cargo
require_command espflash
require_command python3
require_command sha256sum

mkdir -p "${QEMU_OUTPUT_DIR}"

(
    cd "${FIRMWARE_DIR}"
    CARGO_TARGET_DIR="${FIRMWARE_TARGET_DIR}" cargo build \
        --locked \
        --release \
        --no-default-features \
        --features qemu-tests
)

espflash save-image \
    --chip esp32s3 \
    --flash-size 8mb \
    --merge \
    "${QEMU_ELF}" \
    "${QEMU_FLASH_IMAGE}"

python3 - "${QEMU_FLASH_IMAGE}" "${QEMU_FLASH_BYTES}" <<'PY'
from pathlib import Path
import sys

image = Path(sys.argv[1])
required_size = int(sys.argv[2])
actual_size = image.stat().st_size
if actual_size > required_size:
    raise SystemExit(
        f"QEMU flash image is {actual_size} bytes; expected at most {required_size}"
    )
if actual_size < required_size:
    with image.open("ab") as output:
        output.write(b"\xff" * (required_size - actual_size))
PY

printf 'QEMU ELF:   %s\n' "${QEMU_ELF}"
printf 'QEMU flash: %s\n' "${QEMU_FLASH_IMAGE}"
sha256sum "${QEMU_FLASH_IMAGE}"
