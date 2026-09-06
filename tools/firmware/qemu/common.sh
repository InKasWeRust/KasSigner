#!/usr/bin/env bash
# Shared paths and validation for the ESP32-S3 QEMU firmware tools.

QEMU_TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${QEMU_TOOL_DIR}/../../.." && pwd)"
FIRMWARE_DIR="${ROOT_DIR}/apps/signer-firmware"
TARGET_TRIPLE="xtensa-esp32s3-none-elf"
FIRMWARE_TARGET_DIR="${FIRMWARE_DIR}/target"
QEMU_ELF="${FIRMWARE_TARGET_DIR}/${TARGET_TRIPLE}/release/kassigner-firmware"
QEMU_OUTPUT_DIR="${ROOT_DIR}/target/qemu"
QEMU_FLASH_IMAGE="${QEMU_OUTPUT_DIR}/kassigner-qemu-flash.bin"
QEMU_FLASH_BYTES=$((8 * 1024 * 1024))

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'ERROR: required command not found: %s\n' "$1" >&2
        return 127
    }
}
