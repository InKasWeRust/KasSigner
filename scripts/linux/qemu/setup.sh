#!/usr/bin/env bash
# Install every host/toolchain dependency required by the QEMU firmware target.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/linux/lib/qemu-common.sh
source "${SCRIPT_DIR}/../lib/qemu-common.sh"
# shellcheck source=scripts/linux/lib/qemu-packages.sh
source "${SCRIPT_DIR}/../lib/qemu-packages.sh"
# shellcheck source=scripts/linux/lib/qemu-rust.sh
source "${SCRIPT_DIR}/../lib/qemu-rust.sh"
# shellcheck source=scripts/linux/lib/qemu-espressif.sh
source "${SCRIPT_DIR}/../lib/qemu-espressif.sh"

install_qemu_host_packages
install_rustup_if_missing
install_esp_rust_toolchain
install_espflash
install_espressif_qemu

printf 'QEMU environment ready: %s\n' "${QEMU_SYSTEM_XTENSA}"
