#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${DIR}/../.." && pwd)"
PKG_DIR="${KASSIGNER_SDK_OUTPUT_ROOT:-${ROOT}/target/sdk}/kassigner-protocol/pkg"
exec "${DIR}/../../scripts/linux/lib/rust-wasm-sdk.sh" kassigner-protocol kassigner_protocol "${PKG_DIR}" "KasSigner protocol Rust/WASM" "@kassigner/protocol"
