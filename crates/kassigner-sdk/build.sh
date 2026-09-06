#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${DIR}/../.." && pwd)"
PKG_DIR="${KASSIGNER_SDK_OUTPUT_ROOT:-${ROOT}/target/sdk}/kassigner-sdk/pkg"
exec "${DIR}/../../scripts/linux/lib/rust-wasm-sdk.sh" kassigner-sdk kassigner_sdk "${PKG_DIR}" "KasSigner SDK Rust/WASM" "@kassigner/sdk"
