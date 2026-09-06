#!/usr/bin/env bash
# Build one first-party Rust SDK crate as standalone WebAssembly.
set -Eeuo pipefail

[[ $# -eq 5 ]] || { echo "usage: $0 <package> <wasm-stem> <pkg-dir> <label> <npm-name>" >&2; exit 2; }
PACKAGE="$1"
WASM_STEM="$2"
PKG_DIR="$3"
LABEL="$4"
NPM_NAME="$5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WASM_TARGET="wasm32-unknown-unknown"
source "${ROOT_DIR}/qa/config/toolchains.env"
# shellcheck source=scripts/linux/lib/cargo_locks.sh
source "${ROOT_DIR}/scripts/linux/lib/cargo_locks.sh"

TOOL_CACHE_BASE="${KASSIGNER_TOOL_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/kassigner/tools}"
WASM_TOOL_ROOT="${TOOL_CACHE_BASE}/wasm-bindgen-cli-${KASSIGNER_WASM_BINDGEN_CLI_VERSION}"
WASM_BINDGEN_BIN="${WASM_TOOL_ROOT}/bin/wasm-bindgen"
TARGET_DIR="${ROOT_DIR}/target/${PACKAGE}-wasm"

host_env() {
    env -u RUSTC -u RUSTDOC -u CARGO_BUILD_TARGET -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
        PATH="${HOME}/.cargo/bin:${PATH}" \
        RUSTUP_TOOLCHAIN="${KASSIGNER_STABLE_RUST}" \
        "$@"
}

kassigner_reconcile_one_host_lock "$ROOT_DIR" "Root workspace" "Cargo.toml" "Cargo.lock"

if ! rustup target list --toolchain "${KASSIGNER_STABLE_RUST}" --installed | grep -qx "${WASM_TARGET}"; then
    rustup target add "${WASM_TARGET}" --toolchain "${KASSIGNER_STABLE_RUST}"
fi

expected="wasm-bindgen ${KASSIGNER_WASM_BINDGEN_CLI_VERSION}"
actual=""
if [[ -x "${WASM_BINDGEN_BIN}" ]]; then
    actual="$(${WASM_BINDGEN_BIN} --version 2>/dev/null || true)"
fi
if [[ "${actual}" != "${expected}" ]]; then
    rm -rf "${WASM_TOOL_ROOT}"
    host_env rustup run "${KASSIGNER_STABLE_RUST}" cargo install \
        wasm-bindgen-cli --version "${KASSIGNER_WASM_BINDGEN_CLI_VERSION}" \
        --locked --root "${WASM_TOOL_ROOT}"
fi

host_env env CARGO_TARGET_DIR="${TARGET_DIR}" \
    rustup run "${KASSIGNER_STABLE_RUST}" cargo rustc \
    --manifest-path "${ROOT_DIR}/Cargo.toml" --locked --package "${PACKAGE}" \
    --target "${WASM_TARGET}" --release --no-default-features --features wasm \
    --crate-type=cdylib

WASM_INPUT="${TARGET_DIR}/${WASM_TARGET}/release/${WASM_STEM}.wasm"
[[ -s "${WASM_INPUT}" ]] || { echo "ERROR: missing ${WASM_INPUT}" >&2; exit 2; }
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}"
cp "${ROOT_DIR}/crates/${PACKAGE}/LICENSE-MIT" "${PKG_DIR}/LICENSE-MIT"
cp "${ROOT_DIR}/crates/${PACKAGE}/LICENSE-APACHE" "${PKG_DIR}/LICENSE-APACHE"
host_env "${WASM_BINDGEN_BIN}" --target web --out-dir "${PKG_DIR}" \
    --out-name "${WASM_STEM}" "${WASM_INPUT}"
for generated in "${WASM_STEM}.js" "${WASM_STEM}_bg.wasm"; do
    [[ -s "${PKG_DIR}/${generated}" ]] || { echo "ERROR: missing ${PKG_DIR}/${generated}" >&2; exit 2; }
done
cat > "${PKG_DIR}/package.json" <<JSON
{
  "name": "${NPM_NAME}",
  "version": "2.0.0",
  "type": "module",
  "module": "./${WASM_STEM}.js",
  "types": "./${WASM_STEM}.d.ts",
  "license": "MIT OR Apache-2.0",
  "files": ["${WASM_STEM}.js", "${WASM_STEM}.d.ts", "${WASM_STEM}_bg.wasm", "${WASM_STEM}_bg.wasm.d.ts", "LICENSE-MIT", "LICENSE-APACHE"]
}
JSON
printf '%s built: %s\n' "${LABEL}" "${PKG_DIR}/${WASM_STEM}_bg.wasm"
