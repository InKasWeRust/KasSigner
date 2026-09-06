#!/usr/bin/env bash
# Verify the public KasSigner Rust crates and generated WASM/npm packages.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
source "${ROOT_DIR}/qa/config/toolchains.env"

REGISTRY_DRY_RUN=0
if [[ "${1:-}" == "--registry-dry-run" ]]; then
    REGISTRY_DRY_RUN=1
    shift
fi
[[ $# -eq 0 ]] || { echo "usage: $0 [--registry-dry-run]" >&2; exit 2; }

for command in rustup tar npm python3; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "ERROR: required command is missing: ${command}" >&2
        exit 2
    }
done

STAGE="${ROOT_DIR}/target/sdk-distribution-check"
CRATE_STAGE="${STAGE}/crates"
UNPACKED="${STAGE}/unpacked"
CONSUMER="${STAGE}/consumer"
rm -rf "${STAGE}"
mkdir -p "${CRATE_STAGE}" "${UNPACKED}" "${CONSUMER}/src"

cargo_stable() {
    env -u RUSTC -u RUSTDOC -u CARGO_BUILD_TARGET -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
        PATH="${HOME}/.cargo/bin:${PATH}" \
        RUSTUP_TOOLCHAIN="${KASSIGNER_STABLE_RUST}" \
        rustup run "${KASSIGNER_STABLE_RUST}" cargo "$@"
}

package_crate() {
    local name="$1"
    cargo_stable package --manifest-path "${ROOT_DIR}/Cargo.toml" --locked \
        --package "${name}" --allow-dirty --no-verify
    local archive="${ROOT_DIR}/target/package/${name}-2.0.0.crate"
    [[ -s "${archive}" ]] || { echo "ERROR: missing packaged crate ${archive}" >&2; exit 2; }
    cp "${archive}" "${CRATE_STAGE}/"
    tar -xzf "${archive}" -C "${UNPACKED}"
}

for name in shared-signer kassigner-protocol kassigner-sdk; do
    package_crate "${name}"
done

cargo_stable check --manifest-path "${ROOT_DIR}/Cargo.toml" --locked --package offline-signer
printf 'PASS: offline-signer consumes the no_std kassigner-protocol wire core\n'

native_tree="$(cargo_stable tree --manifest-path "${ROOT_DIR}/Cargo.toml" --locked --package kassigner-sdk --edges normal --no-default-features --features native)"
if grep -Eq '(^|[[:space:]])(wasm-bindgen|js-sys) v' <<<"${native_tree}"; then
    echo 'ERROR: native kassigner-sdk dependency graph pulled WASM-only dependencies' >&2
    exit 2
fi
printf 'PASS: native SDK dependency graph excludes wasm-bindgen/js-sys\n'

python3 - "${UNPACKED}" <<'PY'
from pathlib import Path
import sys
import tomllib

root = Path(sys.argv[1])
expected = {
    "shared-signer": None,
    "kassigner-protocol": ("shared-signer", "=2.0.0"),
    "kassigner-sdk": ("kassigner-protocol", "=2.0.0"),
}
for name, dependency in expected.items():
    manifest_path = root / f"{name}-2.0.0" / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text())
    package = manifest["package"]
    if package["name"] != name or package["version"] != "2.0.0":
        raise SystemExit(f"ERROR: normalized package identity mismatch: {manifest_path}")
    if package.get("license") != "MIT OR Apache-2.0":
        raise SystemExit(f"ERROR: public SDK crate is not dual MIT/Apache: {manifest_path}")
    for license_name in ("LICENSE-MIT", "LICENSE-APACHE"):
        if not (manifest_path.parent / license_name).is_file():
            raise SystemExit(f"ERROR: packaged crate is missing {license_name}: {manifest_path}")
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dep_name, spec in manifest.get(section, {}).items():
            if isinstance(spec, dict) and "path" in spec:
                raise SystemExit(f"ERROR: packaged dependency retained path: {name} -> {dep_name}")
    if dependency:
        dep_name, version = dependency
        spec = manifest.get("dependencies", {}).get(dep_name)
        actual = spec.get("version") if isinstance(spec, dict) else spec
        if actual != version:
            raise SystemExit(f"ERROR: {name} packaged {dep_name} version is {actual!r}, expected {version!r}")
print("PASS: normalized crates contain registry-ready dependency metadata")
PY

protocol_path="${UNPACKED}/kassigner-protocol-2.0.0"
sdk_path="${UNPACKED}/kassigner-sdk-2.0.0"
shared_path="${UNPACKED}/shared-signer-2.0.0"
cat > "${CONSUMER}/Cargo.toml" <<EOF_CONSUMER
[package]
name = "kassigner-sdk-package-consumer"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
kassigner-sdk = "=2.0.0"
kassigner-protocol = "=2.0.0"

[patch.crates-io]
shared-signer = { path = "${shared_path}" }
kassigner-protocol = { path = "${protocol_path}" }
kassigner-sdk = { path = "${sdk_path}" }
EOF_CONSUMER
cat > "${CONSUMER}/src/main.rs" <<'EOF_RUST'
use kassigner_sdk::Network;
fn main() {
    let _network = Network::Mainnet;
}
EOF_RUST
cargo_stable check --manifest-path "${CONSUMER}/Cargo.toml"
printf 'PASS: packaged crates compile as an external consumer graph\n'

"${ROOT_DIR}/crates/kassigner-protocol/build.sh"
"${ROOT_DIR}/crates/kassigner-sdk/build.sh"
for package_dir in \
    "${ROOT_DIR}/target/sdk/kassigner-protocol/pkg" \
    "${ROOT_DIR}/target/sdk/kassigner-sdk/pkg"; do
    (cd "${package_dir}" && npm pack --dry-run >/dev/null)
done
printf 'PASS: generated WASM/npm packages pass npm pack dry-run\n'

if [[ ${REGISTRY_DRY_RUN} -eq 1 ]]; then
    for name in shared-signer kassigner-protocol kassigner-sdk; do
        cargo_stable publish --manifest-path "${ROOT_DIR}/Cargo.toml" --locked \
            --package "${name}" --allow-dirty --dry-run
    done
    printf 'PASS: Cargo registry dry-runs completed\n'
fi

printf 'PASS: KasSigner SDK distribution verification completed\n'
