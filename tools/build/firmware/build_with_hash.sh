#!/usr/bin/env bash
# Build one firmware configuration through mandatory five-pass hash convergence.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)

read_expected_firmware_hash() {
    local file="$1"
    [[ -f "$file" ]] || {
        echo "ERROR: generated firmware hash source not found: $file" >&2
        return 1
    }

    local start='pub static EXPECTED_FIRMWARE_HASH: [u8; 32] = ['
    local start_count
    start_count=$(grep -Fxc "$start" "$file" || true)
    [[ "$start_count" == "1" ]] || {
        echo "ERROR: expected exactly one static EXPECTED_FIRMWARE_HASH declaration; found $start_count" >&2
        return 1
    }

    local block
    block=$(awk '
        $0 == "pub static EXPECTED_FIRMWARE_HASH: [u8; 32] = [" { in_hash=1; next }
        in_hash && $0 == "];" { in_hash=0; done=1; exit }
        in_hash { print }
        END { if (!done) exit 3 }
    ' "$file") || {
        echo "ERROR: EXPECTED_FIRMWARE_HASH declaration is not terminated canonically" >&2
        return 1
    }

    local -a bytes=()
    mapfile -t bytes < <(printf '%s\n' "$block" | grep -oE '0x[0-9a-fA-F]{2}' || true)
    [[ "${#bytes[@]}" == "32" ]] || {
        echo "ERROR: EXPECTED_FIRMWARE_HASH must contain exactly 32 byte literals; found ${#bytes[@]}" >&2
        return 1
    }

    local residual
    residual=$(printf '%s\n' "$block" \
        | sed -E 's/0x[0-9a-fA-F]{2}//g; s/[[:space:],]//g')
    [[ -z "$residual" ]] || {
        echo "ERROR: EXPECTED_FIRMWARE_HASH contains non-canonical content" >&2
        return 1
    }

    local hash="" byte
    for byte in "${bytes[@]}"; do
        hash+="${byte#0x}"
    done
    hash=$(printf '%s' "$hash" | tr 'A-F' 'a-f')
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || {
        echo "ERROR: EXPECTED_FIRMWARE_HASH did not decode to 64 lowercase hex characters" >&2
        return 1
    }
    printf '%s\n' "$hash"
}

if [[ "${1:-}" == "--read-generated-hash" ]]; then
    (($# == 2)) || {
        echo "usage: $(basename "$0") --read-generated-hash <firmware_hash.rs>" >&2
        exit 2
    }
    read_expected_firmware_hash "$2"
    exit $?
fi

BOARD=""
if [[ "${1:-}" == "--board" ]]; then
    (($# >= 2)) || { echo "ERROR: --board requires a value" >&2; exit 2; }
    BOARD="$2"
    shift 2
fi

LABEL=${1:-firmware}
shift || true
CARGO_ARGS=("$@")
APP="$ROOT/apps/signer-firmware"
ELF="$APP/target/xtensa-esp32s3-none-elf/release/kassigner-firmware"
HASH_SOURCE="$APP/src/firmware_hash.rs"
BOARD_HELPER="$ROOT/tools/build/firmware/board_layout.py"
VERIFY_HELPER="$ROOT/tools/build/firmware/verify_image_hash.py"
STACK_BUDGET_HELPER="$ROOT/qa/checks/firmware/compiled_stack_budget.py"
LOCK_RECONCILER="$ROOT/tools/build/firmware/reconcile_tools_lock.py"
TOOLS_LOCK="$ROOT/tools/Cargo.lock"
ESPFLASH_ARGS=()
if [[ -n "$BOARD" ]]; then
    python3 "$BOARD_HELPER" check --board "$BOARD"
    mapfile -t ESPFLASH_ARGS < <(python3 "$BOARD_HELPER" espflash-args --board "$BOARD")
fi

SIGNING_KEY="${KASSIGNER_SIGNING_KEY:-}"
GEN_HASH_KEY_ARGS=()
if [[ -n "$SIGNING_KEY" ]]; then
    [[ -f "$SIGNING_KEY" ]] || { echo "ERROR: KASSIGNER_SIGNING_KEY not found: $SIGNING_KEY" >&2; exit 2; }
    key_size=$(wc -c < "$SIGNING_KEY" | tr -d '[:space:]')
    [[ "$key_size" == "32" ]] || { echo "ERROR: KASSIGNER_SIGNING_KEY must be exactly 32 bytes; got $key_size" >&2; exit 2; }
    SIGNING_KEY="$(cd "$(dirname "$SIGNING_KEY")" && pwd)/$(basename "$SIGNING_KEY")"
fi

CARGO_TEXT=" ${CARGO_ARGS[*]} "
if [[ -n "$SIGNING_KEY" ]]; then
    SIGNING_IDENTITY="development"
    if [[ "$CARGO_TEXT" == *production* ]]; then
        SIGNING_IDENTITY="production"
    fi
    GEN_HASH_KEY_ARGS=("$SIGNING_KEY" "$SIGNING_IDENTITY")
fi
if [[ "$CARGO_TEXT" == *m5stack* && "$BOARD" != "m5stack" ]]; then
    echo "ERROR: M5Stack builds require explicit --board m5stack so the CoreS3 partition table cannot be omitted" >&2
    exit 2
fi
if [[ "$BOARD" == "m5stack" && "$CARGO_TEXT" != *m5stack* ]]; then
    echo "ERROR: --board m5stack requires an m5stack firmware feature set" >&2
    exit 2
fi

TMP=$(mktemp -d)
TOOLS_LOCK_BACKUP="$TMP/tools-Cargo.lock.original"
cp -p "$TOOLS_LOCK" "$TOOLS_LOCK_BACKUP"
cleanup() {
    if [[ -f "$TOOLS_LOCK_BACKUP" ]]; then
        cp -p "$TOOLS_LOCK_BACKUP" "$TOOLS_LOCK"
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT
python3 "$LOCK_RECONCILER" --workspace "$ROOT/tools"
HASHES=()

firmware_cargo_build() {
    (cd "$APP" && RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Z emit-stack-sizes" \
        cargo build --locked --release "${CARGO_ARGS[@]}")
}

for pass in 1 2 3 4 5; do
    firmware_cargo_build
    image="$TMP/${LABEL}-pass${pass}.bin"
    espflash save-image --chip esp32s3 "${ESPFLASH_ARGS[@]}" "$ELF" "$image"
    cargo run --locked --manifest-path "$ROOT/tools/Cargo.toml" \
        --bin gen-hash --release -- "$image" "${GEN_HASH_KEY_ARGS[@]}"
    hash=$(read_expected_firmware_hash "$HASH_SOURCE") || {
        echo "failed to read generated EXPECTED_FIRMWARE_HASH" >&2
        exit 1
    }
    HASHES+=("$hash")
    printf 'pass %s: %s\n' "$pass" "$hash"
done

if [[ "${HASHES[1]}" != "${HASHES[2]}" || "${HASHES[2]}" != "${HASHES[3]}" || "${HASHES[3]}" != "${HASHES[4]}" ]]; then
    echo "error: passes 2 through 5 did not converge; generated identity must not affect executable bytes" >&2
    exit 1
fi

firmware_cargo_build
python3 "$STACK_BUDGET_HELPER" "$ELF"
FINAL_IMAGE="$TMP/${LABEL}-final.bin"
espflash save-image --chip esp32s3 "${ESPFLASH_ARGS[@]}" "$ELF" "$FINAL_IMAGE"
python3 "$VERIFY_HELPER" "$FINAL_IMAGE" "$HASH_SOURCE"
FINAL_HASH=$(read_expected_firmware_hash "$HASH_SOURCE")
[[ "$FINAL_HASH" == "${HASHES[4]}" ]] || {
    echo "error: final embedded hash drifted after convergence" >&2
    exit 1
}
printf 'converged: %s\n' "${HASHES[4]}"
if [[ -n "${KASSIGNER_FINAL_IMAGE_OUT:-}" ]]; then
    mkdir -p "$(dirname "$KASSIGNER_FINAL_IMAGE_OUT")"
    cp "$FINAL_IMAGE" "$KASSIGNER_FINAL_IMAGE_OUT"
    printf 'final image: %s\n' "$KASSIGNER_FINAL_IMAGE_OUT"
fi
