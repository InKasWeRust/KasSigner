#!/usr/bin/env bash
# Build the signed ESP-IDF second-stage bootloader for KasSigner CoreS3.
# It verifies signed applications and defers every irreversible security transition
# to explicit user-controlled Owner Firmware / Pop It consent.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../../../.." && pwd)
# shellcheck source=../../lib/release_policy.sh
source "$ROOT/tools/build/firmware/lib/release_policy.sh"
PROFILE="$ROOT/tools/build/firmware/secure_bootloader/m5stack"
PARTITIONS="$ROOT/apps/signer-firmware/partitions/m5stack-cores3.csv"
SIGNING_KEY="${KASSIGNER_SECURE_BOOT_SIGNING_KEY:-}"
AUTHORITY_MODE="${KASSIGNER_SECURE_BOOT_AUTHORITY_MODE:-dual}"
OUTPUT="${1:-$ROOT/target/qa/state/m5stack-secure-bootloader}"
case "$AUTHORITY_MODE" in
    dual|owner-only) ;;
    *) echo "ERROR: KASSIGNER_SECURE_BOOT_AUTHORITY_MODE must be dual or owner-only." >&2; exit 2 ;;
esac

[[ -n "${IDF_PATH:-}" && -d "$IDF_PATH" ]] || {
    echo 'ERROR: IDF_PATH must point to an ESP-IDF checkout/tool environment.' >&2
    exit 2
}
command -v idf.py >/dev/null 2>&1 || { echo 'ERROR: idf.py is required.' >&2; exit 2; }
command -v espsecure >/dev/null 2>&1 || { echo 'ERROR: espsecure is required.' >&2; exit 2; }
[[ -n "$SIGNING_KEY" && -f "$SIGNING_KEY" ]] || {
    echo 'ERROR: KASSIGNER_SECURE_BOOT_SIGNING_KEY must point to the offline RSA-3072 Secure Boot v2 private key.' >&2
    exit 2
}

mkdir -p "$ROOT/target/qa/state" "$OUTPUT"
WORK=$(mktemp -d "$ROOT/target/qa/state/m5-secure-bootloader.XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
cp -R "$PROFILE"/. "$WORK"/
cp "$PARTITIONS" "$WORK/partitions.csv"

# ESP-IDF explicitly supports project bootloader_components for custom
# second-stage bootloader behavior. Copy the pinned built-in component into the
# temporary build tree, then apply the narrow consent gate without modifying the
# developer's ESP-IDF checkout.
mkdir -p "$WORK/bootloader_components"
cp -R "$IDF_PATH/components/bootloader_support" "$WORK/bootloader_components/bootloader_support"
KEY=$(cd "$(dirname "$SIGNING_KEY")" && pwd)/$(basename "$SIGNING_KEY")
EXPECTED_DIGEST="$WORK/kassigner-sbv2-authority-key-digest.bin"
espsecure digest-sbv2-public-key --keyfile "$KEY" --output "$EXPECTED_DIGEST"
[[ $(wc -c < "$EXPECTED_DIGEST") -eq 32 ]] || {
    echo 'ERROR: espsecure did not produce a 32-byte Secure Boot v2 public-key digest.' >&2
    exit 1
}
python3 "$PROFILE/patch_pop_it_bootloader.py" \
    "$WORK/bootloader_components/bootloader_support" \
    --expected-key-digest "$EXPECTED_DIGEST" \
    --authority-mode "$AUTHORITY_MODE"
printf '\nCONFIG_SECURE_BOOT_SIGNING_KEY="%s"\nCONFIG_BOOTLOADER_APP_SECURE_VERSION=%s\n' \
    "$KEY" "$KASSIGNER_SECURITY_VERSION" >> "$WORK/sdkconfig.defaults"

(
    cd "$WORK"
    idf.py set-target esp32s3 >/dev/null
    idf.py bootloader
)

BOOTLOADER="$WORK/build/bootloader/bootloader.bin"
[[ -s "$BOOTLOADER" ]] || { echo 'ERROR: signed bootloader.bin was not produced.' >&2; exit 1; }
cp "$BOOTLOADER" "$OUTPUT/kassigner-m5stack-secure-bootloader.bin"
cp "$EXPECTED_DIGEST" "$OUTPUT/kassigner-m5stack-secure-boot-key-digest.bin"
python3 "$IDF_PATH/components/partition_table/gen_esp32part.py" \
    "$PARTITIONS" "$OUTPUT/kassigner-m5stack-partition-table.bin"
cp "$PARTITIONS" "$OUTPUT/kassigner-m5stack-partitions.csv"
printf '%s\n' "$AUTHORITY_MODE" > "$OUTPUT/AUTHORITY-MODE"
sha256sum \
    "$OUTPUT/kassigner-m5stack-secure-bootloader.bin" \
    "$OUTPUT/kassigner-m5stack-secure-boot-key-digest.bin" \
    "$OUTPUT/kassigner-m5stack-partition-table.bin" \
    "$OUTPUT/kassigner-m5stack-partitions.csv" \
    "$OUTPUT/AUTHORITY-MODE" \
    > "$OUTPUT/SHA256SUMS"
echo "Built signed CoreS3 secure bootloader profile ($AUTHORITY_MODE): $OUTPUT"
