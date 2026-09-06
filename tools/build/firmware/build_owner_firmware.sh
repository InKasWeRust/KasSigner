#!/usr/bin/env bash
# Build and sign an owner-authorized CoreS3 application image.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT="${1:-$ROOT/target/owner-firmware}"
KEY="${KASSIGNER_OWNER_SECURE_BOOT_KEY:-}"
[[ -n "$KEY" && -f "$KEY" ]] || {
    echo 'ERROR: KASSIGNER_OWNER_SECURE_BOOT_KEY must point to the owner RSA-3072 Secure Boot v2 private key.' >&2
    exit 2
}
mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
UNSIGNED="$TMP/owner-firmware-unsigned.bin"
# Owner firmware is authorized by the enrolled Secure Boot RSA owner key. Do not
# accidentally embed a vendor/development Schnorr identity inherited from the
# caller's shell.
(
    unset KASSIGNER_SIGNING_KEY
    KASSIGNER_FINAL_IMAGE_OUT="$UNSIGNED" \
        "$ROOT/tools/build/firmware/build_with_hash.sh" --board m5stack owner-firmware \
        --no-default-features --features m5stack,owner-firmware
)
KASSIGNER_SECURE_BOOT_SIGNING_KEY="$KEY" \
    "$ROOT/tools/build/firmware/secure_bootloader/m5stack/sign_app.sh" \
    "$UNSIGNED" "$OUT/OWNERFW.BIN"
python3 "$ROOT/tools/build/firmware/owner_authority.py" --key "$KEY" --output "$OUT/OWNERKEY.KAS"
sha256sum "$OUT/OWNERFW.BIN" "$OUT/OWNERKEY.KAS" > "$OUT/SHA256SUMS"
echo "Owner-authority media prepared in: $OUT"
