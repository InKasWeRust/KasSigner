#!/usr/bin/env bash
# Prepare signed CoreS3 Secure Boot provisioning artifacts without touching hardware.
# Default: vendor + optional owner dual authority. --owner-only restores the
# original sole-owner model: the owner's RSA key is the only hardware trust root.
set -euo pipefail

MODE=dual
if [[ "${1:-}" == "--owner-only" ]]; then
    MODE=owner-only
    shift
fi
[[ $# -eq 1 ]] || {
    echo "usage: $(basename "$0") [--owner-only] <output-dir>" >&2
    exit 2
}
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
# shellcheck source=lib/release_policy.sh
source "$ROOT/tools/build/firmware/lib/release_policy.sh"
PACKAGE_VERSION=$(kassigner_package_version)
OUT="$1"
mkdir -p "$OUT"
if [[ -f "$OUT/TRUST-POLICY" ]]; then
    EXISTING_MODE=$(tr -d '\r\n' < "$OUT/TRUST-POLICY")
    [[ "$EXISTING_MODE" == "$MODE" ]] || {
        echo "ERROR: refusing to mix secure trust policies in $OUT (existing=$EXISTING_MODE requested=$MODE). Use a clean output directory." >&2
        exit 2
    }
fi
if [[ -f "$OUT/AUTHORITY-MODE" ]]; then
    EXISTING_AUTHORITY=$(tr -d '\r\n' < "$OUT/AUTHORITY-MODE")
    [[ "$EXISTING_AUTHORITY" == "$MODE" ]] || {
        echo "ERROR: refusing to mix secure authority modes in $OUT (existing=$EXISTING_AUTHORITY requested=$MODE). Use a clean output directory." >&2
        exit 2
    }
fi
if [[ "$MODE" == owner-only ]]; then
    for stale in         "$OUT/kassigner-m5stack-secure-provisioning.bin"         "$OUT/kassigner-m5stack-app-secureboot-signed.bin"         "$OUT/kassigner-m5stack-update.ksfu"; do
        [[ ! -e "$stale" ]] || {
            echo "ERROR: owner-only output contains stale dual-authority artifact $(basename "$stale"). Use a clean output directory." >&2
            exit 2
        }
    done
else
    for stale in         "$OUT/kassigner-m5stack-secure-owner-only.bin"         "$OUT/kassigner-m5stack-owner-only-app-secureboot-signed.bin"; do
        [[ ! -e "$stale" ]] || {
            echo "ERROR: dual-authority output contains stale owner-only artifact $(basename "$stale"). Use a clean output directory." >&2
            exit 2
        }
    done
fi

if [[ "$MODE" == owner-only ]]; then
    OWNER_KEY="${KASSIGNER_OWNER_SECURE_BOOT_KEY:-}"
    [[ -n "$OWNER_KEY" && -f "$OWNER_KEY" ]] || {
        echo 'ERROR: set KASSIGNER_OWNER_SECURE_BOOT_KEY to the owner RSA-3072 Secure Boot v2 private key.' >&2
        exit 2
    }
    # The selected owner key signs both enforcing images and is the exact digest
    # that enrollment will burn into SECURE_BOOT_DIGEST0. A vendor Schnorr key
    # is intentionally neither required nor embedded in this profile.
    export KASSIGNER_SECURE_BOOT_SIGNING_KEY="$OWNER_KEY"
    export KASSIGNER_SECURE_BOOT_AUTHORITY_MODE=owner-only
    unset KASSIGNER_SIGNING_KEY
    APP="$OUT/kassigner-m5stack-secure-owner-only.bin"
    SIGNED_APP="$OUT/kassigner-m5stack-owner-only-app-secureboot-signed.bin"
    KASSIGNER_FINAL_IMAGE_OUT="$APP" \
        "$ROOT/tools/build/firmware/build_production.sh" --secure-owner-only
    "$ROOT/tools/build/firmware/secure_bootloader/m5stack/build.sh" "$OUT"
    "$ROOT/tools/build/firmware/secure_bootloader/m5stack/sign_app.sh" "$APP" "$SIGNED_APP"
    python3 "$ROOT/tools/build/firmware/owner_authority.py" \
        --key "$OWNER_KEY" --output "$OUT/OWNERKEY.KAS"
    printf '%s\n' owner-only > "$OUT/TRUST-POLICY"
    # There is deliberately no vendor-Schnorr KSFU manifest in sole-owner mode.
    # Future owner updates use OWNERFW.BIN signed by the same enrolled RSA key.
else
    [[ -n "${KASSIGNER_SECURE_BOOT_SIGNING_KEY:-}" ]] || {
        echo 'ERROR: set KASSIGNER_SECURE_BOOT_SIGNING_KEY to the offline vendor RSA-3072 Secure Boot v2 key.' >&2
        exit 2
    }
    [[ -f "$KASSIGNER_SECURE_BOOT_SIGNING_KEY" ]] || {
        echo "ERROR: Secure Boot key not found: $KASSIGNER_SECURE_BOOT_SIGNING_KEY" >&2
        exit 2
    }
    [[ -n "${KASSIGNER_SIGNING_KEY:-}" ]] || {
        echo 'ERROR: set KASSIGNER_SIGNING_KEY to the 32-byte Schnorr release key.' >&2
        exit 2
    }
    [[ -f "$KASSIGNER_SIGNING_KEY" ]] || { echo "ERROR: Schnorr release key not found: $KASSIGNER_SIGNING_KEY" >&2; exit 2; }
    [[ $(wc -c < "$KASSIGNER_SIGNING_KEY") -eq 32 ]] || { echo 'ERROR: Schnorr release key must be exactly 32 bytes.' >&2; exit 2; }
    export KASSIGNER_SECURE_BOOT_AUTHORITY_MODE=dual
    APP="$OUT/kassigner-m5stack-secure-provisioning.bin"
    SIGNED_APP="$OUT/kassigner-m5stack-app-secureboot-signed.bin"
    KASSIGNER_FINAL_IMAGE_OUT="$APP" \
        "$ROOT/tools/build/firmware/build_production.sh" --secure-provisioning
    "$ROOT/tools/build/firmware/secure_bootloader/m5stack/build.sh" "$OUT"
    "$ROOT/tools/build/firmware/secure_bootloader/m5stack/sign_app.sh" "$APP" "$SIGNED_APP"

    # The KSFU manifest binds the exact RSA-signed app bytes that the Secure
    # Boot v2 bootloader will verify, not the pre-Secure-Boot application image.
    cargo run --offline --locked --manifest-path "$ROOT/tools/Cargo.toml" \
        --bin gen-update-manifest --release -- \
        "$SIGNED_APP" "$KASSIGNER_SIGNING_KEY" m5stack "$PACKAGE_VERSION" \
        "$KASSIGNER_UPDATE_SEQUENCE" "$KASSIGNER_SECURITY_VERSION" \
        "$ROOT/apps/signer-firmware/partitions/m5stack-cores3.csv" \
        "$OUT/kassigner-m5stack-update.ksfu"
    printf '%s\n' dual > "$OUT/TRUST-POLICY"
fi

sha256sum "$OUT"/kassigner-m5stack-* "$OUT/TRUST-POLICY" "$OUT/AUTHORITY-MODE" \
    > "$OUT/SECURE-BOOT-SHA256SUMS"
if [[ "$MODE" == owner-only ]]; then
    sha256sum "$OUT/OWNERKEY.KAS" >> "$OUT/SECURE-BOOT-SHA256SUMS"
fi
echo "Prepared non-flashing CoreS3 secure release artifacts ($MODE): $OUT"
