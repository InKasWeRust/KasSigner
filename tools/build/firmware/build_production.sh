#!/bin/bash
# KasSigner — production M5Stack CoreS3 application build.
# Default is the non-destructive normal release profile. Dedicated provisioning
# profiles are opt-in and never selected by make release/flash-release.
set -euo pipefail

FEATURES=m5stack,production
LABEL=m5stack-production
REQUIRE_SCHNORR=1
case "${1:-}" in
  --secure-provisioning)
    FEATURES=m5stack,secure-provisioning
    LABEL=m5stack-secure-provisioning
    shift
    ;;
  --secure-owner-only)
    FEATURES=m5stack,secure-owner-only
    LABEL=m5stack-secure-owner-only
    REQUIRE_SCHNORR=0
    shift
    ;;
esac

if (( REQUIRE_SCHNORR )); then
  [[ -n "${KASSIGNER_SIGNING_KEY:-}" && -f "$KASSIGNER_SIGNING_KEY" ]] || {
    echo 'ERROR: KASSIGNER_SIGNING_KEY must point to the 32-byte Schnorr firmware release key.' >&2
    exit 2
  }
else
  # Owner-only deliberately has no vendor software-signing authority. Its
  # pre-Pop image is self-provisioning; Pop It binds the owner RSA digest into
  # hardware and all subsequent trust is enforced by Secure Boot v2.
  unset KASSIGNER_SIGNING_KEY
fi

exec "$(dirname "$0")/build_with_hash.sh" \
  --board m5stack \
  "$LABEL" \
  --no-default-features \
  --features "$FEATURES" \
  "$@"
