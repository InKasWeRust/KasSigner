#!/bin/bash
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
set -e

echo "╔════════════════════════════════════════════════╗"
echo "║  KasSigner — Signed Build with Hash             ║"
echo "║  Iterative convergence + Schnorr signing        ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# ── Why this script changed, 2026-08-01 ─────────────────────────────
#
# The previous version built with `cargo build --release $FEATURES`, where
# FEATURES was either empty or `--features production`. It never passed the
# target selection. So it compiled the DEFAULT-feature binary, converged a hash
# for that, wrote it into bootloader/src/firmware_hash.rs, and then the
# developer flashed a differently-configured build. The embedded hash was
# correct for a firmware nobody ran, and every boot printed
# "FAIL: Hash does NOT match".
#
# Evidence: firmware_hash.rs carried FIRMWARE_SIZE = 426204 while the flashed
# code segments measured 568,252 bytes (M5Stack) and 578,640 (Waveshare).
#
# This version takes the build configuration verbatim and passes it through
# unchanged, and inherits the environment so variables such as
# ESP_HAL_CONFIG_PSRAM_MODE reach the compiler. Pass exactly the arguments you
# would use to flash.
#
# The two boards produce different code segments and therefore different
# hashes. firmware_hash.rs holds ONE hash, so it is valid only for the target
# it was last generated for. Regenerate before flashing the other board.

cd "$(dirname "$0")/.."

ELF="bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader"
BIN="bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader.bin"

# ── Parse arguments ─────────────────────────────────────────
#
# Everything that is not --key is forwarded to cargo untouched:
#
#   build_with_hash.sh --features ov5640-af
#   build_with_hash.sh --no-default-features --features m5stack
#   build_with_hash.sh --features production --key keys/dev_signing_key.bin
#
# Environment is inherited, so prefix as you normally would:
#
#   ESP_HAL_CONFIG_PSRAM_MODE=octal ./tools/build_with_hash.sh --features ov5640-af
#
# The old parser silently dropped every unrecognised argument, which is how a
# target selection could be passed and ignored without warning.

CARGO_ARGS=()
SIGNING_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)
            SIGNING_KEY="$2"
            shift 2
            ;;
        production)
            # Backward compatibility: build_production.sh invokes this with a
            # bare `production` token. Everything else is forwarded verbatim.
            CARGO_ARGS+=("--features" "production")
            echo "  Mode: PRODUCTION (silent + strict verification + signed)"
            shift
            ;;
        *)
            CARGO_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ ${#CARGO_ARGS[@]} -eq 0 ]; then
    echo "  Build config: (cargo defaults)"
    echo ""
    echo "  WARNING: no build arguments given. If you flash with feature flags,"
    echo "  this hash will not match what you run. Pass the SAME arguments."
else
    echo "  Build config: ${CARGO_ARGS[*]}"
fi
if [ -n "$ESP_HAL_CONFIG_PSRAM_MODE" ]; then
    echo "  ESP_HAL_CONFIG_PSRAM_MODE=$ESP_HAL_CONFIG_PSRAM_MODE"
fi

# Auto-detect signing key if not specified
if [ -z "$SIGNING_KEY" ]; then
    for candidate in \
        "dev_signing_key.bin" \
        "keys/dev_signing_key.bin" \
        "../dev_signing_key.bin" \
        "$HOME/.kassigner/dev_signing_key.bin"; do
        if [ -f "$candidate" ]; then
            SIGNING_KEY="$candidate"
            break
        fi
    done
fi

if [ -n "$SIGNING_KEY" ] && [ -f "$SIGNING_KEY" ]; then
    echo "  Signing key: $SIGNING_KEY"
    SIGN_ARG="$SIGNING_KEY"
else
    echo "  Signing key: NONE (unsigned development build)"
    SIGN_ARG=""
fi
echo ""

# ── Step 1: First compilation ───────────────────────────────
echo "[1] Compiling bootloader (first pass)..."
cd bootloader
# PIPESTATUS, not the pipeline's status. `| grep` makes the exit code grep's,
# and the `|| true` that used to be here (added so a build producing no matching
# output would not abort under `set -e`) swallowed cargo's failure entirely.
# The result was a script that printed CONVERGED and BUILD COMPLETE after every
# compile failed, reporting the hash of a stale binary from an earlier build.
# A build script that claims success on a failed compile is worse than one that
# never runs. Observed 2026-08-02 on `production`, which does not compile.
set +e
cargo build --release "${CARGO_ARGS[@]}" 2>&1 | grep -E "Compiling|Finished|error"
build_rc=${PIPESTATUS[0]}
set -e
if [ "$build_rc" -ne 0 ]; then
    echo ""
    echo "   BUILD FAILED (cargo exit $build_rc). Nothing hashed, nothing written."
    exit "$build_rc"
fi
cd ..

# ── Iteration: hash → sign → embed → recompile → verify ────
MAX_ITERATIONS=5
PREV_HASH=""
CONVERGED=0

for i in $(seq 1 $MAX_ITERATIONS); do
    echo ""
    echo "── Iteration $i/$MAX_ITERATIONS ──────────────────────────"

    # Generate .bin
    set +e
    espflash save-image --chip esp32s3 "$ELF" "$BIN" 2>&1 | grep -v "INFO"
    img_rc=${PIPESTATUS[0]}
    set -e
    if [ "$img_rc" -ne 0 ]; then
        echo "   save-image FAILED (exit $img_rc)."
        exit "$img_rc"
    fi

    # Compute hash + sign (if key available)
    if [ -n "$SIGN_ARG" ]; then
        HASH_OUTPUT=$(cargo run --manifest-path tools/Cargo.toml --bin gen-hash -- "$BIN" "$SIGN_ARG" 2>&1)
    else
        HASH_OUTPUT=$(cargo run --manifest-path tools/Cargo.toml --bin gen-hash -- "$BIN" 2>&1)
    fi
    CURRENT_HASH=$(echo "$HASH_OUTPUT" | grep "SHA256:" | awk '{print $2}')
    SEG_SIZE=$(echo "$HASH_OUTPUT" | grep "Segment size:" | awk '{print $3}')
    SIGNED=$(echo "$HASH_OUTPUT" | grep "Status:" | head -1)

    echo "   Hash: ${CURRENT_HASH:0:16}..."
    echo "   Segment: $SEG_SIZE bytes"
    [ -n "$SIGNED" ] && echo "   $SIGNED"

    # Converged?
    if [ "$CURRENT_HASH" = "$PREV_HASH" ]; then
        echo ""
        echo "   CONVERGED at iteration $i"
        echo "   Stable hash: $CURRENT_HASH"
        CONVERGED=1
        break
    fi

    PREV_HASH="$CURRENT_HASH"

    # Recompile with embedded hash + signature
    echo "   Recompiling with embedded hash..."
    cd bootloader
    set +e
    cargo build --release "${CARGO_ARGS[@]}" 2>&1 | grep -E "Compiling|Finished|error"
    build_rc=${PIPESTATUS[0]}
    set -e
    if [ "$build_rc" -ne 0 ]; then
        echo ""
        echo "   BUILD FAILED on iteration $i (cargo exit $build_rc)."
        echo "   firmware_hash.rs now holds a hash for a binary that does not build."
        exit "$build_rc"
    fi
    cd ..

    if [ $i -eq $MAX_ITERATIONS ]; then
        echo ""
        echo "   WARNING: Did not converge after $MAX_ITERATIONS iterations."
        echo "   The device will print 'Hash does NOT match' at boot."
    fi
done

# ── Generate final .bin ─────────────────────────────────────
echo ""
echo "[Final] Generating final .bin..."
set +e
espflash save-image --chip esp32s3 "$ELF" "$BIN" 2>&1 | grep -v "INFO"
img_rc=${PIPESTATUS[0]}
set -e
if [ "$img_rc" -ne 0 ]; then
    echo "   save-image FAILED (exit $img_rc)."
    exit "$img_rc"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  BUILD COMPLETE"
echo "════════════════════════════════════════════════"
echo ""
echo "  Hash: ${CURRENT_HASH:0:16}..."
if [ -n "$SIGN_ARG" ]; then
    echo "  Status: SIGNED"
else
    echo "  Status: UNSIGNED (development)"
fi
if [ "$CONVERGED" -ne 1 ]; then
    echo "  Convergence: FAILED — boot verification will report a mismatch"
    exit 1
fi
echo ""
echo "  Valid ONLY for this build config: ${CARGO_ARGS[*]:-cargo defaults}"
echo "  Regenerate before building the other board."
echo ""
echo "  To flash:"
echo "    cd bootloader"
echo "    espflash flash --monitor $ELF"
