#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════╗"
echo "║  KasSigner — Signed Build with Hash             ║"
echo "║  Iterative convergence + Schnorr signing        ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")/.."

ELF="bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader"
BIN="bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader.bin"

# ── Parse arguments ─────────────────────────────────────────
# Usage: build_with_hash.sh [production] [--key path/to/dev_signing_key.bin]
FEATURES=""
SIGNING_KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        production)
            FEATURES="--features production"
            echo "  Mode: PRODUCTION (silent + strict verification + signed)"
            shift
            ;;
        --key)
            SIGNING_KEY="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$FEATURES" ]; then
    echo "  Mode: DEVELOPMENT"
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
cargo build --release $FEATURES 2>&1 | grep -E "Compiling|Finished|error"
cd ..

# ── Iteration: hash → sign → embed → recompile → verify ────
MAX_ITERATIONS=5
PREV_HASH=""

for i in $(seq 1 $MAX_ITERATIONS); do
    echo ""
    echo "── Iteration $i/$MAX_ITERATIONS ──────────────────────────"

    # Generate .bin
    espflash save-image --chip esp32s3 "$ELF" "$BIN" 2>&1 | grep -v "INFO"

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
        break
    fi

    PREV_HASH="$CURRENT_HASH"

    # Recompile with embedded hash + signature
    echo "   Recompiling with embedded hash..."
    cd bootloader
    cargo build --release $FEATURES 2>&1 | grep -E "Compiling|Finished|error"
    cd ..

    if [ $i -eq $MAX_ITERATIONS ]; then
        echo ""
        echo "   WARNING: Did not converge after $MAX_ITERATIONS iterations."
    fi
done

# ── Generate final .bin ─────────────────────────────────────
echo ""
echo "[Final] Generating final .bin..."
espflash save-image --chip esp32s3 "$ELF" "$BIN" 2>&1 | grep -v "INFO"

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
echo ""
echo "  To flash:"
echo "    cd bootloader"
echo "    espflash flash --monitor $ELF"
