#!/bin/bash
# KasSee Web — Build script
# Pure Rust → WASM. No C compilation.
#
# Prerequisites:
#   cargo install wasm-pack
#   rustup target add wasm32-unknown-unknown --toolchain stable
#
# Usage:
#   RUSTUP_TOOLCHAIN=stable ./build.sh          # release
#   RUSTUP_TOOLCHAIN=stable ./build.sh dev      # debug (faster)

set -e

MODE=${1:-release}

echo "KasSee Web — Building ($MODE)..."

if [ "$MODE" = "dev" ]; then
    wasm-pack build --target web --dev --out-dir web/pkg
else
    wasm-pack build --target web --release --out-dir web/pkg
fi

echo ""
echo "Build complete. Serve the web/ directory:"
echo "  cd web && python3 -m http.server 8080"
echo "  Open http://localhost:8080"
