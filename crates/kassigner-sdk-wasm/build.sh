#!/bin/sh
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# The SDK as a browser package: `kassigner-sdk-wasm` built for
# `wasm32-unknown-unknown` in the workspace's release profile, then
# `wasm-bindgen` over it, into `pkg/`:
#
#   kassigner_sdk.js          the module (`import init, * as sdk from ...`)
#   kassigner_sdk_bg.wasm     the code
#   kassigner_sdk.d.ts        the TypeScript declarations
#   LICENSE                   MPL-2.0, this package's own
#   THIRD_PARTY_NOTICES       the licenses of what is compiled in with it
#
#   sh crates/kassigner-sdk-wasm/build.sh          the full package, into pkg/
#   sh crates/kassigner-sdk-wasm/build.sh watch    the watch-only one, into pkg-watch/
#
# The watch-only package is the crate without its `transactions` feature:
# imports, addresses, coins, signed messages, cards, codes and a node's
# reads, and nothing that builds, checks, finishes or sends a transaction.
# kassigner.org serves it; `check/check-watch.mjs` checks both halves.
#
# Runs from anywhere. Needs the target (`rustup target add
# wasm32-unknown-unknown`), the `wasm-bindgen` command at exactly the
# version the lock pins for the `wasm-bindgen` crate, as wasm-bindgen
# requires (`cargo install wasm-bindgen-cli --version <that>`), and
# Binaryen's `wasm-opt` at the version pinned below (`brew install
# binaryen`, or Binaryen's release).
# Both are checked before building, so two builds of one commit make the
# same bytes.
#
# The package names no folder of the machine that built it: the compiler
# is told to write `/cargo`, `/rustup` and `/kassigner` for cargo's home,
# rustup's and this tree, and the build fails if one of them, or the home
# folder, is still in a file of the package. The flags go through
# `CARGO_ENCODED_RUSTFLAGS`, which a path with spaces survives; a
# `RUSTFLAGS` of the caller's is not used.
#
# `wasm-opt -Oz` runs whole-module passes the Rust compiler cannot, for a
# file about 40% smaller. With Node.js on the PATH, `check/check.mjs` then
# runs the package through the native binding's `check.py` round over
# `spec/vectors/v110/`; without it the package is left unchecked. Last,
# the SHA-256 of every file in `pkg/`, to compare with another build.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TARGET=wasm32-unknown-unknown
WASM_OPT=133

case "${1:-}" in
"")
    KIND=full
    PKG="$HERE/pkg"
    CHECK=check.mjs
    ;;
watch)
    KIND=watch
    PKG="$HERE/pkg-watch"
    CHECK=check-watch.mjs
    ;;
*)
    echo "usage: sh crates/kassigner-sdk-wasm/build.sh [watch]" >&2
    exit 2
    ;;
esac

pinned="$(awk '/^name = "wasm-bindgen"$/ { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }' "$ROOT/Cargo.lock")"
have="$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }' || true)"
if [ "$have" != "$pinned" ]; then
    echo "wasm-bindgen $pinned is needed (the lock's); found '${have:-none}':" >&2
    echo "    cargo install -f wasm-bindgen-cli --version $pinned" >&2
    exit 1
fi
have="$(wasm-opt --version 2>/dev/null | awk '{ print $3 }' || true)"
if [ "$have" != "$WASM_OPT" ]; then
    echo "wasm-opt $WASM_OPT is needed (Binaryen's); found '${have:-none}':" >&2
    echo "    brew install binaryen, or Binaryen's own release:" >&2
    echo "    https://github.com/WebAssembly/binaryen/releases/tag/version_$WASM_OPT" >&2
    exit 1
fi

cd "$ROOT"
CARGO_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
sep="$(printf '\037')"
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$CARGO_DIR=/cargo$sep--remap-path-prefix=$RUSTUP_DIR=/rustup$sep--remap-path-prefix=$ROOT=/kassigner"
export CARGO_ENCODED_RUSTFLAGS
if [ "$KIND" = watch ]; then
    cargo build --locked -p kassigner-sdk-wasm --no-default-features \
        --release --target "$TARGET"
else
    cargo build --locked -p kassigner-sdk-wasm --release --target "$TARGET"
fi
# Made new: a file of the other package, or of an earlier build, must not
# stay beside this one's.
rm -rf "$PKG"
mkdir -p "$PKG"
wasm-bindgen --target web --out-dir "$PKG" --out-name kassigner_sdk \
    "target/$TARGET/release/kassigner_sdk_wasm.wasm"

code="$PKG/kassigner_sdk_bg.wasm"
before="$(wc -c < "$code")"
# The two features rustc enables for wasm32 by default, which wasm-opt
# does not assume.
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int \
    "$code" -o "$code.opt"
mv "$code.opt" "$code"
echo "wasm-opt $WASM_OPT: $before -> $(wc -c < "$code") bytes"
# A `.wasm` carries no header: its licenses travel beside it.
cp "$HERE/LICENSE" "$HERE/THIRD_PARTY_NOTICES" "$PKG/"
for dir in "$CARGO_DIR" "$RUSTUP_DIR" "$ROOT" "${HOME%/}/"; do
    [ "$dir" = / ] && continue
    for file in "$PKG"/*; do
        if LC_ALL=C grep -q -F -e "$dir" "$file"; then
            echo "$file names a folder of this machine: $dir" >&2
            exit 1
        fi
    done
done
echo "no folder of this machine is named in the package"
if command -v node >/dev/null 2>&1; then
    node "$HERE/check/$CHECK" "$PKG" "$ROOT/spec/vectors/v110"
else
    echo "node not found: the package is not checked (https://nodejs.org)"
fi
ls -l "$PKG"
echo "SHA-256:"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$PKG" && sha256sum -- *)
else
    (cd "$PKG" && shasum -a 256 -- *)
fi
