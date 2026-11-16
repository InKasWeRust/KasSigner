#!/bin/sh
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0-or-later
#
# The SDK half of the release build, run in the container by
# `release/Dockerfile`: the browser package, full and watch-only, and the
# Swift, Kotlin and Python bindings, each built by its crate's own
# `build.sh`, then packed into two archives.
#
#   sh release/sdk.sh <output folder>
#
# From the repository root. Each archive's name starts with
# `kassigner-sdk-<version>-`, the version `release/version.sh` reads from
# the root `Cargo.toml`, and unpacks into one folder of its own name:
#
#   kassigner-sdk-<version>-web.tar.gz
#       pkg/          the full browser package: `kassigner_sdk.js`,
#                     `kassigner_sdk_bg.wasm`, the TypeScript declarations,
#                     `LICENSE` (MPL-2.0) and `THIRD_PARTY_NOTICES`
#       pkg-watch/    the watch-only one, the same files: the crate without
#                     its `transactions` feature
#   kassigner-sdk-<version>-bindings.tar.gz
#       KasSignerSdk.swift, KasSignerSdkFFI.h, KasSignerSdkFFI.modulemap
#                     the Swift binding
#       org/kassigner/sdk/kassigner_sdk.kt
#                     the Kotlin binding
#       kassigner_sdk.py
#                     the Python binding
#       LICENSE, THIRD_PARTY_NOTICES
#                     MPL-2.0, and the licenses of what the library is
#                     compiled with
#
# The bindings archive holds no library. A library is one target's, and an
# app builds its own from this source at the release's tag, as
# `crates/kassigner-sdk-ffi/build.sh` says for each platform; the bindings
# are the same for every target.
#
# The container has no Node.js, Python, Swift or Kotlin, so the packages
# are built here and not run: each `build.sh` says so and goes on. CI runs
# all four bindings over the vectors on every push (`crates.yml`).
#
# Nothing may depend on the time, the folder or the user. Both `build.sh`
# write fixed names for the folders the compiler would otherwise record;
# the archives are packed with their entries sorted, owned by nobody, with
# fixed permissions and `SOURCE_DATE_EPOCH` as every entry's time, and
# compressed without a name or a time in the header. GNU tar is needed for
# that (`--sort`), which the container has and a Mac does not.

set -eu

OUT="$1"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="kassigner-sdk-$(sh "$ROOT/release/version.sh")"
WASM="$ROOT/crates/kassigner-sdk-wasm"
FFI="$ROOT/crates/kassigner-sdk-ffi"

: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set, or the archives carry the time they were packed}"

sh "$ROOT/firmware/kassigner-hal-esp32p4/esp-hal-fork/fork.sh"

echo "== the browser package"
sh "$WASM/build.sh"
echo "== the watch-only browser package"
sh "$WASM/build.sh" watch
echo "== the bindings"
sh "$FFI/build.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Each browser package whole: its `build.sh` makes the folder new, so it
# holds that build's files and no other. One of these missing stops the
# build.
web="$WORK/$NAME-web"
mkdir -p "$web"
for pkg in pkg pkg-watch; do
    for file in kassigner_sdk.js kassigner_sdk_bg.wasm kassigner_sdk.d.ts \
        LICENSE THIRD_PARTY_NOTICES; do
        test -f "$WASM/$pkg/$file"
    done
    cp -R "$WASM/$pkg" "$web/$pkg"
done

# The bindings, by name: `out/` also holds the library and the checks' own
# files, which stay behind.
bind="$WORK/$NAME-bindings"
mkdir -p "$bind/org/kassigner/sdk"
for file in KasSignerSdk.swift KasSignerSdkFFI.h KasSignerSdkFFI.modulemap \
    kassigner_sdk.py org/kassigner/sdk/kassigner_sdk.kt LICENSE \
    THIRD_PARTY_NOTICES; do
    cp "$FFI/out/$file" "$bind/$file"
done

# One folder into one archive, the same bytes for the same files.
pack() {
    find "$WORK/$1" -type d -exec chmod 755 {} +
    find "$WORK/$1" -type f -exec chmod 644 {} +
    tar --sort=name --format=ustar --owner=0 --group=0 --numeric-owner \
        --mtime="@$SOURCE_DATE_EPOCH" -C "$WORK" -cf - "$1" |
        gzip -n -9 > "$OUT/$1.tar.gz"
    chmod 644 "$OUT/$1.tar.gz"
    tar -tzf "$OUT/$1.tar.gz"
}

pack "$NAME-web"
pack "$NAME-bindings"
echo "SHA-256:"
(cd "$OUT" && sha256sum -- "$NAME-web.tar.gz" "$NAME-bindings.tar.gz")
