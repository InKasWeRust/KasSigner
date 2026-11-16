#!/bin/sh
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Builds the SDK as a native library with its Swift, Kotlin and Python
# bindings (release profile, this crate's `uniffi-bindgen`) into `out/`:
#
#   libkassigner_sdk_ffi.{a,so|dylib}   the library, static and dynamic
#   KasSignerSdk.swift, KasSignerSdkFFI.h, KasSignerSdkFFI.modulemap
#                                        the Swift binding (iOS, macOS)
#   org/kassigner/sdk/kassigner_sdk.kt   the Kotlin binding (Android, JNA)
#   kassigner_sdk.py                     the Python binding (ctypes)
#   LICENSE, THIRD_PARTY_NOTICES         the licenses an app shipping the
#                                        library ships with it
#
#   sh crates/kassigner-sdk-ffi/build.sh [<target triple>]
#
# With no target the library is the host's and the bindings are checked:
# with `python3` there `check/check.py`, and on a Mac with `swiftc`
# (`xcode-select --install`) `check/check.swift`. A Swift that refuses its own SDK ("this SDK is not
# supported by the compiler") has mismatched Command Line Tools: remove
# `/Library/Developer/CommandLineTools` and reinstall them. With `kotlinc`
# and `java` there and `JNA_JAR` naming JNA's jar (5.14.0 was used),
# `check/check.kt` too, on a JVM (`JNA_JAR=<path>/jna.jar sh build.sh`).
# With a target (added with `rustup target add`) the output goes to
# `out/<triple>/`, unchecked; the bindings are the same for every target.
#
# Apple: build for `aarch64-apple-ios`, `aarch64-apple-ios-sim` and
# `aarch64-apple-darwin`, then:
#   xcodebuild -create-xcframework \
#     -library out/aarch64-apple-ios/libkassigner_sdk_ffi.a -headers out/include \
#     -library out/aarch64-apple-ios-sim/libkassigner_sdk_ffi.a -headers out/include \
#     -library out/aarch64-apple-darwin/libkassigner_sdk_ffi.a -headers out/include \
#     -output out/KasSignerSdkFFI.xcframework
# with the header and the modulemap, renamed `module.modulemap`, in
# `out/include/`; `KasSignerSdk.swift` goes into the app.
# Android: `cargo ndk -t arm64-v8a -t x86_64 build --release` puts each
# ABI's `.so` under `jniLibs/`; the Kotlin file goes into the app, with JNA.
#
# Built `--locked`; the SHA-256 of each output but the Swift and Kotlin
# checks' own files is printed last, to compare builds of one commit.
#
# The output names no folder of the machine that built it: the compiler
# is told to write `/cargo`, `/rustup` and `/kassigner` for cargo's home,
# rustup's and this tree, and the build fails if one of them, or the home
# folder, is still in a file of `out/`. The flags go through
# `CARGO_ENCODED_RUSTFLAGS`, which a path with spaces survives; a
# `RUSTFLAGS` of the caller's is not used. `-C strip=debuginfo` is there
# for the dynamic library: the workspace's release profile keeps the
# linker's debug map (`strip = false`, for the device image), and on a Mac
# that map lists every object file linked, by its full path.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TARGET="${1:-}"
OUT="$HERE/out${TARGET:+/$TARGET}"

cd "$ROOT"
CARGO_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
sep="$(printf '\037')"
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$CARGO_DIR=/cargo$sep--remap-path-prefix=$RUSTUP_DIR=/rustup$sep--remap-path-prefix=$ROOT=/kassigner$sep-C${sep}strip=debuginfo"
export CARGO_ENCODED_RUSTFLAGS
if [ -n "$TARGET" ]; then
    cargo build --locked -p kassigner-sdk-ffi --release --target "$TARGET"
    lib="target/$TARGET/release"
else
    cargo build --locked -p kassigner-sdk-ffi --release
    lib="target/release"
fi

mkdir -p "$OUT"
cp "$lib"/libkassigner_sdk_ffi.a "$OUT"/
for dyn in "$lib"/libkassigner_sdk_ffi.so "$lib"/libkassigner_sdk_ffi.dylib; do
    [ -f "$dyn" ] && cp "$dyn" "$OUT"/
done

# The bindings come from the library's own metadata, so they match it: the
# static library's, which every build makes (copied above).
built="$lib"/libkassigner_sdk_ffi.a
cargo run --locked -q -p kassigner-sdk-ffi --release --bin uniffi-bindgen -- generate \
    --library "$built" --language swift --language kotlin --language python \
    --config "$HERE/uniffi.toml" --out-dir "$OUT" --no-format

cp "$HERE/LICENSE" "$HERE/THIRD_PARTY_NOTICES" "$OUT"/

if [ -z "$TARGET" ]; then
    # `-B`: Python leaves no compiled copy of the binding in `out/`, and
    # one an earlier build left goes.
    rm -rf "$OUT/__pycache__"
    if command -v python3 >/dev/null 2>&1; then
        python3 -I -B "$HERE/check/check.py" "$OUT" "$ROOT/spec/vectors/v110/sdk"
    else
        echo "python3 not found: the Python binding is not checked"
    fi
    if [ "$(uname)" = Darwin ] && command -v swiftc >/dev/null 2>&1; then
        # One module, as an app compiles the binding; the static library
        # alone in its folder, so the linker cannot take the dynamic one.
        mkdir -p "$OUT/swift-check"
        ln -sf ../libkassigner_sdk_ffi.a "$OUT/swift-check/libkassigner_sdk_ffi.a"
        swiftc -parse-as-library -module-name KasSignerSdkCheck \
            -Xcc -fmodule-map-file="$OUT/KasSignerSdkFFI.modulemap" \
            "$OUT/KasSignerSdk.swift" "$HERE/check/check.swift" \
            -L "$OUT/swift-check" -lkassigner_sdk_ffi \
            -o "$OUT/swift-check/check-swift"
        "$OUT/swift-check/check-swift" "$ROOT/spec/vectors/v110/sdk"
    elif [ "$(uname)" = Darwin ]; then
        echo "swiftc not found: the Swift binding is not compiled (xcode-select --install)"
    fi
    # The Kotlin binding on a JVM, as an Android app loads it through JNA:
    # one jar of the binding and the check with Kotlin's runtime in it, the
    # dynamic library found beside the bindings.
    if command -v kotlinc >/dev/null 2>&1 && command -v java >/dev/null 2>&1 && [ -f "${JNA_JAR:-}" ]; then
        mkdir -p "$OUT/kotlin-check"
        kotlinc -nowarn -cp "$JNA_JAR" -include-runtime \
            "$OUT/org/kassigner/sdk/kassigner_sdk.kt" "$HERE/check/check.kt" \
            -d "$OUT/kotlin-check/check.jar"
        java -cp "$OUT/kotlin-check/check.jar:$JNA_JAR" -Djna.library.path="$OUT" \
            CheckKt "$ROOT/spec/vectors/v110/sdk"
    else
        echo "kotlinc, java or JNA_JAR not found: the Kotlin binding is not compiled (JNA_JAR=<path>/jna.jar)"
    fi
fi
# Finder's `.DS_Store` is no part of the build: it is neither checked nor
# listed.
#
# One path is not this machine's and is let through: Rust's own standard
# library, as rustup installs it, carries the folder of the machine the Rust
# project built it on, `/Users/runner/work/rust/rust/`. Where this build's
# home folder is also `/Users/runner`, as on GitHub's Macs, that path would
# otherwise read as a folder of this machine.
RUST_BUILT_IN=/Users/runner/work/rust/rust/
for dir in "$CARGO_DIR" "$RUSTUP_DIR" "$ROOT" "${HOME%/}/"; do
    [ "$dir" = / ] && continue
    found="$(cd "$OUT" && find . -type f -not -path "./swift-check/*" -not -path "./kotlin-check/*" -not -name .DS_Store -exec env LC_ALL=C grep -l -F -e "$dir" {} + || true)"
    [ -n "$found" ] || continue
    named="$(echo "$found" | while IFS= read -r file; do
        (cd "$OUT" && LC_ALL=C tr -c '[:print:]' '\n' < "$file" |
            grep -F -e "$dir" | grep -v -F -e "$RUST_BUILT_IN" | sort -u | head -5 |
            sed "s|^|$file: |") || true
    done)"
    if [ -n "$named" ]; then
        echo "these name a folder of this machine, $dir:" >&2
        echo "$named" >&2
        exit 1
    fi
done
echo "no folder of this machine is named in the output"
ls -l "$OUT"
echo "SHA-256:"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT" && find . -type f -not -path "./swift-check/*" -not -path "./kotlin-check/*" -not -name .DS_Store | sort | xargs sha256sum)
else
    (cd "$OUT" && find . -type f -not -path "./swift-check/*" -not -path "./kotlin-check/*" -not -name .DS_Store | sort | xargs shasum -a 256)
fi
