#!/bin/sh
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0-or-later
#
# The SDK's two archives, as someone who downloads them has them: unpacked
# into an empty folder and used from there. `release/sdk.sh` packs them and
# lists them; every other check of the SDK runs on the folders the build
# leaves, so a file the packing left out, put in the wrong place or took
# from an older build would otherwise be found by the first person to
# unpack a release.
#
#   sh release/sdk-check.sh <folder holding the two archives> [web|bindings]
#
# From the repository root, after `release/sdk.sh <that folder>`. With no
# second word, both archives.
#
#   web        `kassigner-sdk-<version>-web.tar.gz`: holds exactly the two
#              browser packages' files, and each package, loaded from the
#              unpacked folder, runs its crate's own check over the vectors
#              (`check/check.mjs`, `check/check-watch.mjs`). Needs Node.js.
#   bindings   `kassigner-sdk-<version>-bindings.tar.gz`: holds exactly the
#              bindings' files, and each binding, taken from the unpacked
#              folder, runs its crate's own check over the vectors against
#              this machine's library. The archive holds no library: an app
#              builds its own, and so does this, with
#              `crates/kassigner-sdk-ffi/build.sh`, run first. Python always;
#              Kotlin with `kotlinc`, `java` and `JNA_JAR`; Swift on a Mac
#              with `swiftc`: what is missing is said and skipped, as
#              `build.sh` does, and CI asks for the lines it must see.
#
# "Exactly" both ways: a file missing fails, and so does one that is there
# and not named here, so adding a file to an archive means naming it here.

set -eu

USAGE="usage: sh release/sdk-check.sh <folder> [web|bindings]"
# The folder first, said plainly: `cd` on its own would stop the script
# with only the shell's words.
if [ "$#" -eq 0 ]; then
    echo "$USAGE" >&2
    exit 2
fi
if [ ! -d "$1" ]; then
    echo "$1 is not a folder: pack the archives into it first, sh release/sdk.sh $1" >&2
    echo "$USAGE" >&2
    exit 2
fi
DIR="$(cd "$1" && pwd)"
WHAT="${2:-both}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="kassigner-sdk-$(sh "$ROOT/release/version.sh")"
WASM="$ROOT/crates/kassigner-sdk-wasm"
FFI="$ROOT/crates/kassigner-sdk-ffi"
VECTORS="$ROOT/spec/vectors/v110"

case "$WHAT" in
both | web | bindings) ;;
*)
    echo "$USAGE" >&2
    exit 2
    ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Unpack `$1.tar.gz` into an empty folder and hold it to its list: one
# folder of the archive's own name, the files named on standard input and
# no other, none of them empty.
unpacked() {
    archive="$DIR/$1.tar.gz"
    if [ ! -f "$archive" ]; then
        echo "$archive is not there: sh release/sdk.sh $DIR" >&2
        exit 1
    fi
    mkdir "$WORK/$1.d"
    tar -xzf "$archive" -C "$WORK/$1.d"
    if [ "$(ls -A "$WORK/$1.d")" != "$1" ]; then
        echo "$1.tar.gz does not unpack into one folder named $1:" >&2
        ls -A "$WORK/$1.d" >&2
        exit 1
    fi
    sort > "$WORK/$1.want"
    (cd "$WORK/$1.d/$1" && find . -type f | sed 's|^\./||' | sort) > "$WORK/$1.have"
    if ! diff "$WORK/$1.want" "$WORK/$1.have" > "$WORK/$1.diff"; then
        echo "$1.tar.gz does not hold what it should (< missing, > not named in release/sdk-check.sh):" >&2
        cat "$WORK/$1.diff" >&2
        exit 1
    fi
    while IFS= read -r file; do
        if [ ! -s "$WORK/$1.d/$1/$file" ]; then
            echo "$1.tar.gz: $file is empty" >&2
            exit 1
        fi
    done < "$WORK/$1.want"
    echo "$1.tar.gz: $(wc -l < "$WORK/$1.want" | tr -d ' ') files, as named"
}

if [ "$WHAT" != bindings ]; then
    echo "== the browser packages, from the archive"
    if ! command -v node >/dev/null 2>&1; then
        echo "node not found: the browser packages cannot be checked (https://nodejs.org)" >&2
        exit 1
    fi
    unpacked "$NAME-web" <<LIST
pkg/LICENSE
pkg/THIRD_PARTY_NOTICES
pkg/kassigner_sdk.d.ts
pkg/kassigner_sdk.js
pkg/kassigner_sdk_bg.wasm
pkg/kassigner_sdk_bg.wasm.d.ts
pkg-watch/LICENSE
pkg-watch/THIRD_PARTY_NOTICES
pkg-watch/kassigner_sdk.d.ts
pkg-watch/kassigner_sdk.js
pkg-watch/kassigner_sdk_bg.wasm
pkg-watch/kassigner_sdk_bg.wasm.d.ts
LIST
    web="$WORK/$NAME-web.d/$NAME-web"
    node "$WASM/check/check.mjs" "$web/pkg" "$VECTORS"
    node "$WASM/check/check-watch.mjs" "$web/pkg-watch" "$VECTORS"
    echo "the archive's browser packages: checked"
fi

if [ "$WHAT" != web ]; then
    echo "== the bindings, from the archive"
    unpacked "$NAME-bindings" <<LIST
KasSignerSdk.swift
KasSignerSdkFFI.h
KasSignerSdkFFI.modulemap
LICENSE
THIRD_PARTY_NOTICES
kassigner_sdk.py
org/kassigner/sdk/kassigner_sdk.kt
LIST
    bind="$WORK/$NAME-bindings.d/$NAME-bindings"
    # This machine's library, as an app's own build of it: the dynamic one
    # beside the Python binding, where the binding looks for it.
    lib=
    for dyn in "$FFI/out/libkassigner_sdk_ffi.so" "$FFI/out/libkassigner_sdk_ffi.dylib"; do
        [ -f "$dyn" ] && lib="$dyn"
    done
    if [ -z "$lib" ] || [ ! -f "$FFI/out/libkassigner_sdk_ffi.a" ]; then
        echo "no library in $FFI/out: sh crates/kassigner-sdk-ffi/build.sh" >&2
        exit 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 not found: the Python binding cannot be checked" >&2
        exit 1
    fi
    use="$WORK/use"
    mkdir "$use"
    cp "$bind/kassigner_sdk.py" "$use/"
    ln -s "$lib" "$use/"
    python3 -I -B "$FFI/check/check.py" "$use" "$VECTORS/sdk"
    echo "the archive's Python binding: checked"

    if [ "$(uname)" = Darwin ] && command -v swiftc >/dev/null 2>&1; then
        # As `build.sh` compiles it: one module, the static library alone
        # in its folder.
        mkdir "$WORK/swift"
        ln -s "$FFI/out/libkassigner_sdk_ffi.a" "$WORK/swift/"
        swiftc -parse-as-library -module-name KasSignerSdkCheck \
            -Xcc -fmodule-map-file="$bind/KasSignerSdkFFI.modulemap" \
            "$bind/KasSignerSdk.swift" "$FFI/check/check.swift" \
            -L "$WORK/swift" -lkassigner_sdk_ffi \
            -o "$WORK/swift/check-swift"
        "$WORK/swift/check-swift" "$VECTORS/sdk"
        echo "the archive's Swift binding: checked"
    else
        echo "not a Mac with swiftc: the archive's Swift binding is not compiled"
    fi

    # A `java` that runs, not one that is only found: a Mac with no Java still
    # has `/usr/bin/java`, a placeholder that says to install one and fails.
    if command -v kotlinc >/dev/null 2>&1 && java -version >/dev/null 2>&1 && [ -f "${JNA_JAR:-}" ]; then
        mkdir "$WORK/kotlin"
        kotlinc -nowarn -cp "$JNA_JAR" -include-runtime \
            "$bind/org/kassigner/sdk/kassigner_sdk.kt" "$FFI/check/check.kt" \
            -d "$WORK/kotlin/check.jar"
        # JNA loads the library, which a newer Java warns of and a later one
        # will refuse unless allowed. An older Java refuses the flag itself,
        # so it is given only to a Java that takes it.
        native=""
        if java --enable-native-access=ALL-UNNAMED -version >/dev/null 2>&1; then
            native="--enable-native-access=ALL-UNNAMED"
        fi
        java $native -cp "$WORK/kotlin/check.jar:$JNA_JAR" -Djna.library.path="$FFI/out" \
            CheckKt "$VECTORS/sdk"
        echo "the archive's Kotlin binding: checked"
    else
        echo "kotlinc, a java that runs, or JNA_JAR not found: the archive's Kotlin binding is not compiled"
    fi
fi
