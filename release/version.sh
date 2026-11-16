#!/bin/sh
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0-or-later
#
# The release's version, as the release's file names carry it: the root
# `Cargo.toml`'s `[workspace.package]` version, which every crate takes, so
# it is never typed twice.
#
#   sh release/version.sh [<Cargo.toml>]
#
# With no argument, the root `Cargo.toml` beside this folder. `build.sh`
# and the Dockerfile's bootloader stage both ask it.

set -eu

TOML="${1:-$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml}"

version="$(awk '
    /^\[workspace\.package\]/ { inside = 1; next }
    /^\[/ { inside = 0 }
    inside && /^version = "/ {
        sub(/^version = "/, ""); sub(/".*$/, ""); print; exit
    }
' "$TOML")"

if [ -z "$version" ]; then
    echo "no version in $TOML's [workspace.package]" >&2
    exit 1
fi
printf '%s\n' "$version"
