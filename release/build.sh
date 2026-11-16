#!/bin/sh
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0-or-later
#
# The firmware half of the release build, run in the container by
# `release/Dockerfile`: the P4's esp-hal fork, then each board's firmware
# and its two images.
#
#   sh release/build.sh <output folder>
#
# From the repository root. Every image's name starts with
# `kassigner-<version>-`, the version `release/version.sh` reads from the
# root `Cargo.toml`, so two releases' files never share a name. Per board:
#
#   kassigner-<version>-<board>.bin
#                               the app image, flashed at 0x10000; its
#                               SHA-256 is the hash the board's verification
#                               screen shows (`kassigner_hal::image`)
#   kassigner-<version>-<board>-full.bin
#                               espflash's plain bootloader, the partition
#                               table and the app, for an unprovisioned unit
#
# and once, `kassigner-<version>-partition-table.bin` from
# `release/partitions.csv`, `kassigner-<version>-partition-table-p4-secure.bin`
# from `release/partitions-p4-secure.csv` for a P4 provisioned with the
# Secure Boot bootloader, `COPYING`, the firmware's license (GPL-3.0), and
# `THIRD_PARTY_NOTICES`, the firmware's, as `release/notices.sh` wrote it.
#
# Each board is built with `--features <board>` only: one firmware for every
# unit. A blank unit says it is not provisioned; one provisioned by its
# owner, running it signed with the owner's key, says Verified OK.
#
# Nothing may depend on the time or the folder: the Dockerfile pins the
# folder and `SOURCE_DATE_EPOCH`, which `esp-bootloader-esp-idf` writes into
# the app descriptor as the build date.

set -eu

OUT="$1"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TABLE="$ROOT/release/partitions.csv"
NAME="kassigner-$(sh "$ROOT/release/version.sh")"

: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set, or the build date makes every build differ}"

sh "$ROOT/firmware/kassigner-hal-esp32p4/esp-hal-fork/fork.sh"

# One board: build it and write its two images before the next board is
# built, since the two S3 boards build to the same path.
board() {
    name="$1"
    target="$2"
    chip="$3"
    echo "== $name"
    (cd "$ROOT/firmware/kassigner-signer" &&
        cargo build --locked --release --features "$name" \
            --target "$target" -Z build-std=core,alloc)
    elf="$ROOT/target/$target/release/kassigner-signer"
    espflash save-image -S --chip "$chip" --flash-size 16mb \
        "$elf" "$OUT/$NAME-$name.bin"
    espflash save-image -S --chip "$chip" --flash-size 16mb \
        --merge --skip-padding --partition-table "$TABLE" \
        "$elf" "$OUT/$NAME-$name-full.bin"
}

board m5stack xtensa-esp32s3-none-elf esp32s3
board waveshare xtensa-esp32s3-none-elf esp32s3
board p4 riscv32imafc-unknown-none-elf esp32p4

espflash partition-table -S --to-binary \
    -o "$OUT/$NAME-partition-table.bin" "$TABLE"
espflash partition-table -S --to-binary \
    -o "$OUT/$NAME-partition-table-p4-secure.bin" \
    "$ROOT/release/partitions-p4-secure.csv"
cp "$ROOT/COPYING" "$ROOT/firmware/kassigner-signer/THIRD_PARTY_NOTICES" "$OUT/"
