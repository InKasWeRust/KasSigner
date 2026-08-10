#!/usr/bin/env python3
# KasSigner - Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0-only
#
# Extract the second-stage bootloader from a merged full-flash image.
#
# Why this exists: `espflash save-image --merge` writes bootloader, partition
# table and app into one file. Secure Boot V2 signs each image separately, so
# a merged file cannot be signed as a unit. The bootloader has to come out on
# its own, at its exact length, before espsecure can sign it and esptool can
# write it to 0x0.
#
# Trailing 0xFF padding matters. espsecure pads its input to a 4096-byte
# multiple and appends a 4096-byte signature sector. Feeding it the whole
# 0x0..0x8000 region would produce a 36 KiB result that runs past the
# partition table at 0x8000. This walks the ESP image header and segment
# table to find where the bootloader actually ends.
#
# Usage:
#   python3 tools/extract_bootloader.py kassigner-m5stack-full.bin
#   python3 tools/extract_bootloader.py kassigner-m5stack-full.bin -o boot.bin

import argparse
import hashlib
import struct
import sys

ESP_IMAGE_MAGIC = 0xE9
HEADER_LEN = 24
SEGMENT_HEADER_LEN = 8
PARTITION_TABLE_OFFSET = 0x8000
SIGNATURE_SECTOR_LEN = 4096
CHIP_IDS = {0: "ESP32", 2: "ESP32-S2", 9: "ESP32-S3", 5: "ESP32-C3"}


def parse_image_length(blob, base=0):
    """Return (length, info) for the ESP application image starting at base."""
    if len(blob) < base + HEADER_LEN:
        raise ValueError("file too short to contain an image header")

    magic = blob[base]
    if magic != ESP_IMAGE_MAGIC:
        raise ValueError(
            "no ESP image magic at offset 0x%X (found 0x%02X, expected 0xE9)"
            % (base, magic)
        )

    segment_count = blob[base + 1]
    if segment_count == 0 or segment_count > 16:
        raise ValueError("implausible segment count %d" % segment_count)

    entry_addr = struct.unpack_from("<I", blob, base + 4)[0]
    chip_id = struct.unpack_from("<H", blob, base + 12)[0]
    hash_appended = blob[base + 23] == 1

    pos = base + HEADER_LEN
    segments = []
    for i in range(segment_count):
        if pos + SEGMENT_HEADER_LEN > len(blob):
            raise ValueError("segment %d header runs past end of file" % i)
        load_addr, data_len = struct.unpack_from("<II", blob, pos)
        pos += SEGMENT_HEADER_LEN
        if data_len > len(blob):
            raise ValueError("segment %d length 0x%X is implausible" % (i, data_len))
        if pos + data_len > len(blob):
            raise ValueError("segment %d data runs past end of file" % i)
        segments.append((load_addr, data_len))
        pos += data_len

    # One checksum byte, placed so the image length is a multiple of 16.
    pad = 15 - ((pos - base) % 16)
    pos += pad + 1

    if hash_appended:
        pos += 32

    if pos > len(blob):
        raise ValueError("image tail runs past end of file")

    info = {
        "entry_addr": entry_addr,
        "chip_id": chip_id,
        "chip": CHIP_IDS.get(chip_id, "unknown (0x%X)" % chip_id),
        "segments": segments,
        "hash_appended": hash_appended,
    }
    return pos - base, info


def main():
    ap = argparse.ArgumentParser(
        description="Extract the second-stage bootloader from a merged full-flash image"
    )
    ap.add_argument("image", help="merged image, e.g. kassigner-m5stack-full.bin")
    ap.add_argument(
        "-o",
        "--output",
        default=None,
        help="output path (default: <image basename>-bootloader.bin)",
    )
    ap.add_argument(
        "--offset",
        type=lambda s: int(s, 0),
        default=0x0,
        help="bootloader offset within the merged image (ESP32-S3 default: 0x0)",
    )
    args = ap.parse_args()

    with open(args.image, "rb") as f:
        blob = f.read()

    try:
        length, info = parse_image_length(blob, args.offset)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 1

    out = args.output
    if out is None:
        base = args.image
        for suffix in ("-full.bin", ".bin"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        out = base + "-bootloader.bin"

    boot = blob[args.offset : args.offset + length]

    print("Source      : %s (%d bytes)" % (args.image, len(blob)))
    print("Offset      : 0x%X" % args.offset)
    print("Chip ID     : %s" % info["chip"])
    print("Entry point : 0x%08X" % info["entry_addr"])
    print("Segments    : %d" % len(info["segments"]))
    for i, (addr, dlen) in enumerate(info["segments"]):
        print("  [%d] load 0x%08X  len %6d" % (i, addr, dlen))
    print("SHA appended: %s" % ("yes" if info["hash_appended"] else "no"))
    print("Length      : %d bytes (0x%X)" % (length, length))
    print("SHA-256     : %s" % hashlib.sha256(boot).hexdigest())

    if info["chip_id"] != 9:
        print(
            "\nWARNING: chip ID is not ESP32-S3. Wrong file, or wrong offset.",
            file=sys.stderr,
        )

    # A signed bootloader is padded to a 4096-byte multiple, then gains a
    # 4096-byte signature sector. It has to stay clear of the partition table.
    padded = ((length + SIGNATURE_SECTOR_LEN - 1) // SIGNATURE_SECTOR_LEN) * SIGNATURE_SECTOR_LEN
    signed = padded + SIGNATURE_SECTOR_LEN
    print("Signed size : %d bytes (0x%X) after padding + signature sector" % (signed, signed))

    if args.offset + signed > PARTITION_TABLE_OFFSET:
        print(
            "\nERROR: signed bootloader would reach 0x%X and overwrite the "
            "partition table at 0x8000. Do not flash this." % (args.offset + signed),
            file=sys.stderr,
        )
        return 2

    print(
        "Headroom    : %d bytes below the partition table at 0x8000"
        % (PARTITION_TABLE_OFFSET - (args.offset + signed))
    )

    with open(out, "wb") as f:
        f.write(boot)
    print("\nWrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
