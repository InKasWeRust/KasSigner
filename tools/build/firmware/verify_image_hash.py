#!/usr/bin/env python3
"""Independently verify the final ESP app image against firmware_hash.rs."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys

ESP_IMAGE_MAGIC = 0xE9
ESP_IMAGE_HEADER_SIZE = 24
SEGMENT_HEADER_SIZE = 8
IRAM_FLASH_BASE = 0x4200_0000
IRAM_FLASH_END = 0x4400_0000


def _generated_metadata(path: Path) -> tuple[bytes, int, int]:
    source = path.read_text(encoding="utf-8")
    match = re.search(
        r"pub static EXPECTED_FIRMWARE_HASH: \[u8; 32\] = \[\s*(.*?)\s*\];",
        source,
        re.S,
    )
    if match is None:
        raise ValueError("EXPECTED_FIRMWARE_HASH declaration missing")
    values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
    residual = re.sub(r"0x[0-9a-fA-F]{2}", "", match.group(1))
    residual = re.sub(r"[\s,]", "", residual)
    if len(values) != 32 or residual:
        raise ValueError("EXPECTED_FIRMWARE_HASH is not the canonical 32-byte array")
    size_match = re.search(r"pub static FIRMWARE_SIZE: usize = (\d+);", source)
    addr_match = re.search(r"pub static FIRMWARE_IADDR: u32 = 0x([0-9A-Fa-f]{8});", source)
    if size_match is None or addr_match is None:
        raise ValueError("generated firmware size/address metadata is missing")
    return bytes.fromhex("".join(values)), int(size_match.group(1)), int(addr_match.group(1), 16)


def _image_code_segment(path: Path) -> tuple[bytes, int, int]:
    data = path.read_bytes()
    if len(data) < ESP_IMAGE_HEADER_SIZE or data[0] != ESP_IMAGE_MAGIC:
        raise ValueError("final image is not an ESP application image")
    count = data[1]
    offset = ESP_IMAGE_HEADER_SIZE
    code_segments: list[tuple[bytes, int, int]] = []
    for index in range(count):
        if offset + SEGMENT_HEADER_SIZE > len(data):
            raise ValueError(f"segment {index} header exceeds image length")
        load_addr = int.from_bytes(data[offset:offset + 4], "little")
        size = int.from_bytes(data[offset + 4:offset + 8], "little")
        data_offset = offset + SEGMENT_HEADER_SIZE
        end = data_offset + size
        if size == 0 or end > len(data):
            raise ValueError(f"segment {index} has invalid size")
        if IRAM_FLASH_BASE <= load_addr < IRAM_FLASH_END:
            code_segments.append((data[data_offset:end], size, load_addr))
        offset = end
    if len(code_segments) != 1:
        raise ValueError(f"expected exactly one flash-mapped code segment; found {len(code_segments)}")
    return code_segments[0]


def verify(image: Path, generated: Path) -> str:
    expected_hash, expected_size, expected_addr = _generated_metadata(generated)
    segment, actual_size, actual_addr = _image_code_segment(image)
    actual_hash = hashlib.sha256(segment).digest()
    if actual_addr != expected_addr:
        raise ValueError(
            f"code-segment address mismatch: image=0x{actual_addr:08X}, generated=0x{expected_addr:08X}"
        )
    if actual_size != expected_size:
        raise ValueError(
            f"code-segment size mismatch: image={actual_size}, generated={expected_size}"
        )
    if actual_hash != expected_hash:
        raise ValueError(
            f"code-segment SHA-256 mismatch: image={actual_hash.hex()}, generated={expected_hash.hex()}"
        )
    return actual_hash.hex()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("generated_hash_source", type=Path)
    args = parser.parse_args()
    try:
        digest = verify(args.image, args.generated_hash_source)
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"verified-final-codehash: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
