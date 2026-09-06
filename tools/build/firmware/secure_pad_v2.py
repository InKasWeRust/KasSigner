#!/usr/bin/env python3
"""Rewrite an ESP32-S3 application image with canonical Secure Boot v2 padding.

ESP32-S3 Secure Boot v2 signs an application only after it has been padded to
the flash MMU page boundary.  This uses the pinned esptool image serializer so
the padding is represented as a real ESP image segment, not raw trailing bytes.
"""
from __future__ import annotations

import argparse
import importlib
from pathlib import Path

EXPECTED_ESPTOOL_VERSION = "5.3.1"
MMU_PAGE_SIZE = 64 * 1024


def secure_pad(input_path: Path, output_path: Path) -> None:
    try:
        esptool = importlib.import_module("esptool")
        bin_image = importlib.import_module("esptool.bin_image")
    except ModuleNotFoundError as error:
        raise SystemExit(
            "esptool Python package is required; install the version pinned in "
            "apps/signer-firmware/release-policy.env"
        ) from error

    version = getattr(esptool, "__version__", "")
    if version != EXPECTED_ESPTOOL_VERSION:
        raise SystemExit(
            f"esptool {EXPECTED_ESPTOOL_VERSION} is required for deterministic Secure Boot padding; got {version or 'unknown'}"
        )

    data = input_path.read_bytes()
    image = bin_image.LoadFirmwareImage("esp32s3", data)
    if not getattr(image, "append_digest", False):
        raise SystemExit("ESP32-S3 application image must contain its normal SHA-256 image digest")
    image.secure_pad = "2"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(str(output_path))

    padded = output_path.read_bytes()
    if not padded or len(padded) % MMU_PAGE_SIZE != 0:
        raise SystemExit(
            f"Secure Boot v2 padded image must end on a 64 KiB boundary; got {len(padded)} bytes"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not args.input.is_file():
        raise SystemExit(f"application image not found: {args.input}")
    secure_pad(args.input, args.output)
    print(f"Secure Boot v2 padded image: {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
