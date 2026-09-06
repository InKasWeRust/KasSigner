#!/usr/bin/env python3
"""Secure-pad and sign an ESP32-S3 application for Secure Boot v2."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
SIGNATURE_SECTOR_SIZE = 4096


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="unsigned ESP32-S3 application image")
    parser.add_argument("output", type=Path, help="Secure Boot v2 signed application image")
    parser.add_argument(
        "--key",
        type=Path,
        default=None,
        help="RSA-3072 key path; defaults to KASSIGNER_SECURE_BOOT_SIGNING_KEY",
    )
    args = parser.parse_args()

    key = args.key
    if key is None:
        raw = os.environ.get("KASSIGNER_SECURE_BOOT_SIGNING_KEY", "").strip()
        if not raw:
            parser.error("KASSIGNER_SECURE_BOOT_SIGNING_KEY or --key is required")
        key = Path(raw)
    if not args.input.is_file():
        parser.error(f"application image not found: {args.input}")
    if not key.is_file():
        parser.error(f"Secure Boot RSA-3072 key not found: {key}")
    espsecure = shutil.which("espsecure")
    if espsecure is None:
        parser.error("espsecure is required")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kassigner-secure-sign-") as directory:
        padded = Path(directory) / "app-secure-pad-v2.bin"
        run([sys.executable, str(ROOT / "tools/build/firmware/secure_pad_v2.py"), str(args.input), str(padded)])
        run([
            sys.executable,
            str(ROOT / "tools/build/firmware/verify_image_hash.py"),
            str(padded),
            str(ROOT / "apps/signer-firmware/src/firmware_hash.rs"),
        ])
        run([
            espsecure,
            "sign-data",
            "--version", "2",
            "--keyfile", str(key),
            "--skip-padding",
            "--output", str(args.output),
            str(padded),
        ])
        if not args.output.is_file() or args.output.stat().st_size == 0:
            raise SystemExit("espsecure did not produce a signed application image")
        expected_size = padded.stat().st_size + SIGNATURE_SECTOR_SIZE
        if args.output.stat().st_size != expected_size:
            raise SystemExit(
                "Secure Boot v2 signature sector size mismatch: "
                f"padded={padded.stat().st_size} signed={args.output.stat().st_size}"
            )
        run([
            espsecure,
            "verify-signature",
            "--version", "2",
            "--keyfile", str(key),
            "--skip-padding",
            str(args.output),
        ])

    print(f"Secure Boot v2 signed app: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
