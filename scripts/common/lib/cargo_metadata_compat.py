#!/usr/bin/env python3
"""Check Cargo metadata package rust-version requirements against a ceiling."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _version_tuple(text: str) -> tuple[int, int, int]:
    parts = [int(part) for part in text.split(".")]
    return tuple((parts + [0, 0, 0])[:3])  # type: ignore[return-value]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--max-rust", required=True)
    args = parser.parse_args()

    data = json.loads(args.metadata.read_text(encoding="utf-8-sig"))
    packages = data.get("packages")
    if not isinstance(packages, list):
        raise SystemExit("Cargo metadata JSON is missing a packages array")

    limit = _version_tuple(args.max_rust)
    bad: list[tuple[str, str, str]] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        rust_version = package.get("rust_version")
        if rust_version and _version_tuple(str(rust_version)) > limit:
            bad.append(
                (
                    str(package.get("name", "?")),
                    str(package.get("version", "?")),
                    str(rust_version),
                )
            )

    for name, version, rust_version in sorted(bad):
        print(f"{name} {version} requires Rust {rust_version}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
