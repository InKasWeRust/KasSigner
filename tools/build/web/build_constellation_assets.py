#!/usr/bin/env python3
"""Build Constellation's stable browser assets from ordered source modules."""

from __future__ import annotations

from pathlib import Path
import sys

try:
    from .ordered_manifest import OrderedManifest, run_manifest_builder
except ImportError:
    from ordered_manifest import OrderedManifest, run_manifest_builder

ROOT = Path(__file__).resolve().parents[3]
CONSTELLATION = ROOT / "apps/kassee-web/web/constellation"
ASSETS = (
    OrderedManifest(
        manifest=CONSTELLATION / "css/source/manifest.txt",
        source_root=CONSTELLATION / "css/source",
        output=CONSTELLATION / "css/constellation.css",
        suffix=".css",
        label="Constellation CSS",
    ),
    OrderedManifest(
        manifest=CONSTELLATION / "js/source/manifest.txt",
        source_root=CONSTELLATION / "js/source",
        output=CONSTELLATION / "js/main.js",
        suffix=".js",
        label="Constellation JavaScript",
    ),
)


def main() -> int:
    return run_manifest_builder(
        ASSETS,
        ROOT,
        check_message="PASS: Constellation assets match their ordered source modules",
    )


if __name__ == "__main__":
    sys.exit(main())
