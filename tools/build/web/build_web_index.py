#!/usr/bin/env python3
"""Build KasSee's stable web/index.html from ordered source fragments."""

from __future__ import annotations

from pathlib import Path
import sys

try:
    from .ordered_manifest import OrderedManifest, run_manifest_builder
except ImportError:
    from ordered_manifest import OrderedManifest, run_manifest_builder

ROOT = Path(__file__).resolve().parents[3]
WEB_ROOT = ROOT / "apps/kassee-web/web"
INDEX = OrderedManifest(
    manifest=WEB_ROOT / "html/manifest.txt",
    source_root=WEB_ROOT / "html",
    output=WEB_ROOT / "index.html",
    suffix=".html",
    label="HTML",
)

SOURCE_ROOT = INDEX.source_root
MANIFEST = INDEX.manifest
OUTPUT = INDEX.output


def manifest_entries() -> list[str]:
    return [path.relative_to(SOURCE_ROOT).as_posix() for path in INDEX.entries(ROOT)]


def render(entries: list[str]) -> str:
    return "".join((SOURCE_ROOT / entry).read_text(encoding="utf-8") for entry in entries)


def main() -> int:
    return run_manifest_builder(
        (INDEX,),
        ROOT,
        check_message="PASS: web/index.html matches its ordered source fragments",
        stale_message=(
            "web/index.html is stale; run tools/build/web/build_web_index.py"
        ),
    )


if __name__ == "__main__":
    sys.exit(main())
