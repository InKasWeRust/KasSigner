#!/usr/bin/env python3
"""Build the stable KasSee stylesheet from ordered source modules."""

from __future__ import annotations

from pathlib import Path
import sys

try:
    from .ordered_manifest import OrderedManifest, run_manifest_builder
except ImportError:
    from ordered_manifest import OrderedManifest, run_manifest_builder

ROOT = Path(__file__).resolve().parents[3]
CSS_ROOT = ROOT / "apps/kassee-web/web/css"
STYLESHEET = OrderedManifest(
    manifest=CSS_ROOT / "app/manifest.txt",
    source_root=CSS_ROOT / "app",
    output=CSS_ROOT / "app.css",
    suffix=".css",
    label="CSS",
    separator="\n\n",
    strip_trailing=True,
    trailing_newline=True,
)


def main() -> int:
    return run_manifest_builder(
        (STYLESHEET,),
        ROOT,
        check_message="PASS: web/css/app.css matches its ordered source modules",
        stale_message=(
            "web/css/app.css is stale; run tools/build/web/build_app_css.py"
        ),
    )


if __name__ == "__main__":
    sys.exit(main())
