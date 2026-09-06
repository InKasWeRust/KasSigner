#!/usr/bin/env python3
"""Synchronize the generated KasSee Web site into iOS build resources under target/."""
from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "target" / "kassee-web" / "site"
DEST = ROOT / "target" / "kassee-runtime" / "ios" / "KasSeeUI"


def main() -> int:
    required = (
        WEB / "index.html",
        WEB / "pkg" / "kassee_web.js",
        WEB / "pkg" / "kassee_web_bg.wasm",
    )
    missing = [path for path in required if not path.is_file() or path.stat().st_size == 0]
    if missing:
        joined = ", ".join(str(path.relative_to(ROOT)) for path in missing)
        raise SystemExit(f"ERROR: build KasSee Web before iOS synchronization; missing: {joined}")

    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(WEB, DEST)

    for relative in ("index.html", "pkg/kassee_web.js", "pkg/kassee_web_bg.wasm"):
        target = DEST / relative
        if not target.is_file() or target.stat().st_size == 0:
            raise SystemExit(f"ERROR: missing synchronized iOS runtime asset: {relative}")
    print("KasSigner iOS - synchronized generated KasSee site into target build resources.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
