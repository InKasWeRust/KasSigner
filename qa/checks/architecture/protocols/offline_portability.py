from __future__ import annotations

from pathlib import Path
import re


def portable_crate_boundary_errors(root: Path) -> list[str]:
    """Reject board-specific logging and firmware-only feature gates in offline-signer."""
    errors: list[str] = []
    source_root = root / "crates/offline-signer/src"
    if not source_root.exists():
        return errors
    for path in source_root.rglob("*.rs"):
        source = path.read_text(errors="ignore")
        relative = path.relative_to(root)
        if "esp_println" in source:
            errors.append(
                f"portable offline-signer source depends on firmware logging: {relative}"
            )
        if re.search(r'feature\s*=\s*"silent"', source):
            errors.append(
                f"portable offline-signer source uses firmware-only silent feature: {relative}"
            )
    return errors


def check(root: Path) -> list[str]:
    return portable_crate_boundary_errors(root)
