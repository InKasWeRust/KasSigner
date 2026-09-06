#!/usr/bin/env python3
"""Regression tests for scope-aligned CRAP report composition."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
MERGER = ROOT / "qa/checks/quality/crap/merge_reports.py"

spec = importlib.util.spec_from_file_location("kassigner_crap_merge", MERGER)
assert spec is not None and spec.loader is not None
merge_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge_module)


def report(file_name: str, *, with_diagnostics: bool) -> dict[str, object]:
    document: dict[str, object] = {
        "version": "0.4.1",
        "entries": [
            {
                "file": file_name,
                "function": "example",
                "line": 3,
                "cyclomatic": 2.0,
                "coverage": 100.0 if with_diagnostics else None,
                "crap": 2.0 if with_diagnostics else 6.0,
            }
        ],
    }
    if with_diagnostics:
        document["diagnostics"] = {
            "analyzed_files": 1,
            "lcov_files": 1,
            "matched_files": 1,
            "source_only": {"count": 0, "examples": []},
            "lcov_only": {"count": 0, "examples": []},
        }
    return document


class CrapScopeMergeTests(unittest.TestCase):
    def test_merge_preserves_explicit_repository_scope_for_secondary_workspaces(self) -> None:
        merged = merge_module.merge_reports(
            report("C:/repo/kassigner/crates/shared-signer/src/lib.rs", with_diagnostics=True),
            report("src/main.rs", with_diagnostics=False),
            report("src/lib.rs", with_diagnostics=True),
        )
        files = {entry["file"] for entry in merged["entries"]}
        self.assertIn("C:/repo/kassigner/crates/shared-signer/src/lib.rs", files)
        self.assertIn("apps/signer-firmware/src/main.rs", files)
        self.assertIn("apps/kassee-web/src/lib.rs", files)

    def test_merge_rejects_any_coverage_scope_mismatch(self) -> None:
        host = report("src/lib.rs", with_diagnostics=True)
        host["diagnostics"]["source_only"]["count"] = 1  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "do not match exactly"):
            merge_module.merge_reports(
                host,
                report("src/main.rs", with_diagnostics=False),
                report("src/lib.rs", with_diagnostics=True),
            )

    def test_human_report_explains_firmware_coverage_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for name in ("host", "firmware", "kassee"):
                path = root / f"{name}.txt"
                path.write_text(f"{name} report\n", encoding="utf-8")
                paths.append(path)
            output = root / "full.txt"
            merge_module._write_human(
                output,
                [
                    ("Root Cargo workspace (coverage-backed CRAP)", paths[0]),
                    ("KasSee Web Rust shell (coverage-backed CRAP)", paths[2]),
                    ("Signer firmware (complexity-only CRAP)", paths[1]),
                ],
            )
            text = output.read_text(encoding="utf-8")
            self.assertIn("host LCOV cannot instrument Xtensa firmware", text)
            self.assertIn("coverage-backed CRAP", text)
            self.assertIn("complexity-only CRAP", text)


if __name__ == "__main__":
    unittest.main()
