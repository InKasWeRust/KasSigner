#!/usr/bin/env python3
"""Regression coverage for Rust integration-test root/module collisions."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))

from architecture.core.workspace import _check_qa_test_layout  # noqa: E402


class QaTestLayoutTests(unittest.TestCase):
    def _root(self, harness: str) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        tests = root / "qa/tests"
        (tests / "conformance").mkdir(parents=True)
        (tests / "conformance/mod.rs").write_text("mod vectors;\n")
        (tests / "conformance.rs").write_text(harness)
        return temporary, root

    def test_rejects_same_name_module_collision(self) -> None:
        temporary, root = self._root("mod conformance;\n")
        with temporary:
            errors = _check_qa_test_layout(root)
            self.assertTrue(any("ambiguous Rust integration-test module" in error for error in errors))

    def test_accepts_explicit_path_alias(self) -> None:
        temporary, root = self._root(
            '#[path = "conformance/mod.rs"]\nmod conformance_suite;\n'
        )
        with temporary:
            self.assertEqual(_check_qa_test_layout(root), [])


if __name__ == "__main__":
    unittest.main()
