"""Shared fixture support for CRAP quality regression tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECK_DIR = ROOT / "qa/checks/quality/crap"
CHECKER = CHECK_DIR / "check.py"
POLICY = CHECK_DIR / "policy.json"
SOURCE_COMPLEXITY = CHECK_DIR / "source_complexity.py"

spec = importlib.util.spec_from_file_location("source_complexity", SOURCE_COMPLEXITY)
assert spec and spec.loader
source_complexity = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = source_complexity
spec.loader.exec_module(source_complexity)


def report_document(status: str) -> dict[str, object]:
    statuses = {"fail": 0, "warning": 0, "pass": 0}
    statuses[status] = 1
    empty_statuses = {"fail": 0, "warning": 0, "pass": 0}
    empty_coverage = {"measured": 0, "zero": 0, "unavailable": 0}
    return {
        "schema_version": 1,
        "source": {
            "label": "test report",
            "report_sha256": "0" * 64,
            "threshold": 30.0,
        },
        "summary": {
            "all": {
                "functions": 1,
                "status": dict(statuses),
                "coverage": {"measured": 1, "zero": 0, "unavailable": 0},
            },
            "scopes": {
                "production": {
                    "functions": 1,
                    "status": dict(statuses),
                    "coverage": {"measured": 1, "zero": 0, "unavailable": 0},
                },
                "tests": {
                    "functions": 0,
                    "status": dict(empty_statuses),
                    "coverage": dict(empty_coverage),
                },
                "external": {
                    "functions": 0,
                    "status": dict(empty_statuses),
                    "coverage": dict(empty_coverage),
                },
                "tools": {
                    "functions": 0,
                    "status": dict(empty_statuses),
                    "coverage": dict(empty_coverage),
                },
            },
        },
        "functions": [
            {
                "complexity": 1,
                "coverage_percent": 100.0,
                "coverage_state": "measured",
                "crap": 1.0 if status == "pass" else 31.0,
                "function": "example",
                "line": 1,
                "path": "crates/shared-signer/src/example.rs",
                "scope": "production",
                "status": status,
            }
        ],
    }


class CrapCheckTestCase(unittest.TestCase):
    def run_checker(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
