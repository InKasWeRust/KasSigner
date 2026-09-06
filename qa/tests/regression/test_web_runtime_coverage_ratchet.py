#!/usr/bin/env python3
"""Regression contract for whole-KasSee runtime behavioral coverage ratchets."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "qa/checks/web/run_web_runtime_coverage.py"
RUST_CORE_LINE_FLOOR = 92.46
RUST_CORE_FUNCTION_FLOOR = 84.75


def load_runner():
    spec = importlib.util.spec_from_file_location("web_runtime_coverage_ratchet", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class WebRuntimeCoverageRatchet(unittest.TestCase):
    def test_whole_runtime_ratchets_cannot_fall_below_rust_core_tier(self) -> None:
        module = load_runner()
        self.assertGreaterEqual(module.MIN_LINE_COVERAGE_PERCENT, RUST_CORE_LINE_FLOOR)
        self.assertGreaterEqual(module.MIN_FUNCTION_COVERAGE_PERCENT, RUST_CORE_FUNCTION_FLOOR)
        self.assertEqual(module.MIN_LINE_COVERAGE_PERCENT, 92.72)
        self.assertEqual(module.MIN_FUNCTION_COVERAGE_PERCENT, 91.01)
        self.assertEqual(module.MIN_BRANCH_COVERAGE_PERCENT, 90.0)

    def test_runner_enforces_mapping_line_function_and_integration_requirements(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            '"mapping_percent": 100.0',
            '"lines_percent": MIN_LINE_COVERAGE_PERCENT',
            '"functions_percent": MIN_FUNCTION_COVERAGE_PERCENT',
            'line_rounded >= MIN_LINE_COVERAGE_PERCENT',
            'funcs_rounded >= MIN_FUNCTION_COVERAGE_PERCENT',
            'branches_rounded >= MIN_BRANCH_COVERAGE_PERCENT',
            '"branches_percent": MIN_BRANCH_COVERAGE_PERCENT',
            'passed',
            'len(measured) == len(expected)',
        ):
            self.assertIn(required, source)
        self.assertNotIn('MIN_LINE_COVERAGE_PERCENT = 0', source)
        self.assertNotIn('MIN_FUNCTION_COVERAGE_PERCENT = 0', source)
        self.assertNotIn('MIN_BRANCH_COVERAGE_PERCENT = 0', source)

    def test_all_runtime_modules_remain_reachable_and_measured_scope_is_complete(self) -> None:
        module = load_runner()
        reachable = module.reachable_modules()
        all_js = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "apps/kassee-web/web/js").rglob("*.js")
        }
        self.assertEqual(reachable, all_js)
        self.assertGreaterEqual(len(reachable), 308)
        portfolio = {
            f"apps/kassee-web/web/js/features/portfolio/{name}"
            for name in (
                "calculations.js", "controller.js", "csv.js", "exact_money.js", "index.js",
                "pricing.js", "render.js", "repository.js", "wallet_history.js",
            )
        }
        self.assertTrue(portfolio.issubset(reachable))


if __name__ == "__main__":
    unittest.main()
