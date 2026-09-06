#!/usr/bin/env python3
"""Tests for complete CRAP/coverage health measurement."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
HEALTH_PATH = ROOT / "qa/checks/quality/crap/health.py"
POLICY_PATH = ROOT / "qa/checks/quality/crap/policy.json"

spec = importlib.util.spec_from_file_location("crap_health", HEALTH_PATH)
assert spec and spec.loader
health = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = health
spec.loader.exec_module(health)


def report(functions: list[dict[str, object]]) -> dict[str, object]:
    return {"functions": functions}


def function(
    path: str,
    *,
    status: str = "pass",
    complexity: int = 1,
) -> dict[str, object]:
    return {
        "path": path,
        "line": 1,
        "function": "example",
        "scope": "production",
        "status": status,
        "complexity": complexity,
    }


def policy() -> dict[str, object]:
    return {
        "health": {
            "maximum_production_failures": 0,
            "maximum_production_warnings": 1,
            "maximum_production_warning_percent": 10.0,
            "minimum_host_line_coverage_percent": 90.0,
            "minimum_host_function_coverage_percent": 90.0,
            "minimum_host_branch_coverage_percent": 90.0,
            "minimum_critical_domain_coverage_percent": 90.0,
            "minimum_web_runtime_mapping_percent": 100.0,
            "maximum_board_adapter_cc": 4,
            "require_branch_coverage": True,
            "host_production_roots": ["crates/shared-signer/src/"],
            "board_adapter_roots": ["apps/signer-firmware/src/hw/m5stack/"],
            "critical_domains": {
                "parsers": {
                    "label": "parsers",
                    "paths": ["crates/shared-signer/src/parser.rs"],
                    "minimum_branch_coverage_percent": 90.0,
                    "target_branch_coverage_percent": 90.0,
                }
            },
        },
        "firmware_testability": {
            "model_paths": ["crates/shared-signer/src/parser.rs"]
        },
    }



def web_runtime() -> dict[str, object]:
    return {
        "tests_passed": True,
        "files": {"reachable": 343, "measured": 343, "missing": [], "mapping_percent": 100.0},
        "coverage": {"lines": 40.0, "functions": 35.0, "branches": 70.0},
    }

def run_manifest(branches: bool = True) -> dict[str, object]:
    return {
        "branch_coverage_requested": branches,
        "coverage": {
            "branches": {
                "available": branches,
                "found": 2 if branches else 0,
                "hit": 2 if branches else 0,
                "percent": 100.0 if branches else 0.0,
            }
        },
    }


class CrapHealthTests(unittest.TestCase):
    def test_lcov_parser_derives_missing_summary_totals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lcov.info"
            path.write_text(
                "TN:\n"
                "SF:crates/shared-signer/src/parser.rs\n"
                "FN:1,parse\n"
                "FNDA:1,parse\n"
                "DA:1,1\n"
                "DA:2,0\n"
                "BRDA:1,0,0,1\n"
                "BRDA:1,0,1,0\n"
                "end_of_record\n"
            )
            records = health.parse_lcov(path)

        metrics = records["crates/shared-signer/src/parser.rs"]
        self.assertEqual(metrics["lines"]["found"], 2)
        self.assertEqual(metrics["lines"]["hit"], 1)
        self.assertEqual(metrics["functions"]["percent"], 100.0)
        self.assertEqual(metrics["branches"]["percent"], 50.0)

    def test_lcov_parser_prefers_concrete_branches_over_stale_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lcov = Path(directory) / "stale-branch-summary.info"
            lcov.write_text(
                "\n".join(
                    [
                        "TN:",
                        "SF:crates/shared-signer/src/crypto.rs",
                        "BRDA:10,0,0,1",
                        "BRDA:10,0,1,1",
                        "BRDA:20,1,0,1",
                        "BRDA:20,1,1,1",
                        "BRF:4",
                        "BRH:0",
                        "end_of_record",
                        "",
                    ]
                )
            )
            records = health.parse_lcov(lcov)

        branches = records["crates/shared-signer/src/crypto.rs"]["branches"]
        self.assertEqual(branches["found"], 4)
        self.assertEqual(branches["hit"], 4)
        self.assertEqual(branches["percent"], 100.0)

    def test_lcov_parser_normalizes_versioned_checkout_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lcov.info"
            path.write_text(
                "SF:/home/user/Downloads/KasSigner-build/crates/shared-signer/src/parser.rs\n"
                "DA:1,1\n"
                "end_of_record\n"
                "SF:C:\\src\\KasSigner-build\\apps\\signer-firmware\\src\\main.rs\n"
                "DA:1,1\n"
                "end_of_record\n"
            )
            records = health.parse_lcov(path)

        self.assertIn("crates/shared-signer/src/parser.rs", records)
        self.assertIn("apps/signer-firmware/src/main.rs", records)

    def test_complete_health_passes_when_every_target_is_met(self) -> None:
        records = {
            "crates/shared-signer/src/parser.rs": {
                "lines": {"found": 10, "hit": 10, "percent": 100.0, "available": True},
                "functions": {"found": 2, "hit": 2, "percent": 100.0, "available": True},
                "branches": {"found": 2, "hit": 2, "percent": 100.0, "available": True},
            }
        }
        errors, document = health.audit_health(
            report([function("crates/shared-signer/src/parser.rs")]),
            records,
            run_manifest(),
            policy(),
            {"web_runtime": web_runtime()},
        )

        self.assertEqual(errors, [])
        self.assertTrue(document["healthy"])
        self.assertEqual(document["criteria"]["pure_firmware_models"]["actual"], 1)

    def test_complete_health_reports_every_unmet_target(self) -> None:
        records = {
            "crates/shared-signer/src/parser.rs": {
                "lines": {"found": 10, "hit": 5, "percent": 50.0, "available": True},
                "functions": {"found": 2, "hit": 1, "percent": 50.0, "available": True},
                "branches": {"found": 0, "hit": 0, "percent": 0.0, "available": False},
            }
        }
        entries = [
            function("crates/shared-signer/src/parser.rs", status="fail", complexity=6),
            function(
                "apps/signer-firmware/src/hw/m5stack/adapter.rs",
                status="warning",
                complexity=5,
            ),
        ]
        errors, document = health.audit_health(
            report(entries),
            records,
            run_manifest(False),
            policy(),
            {"web_runtime": web_runtime()},
        )

        self.assertFalse(document["healthy"])
        self.assertGreaterEqual(len(errors), 6)
        self.assertIn("production CRAP failures remain", "\n".join(errors))
        self.assertIn("board adapter complexity", "\n".join(errors))
        self.assertIn("branch coverage", "\n".join(errors))


    def test_wallet_recovery_requires_browser_coverage_as_well_as_rust(self) -> None:
        data = policy()
        data["health"]["critical_domains"] = {
            "wallet_recovery": {
                "label": "wallet recovery",
                "paths": ["crates/shared-signer/src/parser.rs"],
                "supplemental_coverage": "browser_recovery",
                "minimum_branch_coverage_percent": 90.0,
                "target_branch_coverage_percent": 90.0,
            }
        }
        records = {
            "crates/shared-signer/src/parser.rs": {
                "lines": {"found": 10, "hit": 10, "percent": 100.0, "available": True},
                "functions": {"found": 2, "hit": 2, "percent": 100.0, "available": True},
                "branches": {"found": 2, "hit": 2, "percent": 100.0, "available": True},
            }
        }
        browser = {
            "coverage": {
                "lines": {"percent": 97.0, "available": True},
                "functions": {"percent": 96.0, "available": True},
                "branches": {"percent": 95.0, "available": True},
            },
            "files": {"expected": 36, "measured": 36, "missing": []},
        }
        errors, document = health.audit_health(
            report([function("crates/shared-signer/src/parser.rs")]),
            records,
            run_manifest(),
            data,
            {"browser_recovery": browser, "web_runtime": web_runtime()},
        )
        self.assertEqual(errors, [])
        supplemental = document["critical_domains"]["wallet_recovery"]["supplemental"]
        self.assertTrue(supplemental["met"])
        self.assertEqual(supplemental["files"]["measured"], 36)

        errors, document = health.audit_health(
            report([function("crates/shared-signer/src/parser.rs")]),
            records,
            run_manifest(),
            data,
            {"web_runtime": web_runtime()},
        )
        self.assertFalse(document["critical_domains"]["wallet_recovery"]["met"])
        self.assertIn("browser_recovery", "\n".join(errors))

    def test_repository_policy_matches_the_declared_health_contract(self) -> None:
        data = json.loads(POLICY_PATH.read_text())
        contract = data["health"]

        self.assertEqual(contract["maximum_production_failures"], 0)
        self.assertEqual(contract["maximum_production_warnings"], 0)
        self.assertEqual(contract["maximum_production_warning_percent"], 0.0)
        self.assertEqual(contract["minimum_host_line_coverage_percent"], 90.0)
        self.assertEqual(contract["minimum_host_function_coverage_percent"], 90.0)
        self.assertEqual(contract["minimum_host_branch_coverage_percent"], 90.0)
        self.assertEqual(contract["minimum_critical_domain_coverage_percent"], 90.0)
        self.assertEqual(contract["minimum_web_runtime_mapping_percent"], 100.0)
        self.assertEqual(contract["maximum_board_adapter_cc"], 4)
        self.assertTrue(contract["require_branch_coverage"])
        self.assertEqual(len(contract["critical_domains"]), 6)
        for domain in contract["critical_domains"].values():
            self.assertIsInstance(domain["minimum_branch_coverage_percent"], (int, float))
            self.assertIn(domain["target_branch_coverage_percent"], (90.0, 100.0))
            self.assertLessEqual(
                domain["minimum_branch_coverage_percent"],
                domain["target_branch_coverage_percent"],
            )
        self.assertEqual(
            contract["critical_domains"]["wallet_recovery"]["supplemental_coverage"],
            "browser_recovery",
        )
        self.assertEqual(contract["critical_domains"]["critical_crypto"]["minimum_branch_coverage_percent"], 90.0)
        self.assertEqual(contract["critical_domains"]["critical_crypto"]["target_branch_coverage_percent"], 100.0)
        unavailable = data["coverage_unavailable_source_policy"]
        self.assertEqual(unavailable["warning_source_decisions"], 15)
        self.assertEqual(unavailable["failure_source_decisions"], 25)
        self.assertEqual(unavailable["roots"], ["apps/signer-firmware/"])


if __name__ == "__main__":
    unittest.main()
