#!/usr/bin/env python3
"""Policy and regression-gate tests for the consolidated CRAP quality check."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from qa.tests.tooling.crap_check_test_support import (
    CrapCheckTestCase, POLICY, ROOT, report_document, source_complexity,
)


class CrapCheckTests(CrapCheckTestCase):
    def test_source_decisions_counts_control_flow_and_propagation(self) -> None:
        source = """
        fn parse() -> Result<(), Error> {
            if ready && enabled { read()?; }
            for _ in 0..2 { write()?; }
            match state { A => ok(), B => err(), }
            Ok(())
        }
        """
        self.assertEqual(source_complexity.source_decisions(source), 8)

    def test_repository_quality_contract_passes(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: CRAP quality check", result.stdout)
        records = source_complexity.production_records(ROOT)
        actual_max = max((record.decisions for record in records), default=0)
        policy = json.loads(POLICY.read_text())["source_complexity"]
        self.assertLessEqual(actual_max, policy["warning_source_decisions"])
        self.assertIn(f"max source decisions {actual_max}", result.stdout)
        self.assertIn("0 source warnings", result.stdout)

    def test_policy_tracks_models_adapters_tests_and_report_limits(self) -> None:
        data = json.loads(POLICY.read_text())
        firmware = data["firmware_testability"]
        source = data["source_complexity"]
        report = data["report"]

        self.assertGreaterEqual(len(firmware["model_paths"]), 7)
        self.assertGreaterEqual(len(firmware["adapter_targets"]), 9)
        self.assertGreaterEqual(firmware["minimum_host_tests"], 20)
        self.assertEqual(source["maximum_production_source_decisions"], 25)
        self.assertEqual(report["maximum_production_failures"], 0)
        self.assertEqual(report["maximum_production_warnings"], 0)
        self.assertEqual(data["health"]["maximum_production_warnings"], 0)
        self.assertTrue(data["health"]["require_branch_coverage"])
        self.assertTrue(data["regression"]["reject_new_warnings"])
        self.assertNotIn("reference_report_sha256", report)


    def test_checker_can_ignore_generated_report(self) -> None:
        result = self.run_checker("--ignore-generated-report")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: CRAP quality check", result.stdout)
        self.assertNotIn("fresh report", result.stdout)

    def test_fresh_passing_report_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report_document("pass")))
            result = self.run_checker("--report", str(path))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fresh report (debt-aware): 0 failures", result.stdout)

    def test_fresh_failing_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report_document("fail")))
            result = self.run_checker("--report", str(path), "--strict-report")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("production CRAP failures remain", result.stdout)


    def test_fresh_failing_report_is_informational_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report_document("fail")))
            result = self.run_checker("--report", str(path))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fresh report (debt-aware): 1 failures", result.stdout)

    def test_regression_gate_rejects_a_new_production_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.json"
            current = root / "current.json"
            previous.write_text(json.dumps(report_document("pass")))
            current.write_text(json.dumps(report_document("fail")))
            result = self.run_checker(
                "--report",
                str(current),
                "--previous-report",
                str(previous),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("new production CRAP failure", result.stdout)

    def test_regression_gate_rejects_a_new_production_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.json"
            current = root / "current.json"
            previous.write_text(json.dumps(report_document("pass")))
            current.write_text(json.dumps(report_document("warning")))
            result = self.run_checker(
                "--report",
                str(current),
                "--previous-report",
                str(previous),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("new production CRAP warning", result.stdout)

    def test_regression_gate_allows_uncovered_board_adapter_warning_at_cc_four(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.json"
            current = root / "current.json"
            previous.write_text(json.dumps(report_document("pass")))
            document = report_document("warning")
            entry = document["functions"][0]
            entry.update({
                "path": "apps/signer-firmware/src/hw/m5stack/adapter.rs",
                "function": "poll_adapter",
                "complexity": 4,
                "coverage_percent": None,
                "coverage_state": "unavailable",
                "crap": 20.0,
            })
            current.write_text(json.dumps(document))
            result = self.run_checker(
                "--report", str(current), "--previous-report", str(previous)
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 new warnings", result.stdout)

    def test_regression_gate_rejects_uncovered_board_adapter_above_cc_four(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.json"
            current = root / "current.json"
            previous.write_text(json.dumps(report_document("pass")))
            document = report_document("warning")
            entry = document["functions"][0]
            entry.update({
                "path": "apps/signer-firmware/src/hw/waveshare/adapter.rs",
                "function": "poll_adapter",
                "complexity": 5,
                "coverage_percent": None,
                "coverage_state": "unavailable",
                "crap": 30.0,
            })
            current.write_text(json.dumps(document))
            result = self.run_checker(
                "--report", str(current), "--previous-report", str(previous)
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("new production CRAP warning", result.stdout)

    def test_regression_gate_allows_failure_to_improve_to_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.json"
            current = root / "current.json"
            previous.write_text(json.dumps(report_document("fail")))
            current.write_text(json.dumps(report_document("warning")))
            result = self.run_checker(
                "--report",
                str(current),
                "--previous-report",
                str(previous),
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0 new warnings", result.stdout)

    def test_regression_gate_accepts_existing_failure_debt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.json"
            current = root / "current.json"
            previous.write_text(json.dumps(report_document("fail")))
            current.write_text(json.dumps(report_document("fail")))
            result = self.run_checker(
                "--report",
                str(current),
                "--previous-report",
                str(previous),
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("regression gate: 0 new failures", result.stdout)

    def test_regression_gate_does_not_ratchet_raw_workspace_percentages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            previous_run = root / "previous-run.json"
            current_run = root / "current-run.json"
            report.write_text(json.dumps(report_document("pass")))
            previous_run.write_text(json.dumps({
                "coverage_profile": {"dev_opt_level": "0", "test_opt_level": "0", "branch_instrumentation": True},
                "coverage": {
                    "lines": {"percent": 80.0},
                    "functions": {"percent": 80.0},
                    "branches": {"available": False},
                }
            }))
            current_run.write_text(json.dumps({
                "coverage_profile": {"dev_opt_level": "0", "test_opt_level": "0", "branch_instrumentation": True},
                "coverage": {
                    "lines": {"percent": 79.0},
                    "functions": {"percent": 79.0},
                    "branches": {"available": False},
                }
            }))
            result = self.run_checker(
                "--report",
                str(report),
                "--run-manifest",
                str(current_run),
                "--previous-run-manifest",
                str(previous_run),
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("coverage regressed", result.stdout)


    def test_regression_gate_does_not_compare_percentages_across_coverage_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            previous_run = root / "previous-run.json"
            current_run = root / "current-run.json"
            report.write_text(json.dumps(report_document("pass")))
            previous_run.write_text(json.dumps({
                "coverage_profile": {"dev_opt_level": "s", "test_opt_level": "s", "branch_instrumentation": True},
                "branch_coverage_requested": True,
                "coverage": {
                    "lines": {"percent": 91.56},
                    "functions": {"percent": 85.36},
                    "branches": {"available": True, "found": 10, "hit": 8, "percent": 80.0},
                },
            }))
            current_run.write_text(json.dumps({
                "coverage_profile": {"dev_opt_level": "0", "test_opt_level": "0", "branch_instrumentation": True},
                "branch_coverage_requested": True,
                "coverage": {
                    "lines": {"percent": 90.65},
                    "functions": {"percent": 84.12},
                    "branches": {"available": True, "found": 12, "hit": 10, "percent": 83.33},
                },
            }))
            result = self.run_checker(
                "--report", str(report),
                "--run-manifest", str(current_run),
                "--previous-run-manifest", str(previous_run),
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("coverage regressed", result.stdout)

    def test_regression_gate_explains_branchless_run_against_branch_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            previous_run = root / "previous-run.json"
            current_run = root / "current-run.json"
            report.write_text(json.dumps(report_document("pass")))
            previous_run.write_text(json.dumps({
                "branch_coverage_requested": True,
                "coverage": {
                    "lines": {"percent": 90.0},
                    "functions": {"percent": 82.0},
                    "branches": {"available": True, "found": 10, "hit": 8},
                },
            }))
            current_run.write_text(json.dumps({
                "branch_coverage_requested": False,
                "coverage": {
                    "lines": {"percent": 90.0},
                    "functions": {"percent": 82.0},
                    "branches": {"available": False, "found": 0, "hit": 0},
                },
            }))
            result = self.run_checker(
                "--report",
                str(report),
                "--run-manifest",
                str(current_run),
                "--previous-run-manifest",
                str(previous_run),
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not request branch instrumentation", result.stdout)
        self.assertIn("strict QA pipeline", result.stdout)



if __name__ == "__main__":
    unittest.main()
