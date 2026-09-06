#!/usr/bin/env python3
"""Regression tests for CRAP scope classification and reference ownership."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
CRAP_CHECKS = ROOT / "qa/checks/quality/crap"
sys.path.insert(0, str(CRAP_CHECKS))
sys.path.insert(0, str(ROOT / "qa/checks"))

from toolchains import load_toolchains  # noqa: E402

PINS = load_toolchains()

from report import (  # noqa: E402
    apply_coverage_unavailable_source_policy,
    classify_path,
    parse_report_json,
    parse_report_text,
    report_summary,
)


def fixture_report() -> str:
    rows = (
        "│ ✗ ┆ 42.0 ┆ 6 ┆ ░░░░░░░░░░   0.0% ┆ parse_wire ┆ ./crates/online-watcher/src/parser.rs:8 │",
        "│ ✗ ┆ 42.0 ┆ 6 ┆ ░░░░░░░░░░    —   ┆ test_wire ┆ ./crates/online-watcher/src/unit_tests/parser.rs:8 │",
        "│ ✗ ┆ 42.0 ┆ 6 ┆ ░░░░░░░░░░   0.0% ┆ vendor_wire ┆ ./external/vendor/src/parser.rs:8 │",
        "│ ✗ ┆ 42.0 ┆ 6 ┆ ░░░░░░░░░░    —   ┆ tool_wire ┆ ./tools/firmware/verify.rs:8 │",
    )
    return "\n".join((*rows, "✗ 4/4 function(s) exceed CRAP threshold 30.", ""))


class CrapReportTests(unittest.TestCase):
    def test_classifies_repository_ownership_boundaries(self) -> None:
        self.assertEqual(classify_path("crates/offline-signer/src/address.rs"), "production")
        self.assertEqual(classify_path("apps/signer-firmware/src/qemu/validation/cpu.rs"), "tests")
        self.assertEqual(
            classify_path(
                "apps/signer-firmware/src/runtime/workflow_tests/connected/onboarding/creation.rs"
            ),
            "tests",
        )
        self.assertEqual(
            classify_path("apps/signer-firmware/src/runtime/interactions/workflow_tests.rs"),
            "tests",
        )
        self.assertEqual(
            classify_path("apps/signer-firmware/src/runtime/interactions/menu/primary.rs"),
            "production",
        )
        self.assertEqual(classify_path("qa/tests/conformance/account.rs"), "tests")
        self.assertEqual(classify_path("qa/benches/protocol.rs"), "tests")
        self.assertEqual(classify_path("external/rqrr-nostd/src/decode.rs"), "external")
        self.assertEqual(classify_path("tools/firmware/verify.rs"), "tools")

    def test_preserves_zero_and_unavailable_coverage_as_distinct_states(self) -> None:
        report = parse_report_text(fixture_report())
        entries = {entry.function: entry for entry in report.entries}

        self.assertEqual(entries["parse_wire"].coverage_state, "zero")
        self.assertEqual(entries["test_wire"].coverage_state, "unavailable")
        self.assertEqual(entries["parse_wire"].coverage_percent, 0.0)
        self.assertIsNone(entries["test_wire"].coverage_percent)


    def test_parses_native_cargo_crap_json(self) -> None:
        document = {
            "version": PINS["KASSIGNER_CARGO_CRAP_VERSION"],
            "entries": [
                {
                    "file": "crates/shared-signer/src/example.rs",
                    "function": "clean",
                    "line": 3,
                    "cyclomatic": 2.0,
                    "coverage": 100.0,
                    "crap": 2.0,
                },
                {
                    "file": "apps/signer-firmware/src/example.rs",
                    "function": "uncovered",
                    "line": 9,
                    "cyclomatic": 6.0,
                    "coverage": None,
                    "crap": 42.0,
                },
            ],
        }
        report = parse_report_json(json.dumps(document))
        self.assertEqual(len(report.entries), 2)
        self.assertEqual(report.entries[0].status, "pass")
        self.assertEqual(report.entries[1].status, "fail")
        self.assertEqual(report.entries[1].coverage_state, "unavailable")

    def test_coverage_unavailable_firmware_uses_source_complexity_bands(self) -> None:
        document = {
            "version": PINS["KASSIGNER_CARGO_CRAP_VERSION"],
            "entries": [
                {
                    "file": "apps/signer-firmware/src/thin.rs",
                    "function": "thin",
                    "line": 1,
                    "cyclomatic": 6.0,
                    "coverage": None,
                    "crap": 42.0,
                },
                {
                    "file": "apps/signer-firmware/src/complex.rs",
                    "function": "complex",
                    "line": 1,
                    "cyclomatic": 16.0,
                    "coverage": None,
                    "crap": 272.0,
                },
                {
                    "file": "apps/signer-firmware/src/excessive.rs",
                    "function": "excessive",
                    "line": 1,
                    "cyclomatic": 26.0,
                    "coverage": None,
                    "crap": 702.0,
                },
                {
                    "file": "crates/shared-signer/src/measured.rs",
                    "function": "measured",
                    "line": 1,
                    "cyclomatic": 16.0,
                    "coverage": 100.0,
                    "crap": 16.0,
                },
            ],
        }
        raw = parse_report_json(json.dumps(document))
        assessed = apply_coverage_unavailable_source_policy(
            raw,
            {
                "coverage_unavailable_source_policy": {
                    "roots": ["apps/signer-firmware/"],
                    "warning_source_decisions": 15,
                    "failure_source_decisions": 25,
                }
            },
        )
        entries = {entry.function: entry for entry in assessed.entries}
        self.assertEqual(entries["thin"].raw_status, "fail")
        self.assertEqual(entries["thin"].status, "pass")
        self.assertEqual(entries["thin"].assessment_basis, "source_complexity")
        self.assertEqual(entries["complex"].status, "warning")
        self.assertEqual(entries["excessive"].status, "fail")
        self.assertEqual(entries["measured"].status, "warning")
        self.assertEqual(entries["measured"].assessment_basis, "crap")

    def test_summary_separates_all_four_scopes(self) -> None:
        summary = report_summary(parse_report_text(fixture_report()))

        self.assertEqual(summary["all"]["functions"], 4)
        for scope in ("production", "tests", "external", "tools"):
            self.assertEqual(summary["scopes"][scope]["functions"], 1)
            self.assertEqual(summary["scopes"][scope]["status"]["fail"], 1)

    def test_cli_writes_a_real_production_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "full.txt"
            output = root / "classified"
            source.write_text(fixture_report(), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(CRAP_CHECKS / "classify_report.py"),
                    "--input",
                    str(source),
                    "--output-dir",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            production = (output / "crap_report_prod.txt").read_text(encoding="utf-8")
            self.assertIn("parse_wire", production)
            self.assertNotIn("test_wire", production)
            self.assertNotIn("vendor_wire", production)
            self.assertNotIn("tool_wire", production)
            self.assertTrue((output / "crap_report_full.txt").is_file())
            self.assertTrue((output / "crap_summary.json").is_file())
            self.assertTrue((output / "current.json").is_file())

    def test_compact_ratchet_contract_is_source_controlled_and_structurally_valid(self) -> None:
        contract = json.loads(
            (ROOT / "qa/contracts/quality/crap_ratchets.json").read_text()
        )

        self.assertEqual(contract["schema_version"], 1)
        self.assertEqual(
            contract["coverage_profile"],
            {
                "branch_instrumentation": True,
                "dev_opt_level": "0",
                "test_opt_level": "0",
            },
        )
        floors = contract["host_production_minimum_percent"]
        for metric in ("lines", "functions", "branches"):
            self.assertGreater(floors[metric], 90.0)
        self.assertFalse((ROOT / "qa/baselines/crap").exists())

    @unittest.skipUnless(os.name == "posix", "Linux CRAP generator execution is POSIX-specific")
    def test_generator_writes_analysis_artifacts_only_to_target_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "full.txt"
            output = root / "output"
            source.write_text(fixture_report(), encoding="utf-8")
            environment = dict(__import__("os").environ)
            environment["CRAP_OUTPUT_DIR"] = str(output)

            result = subprocess.run(
                [
                    str(ROOT / "scripts/linux/quality/crap.sh"),
                    "--input-report",
                    str(source),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in (
                "crap_report_full.txt",
                "crap_report_prod.txt",
                "crap_summary.json",
                "current.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            refreshed = json.loads((output / "current.json").read_text())
            self.assertEqual(refreshed["summary"]["all"]["functions"], 4)
            self.assertIn("Fresh CRAP artifacts are ready", result.stdout)
            self.assertFalse((ROOT / "qa/baselines/crap").exists())

    def test_consolidated_checker_accepts_committed_ratchet_contract(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CRAP_CHECKS / "check.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: CRAP quality check", result.stdout)



if __name__ == "__main__":
    unittest.main()
