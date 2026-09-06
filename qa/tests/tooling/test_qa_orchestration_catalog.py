#!/usr/bin/env python3
"""Regression contracts for the public make test / make qa orchestration."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
CHECKER_PATH = ROOT / "qa/checks/workspace/check_qa_orchestration.py"
CATALOG = ROOT / "qa/config/run_all_steps.tsv"


def load_checker():
    spec = importlib.util.spec_from_file_location("qa_orchestration_contract", CHECKER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rows() -> list[list[str]]:
    return [
        line.split("\t", 4)
        for line in CATALOG.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


class QaOrchestrationCatalogTests(unittest.TestCase):
    def test_repository_has_no_orphaned_registered_entrypoints(self) -> None:
        checker = load_checker()
        self.assertEqual(checker.check(), [])

    def test_orphaned_entrypoint_is_a_hard_failure(self) -> None:
        checker = load_checker()
        discovered = checker.discover_entrypoints()
        with mock.patch.object(
            checker,
            "discover_entrypoints",
            return_value=set(discovered) | {"qa/checks/example_orphan.py"},
        ):
            errors = checker.check()
        self.assertTrue(any("orphaned registered test/check entrypoints" in error for error in errors))
        self.assertTrue(any("qa/checks/example_orphan.py" in error for error in errors))

    def test_crap_then_core_ci_precede_the_contiguous_make_test_catalog(self) -> None:
        catalog = rows()
        self.assertEqual(catalog[0][0], "qa")
        self.assertEqual(catalog[0][3], "preflight.crap-check")
        self.assertEqual(catalog[1][0], "qa")
        self.assertEqual(catalog[1][3], "preflight.core-ci")
        test_rows = [row for row in catalog if row[0] == "test"]
        self.assertTrue(test_rows)
        first = catalog.index(test_rows[0])
        last = catalog.index(test_rows[-1])
        self.assertEqual(first, 2)
        self.assertEqual(catalog[first:last + 1], test_rows)
        configured = [
            line.strip()
            for line in (ROOT / "qa/config/run_all_test_steps.txt").read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertEqual(configured, [row[3] for row in test_rows])

    def test_make_qa_resume_is_forwarded_to_the_canonical_runner(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        helper = (ROOT / "scripts/common/lib/make_tasks.py").read_text(encoding="utf-8")
        public = (ROOT / "scripts/common/lib/make_public.py").read_text(encoding="utf-8")
        self.assertIn('qa "$(FUZZ_PASSES)" "$(STRICT_LOCKFILES)" "$(RESUME_FROM)"', makefile)
        self.assertIn('p.add_argument("resume_from", nargs="?", default="")', helper)
        self.assertIn('args.extend(["--resume-from", resume_from.strip()])', public)

    def test_resumed_full_qa_bootstraps_missing_ephemeral_crap_evidence(self) -> None:
        commands = (
            ["bash", str(ROOT / "qa/linux/run-all.sh"), "--profile", "full", "--dry-run", "--resume-from", "coverage.critical-branch-targets", "--skip-fuzz", "--skip-qemu"],
            [sys.executable, str(ROOT / "qa/windows/runner/run_all.py"), "--profile", "full", "--dry-run", "--resume-from", "coverage.critical-branch-targets", "--skip-fuzz", "--skip-qemu"],
        )
        for command in commands:
            output = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True).stdout
            self.assertIn("[resume prerequisite] Fresh CRAP/coverage artifacts are required", output)
            self.assertIn("Regenerating preflight.crap-check only", output)
            self.assertIn("pinned-branch-coverage", output)
            self.assertIn("[coverage.critical-branch-targets]", output)

    def test_linux_and_windows_full_qa_start_with_crap_then_core_ci(self) -> None:
        commands = (
            ["bash", str(ROOT / "qa/linux/run-all.sh"), "--profile", "full", "--dry-run", "--skip-fuzz", "--skip-qemu"],
            [sys.executable, str(ROOT / "qa/windows/runner/run_all.py"), "--profile", "full", "--dry-run", "--skip-fuzz", "--skip-qemu"],
        )
        for command in commands:
            output = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True).stdout
            selected = [line[1:line.index("]")] for line in output.splitlines() if line.startswith("[") and "]" in line]
            self.assertGreaterEqual(len(selected), 2)
            self.assertEqual(selected[:2], ["preflight.crap-check", "preflight.core-ci"])
            self.assertIn("target/qa/core-ci/core-ci.log", output.replace("\\", "/"))
            self.assertIn("cargo clippy --workspace --all-targets --locked -- -D warnings", output)
            self.assertIn("make test STRICT_LOCKFILES=1", output)
            self.assertNotIn("[unit.shared-signer]", output)


    def test_make_test_contains_no_android_ios_or_hil_work(self) -> None:
        catalog = rows()
        test_rows = [row for row in catalog if row[0] == "test"]
        self.assertTrue(test_rows)
        self.assertTrue(all(row[2] not in {"kassee-ios", "kassee-android"} for row in test_rows))
        test_ids = {row[3] for row in test_rows}
        self.assertFalse(any("hil" in step_id.lower() or "hardware" in step_id.lower() for step_id in test_ids))
        ownership = json.loads((ROOT / "qa/config/test_entrypoints.json").read_text())
        mobile_prefixes = ("qa/checks/ios/", "qa/checks/android/", "apps/kassee-ios/", "apps/kassee-android/")
        leaked = [entry["path"] for entry in ownership["entrypoints"] if "make test" in entry["commands"] and entry["path"].startswith(mobile_prefixes)]
        self.assertEqual(leaked, [])
        hardware_leaks = [
            entry["path"] for entry in ownership["entrypoints"]
            if entry.get("role") == "hardware-runner" and ({"make test", "make qa"} & set(entry["commands"]))
        ]
        self.assertEqual(hardware_leaks, [])

    def test_qa_excludes_physical_hardware_and_orders_interactive_before_campaigns(self) -> None:
        catalog = rows()
        ids = [row[3] for row in catalog]
        qa_ids = [row[3] for row in catalog if row[0] in {"test", "qa"}]
        hardware_ids = [row[3] for row in catalog if row[0] == "hardware"]
        self.assertTrue(hardware_ids)
        self.assertTrue(set(qa_ids).isdisjoint(hardware_ids))
        for interactive in ("integration.real-node", "integration.funded-testnet-e2e"):
            self.assertLess(ids.index(interactive), ids.index("mutation.repository-security-fresh"))
        self.assertLess(ids.index("bench.shared-signer-protocol-throughput"), ids.index("mutation.repository-security-fresh"))
        self.assertLess(ids.index("mutation.repository-security-fresh"), ids.index("mutation.repository-crypto-certification"))
        self.assertLess(ids.index("mutation.repository-crypto-certification"), ids.index("fuzz.repository-security-targets"))
        self.assertEqual(ids[-1], "hardware.signer-firmware-device")
        self.assertEqual(qa_ids[-1], "fuzz.repository-security-targets")

    def test_linux_and_windows_use_the_same_catalog_and_stable_ids(self) -> None:
        linux = subprocess.run(
            ["bash", str(ROOT / "qa/linux/run-all.sh"), "--list"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        ).stdout
        windows = subprocess.run(
            [sys.executable, str(ROOT / "qa/windows/runner/run_all.py"), "--list"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        ).stdout
        expected = [row[3] for row in rows()]
        def ids(text: str) -> list[str]:
            return [line.split()[0] for line in text.splitlines()[2:] if line.strip()]
        self.assertEqual(ids(linux), expected)
        self.assertEqual(ids(windows), expected)

    def test_platform_ineligible_mobile_work_is_explicitly_skipped(self) -> None:
        ios = (ROOT / "qa/checks/ios/run_xcode_application_tests.py").read_text()
        android = (ROOT / "qa/checks/android/run_instrumentation_tests.py").read_text()
        ios_mutation = (ROOT / "qa/checks/ios/run_mutation_tests.py").read_text()
        android_mutation = (ROOT / "qa/checks/android/run_mutation_tests.py").read_text()
        self.assertIn("SKIP: iOS application XCTest/XCUITest requires", ios)
        self.assertIn("SKIP = 77", android)
        self.assertIn("SKIP = 77", ios_mutation)
        self.assertIn("SKIP = 77", android_mutation)

    def test_make_release_builds_candidate_and_readiness_is_explicit_without_qa_replay(self) -> None:
        source = (ROOT / "scripts/common/lib/make_public.py").read_text(encoding="utf-8")
        release = source[source.index("def release_build"):]
        self.assertIn('platform("reproducible-build"', release)
        self.assertNotIn('platform("release-readiness"', release)
        self.assertNotIn('platform("run-all"', release.split("def ", 1)[0] if "def " in release else release)
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("release-readiness:", makefile)
        self.assertIn("entrypoint release-readiness", makefile)
        help_text = (ROOT / "scripts/common/lib/make_help.txt").read_text(encoding="utf-8")
        self.assertIn("make test -> make qa -> make test-hardware -> make workflow-e2e -> make workflow-hil -> make release -> make release-readiness", help_text)

    def test_ownership_manifest_uses_only_public_workflow_commands(self) -> None:
        document = json.loads((ROOT / "qa/config/test_entrypoints.json").read_text())
        allowed = {
            "make test", "make qa", "make test-hardware", "make workflow-e2e",
            "make workflow-hil", "make release", "make release-readiness",
        }
        for entry in document["entrypoints"]:
            self.assertTrue(entry["commands"])
            self.assertTrue(set(entry["commands"]).issubset(allowed), entry["path"])


if __name__ == "__main__":
    unittest.main()
