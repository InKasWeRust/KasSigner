#!/usr/bin/env python3
"""durable HIL transcripts and unified fuzz evidence contracts."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE_CHECKS = ROOT / "qa" / "checks" / "firmware"
SECURITY_CHECKS = ROOT / "qa" / "checks" / "security"
for path in (FIRMWARE_CHECKS, SECURITY_CHECKS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import hil_evidence  # noqa: E402
import run_hardware_tests  # noqa: E402
import run_workflow_tests  # noqa: E402

FUZZ_SPEC = importlib.util.spec_from_file_location(
    "fuzz_results_contract", SECURITY_CHECKS / "fuzz_results.py"
)
assert FUZZ_SPEC and FUZZ_SPEC.loader
FUZZ_RESULTS = importlib.util.module_from_spec(FUZZ_SPEC)
FUZZ_SPEC.loader.exec_module(FUZZ_RESULTS)


class HilAndFuzzEvidenceTests(unittest.TestCase):

    def test_workflow_hil_build_log_is_tee_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transient = root / "transient-build.log"
            durable = root / "run" / "build.log"
            with mock.patch.object(run_workflow_tests, "BUILD_LOG", transient):
                code, warnings = run_workflow_tests.run_logged_build(
                    [sys.executable, "-c", "print('compiler-line')"],
                    os.environ.copy(),
                    durable,
                )
            self.assertEqual(code, 0)
            self.assertEqual(warnings, [])
            self.assertEqual(transient.read_bytes(), durable.read_bytes())
            self.assertIn("compiler-line", durable.read_text(encoding="utf-8"))

    def test_uart_supervisor_can_persist_exact_monitor_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            transcript = io.StringIO()
            real_popen = subprocess.Popen

            def portable_popen(command, *args, **kwargs):
                if command and command[0] == "espflash":
                    command = [
                        sys.executable,
                        "-c",
                        "print('Flashing has completed!'); print('UART-LINE'); "
                        "print('KASSIGNER_HARDWARE_TESTS: PASS')",
                    ]
                return real_popen(command, *args, **kwargs)

            with mock.patch.object(
                run_hardware_tests.subprocess, "Popen", side_effect=portable_popen
            ):
                result = run_hardware_tests.flash_and_monitor(
                    "waveshare", image, None, 3, uart_log=transcript, connected_transport=False
                )
            self.assertEqual(result, 0)
            self.assertIn("Flashing has completed!", transcript.getvalue())
            self.assertIn("UART-LINE", transcript.getvalue())
            self.assertIn(run_hardware_tests.PASS_MARKER, transcript.getvalue())

    def _run_fuzz_writer(self, root: Path, budget_flag: str, value: str) -> dict[str, object]:
        state = root / "target/qa/fuzz"
        logs = state
        artifacts = state / "artifacts"
        corpus = state / "corpus"
        logs.mkdir(parents=True)
        artifacts.mkdir()
        corpus.mkdir()
        (logs / "target-a.log").write_bytes(b"fuzz log\n")
        statuses = state / "statuses.tsv"
        statuses.write_text("target-a\t0\n", encoding="ascii")
        summary = root / "target/qa/security/fuzz-summary.json"
        latest = root / "target/qa/security/latest"
        with mock.patch.multiple(
            FUZZ_RESULTS,
            ROOT=root,
            SUMMARY=summary,
            LATEST=latest,
            RAW_ZIP=latest / "fuzz-results.zip",
            LOG_ROOT=logs,
            CRASH_ROOT=artifacts,
            CORPUS_ROOT=corpus,
        ), mock.patch.object(
            sys,
            "argv",
            [
                "fuzz_results.py",
                "--statuses", str(statuses),
                "--tool", "cargo-fuzz 0.13.1",
                "--started", "2026-08-28T00:00:00Z",
                "--completed", "2026-08-28T00:01:00Z",
                budget_flag, value,
            ],
        ):
            self.assertEqual(FUZZ_RESULTS.main(), 0)
        document = json.loads(summary.read_text(encoding="utf-8"))
        self.assertTrue((latest / "fuzz-results.zip.sha256").is_file())
        with zipfile.ZipFile(latest / "fuzz-results.zip") as archive:
            self.assertIn("fuzz/fuzz-summary.json", archive.namelist())
            self.assertIn("fuzz/logs/target-a.log", archive.namelist())
        return document

    def test_fuzz_writer_archives_files_with_pre_1980_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "target/qa/fuzz"
            artifacts = state / "artifacts"
            corpus = state / "corpus"
            state.mkdir(parents=True)
            artifacts.mkdir()
            corpus.mkdir()
            log = state / "target-a.log"
            log.write_bytes(b"fuzz log\n")
            os.utime(log, (1, 1))
            summary = root / "target/qa/security/fuzz-summary.json"
            summary.parent.mkdir(parents=True)
            summary.write_text("{}\n", encoding="utf-8")
            latest = root / "target/qa/security/latest"
            with mock.patch.multiple(
                FUZZ_RESULTS,
                ROOT=root,
                SUMMARY=summary,
                LATEST=latest,
                RAW_ZIP=latest / "fuzz-results.zip",
                LOG_ROOT=state,
                CRASH_ROOT=artifacts,
                CORPUS_ROOT=corpus,
            ):
                digest = FUZZ_RESULTS.archive(summary)
            self.assertEqual(len(digest), 64)
            with zipfile.ZipFile(latest / "fuzz-results.zip") as archive:
                member = archive.getinfo("fuzz/logs/target-a.log")
                self.assertEqual(member.date_time, FUZZ_RESULTS.ZIP_TIMESTAMP)
                self.assertEqual(archive.read(member), b"fuzz log\n")

    def test_fuzz_writer_schema_is_shared_for_run_count_and_time_budget(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            runs = self._run_fuzz_writer(Path(first), "--runs", "100000")
            seconds = self._run_fuzz_writer(Path(second), "--seconds", "300")
        self.assertEqual(runs["schema_version"], seconds["schema_version"])
        self.assertEqual(set(runs), set(seconds))
        self.assertEqual(runs["execution_budget"], {"mode": "runs", "value": 100000})
        self.assertEqual(seconds["execution_budget"], {"mode": "seconds", "value": 300})
        self.assertEqual(runs["runs_per_target"], 100000)
        self.assertIsNone(runs["seconds_per_target"])
        self.assertEqual(seconds["seconds_per_target"], 300)
        self.assertIsNone(seconds["runs_per_target"])

    def test_make_test_and_fuzz_security_use_the_same_fuzz_writer(self) -> None:
        linux_master = (ROOT / "qa/linux/runner/commands.sh").read_text(encoding="utf-8")
        windows_master = (ROOT / "qa/windows/runner/run_all.py").read_text(encoding="utf-8")
        linux_security = (ROOT / "qa/linux/run-security-fuzz.sh").read_text(encoding="utf-8")
        windows_security = (ROOT / "qa/windows/run-security-fuzz.ps1").read_text(encoding="utf-8")
        for source in (linux_master, windows_master, linux_security, windows_security):
            self.assertIn("qa/checks/security/fuzz_results.py", source)
            self.assertIn("statuses.tsv", source)
        self.assertIn('--runs "$FUZZ_PASSES"', linux_master)
        self.assertIn('"--runs", str(ns.fuzz_passes)', windows_master)
        self.assertIn('--seconds "$SECONDS_PER_TARGET"', linux_security)
        self.assertIn("'--seconds',[string]$secondsPerTarget", windows_security)

    def test_hil_entrypoints_have_durable_evidence_only_where_requested(self) -> None:
        hardware = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text(encoding="utf-8")
        workflow = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text(encoding="utf-8")
        make_tasks = (ROOT / "scripts/common/lib/make_tasks.py").read_text(encoding="utf-8")
        self.assertIn('kind="hardware"', hardware)
        self.assertIn('include_build_log=False', hardware)
        self.assertIn('kind="workflow"', workflow)
        self.assertIn('include_build_log=True', workflow)
        self.assertIn('if args.hil', workflow)
        self.assertIn('"--board", board, "--timeout", timeout, "--hil"', make_tasks)
        self.assertIn('uart_log=uart_log', hardware)
        self.assertIn('uart_log=uart_log', workflow)


    def test_sigterm_is_converted_into_reportable_interruption(self) -> None:
        checks = ROOT / "qa/checks/firmware"
        sys.path.insert(0, str(checks))
        try:
            import hil_evidence
            with mock.patch.object(hil_evidence.signal, "getsignal", return_value="previous"), \
                 mock.patch.object(hil_evidence.signal, "signal") as install:
                with hil_evidence.reportable_interruptions():
                    handler = install.call_args_list[0].args[1]
                    with self.assertRaises(KeyboardInterrupt):
                        handler(hil_evidence.signal.SIGTERM, None)
                self.assertEqual(install.call_args_list[-1].args, (hil_evidence.signal.SIGTERM, "previous"))
        finally:
            sys.path.pop(0)

        hardware = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text(encoding="utf-8")
        workflow = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text(encoding="utf-8")
        self.assertIn("@reportable_interruptions()\ndef main() -> int:", hardware)
        self.assertIn("@reportable_interruptions()\ndef main() -> int:", workflow)


if __name__ == "__main__":
    unittest.main()
