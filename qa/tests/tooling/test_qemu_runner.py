#!/usr/bin/env python3
"""Behavior tests for the host-side QEMU marker runner."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "qa/checks/firmware/qemu/run.py"


class QemuRunnerPortabilityTests(unittest.TestCase):
    def test_uart_reader_does_not_use_select_on_process_pipes(self) -> None:
        source = RUNNER.read_text()
        self.assertNotIn("import selectors", source)
        self.assertNotIn("selector.select", source)
        self.assertIn("queue.Queue", source)
        self.assertIn("threading.Thread", source)
        self.assertIn('process.stdout.read(4096)', source)
        self.assertIn("stdin=None if args.keep_running else subprocess.PIPE", source)


@unittest.skipUnless(os.name == "posix", "QEMU fake guest fixture is POSIX-specific")
class QemuRunnerTests(unittest.TestCase):
    def make_guest(self, directory: Path, output: str, status: int = 0) -> Path:
        guest = directory / "qemu-system-xtensa"
        guest.write_text(
            "#!/bin/sh\n"
            f"cat <<'EOF'\n{output}\nEOF\n"
            f"exit {status}\n"
        )
        guest.chmod(0o755)
        return guest

    def run_guest(self, output: str, status: int = 0) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            guest = self.make_guest(directory, output, status)
            image = directory / "flash.bin"
            image.write_bytes(b"flash")
            return subprocess.run(
                [
                    "python3",
                    str(RUNNER),
                    "--qemu",
                    str(guest),
                    "--image",
                    str(image),
                    "--timeout",
                    "2",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_pass_requires_all_guest_markers(self) -> None:
        completed = self.run_guest(
            "Board: ESP32-S3 QEMU\n"
            "KASSIGNER_QEMU_TESTS_BEGIN\n"
            "KASSIGNER_QEMU_UART_PROBE\n"
            "KASSIGNER_QEMU_TESTS_PASS"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PASS: ESP32-S3 QEMU hardware tests completed", completed.stdout)

    def test_guest_failure_marker_fails_host(self) -> None:
        completed = self.run_guest(
            "Board: ESP32-S3 QEMU\n"
            "KASSIGNER_QEMU_TESTS_BEGIN\n"
            "KASSIGNER_QEMU_TESTS_FAIL"
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("guest QEMU hardware tests failed", completed.stderr)

    def test_pass_without_uart_probe_is_rejected(self) -> None:
        completed = self.run_guest(
            "Board: ESP32-S3 QEMU\n"
            "KASSIGNER_QEMU_TESTS_BEGIN\n"
            "KASSIGNER_QEMU_TESTS_PASS"
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("KASSIGNER_QEMU_UART_PROBE", completed.stderr)


if __name__ == "__main__":
    unittest.main()
