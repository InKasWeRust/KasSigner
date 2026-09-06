#!/usr/bin/env python3
"""Regression tests for the opt-in connected ESP hardware runner."""

from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "qa" / "checks" / "firmware" / "run_hardware_tests.py"
SPEC = importlib.util.spec_from_file_location("hardware_runner", RUNNER_PATH)
assert SPEC and SPEC.loader
HARDWARE_RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARDWARE_RUNNER)


def _fake_espflash_from_path() -> Path | None:
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / "espflash"
        if candidate.is_file():
            return candidate
    return None


def _windows_bash() -> str | None:
    bash = shutil.which("bash")
    if bash:
        return bash
    # MSYS2 Python can be selected by the Windows QA runner even when usr/bin
    # is not inherited in PATH. Resolve the sibling bash installation directly.
    executable = Path(sys.executable)
    for parent in executable.parents:
        candidate = parent / "usr" / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def simulated_flash_and_monitor(*args: object, **kwargs: object) -> int:
    """Exercise monitor/transport logic without consulting real host serial devices."""
    kwargs["connected_transport"] = False
    if os.name != "nt":
        return HARDWARE_RUNNER.flash_and_monitor(*args, **kwargs)

    fixture = _fake_espflash_from_path()
    if fixture is None:
        return HARDWARE_RUNNER.flash_and_monitor(*args, **kwargs)
    bash = _windows_bash()
    if bash is None:
        raise unittest.SkipTest("MSYS2/Git Bash is unavailable for the fake espflash fixture")

    real_popen = subprocess.Popen

    def portable_popen(command: list[str], *popen_args: object, **popen_kwargs: object):
        if command and command[0] == "espflash":
            command = [bash, fixture.as_posix(), *command[1:]]
        return real_popen(command, *popen_args, **popen_kwargs)

    with mock.patch.object(HARDWARE_RUNNER.subprocess, "Popen", side_effect=portable_popen):
        return HARDWARE_RUNNER.flash_and_monitor(*args, **kwargs)


class HardwareDeviceRunnerTests(unittest.TestCase):
    def run_fake_monitor(self, marker: str) -> int:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            tty_guard = (
                "if [[ ! -t 0 ]]; then printf 'Error: Failed to initialize input reader\\n'; exit 9; fi\n"
                if os.name == "posix" else ""
            )
            executable.write_text(
                "#!/usr/bin/env bash\n"
                + tty_guard
                + ("printf 'Flashing has completed!\\nbooting\\n%s\\n'\n" % marker),
                encoding="utf-8",
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                return simulated_flash_and_monitor("waveshare", image, None, 3)

    def test_pass_marker_returns_success(self) -> None:
        self.assertEqual(self.run_fake_monitor(HARDWARE_RUNNER.PASS_MARKER), 0)

    def test_fail_marker_returns_failure(self) -> None:
        self.assertEqual(self.run_fake_monitor(HARDWARE_RUNNER.FAIL_MARKER), 1)

    def test_terminal_pass_is_rejected_when_required_runtime_evidence_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\nKASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare",
                    image,
                    None,
                    3,
                    required_markers=("REQUIRED-EVIDENCE",),
                )
            self.assertEqual(result, 1)

    def test_required_runtime_evidence_survives_monitor_reconnect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ $1 == flash ]]; then\n"
                "  printf 'Flashing has completed!\nREQUIRED-EVIDENCE\n'\n"
                "  exit 1\n"
                "fi\n"
                "printf 'KASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare",
                    image,
                    None,
                    3,
                    required_markers=("REQUIRED-EVIDENCE",),
                )
            self.assertEqual(result, 0)

    def test_ordered_runtime_evidence_accepts_exact_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\nSTEP-A\nSTEP-B\nSTEP-C\nKASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    ordered_markers=("STEP-A", "STEP-B", "STEP-C"),
                )
            self.assertEqual(result, 0)

    def test_ordered_runtime_evidence_rejects_out_of_order_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\nSTEP-A\nSTEP-C\nSTEP-B\nKASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    ordered_markers=("STEP-A", "STEP-B", "STEP-C"),
                )
            self.assertEqual(result, 1)

    def test_ordered_runtime_evidence_survives_monitor_reconnect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ $1 == flash ]]; then\n"
                "  printf 'Flashing has completed!\nSTEP-A\nSTEP-B\n'\n"
                "  exit 1\n"
                "fi\n"
                "printf 'STEP-C\nKASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    ordered_markers=("STEP-A", "STEP-B", "STEP-C"),
                )
            self.assertEqual(result, 0)

    def test_panic_banner_keeps_following_diagnostic_lines_visible(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        marker = (
            "====================== PANIC ======================\n"
            "panicked at src/example.rs:42:7: synthetic panic detail\n"
            "Backtrace: synthetic-frame"
        )
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = self.run_fake_monitor(marker)
        self.assertEqual(result, 1)
        self.assertIn("synthetic panic detail", stdout.getvalue())
        self.assertIn("synthetic-frame", stdout.getvalue())
        self.assertIn("panic detected; capturing the diagnostic tail", stdout.getvalue())

    def test_monitor_path_runs_serial_permission_preflight_once(self) -> None:
        with mock.patch.object(
            HARDWARE_RUNNER,
            "prepare_serial_command",
            side_effect=lambda command, port: command,
        ) as prepare:
            self.assertEqual(self.run_fake_monitor(HARDWARE_RUNNER.PASS_MARKER), 0)
        prepare.assert_called_once()


    def test_serial_port_busy_preflight_names_process_owner(self) -> None:
        with mock.patch.object(
            HARDWARE_RUNNER,
            "serial_port_owners",
            return_value=((4242, "screen /dev/ttyACM1"),),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                r"/dev/ttyACM1.*PID 4242: screen /dev/ttyACM1",
            ):
                HARDWARE_RUNNER.ensure_serial_port_available("/dev/ttyACM1")

    def test_serial_port_available_preflight_accepts_unowned_device(self) -> None:
        with mock.patch.object(HARDWARE_RUNNER, "serial_port_owners", return_value=()):
            self.assertIsNone(HARDWARE_RUNNER.ensure_serial_port_available("/dev/ttyACM1"))

    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"), "stale monitor reclamation is Linux-specific")
    def test_stale_managed_espflash_owner_is_reclaimed(self) -> None:
        command = (
            "espflash flash --monitor --chip esp32s3 --partition-table "
            + str(HARDWARE_RUNNER.FIRMWARE / "partitions/m5stack-cores3.csv")
            + " --port /dev/ttyACM1 "
            + str(
                HARDWARE_RUNNER.FIRMWARE
                / "target/xtensa-esp32s3-none-elf/release/kassigner-firmware"
            )
        )
        with mock.patch.object(
            HARDWARE_RUNNER,
            "serial_port_owners",
            side_effect=[((11062, command),), ()],
        ), mock.patch.object(
            HARDWARE_RUNNER, "_has_connected_runner_ancestor", return_value=False
        ), mock.patch.object(
            HARDWARE_RUNNER, "_process_parent_pid", return_value=1
        ), mock.patch.object(
            HARDWARE_RUNNER, "_process_has_environment", return_value=False
        ), mock.patch.object(HARDWARE_RUNNER.os, "getpgid", return_value=11062), mock.patch.object(
            HARDWARE_RUNNER.os, "killpg"
        ) as killpg:
            self.assertIsNone(HARDWARE_RUNNER.ensure_serial_port_available("/dev/ttyACM1"))
        killpg.assert_called_once_with(11062, HARDWARE_RUNNER.signal.SIGTERM)

    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"), "stale monitor reclamation is Linux-specific")
    def test_manual_espflash_lookalike_owned_by_shell_is_not_reclaimed(self) -> None:
        command = (
            "espflash flash --monitor --chip esp32s3 --partition-table "
            + str(HARDWARE_RUNNER.FIRMWARE / "partitions/m5stack-cores3.csv")
            + " --port /dev/ttyACM1 "
            + str(
                HARDWARE_RUNNER.FIRMWARE
                / "target/xtensa-esp32s3-none-elf/release/kassigner-firmware"
            )
        )
        with mock.patch.object(
            HARDWARE_RUNNER, "serial_port_owners", return_value=((11063, command),)
        ), mock.patch.object(
            HARDWARE_RUNNER, "_has_connected_runner_ancestor", return_value=False
        ), mock.patch.object(
            HARDWARE_RUNNER, "_process_parent_pid", return_value=777
        ), mock.patch.object(
            HARDWARE_RUNNER, "_process_has_environment", return_value=False
        ), mock.patch.object(HARDWARE_RUNNER.os, "killpg") as killpg:
            with self.assertRaisesRegex(RuntimeError, r"another live process.*PID 11063"):
                HARDWARE_RUNNER.ensure_serial_port_available("/dev/ttyACM1")
        killpg.assert_not_called()

    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"), "stale monitor reclamation is Linux-specific")
    def test_managed_espflash_owned_by_live_runner_is_not_reclaimed(self) -> None:
        command = (
            "espflash flash --monitor --chip esp32s3 --partition-table "
            + str(HARDWARE_RUNNER.FIRMWARE / "partitions/m5stack-cores3.csv")
            + " --port /dev/ttyACM1 "
            + str(
                HARDWARE_RUNNER.FIRMWARE
                / "target/xtensa-esp32s3-none-elf/release/kassigner-firmware"
            )
        )
        with mock.patch.object(
            HARDWARE_RUNNER, "serial_port_owners", return_value=((11062, command),)
        ), mock.patch.object(
            HARDWARE_RUNNER, "_has_connected_runner_ancestor", return_value=True
        ), mock.patch.object(HARDWARE_RUNNER.os, "killpg") as killpg:
            with self.assertRaisesRegex(RuntimeError, r"another live process.*PID 11062"):
                HARDWARE_RUNNER.ensure_serial_port_available("/dev/ttyACM1")
        killpg.assert_not_called()

    def test_simulated_monitor_never_consults_real_serial_ownership(self) -> None:
        with mock.patch.object(
            HARDWARE_RUNNER,
            "serial_port_owners",
            side_effect=AssertionError("simulated monitor consulted real serial ownership"),
        ), mock.patch.object(
            HARDWARE_RUNNER,
            "resolve_noninteractive_port",
            side_effect=AssertionError("simulated monitor auto-detected a real serial port"),
        ):
            self.assertEqual(self.run_fake_monitor(HARDWARE_RUNNER.PASS_MARKER), 0)

    @unittest.skipUnless(os.name == "posix", "private PTY contract is POSIX-specific")
    def test_supervised_monitor_uses_private_tty_not_caller_keyboard(self) -> None:
        with HARDWARE_RUNNER.private_monitor_input() as monitor_stdin:
            self.assertIsInstance(monitor_stdin, int)
            assert isinstance(monitor_stdin, int)
            self.assertTrue(os.isatty(monitor_stdin))
            if sys.stdin.isatty():
                self.assertNotEqual(os.ttyname(monitor_stdin), os.ttyname(sys.stdin.fileno()))

    def test_long_operation_marker_can_extend_monitor_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            marker = "LONG-OP-BEGIN"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\\nLONG-OP-BEGIN\\n'\n"
                "sleep 1.2\n"
                "printf 'KASSIGNER_HARDWARE_TESTS: PASS\\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare",
                    image,
                    None,
                    1,
                    deadline_extension_marker=marker,
                    deadline_extension_seconds=3,
                )
            self.assertEqual(result, 0)

    def test_per_action_timeout_override_allows_cooperative_runtime_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\nACTION BEGIN cooperative\n'\n"
                "sleep 1.2\n"
                "printf 'ACTION PASS cooperative\nKASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    operation_start_prefix="ACTION BEGIN ",
                    operation_end_prefix="ACTION PASS ",
                    operation_timeout=1,
                    operation_timeouts={"cooperative": 3},
                )
            self.assertEqual(result, 0)

    def test_per_action_timeout_keeps_default_for_blocking_runtime_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\nACTION BEGIN blocking\n'\n"
                "sleep 1.2\n"
                "printf 'ACTION PASS blocking\nKASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    operation_start_prefix="ACTION BEGIN ",
                    operation_end_prefix="ACTION PASS ",
                    operation_timeout=1,
                    operation_timeouts={"cooperative": 3},
                )
            self.assertEqual(result, 124)

    def test_device_deadline_starts_after_flash_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "sleep 1.2\n"
                "printf 'Flashing has completed!\\n'\n"
                "sleep 0.2\n"
                "printf 'KASSIGNER_HARDWARE_TESTS: PASS\\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor("waveshare", image, None, 1)
            self.assertEqual(result, 0)

    def test_connection_failure_retries_before_flash_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            counter = root / "attempts"
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "cd -- \"$(dirname -- \"$0\")\"\n"
                "count=$(cat attempts 2>/dev/null || printf 0)\n"
                "count=$((count + 1))\n"
                "printf '%s' \"$count\" > attempts\n"
                "if [[ $count -eq 1 ]]; then\n"
                "  printf 'Error: espflash::connection_failed\\nFailed to connect to the device\\n'\n"
                "  exit 1\n"
                "fi\n"
                "printf 'Flashing has completed!\\nKASSIGNER_HARDWARE_TESTS: PASS\\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}), mock.patch.object(
                HARDWARE_RUNNER.time, "sleep", return_value=None
            ):
                result = simulated_flash_and_monitor("waveshare", image, None, 3)
            self.assertEqual(result, 0)
            self.assertEqual(counter.read_text(encoding="utf-8"), "2")

    def test_failure_after_flash_completion_recovers_monitor_without_reflash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            flash_counter = root / "flash-attempts"
            monitor_counter = root / "monitor-attempts"
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "cd -- \"$(dirname -- \"$0\")\"\n"
                "if [[ $1 == flash ]]; then\n"
                "  count=$(cat flash-attempts 2>/dev/null || printf 0)\n"
                "  count=$((count + 1))\n"
                "  printf '%s' \"$count\" > flash-attempts\n"
                "  printf 'Flashing has completed!\\n'\n"
                "  exit 1\n"
                "fi\n"
                "count=$(cat monitor-attempts 2>/dev/null || printf 0)\n"
                "count=$((count + 1))\n"
                "printf '%s' \"$count\" > monitor-attempts\n"
                "printf 'KASSIGNER_HARDWARE_TESTS: PASS\\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor("waveshare", image, None, 3)
            self.assertEqual(result, 0)
            self.assertEqual(flash_counter.read_text(encoding="utf-8"), "1")
            self.assertEqual(monitor_counter.read_text(encoding="utf-8"), "1")

    def test_monitor_reconnect_command_cannot_reset_or_reflash(self) -> None:
        command = HARDWARE_RUNNER.monitor_reconnect_command(Path("firmware.elf"), "/dev/ttyACM0")
        self.assertEqual(command[0:3], ["espflash", "monitor", "--non-interactive"])
        self.assertIn("--before", command)
        self.assertEqual(command[command.index("--before") + 1], "no-reset-no-sync")
        self.assertEqual(command[command.index("--chip") + 1], "esp32s3")
        self.assertNotIn("flash", command)
        self.assertNotIn("reset", command)

    def test_serial_permission_preflight_runs_after_port_reappears(self) -> None:
        events: list[str] = []
        image = Path("firmware.elf")

        def waited(_port: str | None, timeout: int = HARDWARE_RUNNER.SERIAL_REENUMERATION_TIMEOUT_SECONDS) -> None:
            del timeout
            events.append("wait")

        def prepared(command: list[str], _port: str | None) -> list[str]:
            events.append("prepare")
            return command

        def attempted(*_args: object, **_kwargs: object) -> tuple[int, bool, bool, bool]:
            events.append("open")
            return 0, False, True, True

        with mock.patch.object(HARDWARE_RUNNER, "wait_for_explicit_port", side_effect=waited), \
             mock.patch.object(HARDWARE_RUNNER, "prepare_serial_command", side_effect=prepared), \
             mock.patch.object(HARDWARE_RUNNER, "_run_flash_monitor_attempt", side_effect=attempted):
            result = simulated_flash_and_monitor("m5stack", image, "/dev/ttyACM0", 3)

        self.assertEqual(result, 0)
        self.assertEqual(events, ["wait", "prepare", "open"])

    def test_monitor_reconnect_rechecks_permissions_after_reenumeration(self) -> None:
        events: list[str] = []

        def waited(_port: str | None, timeout: int = HARDWARE_RUNNER.SERIAL_REENUMERATION_TIMEOUT_SECONDS) -> None:
            del timeout
            events.append("wait")

        def prepared(command: list[str], _port: str | None) -> list[str]:
            events.append("prepare")
            return command

        def attempted(*_args: object, **_kwargs: object) -> tuple[int, bool, bool, bool]:
            events.append("open")
            return 0, False, True, True

        with mock.patch.object(HARDWARE_RUNNER, "wait_for_explicit_port", side_effect=waited), \
             mock.patch.object(HARDWARE_RUNNER, "prepare_serial_command", side_effect=prepared), \
             mock.patch.object(HARDWARE_RUNNER, "_run_flash_monitor_attempt", side_effect=attempted):
            result = HARDWARE_RUNNER.reconnect_monitor(
                Path("firmware.elf"),
                "/dev/ttyACM0",
                3,
                pass_marker=HARDWARE_RUNNER.PASS_MARKER,
                fail_marker=HARDWARE_RUNNER.FAIL_MARKER,
                success_label="hardware tests",
                status_interval=None,
                repeat_abort_marker=None,
                phase_start_marker=None,
                phase_end_marker=None,
                phase_timeout=None,
                deadline_extension_marker=None,
                deadline_extension_seconds=None,
            )

        self.assertEqual(result, 0)
        self.assertEqual(events, ["wait", "prepare", "open"])

    @unittest.skipUnless(os.name == "posix", "non-interactive auto-port policy is POSIX-specific")
    def test_auto_port_chooses_only_visible_serial_device(self) -> None:
        with mock.patch.object(HARDWARE_RUNNER.glob, "glob", side_effect=[["/dev/ttyACM7"], []]):
            self.assertEqual(HARDWARE_RUNNER.resolve_noninteractive_port(None), "/dev/ttyACM7")

    @unittest.skipUnless(os.name == "posix", "non-interactive auto-port policy is POSIX-specific")
    def test_auto_port_refuses_ambiguous_unattended_prompt(self) -> None:
        with mock.patch.object(
            HARDWARE_RUNNER.glob,
            "glob",
            side_effect=[["/dev/ttyACM0", "/dev/ttyACM1"], []],
        ), mock.patch.object(HARDWARE_RUNNER, "_usb_vid_pid", return_value=("0000", "0000")):
            with self.assertRaisesRegex(RuntimeError, "multiple serial ports"):
                HARDWARE_RUNNER.resolve_noninteractive_port(None)

    @unittest.skipUnless(os.name == "posix", "non-interactive auto-port policy is POSIX-specific")
    def test_auto_port_prefers_unique_espressif_device(self) -> None:
        def identity(port: Path) -> tuple[str, str]:
            return ("303a", "1001") if port.name == "ttyACM1" else ("1a86", "7523")

        with mock.patch.object(
            HARDWARE_RUNNER.glob,
            "glob",
            side_effect=[["/dev/ttyACM0", "/dev/ttyACM1"], []],
        ), mock.patch.object(HARDWARE_RUNNER, "_usb_vid_pid", side_effect=identity):
            self.assertEqual(HARDWARE_RUNNER.resolve_noninteractive_port(None), "/dev/ttyACM1")


    def test_m5stack_transport_retries_use_distinct_reset_strategies(self) -> None:
        image = Path("firmware.elf")
        seen_modes: list[str] = []

        def attempted(command: list[str], *_args: object, **_kwargs: object) -> tuple[int, bool, bool, bool]:
            before = command.index("--before")
            seen_modes.append(command[before + 1])
            if len(seen_modes) < 3:
                return 1, True, False, False
            return 0, False, True, True

        with mock.patch.object(HARDWARE_RUNNER, "wait_for_explicit_port", return_value=None), \
             mock.patch.object(HARDWARE_RUNNER, "prepare_serial_command", side_effect=lambda command, _port: command), \
             mock.patch.object(HARDWARE_RUNNER, "_run_flash_monitor_attempt", side_effect=attempted), \
             mock.patch.object(HARDWARE_RUNNER.time, "sleep", return_value=None):
            result = simulated_flash_and_monitor("m5stack", image, "/dev/ttyACM0", 3)

        self.assertEqual(result, 0)
        self.assertEqual(seen_modes, ["usb-reset", "no-reset", "default-reset"])

    def test_m5stack_forces_native_usb_reset_and_known_chip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args_file = root / "args"
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$@\" > '{args_file.as_posix()}'\n"
                "printf 'Flashing has completed!\\nKASSIGNER_HARDWARE_TESTS: PASS\\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor("m5stack", image, None, 3)
            self.assertEqual(result, 0)
            args = args_file.read_text().splitlines()
            self.assertEqual(args[0:3], ["flash", "--monitor", "--chip"])
            self.assertIn("esp32s3", args)
            before = args.index("--before")
            self.assertEqual(args[before + 1], "usb-reset")

    def test_repeat_abort_ignores_preflash_marker_from_old_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'Flashing has completed!\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE\n'\n"
                "printf 'WORKFLOW-PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    pass_marker="WORKFLOW-PASS",
                    fail_marker="WORKFLOW-FAIL",
                    success_label="workflow E2E contracts",
                    repeat_abort_marker="KASSIGNER_WORKFLOW_TESTS: BEGIN",
                )
            self.assertEqual(result, 0)

    def test_repeat_abort_tolerates_duplicate_postflash_marker_before_arm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE\n'\n"
                "printf 'WORKFLOW-PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    pass_marker="WORKFLOW-PASS",
                    fail_marker="WORKFLOW-FAIL",
                    success_label="workflow E2E contracts",
                    repeat_abort_marker="KASSIGNER_WORKFLOW_TESTS: BEGIN",
                    repeat_abort_arm_marker="KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE",
                )
            self.assertEqual(result, 0)

    def test_repeat_abort_rejects_marker_after_arm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'WORKFLOW-PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    pass_marker="WORKFLOW-PASS",
                    fail_marker="WORKFLOW-FAIL",
                    success_label="workflow E2E contracts",
                    repeat_abort_marker="KASSIGNER_WORKFLOW_TESTS: BEGIN",
                    repeat_abort_arm_marker="KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE",
                )
            self.assertEqual(result, 1)

    def test_repeat_abort_rejects_second_postflash_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE\n'\n"
                "printf 'KASSIGNER_WORKFLOW_TESTS: BEGIN\n'\n"
                "printf 'WORKFLOW-PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    pass_marker="WORKFLOW-PASS",
                    fail_marker="WORKFLOW-FAIL",
                    success_label="workflow E2E contracts",
                    repeat_abort_marker="KASSIGNER_WORKFLOW_TESTS: BEGIN",
                )
            self.assertEqual(result, 1)

    def test_supervised_monitor_preserves_terminal_and_avoids_devnull_input(self) -> None:
        source = RUNNER_PATH.read_text()
        self.assertNotIn("stdin=subprocess.DEVNULL", source)
        self.assertIn("private_monitor_input", source)
        self.assertIn("stdin=monitor_stdin", source)
        self.assertIn("with preserved_terminal(), private_monitor_input() as monitor_stdin:", source)
        self.assertIn("Serial monitor stopped; terminal state restored.", source)
        self.assertIn("device test still running", source)
        self.assertIn("repeat_abort_marker", source)
        self.assertIn("deadline_extension_marker", source)
        self.assertIn("long-running device operation detected", source)
        self.assertIn("rebooted before", source)
        self.assertIn("FLASH_CONNECT_ATTEMPTS = 3", source)
        self.assertIn("MONITOR_RECONNECT_ATTEMPTS = 3", source)
        self.assertIn("FLASH_COMPLETE_MARKER", source)
        self.assertIn('"no-reset-no-sync"', source)
        self.assertIn("firmware will NOT be reflashed", source)


    def test_graph_derived_runtime_state_evidence_normalizes_payload_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\nKASSIGNER_UI_RUNTIME: RENDER MainMenu\n"
                "KASSIGNER_UI_RUNTIME: RENDER ReviewTx { page: 2 }\n"
                "KASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    runtime_state_prefix="KASSIGNER_UI_RUNTIME: RENDER ",
                    required_runtime_states=("MainMenu", "ReviewTx"),
                )
            self.assertEqual(result, 0)

    def test_terminal_pass_is_rejected_when_graph_derived_runtime_state_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "espflash"
            executable.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'Flashing has completed!\nKASSIGNER_UI_RUNTIME: RENDER MainMenu\n"
                "KASSIGNER_HARDWARE_TESTS: PASS\n'\n"
            )
            executable.chmod(0o755)
            image = root / "firmware"
            image.write_bytes(b"ELF")
            with mock.patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
                result = simulated_flash_and_monitor(
                    "waveshare", image, None, 3,
                    runtime_state_prefix="KASSIGNER_UI_RUNTIME: RENDER ",
                    required_runtime_states=("MainMenu", "ReviewTx"),
                )
            self.assertEqual(result, 1)

if __name__ == "__main__":
    unittest.main()
