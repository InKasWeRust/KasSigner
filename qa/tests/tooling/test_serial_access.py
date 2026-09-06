#!/usr/bin/env python3
"""Regression coverage for Linux dialout remediation used by firmware flashing."""
from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path
import subprocess
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/common/lib/serial_access.py"
SPEC = importlib.util.spec_from_file_location("serial_access", HELPER)
assert SPEC and SPEC.loader
SERIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERIAL)

TEST_USERNAME = "qauser"
TEST_HOME = f"/home/{TEST_USERNAME}"


class SerialAccessTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "dialout remediation is Linux-specific")
    def test_no_protected_serial_device_is_a_noop(self) -> None:
        command = ["espflash", "flash", "firmware"]
        group = types.SimpleNamespace(gr_gid=20, gr_mem=[])
        with (
            mock.patch.object(SERIAL.os, "geteuid", return_value=1000),
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(SERIAL, "_dialout_group", return_value=group),
            mock.patch.object(SERIAL, "_candidate_ports", return_value=[]),
        ):
            self.assertEqual(SERIAL.prepare_serial_command(command), command)

    @unittest.skipUnless(sys.platform.startswith("linux"), "dialout remediation is Linux-specific")
    def test_active_dialout_membership_does_not_wrap_command(self) -> None:
        command = ["espflash", "flash", "firmware"]
        group = types.SimpleNamespace(gr_gid=20, gr_mem=[TEST_USERNAME])
        port = Path("/dev/ttyACM0")
        with (
            mock.patch.object(SERIAL.os, "geteuid", return_value=1000),
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(SERIAL, "_dialout_group", return_value=group),
            mock.patch.object(SERIAL, "_candidate_ports", return_value=[port]),
            mock.patch.object(SERIAL, "_needs_dialout", return_value=True),
            mock.patch.object(SERIAL, "_username", return_value=TEST_USERNAME),
            mock.patch.object(SERIAL, "_persistent_member", return_value=True),
            mock.patch.object(SERIAL, "_active_member", return_value=True),
        ):
            self.assertEqual(SERIAL.prepare_serial_command(command, str(port)), command)

    @unittest.skipUnless(sys.platform.startswith("linux"), "dialout remediation is Linux-specific")
    def test_stale_shell_reexecs_flash_under_dialout_without_sudo(self) -> None:
        command = [f"{TEST_HOME}/.cargo/bin/espflash", "flash", "--port", "/dev/ttyACM0", "firmware path"]
        group = types.SimpleNamespace(gr_gid=20, gr_mem=[TEST_USERNAME])
        port = Path("/dev/ttyACM0")
        with (
            mock.patch.object(SERIAL.os, "geteuid", return_value=1000),
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(SERIAL, "_dialout_group", return_value=group),
            mock.patch.object(SERIAL, "_candidate_ports", return_value=[port]),
            mock.patch.object(SERIAL, "_needs_dialout", return_value=True),
            mock.patch.object(SERIAL, "_username", return_value=TEST_USERNAME),
            mock.patch.object(SERIAL, "_persistent_member", return_value=True),
            mock.patch.object(SERIAL, "_active_member", return_value=False),
            mock.patch.object(SERIAL, "_sudo_add_membership") as add,
            mock.patch.object(SERIAL.shutil, "which", side_effect=lambda name: "/usr/bin/sg" if name == "sg" else None),
        ):
            wrapped = SERIAL.prepare_serial_command(command, str(port))
        add.assert_not_called()
        self.assertEqual(wrapped[:3], ["/usr/bin/sg", "dialout", "-c"])
        self.assertIn("espflash", wrapped[3])
        self.assertIn("'firmware path'", wrapped[3])

    @unittest.skipUnless(sys.platform.startswith("linux"), "dialout remediation is Linux-specific")
    def test_missing_membership_is_added_before_sg_reexec(self) -> None:
        command = ["espflash", "flash", "firmware"]
        group = types.SimpleNamespace(gr_gid=20, gr_mem=[])
        port = Path("/dev/ttyACM0")
        with (
            mock.patch.object(SERIAL.os, "geteuid", return_value=1000),
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(SERIAL, "_dialout_group", return_value=group),
            mock.patch.object(SERIAL, "_candidate_ports", return_value=[port]),
            mock.patch.object(SERIAL, "_needs_dialout", return_value=True),
            mock.patch.object(SERIAL, "_username", return_value=TEST_USERNAME),
            mock.patch.object(SERIAL, "_persistent_member", return_value=False),
            mock.patch.object(SERIAL, "_active_member", return_value=False),
            mock.patch.object(SERIAL, "_sudo_add_membership") as add,
            mock.patch.object(SERIAL.shutil, "which", side_effect=lambda name: "/usr/bin/sg" if name == "sg" else None),
        ):
            wrapped = SERIAL.prepare_serial_command(command, str(port))
        add.assert_called_once_with(TEST_USERNAME)
        self.assertEqual(wrapped[:3], ["/usr/bin/sg", "dialout", "-c"])

    def test_sudo_prompt_explains_scope_and_never_runs_espflash_as_root(self) -> None:
        group = types.SimpleNamespace(gr_gid=20, gr_mem=[TEST_USERNAME])
        completed = subprocess.CompletedProcess(args=[], returncode=0)
        output = io.StringIO()
        with (
            mock.patch.object(SERIAL.sys.stdin, "isatty", return_value=True),
            mock.patch.object(SERIAL.shutil, "which", side_effect=lambda name: {"sudo": "/usr/bin/sudo", "usermod": "/usr/sbin/usermod"}.get(name)),
            mock.patch.object(SERIAL.subprocess, "run", return_value=completed) as run,
            mock.patch.object(SERIAL, "_dialout_group", return_value=group),
            mock.patch.object(SERIAL, "_persistent_member", return_value=True),
            mock.patch("sys.stdout", output),
        ):
            SERIAL._sudo_add_membership(TEST_USERNAME)
        run.assert_called_once_with(
            ["/usr/bin/sudo", "/usr/sbin/usermod", "-aG", "dialout", TEST_USERNAME], check=False
        )
        text = output.getvalue()
        self.assertIn("sudo password may be requested", text)
        self.assertIn("espflash are NOT run as root", text)
        self.assertIn("newgrp-equivalent via sg", text)

    def test_noninteractive_missing_membership_fails_without_sudo(self) -> None:
        with (
            mock.patch.object(SERIAL.sys.stdin, "isatty", return_value=False),
            mock.patch.object(SERIAL.shutil, "which", return_value="/bin/tool"),
            mock.patch.object(SERIAL.subprocess, "run") as run,
        ):
            with self.assertRaises(SERIAL.SerialAccessError):
                SERIAL._sudo_add_membership(TEST_USERNAME)
        run.assert_not_called()

    def test_non_linux_hosts_are_noop(self) -> None:
        command = ["espflash", "flash", "firmware"]
        with mock.patch.object(SERIAL.sys, "platform", "win32"):
            self.assertEqual(SERIAL.prepare_serial_command(command), command)


if __name__ == "__main__":
    unittest.main()
