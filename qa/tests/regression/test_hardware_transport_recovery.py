#!/usr/bin/env python3
"""connected-hardware transport recovery and no-reflash safety contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps" / "signer-firmware"


class HardwareTransportRecoveryTests(unittest.TestCase):
    def test_core_s3_connection_policy_forces_native_usb_reset(self) -> None:
        layout = (ROOT / "tools/build/firmware/board_layout.py").read_text()
        self.assertIn('args = ["--chip", "esp32s3"]', layout)
        self.assertIn('if self.board == "m5stack":', layout)
        self.assertIn('args.extend(("--before", "usb-reset"))', layout)
        for helper in (ROOT / "scripts/common/lib/make_tasks.py",):
            source = helper.read_text()
            self.assertIn('"connection-args", "--board", board', source)
            self.assertIn('command = ["espflash", "flash", "--monitor"', source)

    def test_connected_runner_retries_only_before_flash_completion(self) -> None:
        source = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text()
        self.assertIn("FLASH_CONNECT_ATTEMPTS = 3", source)
        self.assertIn('FLASH_COMPLETE_MARKER = "Flashing has completed!"', source)
        self.assertIn("retryable_transport_failure", source)
        self.assertIn("if flash_complete:", source)
        self.assertIn("firmware will NOT be reflashed", source)
        self.assertIn("wait_for_explicit_port(port)", source)
        self.assertIn("command = prepare_serial_command(base_command, port)", source)
        self.assertIn("resolve_noninteractive_port", source)
        self.assertIn("multiple serial ports are visible", source)

    def test_post_flash_recovery_is_monitor_only_and_cannot_reset(self) -> None:
        source = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text()
        block = source.split("def monitor_reconnect_command", 1)[1].split("def reconnect_monitor", 1)[0]
        self.assertIn('"espflash",\n        "monitor",', block)
        self.assertIn('"--non-interactive"', block)
        self.assertIn('"no-reset-no-sync"', block)
        self.assertIn('"--chip",\n        "esp32s3"', block)
        self.assertNotIn('"flash"', block)
        self.assertNotIn('"reset"', block)



if __name__ == "__main__":
    unittest.main()
