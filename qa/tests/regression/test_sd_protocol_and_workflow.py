#!/usr/bin/env python3
"""CMD42 compatibility, write-protect, and workflow/HIL isolation contracts."""
from pathlib import Path
import importlib.util
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps" / "signer-firmware"


class SdProtocolAndWorkflowTests(unittest.TestCase):
    def test_force_erase_uses_spec_exact_one_byte_cmd42_block_with_computed_crc(self) -> None:
        lock = (FW / "src/hw/m5stack/storage/transport/protocol/lock.rs").read_text()
        self.assertIn("const FORCE_ERASE_MODE: u8 = 0x08;", lock)
        force_len = lock.split("fn force_erase_block_len", 1)[1].split("fn run_force_erase", 1)[0]
        self.assertIn("set_block_length(1)?", force_len)
        self.assertIn("Ok(1)", force_len)
        self.assertNotIn("SdV2Hc", force_len)
        self.assertIn("crc16_ccitt(payload)", lock)
        self.assertIn("payload[0] = FORCE_ERASE_MODE", lock)

    def test_permanent_write_protect_is_checked_before_cmd42(self) -> None:
        capacity = (FW / "src/hw/m5stack/storage/transport/capacity.rs").read_text()
        recovery = (FW / "src/hw/m5stack/storage/transport/card_recovery.rs").read_text()
        self.assertIn("CSD_PERMANENT_WRITE_PROTECT: u8 = 0x20", capacity)
        self.assertIn("CSD_TEMPORARY_WRITE_PROTECT: u8 = 0x10", capacity)
        self.assertIn("sd_write_protect_flags()?", recovery)
        self.assertIn("PERMANENT WRITE PROTECT", recovery)
        self.assertIn("CMD42 force erase is not permitted", recovery)
        recover = recovery.split("fn recover_if_locked", 1)[1].split("fn resolve_force_erase_attempt", 1)[0]
        self.assertLess(
            recover.index("reject_permanent_write_protect()?"),
            recover.index("protocol_force_erase_locked_card(card_type, delay, liveness, timeout_ms)"),
        )

    def test_timeout_leaves_card_powered_and_never_restarts_erase(self) -> None:
        recovery = (FW / "src/hw/m5stack/storage/transport/card_recovery.rs").read_text()
        resolution = recovery.split("fn resolve_force_erase_attempt", 1)[1]
        self.assertIn("CARD LEFT POWERED", resolution)
        self.assertIn("card left powered and was not reset", resolution)
        self.assertNotIn("power_cycle_card", resolution)
        self.assertNotIn("retry_force_erase", resolution)

    def test_physical_media_mutation_workflow_remains_hil_only(self) -> None:
        transport = (FW / "src/hw/m5stack/storage/transport/mod.rs").read_text()
        service = (FW / "src/services/hardware/storage_device.rs").read_text()
        media = (FW / "src/runtime/workflow_tests/connected/sd_media.rs").read_text()
        self.assertIn("mod card_recovery;", transport)
        self.assertIn(
            '#[cfg(all(feature = "workflow-hil-auto", feature = "m5stack"))]\n'
            'pub(crate) fn workflow_force_erase_locked_card',
            service,
        )
        self.assertIn("pub(crate) fn force_erase_locked_card(", service)
        self.assertIn("runtime hold-to-confirm gate", service)
        self.assertIn("PHYSICAL MEDIA MUTATION SKIPPED IN CONTROLLER E2E", media)
        self.assertIn("fn prepare_controller_e2e(sd: &Option<SdCardType>)", media)
        self.assertIn("PHYSICAL TRANCHE DEFERRED TO workflow-hil", media)
        self.assertIn('#[cfg(feature = "workflow-hil-auto")]\nfn prepare_hil_media', media)

    def test_physical_verification_marker_is_emitted_only_after_real_round_trip(self) -> None:
        media = (FW / "src/runtime/workflow_tests/connected/sd_media.rs").read_text()
        workflows = (FW / "src/runtime/workflow_tests/connected/sd_workflows/mod.rs").read_text()
        round_trip = media.split("fn verify_round_trip", 1)[1]
        self.assertIn("SD MEDIA READ-WRITE-DELETE OK", round_trip)
        self.assertIn("SD PHYSICAL SPI/FAT32 READ-WRITE VERIFIED", round_trip)
        self.assertNotIn("SD PHYSICAL SPI/FAT32 READ-WRITE VERIFIED", workflows)

    def test_real_card_scan_is_hil_only_but_controller_browser_tests_remain(self) -> None:
        browser = (FW / "src/runtime/workflow_tests/connected/sd_workflows/browser.rs").read_text()
        self.assertIn('#[cfg(feature = "workflow-hil-auto")]\nfn import_menu_card_scan', browser)
        self.assertIn("SD IMPORT MENU PHYSICAL CARD SCAN DEFERRED TO workflow-hil", browser)
        self.assertIn("paging_and_delete_cancel(ctx)", browser)


    def test_workflow_e2e_excludes_physical_sd_hil_markers_but_hil_requires_them(self) -> None:
        scenarios_path = ROOT / "qa/config/workflow/production_e2e_scenarios.json"
        scenarios = {entry["id"]: entry for entry in json.loads(scenarios_path.read_text())["scenarios"]}
        physical = {
            "SD IMPORT MENU REAL-CARD SCAN/BACK OWNER OK",
            "SD MEDIA READ-WRITE-DELETE OK",
            "SD PHYSICAL SPI/FAT32 READ-WRITE VERIFIED",
        }
        declared = set(scenarios["connected-sd-browser-navigation"]["hil_only_serial_markers"])
        declared.update(scenarios["connected-sd-backup-crypto-overwrite"]["hil_only_serial_markers"])
        self.assertEqual(declared, physical)

        checks = ROOT / "qa/checks/firmware"
        sys.path.insert(0, str(checks))
        try:
            spec = importlib.util.spec_from_file_location("workflow_runner_contract", checks / "run_workflow_tests.py")
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        finally:
            sys.path.pop(0)

        normal = set(module.required_connected_markers())
        hil = set(module.required_connected_markers(include_hil_only=True))
        self.assertTrue(physical.isdisjoint(normal))
        self.assertTrue(physical.issubset(hil))
        self.assertEqual(hil - normal, physical)
        runner = (checks / "run_workflow_tests.py").read_text()
        self.assertIn("required_runtime_evidence_markers(", runner)
        self.assertIn("args.resume_from, args.board, hil=args.hil", runner)

        coverage = (checks / "production_e2e_coverage.py").read_text()
        self.assertIn("hil_only_serial_markers must be a subset of serial_markers", coverage)


if __name__ == "__main__":
    unittest.main()
