#!/usr/bin/env python3
"""Regression contracts for host-owned firmware decisions and thin board adapters."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks/quality/crap"))

from source_complexity import function_decisions  # noqa: E402


ADAPTER_PATHS = (
    "apps/signer-firmware/src/hw/m5stack/storage/transport/protocol/initialization.rs",
    "apps/signer-firmware/src/hw/m5stack/storage/transport/protocol/wire.rs",
    "apps/signer-firmware/src/hw/m5stack/storage/transport/block.rs",
    "apps/signer-firmware/src/hw/m5stack/storage/transport/multi_block.rs",
    "apps/signer-firmware/src/hw/m5stack/storage/transport/card.rs",
    "apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/block.rs",
    "apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/multi_block.rs",
    "apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/multi_block/fifo.rs",
)


class FirmwareDecisionExtractionTests(unittest.TestCase):
    def test_no_std_firmware_parsing_tests_import_vec_macro_explicitly(self) -> None:
        tests = (ROOT / "crates/signer-firmware-core/src/unit_tests/firmware_decisions/parsing.rs").read_text()
        self.assertIn("use std::vec;", tests)
        self.assertIn("vec![b'0'; covenant_len]", tests)
        self.assertIn("vec![b'0'; private_len]", tests)

    def test_firmware_update_paths_follow_extracted_update_manifest_owner(self) -> None:
        classifier = (ROOT / "crates/signer-firmware-core/src/qr/classification.rs").read_text()
        tests = (ROOT / "crates/signer-firmware-core/src/unit_tests/firmware_decisions/update_manifest.rs").read_text()
        self.assertIn("crate::update::manifest::MANIFEST_LEN", classifier)
        self.assertNotIn("super::update_manifest", classifier)
        self.assertIn("use crate::update::manifest as update_manifest;", tests)
        self.assertIn("update_manifest::MANIFEST_LEN", tests)

        generator = (ROOT / "tools/firmware/gen_update_manifest.rs").read_text()
        self.assertIn("use signer_firmware_core::update::manifest as update_manifest;", generator)
        self.assertIn("use signer_firmware_core::update::manifest::FirmwareUpdateManifest;", generator)
        self.assertIn("update_manifest::SCHEMA_VERSION", generator)
        self.assertNotIn("manifest::{\n    self, FirmwareUpdateManifest,", generator)

    def test_extracted_storage_adapters_stay_at_four_decisions_or_less(self) -> None:
        offenders: list[str] = []
        for relative in ADAPTER_PATHS:
            source = (ROOT / relative).read_text()
            for record in function_decisions(source, relative):
                if record.decisions > 4:
                    offenders.append(
                        f"{relative}:{record.line} {record.name}={record.decisions}"
                    )
        self.assertEqual(offenders, [])

    def test_retry_fifo_parsing_and_routing_decisions_are_host_owned(self) -> None:
        retry = (ROOT / "crates/signer-firmware-core/src/storage/retry.rs").read_text()
        fifo = (ROOT / "crates/signer-firmware-core/src/storage/fifo.rs").read_text()
        parsing = (ROOT / "crates/signer-firmware-core/src/qr/classification.rs").read_text()
        routing = (ROOT / "crates/signer-firmware-core/src/storage/routing.rs").read_text()

        for fragment in (
            "run_response_retry",
            "poll_read_token",
            "poll_register",
            "validate_cmd8_echo",
        ):
            self.assertIn(fragment, retry)
        for fragment in (
            "drive_fifo_read",
            "drive_fifo_write",
            "transfer_mode",
            "write_words",
        ):
            self.assertIn(fragment, fifo)
        self.assertIn("QR_CLASSIFIERS", parsing)
        self.assertIn("import_scan_plan", routing)

    def test_sd_import_dispatch_uses_current_format_host_plan(self) -> None:
        relative = "apps/signer-firmware/src/runtime/interactions/sd/imports/import_menu.rs"
        source = (ROOT / relative).read_text()
        records = {record.name: record for record in function_decisions(source, relative)}
        self.assertNotIn("dispatch_import_plan", records)
        self.assertNotIn("scan_seed_backup_plan", records)
        self.assertLessEqual(records["dispatch_import_scan"].decisions, 2)
        self.assertLessEqual(records["scan_rule_plan"].decisions, 1)
        self.assertIn("import_scan_plan(item)", source)
        self.assertNotIn("IMPORT_SCAN_HANDLERS", source)
        self.assertNotIn("is_seed_backup_candidate", source)

    def test_regression_gate_only_exempts_unavailable_board_warnings_within_cc_four(self) -> None:
        regression = (ROOT / "qa/checks/quality/crap/regression.py").read_text()
        policy = (ROOT / "qa/checks/quality/crap/policy.json").read_text()
        self.assertIn("_allowed_board_adapter_warning", regression)
        self.assertIn('"allowed_unavailable_board_adapter_warning_cc": 4', policy)
        self.assertIn('"reject_new_failures": true', policy)
        self.assertIn('"reject_new_warnings": true', policy)


if __name__ == "__main__":
    unittest.main()
