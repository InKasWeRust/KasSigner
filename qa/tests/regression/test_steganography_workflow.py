#!/usr/bin/env python3
"""connected steganography E2E tranche contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"
CONNECTED = FW / "src/runtime/workflow_tests/connected"
SCENARIOS = ROOT / "qa/config/workflow/production_e2e_scenarios.json"
MANIFEST = ROOT / "qa/config/workflow/production_e2e_manifest.json"
REQUIREMENTS = ROOT / "qa/specs/production_e2e_requirements.md"


class SteganographyE2ETrancheTests(unittest.TestCase):
    def test_stego_runner_is_partitioned_and_emits_bounded_markers(self) -> None:
        root = (CONNECTED / "mod.rs").read_text()
        stego_dir = CONNECTED / "stego"
        self.assertEqual(
            {path.name for path in stego_dir.glob("*.rs")},
            {"mod.rs", "entry.rs", "export.rs", "media.rs", "restore.rs"},
        )
        self.assertIn("mod stego;", root)
        self.assertIn("(\"STEGO\", stego::exercise)", root)
        source = "\n".join(path.read_text() for path in sorted(stego_dir.glob("*.rs")))
        for marker in (
            "STEGO ENTRY BACK/NO-SD/RAW-KEY/NO-MNEMONIC REJECT PASS",
            "STEGO CARRIER/SECURITY DEVICE-BOUND+PORTABLE ROUTES PASS",
            "STEGO JPEG PICKER PAGING/SELECT/BACK BOUNDARIES PASS",
            "STEGO DESCRIPTION TXT EMPTY/OVERSIZED/VALID BOUNDARY PASS",
            "STEGO DESCRIPTION EDIT/PREVIEW + PRESET/CUSTOM HINT PASS",
            "STEGO PORTABLE PASSWORD INVALID/MISMATCH/CONFIRM/BACK PASS",
            "STEGO FINAL REVIEW BACK/CANCEL OWNER/CLEAR PASS",
            "STEGO DESCRIPTOR JPEG VALID/EXTRACT ROUND-TRIP PASS",
            "STEGO PICTURE CAPACITY/EMBED/EXTRACT + LOW-CAPACITY REJECT PASS",
            "STEGO RESTORE PICKER/DESCRIPTOR TXT VALIDATION/BACK OWNERS PASS",
            "STEGO DEVICE-BOUND JPEG HINT/RESTORE ROUND-TRIP PASS",
            "STEGO PORTABLE WRONG-PASSWORD REJECT + CROSS-DEVICE RESTORE PASS",
            "STEGO PHYSICAL SD/JPEG MEDIA HIL DEFERRED TO PERIPHERAL TRANCHE",
            "STEGANOGRAPHY TRANCHE PASS",
        ):
            self.assertIn(marker, source)

    def test_return_ownership_repairs_keep_stego_inside_calling_hierarchy(self) -> None:
        picker = (FW / "src/runtime/interactions/stego/export_description/image_picker.rs").read_text()
        mode = (FW / "src/runtime/interactions/stego/mode.rs").read_text()
        confirm = (FW / "src/runtime/interactions/stego/export_confirm/mod.rs").read_text()
        self.assertIn("route(ad, crate::runtime::navigation::route!(StegoSecuritySelect))", picker)
        self.assertIn('"No .JPG files on SD"', mode)
        no_jpeg = mode.split('"No .JPG files on SD"', 1)[1].split("return true", 1)[0]
        self.assertIn("route!(StegoSecuritySelect)", no_jpeg)
        self.assertGreaterEqual(confirm.count("ReturnScope::SeedBackup"), 2)
        self.assertNotIn("route(ad, crate::runtime::navigation::route!(ExportChoice))", confirm)

    def test_media_boundary_uses_real_stego_algorithms_and_workflow_only_crypto_hooks(self) -> None:
        media = (CONNECTED / "stego/media.rs").read_text()
        for owner in (
            "build_exif_template",
            "inject_exif",
            "find_exif_app1",
            "extract_user_comment",
            "capacity_bits",
            "embed_picture",
            "extract_picture",
            "pack_for_test",
        ):
            self.assertIn(owner, media)
        self.assertIn("FLAT_JPEG", media)
        self.assertIn("capacity_bits(FLAT_JPEG", media)
        self.assertIn(">= required", media)
        payload = (FW / "src/services/stego/payload.rs").read_text()
        self.assertIn('feature = "workflow-test-auto"', payload)
        facade = (FW / "src/runtime/interactions/stego.rs").read_text()
        self.assertIn('workflow_accept_description_file', facade)
        self.assertIn('workflow_select_security_with_jpegs', facade)
        workflow = (FW / "src/runtime/interactions/stego/import_decrypt/workflow.rs").read_text()
        self.assertIn('workflow_open_payload', workflow)
        self.assertIn('unpack_device_bound_payload', workflow)
        self.assertIn('unpack_portable_payload', workflow)
        self.assertNotIn('cfg(not(feature = "workflow-test-auto"))', workflow)

    def test_jpeg_fixtures_are_small_deterministic_baseline_assets(self) -> None:
        fixtures = FW / "src/runtime/workflow_tests/fixtures"
        noise = (fixtures / "stego_noise.jpg").read_bytes()
        flat = (fixtures / "stego_flat.jpg").read_bytes()
        for jpeg in (noise, flat):
            self.assertTrue(jpeg.startswith(b"\xff\xd8"))
            self.assertTrue(jpeg.endswith(b"\xff\xd9"))
            self.assertNotIn(b"\xff\xc2", jpeg)  # progressive SOF2 is intentionally unsupported
        self.assertGreater(len(noise), len(flat) * 10)
        self.assertLess(len(noise), 100_000)


    def test_action_discovery_does_not_leak_cfg_from_reexports(self) -> None:
        checker = (ROOT / "qa/checks/firmware/production_e2e_coverage.py").read_text()
        self.assertIn("Attributes apply only to the immediately following declaration", checker)
        manifest = json.loads(MANIFEST.read_text())
        action = "apps/signer-firmware/src/runtime/interactions/stego.rs::handle_stego_touch"
        self.assertIn(action, manifest["surface"]["actions"])

    def test_requirements_remain_frozen(self) -> None:
        self.assertEqual(
            hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest(),
            "d645cd7483ddc4443936e60a1b063bd596cb0fe31f5216d79e520009eabf8ef7",
        )


if __name__ == "__main__":
    unittest.main()
