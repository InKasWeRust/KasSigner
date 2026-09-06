#!/usr/bin/env python3
"""stage-4 recoverable-error UX and stable-screen return contracts."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class RecoverableErrorStage4Tests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8", errors="strict")

    def test_error_catalog_has_stable_non_secret_diagnostic_codes(self) -> None:
        errors = self.read("apps/signer-firmware/src/runtime/presentation/errors.rs")
        for code in (
            "CAM-01", "CAM-02", "CAM-03", "SD-WRITE-01", "STORE-SYNC-01",
            "POLICY-SAVE-01", "QR-FRAME-01", "SIGN-ENTROPY-01", "SIGN-INPUT-01",
            "SIGN-REVIEW-01", "SIGN-KEY-01", "SIGN-POLICY-01", "SIGN-FINAL-01",
            "TX-IMPORT-01", "AK-01", "COV-01", "SWAP-01", "UI-NAV-01",
        ):
            self.assertIn(code, errors)

    def test_modal_ok_returns_only_to_current_or_bounded_history(self) -> None:
        presentation = self.read("apps/signer-firmware/src/runtime/presentation/mod.rs")
        kernel = self.read("apps/signer-firmware/src/runtime/navigation/kernel.rs")
        self.assertIn("navigation::return_from_error(ad, return_to)", presentation)
        self.assertIn("target == ad.navigation.committed_state", kernel)
        self.assertIn("ad.navigation.history.target(&[target]).is_none()", kernel)
        self.assertIn("HistoryEffect::PopTo(target)", kernel)

    def test_camera_faults_use_modal_and_return_to_previous_stable_screen(self) -> None:
        cycle = self.read("apps/signer-firmware/src/runtime/interactions/camera_loop/cycle.rs")
        self.assertIn("previous_stable_screen(ad)", cycle)
        self.assertIn("show_error_spec_to", cycle)
        self.assertNotIn("draw_camera_fault_screen", cycle)
        self.assertNotIn("request_camera_retry", self.read("apps/signer-firmware/src/runtime/data/qr.rs"))

    def test_runtime_signing_failures_do_not_draw_ad_hoc_rejection_screens(self) -> None:
        workflow = self.read("apps/signer-firmware/src/runtime/signing/workflow.rs")
        self.assertNotIn("draw_rejected_screen", workflow)
        for token in ("SIGN_ENTROPY", "SIGN_INPUT", "SIGN_KEY", "SIGN_POLICY", "SIGN_REVIEW", "POLICY_SAVE"):
            self.assertIn(token, workflow)
        self.assertIn("fail_recoverable_spec(ad, error)", workflow)

    def test_qr_sd_and_persistence_failures_use_recoverable_catalog(self) -> None:
        qr = self.read("apps/signer-firmware/src/runtime/signing/qr.rs")
        frame = self.read("apps/signer-firmware/src/runtime/event_loop/frame.rs")
        persistence = self.read("apps/signer-firmware/src/runtime/event_loop/persistence.rs")
        self.assertIn("show_error_spec_previous", qr)
        self.assertIn("QR_FRAME", qr)
        self.assertNotIn("draw_rejected_screen", qr)
        self.assertIn("SD_WRITE", frame)
        self.assertNotIn("draw_rejected_screen", frame)
        self.assertIn("POLICY_SAVE", persistence)
        self.assertIn("STORAGE_SYNC", persistence)
        self.assertNotIn("draw_rejected_screen", persistence)

    def test_parsing_protocol_failures_use_modal_not_rejected_state(self) -> None:
        paths_and_tokens = {
            "apps/signer-firmware/src/runtime/interactions/tx/transaction.rs": "TX_IMPORT",
            "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/anti_klepto.rs": "ANTI_KLEPTO",
            "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/covenant_sign.rs": "COVENANT",
            "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/private_swap.rs": "PRIVATE_SWAP",
        }
        for relative, token in paths_and_tokens.items():
            source = self.read(relative)
            self.assertIn(token, source, relative)
            if "anti_klepto" not in relative:  # controller-only anti-klepto fixture retains Rejected semantics
                self.assertNotIn("draw_tx_error_screen", source, relative)

    def test_navigation_recovery_surfaces_error_in_production_and_runtime_hil(self) -> None:
        kernel = self.read("apps/signer-firmware/src/runtime/navigation/kernel.rs")
        self.assertIn('feature = "workflow-runtime-auto"', kernel)
        self.assertIn("presentation::NAVIGATION", kernel)
        self.assertIn("presentation::show_error_spec", kernel)

    def test_software_reset_is_reserved_for_duress_and_pop_it(self) -> None:
        hits = []
        for path in (ROOT / "apps/signer-firmware/src").rglob("*.rs"):
            source = path.read_text(errors="ignore")
            if "software_reset" in source:
                hits.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(sorted(hits), sorted([
            "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/result.rs",
            "apps/signer-firmware/src/runtime/interactions/settings/advanced/factory_reset.rs",
            "apps/signer-firmware/src/runtime/interactions/settings/advanced/pop_it.rs",
        "apps/signer-firmware/src/runtime/interactions/settings/advanced/owner_firmware.rs",
        ]))


if __name__ == "__main__":
    unittest.main()
