#!/usr/bin/env python3
"""regressions for the last live connected E2E contract failures."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"
CONNECTED = FW / "src/runtime/workflow_tests/connected"


class MultisigSigningIsolationTests(unittest.TestCase):

    def test_multisig_signing_traverses_imported_review_page_count(self) -> None:
        source = (CONNECTED / "multisig/signing.rs").read_text(encoding="utf-8")
        self.assertIn("let review_pages = ctx.ad.navigation.app.review_pages;", source)
        self.assertIn(
            "review_pages == 1 + ctx.ad.signing.transaction.active.num_outputs as u8",
            source,
        )
        self.assertIn("for page in 1..review_pages", source)
        self.assertIn("AppState::ReviewTx { page }", source)
        self.assertIn("ctx.ad.navigation.app.state != AppState::ConfirmTx", source)
        self.assertNotIn("AppState::ReviewTx { page: 2 }, AppState::ConfirmTx", source)

    def test_multisig_fixture_is_one_output_so_live_trace_has_two_review_pages(self) -> None:
        source = (CONNECTED / "multisig/signing.rs").read_text(encoding="utf-8")
        wire = source.split("fn multisig_wire", 1)[1]
        self.assertIn("tx.num_outputs = 1;", wire)
        navigation = (FW / "src/runtime/navigation/transaction.rs").read_text(encoding="utf-8")
        self.assertIn("ad.navigation.app.review_pages = 1 + num_outputs;", navigation)

    def test_xprv_no_sd_probe_uses_explicit_no_card_export_context(self) -> None:
        context = (CONNECTED / "advanced_tools/mod.rs").read_text(encoding="utf-8")
        exports = (CONNECTED / "advanced_tools/exports.rs").read_text(encoding="utf-8")
        self.assertIn("fn export_touch_without_sd", context)
        helper = context.split("fn export_touch_without_sd", 1)[1].split("pub(super) fn set_text", 1)[0]
        self.assertIn("let no_sd = None;", helper)
        self.assertIn("sd_card_type: &no_sd", helper)
        no_sd = exports.split("fn xprv_no_sd", 1)[1].split("fn xprv_raw_key_reject", 1)[0]
        self.assertIn("ctx.export_touch_without_sd(", no_sd)
        self.assertNotIn("ctx.export_touch(second.x + second.w / 2", no_sd)
        self.assertIn("ctx.ad.navigation.app.state == AppState::XprvExportMenu", no_sd)

    def test_normal_export_path_still_uses_real_sd_context(self) -> None:
        context = (CONNECTED / "advanced_tools/mod.rs").read_text(encoding="utf-8")
        normal = context.split("pub(super) fn export_touch(", 1)[1].split(
            "pub(super) fn export_touch_without_sd", 1
        )[0]
        self.assertIn("sd_card_type: self.sd", normal)


if __name__ == "__main__":
    unittest.main()
