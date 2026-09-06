from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW_MAIN = ROOT / "apps/signer-firmware/src/main.rs"
SEND_FORM = ROOT / "apps/kassee-web/web/js/features/transactions/send/compose/send_form.js"
UTXO_VIEW = ROOT / "apps/kassee-web/web/js/features/wallet/tools/address_views.js"
CONSOLIDATION = ROOT / "apps/kassee-web/web/js/features/wallet/tools/consolidation.js"
UTXO_HTML = ROOT / "apps/kassee-web/web/html/screens/wallet/utxos.html"
INDEX = ROOT / "apps/kassee-web/web/index.html"


class KasSeeCoinControlAndHilPolicyTests(unittest.TestCase):
    def test_packaged_firmware_source_never_disables_crate_dead_code_for_hil(self) -> None:
        main = FW_MAIN.read_text(errors="ignore")
        self.assertIn("#![warn(dead_code)]", main)
        self.assertIn("#![deny(unused_imports)]", main)
        self.assertNotRegex(main, r"#!\s*\[.*allow\s*\(\s*dead_code\s*\).*")

    def test_utxo_explorer_can_transfer_exact_outpoints_into_send_coin_control(self) -> None:
        consolidation = CONSOLIDATION.read_text(errors="ignore")
        send_form = SEND_FORM.read_text(errors="ignore")
        self.assertIn("handleSendSelectedUtxos", consolidation)
        self.assertIn("openSendScreenWithSelectedUtxos", consolidation)
        self.assertIn(".map(utxoId)", consolidation)
        self.assertIn("openSendScreenWithSelectedUtxos", send_form)
        self.assertIn("revealCoinControl", send_form)
        self.assertIn("liveIds", send_form)

    def test_utxo_details_surface_has_send_with_selected_control_and_sdk_limit(self) -> None:
        fragment = UTXO_HTML.read_text(errors="ignore")
        index = INDEX.read_text(errors="ignore")
        view = UTXO_VIEW.read_text(errors="ignore")
        self.assertIn('id="btn-send-selected-utxos"', fragment)
        self.assertIn('id="btn-send-selected-utxos"', index)
        self.assertIn("signerMaxInputs()", view)
        self.assertNotIn("Max 8 UTXOs per consolidation", view)


if __name__ == "__main__":
    unittest.main()
