from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class StandardImportLivenessTests(unittest.TestCase):

    def test_camera_transaction_dispatch_passes_liveness(self):
        dispatch = (ROOT / "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch.rs").read_text()
        tx_dispatch = (ROOT / "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/transaction.rs").read_text()
        self.assertIn("dispatch_transaction(kind, data, ad, liveness)", dispatch)
        self.assertIn("transaction::process_kspt(data, ad, liveness)", dispatch)
        self.assertIn("load_compact_transaction_with_checkpoint(data, ad, liveness)", tx_dispatch)
        self.assertIn("load_standard_transaction_with_checkpoint(data, ad, liveness)", tx_dispatch)

    def test_standard_import_uses_checkpointed_ownership_verification(self):
        tx = (ROOT / "apps/signer-firmware/src/runtime/interactions/tx/transaction.rs").read_text()
        self.assertIn("finish_compact_import_with_checkpoint(ad, checkpoint)", tx)
        self.assertIn("begin_import_review_with_checkpoint(ad, checkpoint)", tx)
        self.assertIn("verify_transaction_output_ownership_with_checkpoint(ad, checkpoint)", tx)
        self.assertIn("TX import ownership verification BEGIN", tx)
        self.assertIn("TX import ownership verification DONE", tx)

    def test_standard_is_first_recommended_relay_and_antiklepto_is_maximum_security(self):
        for relative in [
            "apps/kassee-web/web/html/screens/transactions/pskt_review.html",
            "apps/kassee-web/web/index.html",
        ]:
            html = (ROOT / relative).read_text()
            standard = html.index('id="btn-relay-kassigner-standard"')
            anti = html.index('id="btn-relay-compact"')
            self.assertLess(standard, anti)
            self.assertIn('<button class="btn btn-primary" id="btn-relay-kassigner-standard">', html)
            self.assertIn("Recommended · compact KSPT QR · simple signing flow", html)
            self.assertIn("Maximum security · adds nonce-exfiltration protection", html)


if __name__ == "__main__":
    unittest.main()
