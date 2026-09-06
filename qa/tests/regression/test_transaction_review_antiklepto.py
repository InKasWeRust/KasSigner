from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(errors="strict")


class TransactionReviewAntiKleptoTests(unittest.TestCase):
    def test_qr_processing_uses_literal_loading_surface(self):
        for relative in (
            "apps/signer-firmware/src/runtime/interactions/camera_loop/decoder.rs",
            "apps/signer-firmware/src/runtime/interactions/camera_loop/multiframe.rs",
        ):
            source = read(relative)
            self.assertIn('draw_loading_screen("Processing QR...")', source)
            self.assertNotIn('draw_saving_screen("Processing QR...")', source)

    def test_confirm_send_is_primary_and_inspection_is_optional(self):
        navigation = read("apps/signer-firmware/src/runtime/navigation/transaction.rs")
        menus = read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
        reducer = read("crates/signer-firmware-core/src/presentation/transaction.rs")
        footer = read("apps/signer-firmware/src/ui/screens/signing/transaction_review/footer.rs")
        confirmation = read("apps/signer-firmware/src/ui/screens/components/send_confirmation.rs")
        self.assertIn("Route(route!(ConfirmTx))", navigation)
        self.assertIn('"Inspect", "tx.inspect", ReviewTx', menus)
        self.assertIn("ConfirmChoice(2)", reducer)
        self.assertIn('draw_review_footer_button(18, "Inspect", true)', footer)
        self.assertIn('draw_review_footer_button(224, "Next", false)', footer)
        self.assertIn('"CONFIRM"', confirmation)
        self.assertIn('"INSPECT"', confirmation)
        self.assertIn('"CANCEL"', confirmation)


    def test_review_spacing_keeps_network_below_separator_and_verification_64_bit(self):
        summary = read("apps/signer-firmware/src/ui/screens/signing/transaction_review/summary.rs")
        self.assertIn("Point::new(20, 43)", summary)
        self.assertIn("centered_body(self, tx.network.label(), 64, KASPA_ACCENT)", summary)
        self.assertIn("hash.iter().take(8)", summary)

    def test_confirm_screen_shows_abbreviated_single_destination(self):
        redraw = read("apps/signer-firmware/src/ui/redraw/signing/transaction.rs")
        self.assertIn('write_str(&mut result, &payload[..4])', redraw)
        self.assertIn('write_str(&mut result, "...")', redraw)
        self.assertIn('write_str(&mut result, &payload[payload.len() - 4..])', redraw)
        self.assertIn('"MULTI ({count} outputs)"', redraw)

    def test_kassee_decoder_accepts_raw_single_frame_and_keeps_session_splice_rejection(self):
        decoder = read("crates/online-watcher/src/protocol/qr.rs")
        protocol = read("crates/kassigner-protocol/src/qr/mod.rs")
        self.assertIn("kassigner_protocol::qr::{encode_frames, QrDecoder}", decoder)
        self.assertIn(".accept(&payload)", decoder)
        self.assertNotIn("shared_signer::qr_frame", decoder)
        self.assertIn("if !shared_signer::qr_frame::is_session_frame(payload)", protocol)
        self.assertIn('ProtocolError::qr("mixed multi-frame QR session rejected")', protocol)
        self.assertIn("payload.starts_with(&shared_signer::qr_frame::FRAME_MAGIC)", protocol)

    def test_kassee_anti_klepto_accepts_protocol_v2(self):
        session = read("apps/kassee-web/web/js/features/transactions/anti_klepto/session.js")
        web_test = read("qa/checks/web/web_branch_hardening.test.mjs")
        self.assertIn("version !== 2", session)
        self.assertIn("4B414B500204", web_test)


if __name__ == "__main__":
    unittest.main()
