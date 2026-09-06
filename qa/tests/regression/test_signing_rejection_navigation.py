from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class SigningRejectionNavigationTests(unittest.TestCase):
    def test_parser_and_confirm_rejections_use_distinct_production_return_owners(self):
        signing = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs").read_text()
        self.assertIn("dismiss_rejected_to(AppState::ScanQR)", signing)
        self.assertIn("route_camera_back(self.ad)", signing)
        self.assertIn("dismiss_rejected_to(AppState::ConfirmTx)", signing)
        self.assertIn("self.tx_touch(20, 20, true)", signing)

    def test_compact_review_and_authorization_rejection_expect_confirm_owner(self):
        signing = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs").read_text()
        review = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/review.rs").read_text()
        self.assertIn("dismiss_confirm_rejection_to_home()", signing)
        self.assertIn("dismiss_confirm_rejection_to_home()", review)

    def test_scan_origin_rejections_keep_scan_owner_contract(self):
        signing = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs").read_text()
        anti = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/anti_klepto.rs").read_text()
        self.assertIn("dismiss_scan_rejection_to_home()", signing)
        self.assertIn("dismiss_scan_rejection_to_home()", anti)
        self.assertNotIn("dismiss_confirm_rejection_to_home()", anti)

    def test_production_rejected_modal_uses_navigation_back(self):
        presentation = (ROOT / "apps/signer-firmware/src/runtime/interactions/menu/qr/presentation.rs").read_text()
        transaction = (ROOT / "apps/signer-firmware/src/runtime/navigation/transaction.rs").read_text()
        self.assertIn("AppState::Rejected =>", presentation)
        self.assertIn("crate::runtime::effects::back(ad)", presentation)
        self.assertIn("UiEvent::Route(route!(Rejected))", transaction)


if __name__ == "__main__":
    unittest.main()
