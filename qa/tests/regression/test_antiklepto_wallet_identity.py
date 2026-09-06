from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(errors="strict")


class AntiKleptoWalletIdentityTests(unittest.TestCase):
    def test_test_only_matching_material_wrapper_does_not_warn_in_library_build(self):
        source = read("crates/offline-signer/src/transaction/kspt/signing/context.rs")
        marker = "#[cfg(test)]\n    pub(super) fn matching_material("
        self.assertIn(marker, source)
        self.assertIn("pub(super) fn matching_material_with_checkpoint(", source)

    def test_change_hint_can_only_be_corrected_by_active_wallet_cryptography(self):
        source = read("apps/signer-firmware/src/runtime/signing/review.rs")
        self.assertIn("find_owned_output_with_checkpoint", source)
        self.assertIn("p2pk_xonly(&output.script_public_key)", source)
        self.assertIn("ADDR_SCAN_DEPTH", source)
        self.assertIn("TX ownership hint corrected output={}", source)
        self.assertIn('return Err("Transaction output does not belong to active wallet")', source)
        self.assertNotIn("ownership[index] = OutputOwnership::External", source)

    def test_scanner_pauses_while_error_modal_owns_presentation(self):
        camera = read("apps/signer-firmware/src/runtime/event_loop/camera.rs")
        redraw = read("apps/signer-firmware/src/ui/redraw/presentation/mod.rs")
        errors = read("apps/signer-firmware/src/ui/screens/signing/errors.rs")
        self.assertIn("camera_screen_active", camera)
        self.assertIn("!$crate::runtime::presentation::blocks_input($ad)", camera)
        self.assertIn("draw_recoverable_error_screen_with_action", redraw)
        self.assertIn('"HOME"', redraw)
        self.assertIn('"BACK"', redraw)
        self.assertIn("action_label", errors)

    def test_tx_ownership_error_names_wallet_mismatch(self):
        errors = read("apps/signer-firmware/src/runtime/presentation/errors.rs")
        self.assertIn('message: "KasSee wallet does not match active wallet"', errors)
        self.assertIn('code: "TX-OWN-01"', errors)

    def test_public_kpub_derivation_is_cross_checked_against_offline_signer(self):
        tests = read("crates/online-watcher/src/account/unit_tests/mod.rs")
        self.assertIn("kpub_public_derivation_matches_offline_signer_receive_and_change", tests)
        self.assertIn("derive_and_serialize_kpub", tests)
        self.assertIn("derive_address_key", tests)
        self.assertIn("derive_change_key", tests)
        self.assertIn("wallet.change_addresses[index as usize]", tests)


if __name__ == "__main__":
    unittest.main()
