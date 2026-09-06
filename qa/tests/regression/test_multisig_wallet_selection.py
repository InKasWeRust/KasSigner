from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class MultisigWalletSelectionTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(errors="ignore")

    def test_multisig_picker_has_no_hidden_delete_zone_and_uses_wallet_cards(self):
        picker = self.read("apps/signer-firmware/src/runtime/interactions/tx/multisig_setup/seed_picker.rs")
        screen = self.read("apps/signer-firmware/src/ui/screens/wallet/multisig/setup.rs")
        slots = self.read("apps/signer-firmware/src/ui/screens/wallet/seed_slots.rs")
        self.assertNotIn("pending_delete_slot", picker)
        self.assertNotIn("ConfirmDeleteSeed", picker)
        self.assertNotIn("x >= 232", picker)
        self.assertIn("Multisig wallet selection intentionally has no destructive touch zone", picker)
        self.assertIn('format_args!("SELECT WALLET {}/{}"', screen)
        self.assertIn("include_add_slot: true", screen)
        self.assertIn('"Choose Wallet"', screen)
        self.assertNotIn('"Use Loaded Seed"', screen)
        self.assertNotIn('"SELECT SEED', screen)
        self.assertIn("slot.source.display_label()", slots)
        self.assertNotIn("draw_seed_slot_delete", slots)
        self.assertNotIn("ICON_TRASH", slots)
        self.assertNotIn("show_slot_number", slots)
        self.assertNotIn("show_delete", slots)

    def test_add_wallet_continuation_returns_to_exact_multisig_key_slot(self):
        session = self.read("apps/signer-firmware/src/runtime/data/wallet/seed_session.rs")
        seed = self.read("apps/signer-firmware/src/runtime/interactions/seed.rs")
        picker = self.read("apps/signer-firmware/src/runtime/interactions/tx/multisig_setup/seed_picker.rs")
        passphrase = self.read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        choice = self.read("apps/signer-firmware/src/runtime/interactions/seed/seed_list.rs")
        workflow = self.read("apps/signer-firmware/src/runtime/workflow_tests/connected/multisig/cosigners.rs")
        self.assertIn("pending_multisig_wallet_key", session)
        self.assertIn("stage_multisig_wallet_return", session)
        self.assertIn("multisig_wallet_return", session)
        self.assertIn("stage_multisig_wallet_return(key_idx)", picker)
        self.assertIn("return_after_add_wallet", passphrase)
        self.assertIn("return_after_add_wallet(ad);", choice)
        self.assertIn("Keep\n    // the continuation token", choice)
        self.assertIn("clear_multisig_wallet_return();", choice)
        self.assertIn("route!(SeedList)", choice)
        self.assertIn("route!(MultisigPickSeed { key_idx })", choice)
        self.assertIn("pending_multisig_wallet_key != 0", workflow)
        self.assertIn("MULTISIG ADD-WALLET RETURN CONTINUATION PASS", workflow)
        self.assertIn("MULTISIG WALLET PICKER NON-DESTRUCTIVE SELECTION PASS", workflow)

    def test_reported_hardware_compile_and_oracle_vector_regressions_remain_closed(self):
        presentation = self.read("apps/signer-firmware/src/ui/redraw/presentation/mod.rs")
        signing = self.read("apps/signer-firmware/src/runtime/signing.rs")
        credential = self.read("apps/signer-firmware/src/services/credential_policy/mod.rs")
        constructors = self.read("crates/online-watcher/src/contracts/unit_tests/construction.rs")
        self.assertIn("runtime::input::is_scan_state", presentation)
        self.assertNotIn("runtime::event_loop::camera::is_scan_state", presentation)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\npub use derivation::{derive_active_account_key, derive_active_seed};', signing)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\npub(crate) use derivation::derive_slot_seed;', signing)
        self.assertIn('#[cfg(not(feature = "hardware-tests"))]\npub use signer_firmware_core::security::credential::retry_delay_millis;', credential)
        for xonly in (
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ):
            self.assertIn(xonly, constructors)
        self.assertNotIn('"11".repeat(32)', constructors)
        self.assertNotIn('"22".repeat(32)', constructors)
        self.assertNotIn('"33".repeat(32)', constructors)


if __name__ == "__main__":
    unittest.main()
