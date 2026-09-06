from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(errors="strict")


class WalletActivationSecurityTests(unittest.TestCase):
    def test_slot_header_authenticates_network_and_per_wallet_protection(self):
        protection = read("apps/signer-firmware/src/wallet/seed_manager/protection.rs")
        codec = read("apps/signer-firmware/src/services/persistent_wallet/codec.rs")
        self.assertIn("pub enum WalletProtection", protection)
        for name in ("DeviceOnly", "Pin", "Password"):
            self.assertIn(name, protection)
        self.assertNotIn("LegacyStore", protection)
        self.assertIn("NETWORK_COUNT * protection.slot_code()", codec)
        self.assertIn("WalletProtection::from_slot_code(tag / NETWORK_COUNT)", codec)
        # Transitional protection tag 0 is intentionally rejected in the current format.
        self.assertNotIn("0 => Some(Self::", protection)

    def test_journal_v8_preserves_v7_and_stores_activation_metadata(self):
        journal = read("apps/signer-firmware/src/services/persistent_wallet/journal.rs")
        config = read("apps/signer-firmware/src/services/persistent_wallet/journal/config.rs")
        self.assertIn("const CONFIG_VERSION: u8 = 8;", journal)
        self.assertIn("const V7_COMPAT_VERSION: u8 = 7;", journal)
        self.assertIn("WalletActivationRecord", journal)
        self.assertIn("pub salt: [u8; SALT_SIZE]", journal)
        self.assertIn("pub verifier: [u8; 32]", journal)
        self.assertIn("read_wallet_activation", config)
        self.assertIn("write_wallet_activation", config)

    def test_wallet_credential_verifier_is_argon2_and_device_hmac_bound(self):
        activation = read("apps/signer-firmware/src/services/persistent_wallet/wallet_activation.rs")
        crypto = read("apps/signer-firmware/src/services/persistent_wallet/crypto.rs")
        task = "\n".join(read(path) for path in (
            "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task.rs",
            "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/activation.rs",
            "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/begin.rs",
        ))
        self.assertIn("derive_wallet_activation_key", activation)
        self.assertIn("wallet_activation_verifier", activation)
        self.assertIn("WALLET_ACTIVATION_MAC_DOMAIN", crypto)
        self.assertIn("WalletActivationMode::Setup", task)
        self.assertIn("WalletActivationMode::Verify", task)
        self.assertIn("verify_wallet_activation_key", task)

    def test_add_wallet_does_not_commit_before_protection_choice(self):
        onboarding = "\n".join(read(path) for path in (
            "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/recovery.rs",
            "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/finalize.rs",
        ))
        seed = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        wallet_state = read("apps/signer-firmware/src/runtime/data/wallet.rs")
        seed_session = read("apps/signer-firmware/src/runtime/data/wallet/seed_session.rs")
        result = read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/result.rs")
        ack = read("apps/signer-firmware/src/runtime/interactions/persistence/onboarding/recovery.rs")
        self.assertIn("StorageProtectionChoice", ack)
        self.assertNotIn("commit_staged_add_wallet", ack)
        self.assertIn("WalletProtection::DeviceOnly", onboarding)
        self.assertIn("PendingWalletActivationState", wallet_state)
        self.assertIn("pending_wallet_activation_ready(&self) -> bool", seed_session)
        self.assertIn("mark_pending_wallet_activation_ready(&mut self)", seed_session)
        self.assertIn("commit_staged_add_wallet", result)
        self.assertIn("confirmation_digest", seed)
        self.assertIn("recovery_words_acknowledged = false", seed)
        self.assertIn("confirmation_pending = false", seed)

    def test_bip39_passphrase_is_staged_separately_from_wallet_pin_password_input(self):
        session = read("apps/signer-firmware/src/runtime/data/wallet/seed_session.rs")
        wallet = read("apps/signer-firmware/src/runtime/data/wallet.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        self.assertIn("pending_bip39_passphrase", wallet)
        self.assertIn("stage_pending_bip39_passphrase", session)
        self.assertIn("pending_bip39_passphrase", passphrase)

    def test_switch_cancel_clears_pending_and_no_active_wallet_cannot_escape(self):
        nav = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        list_rs = read("apps/signer-firmware/src/runtime/interactions/seed/seed_list/list.rs")
        runtime = read("apps/signer-firmware/src/runtime/data/runtime.rs")
        self.assertIn("cancel_pending_wallet_activation", runtime)
        self.assertIn("cancel_pending_wallet_activation()", nav)
        self.assertIn("route!(SeedList)", nav)
        self.assertIn("wallet_resolution_required", nav)
        self.assertIn("active_slot().is_none()", list_rs)
        guarded = list_rs[list_rs.index("if is_back"):list_rs.index("let (loaded, loaded_count)")]
        self.assertNotIn("route!(SeedsMenu)", guarded.split("active_slot().is_none()", 1)[0])


    def test_duplicate_add_cannot_activate_existing_protected_wallet(self):
        seed = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        manager = read("apps/signer-firmware/src/wallet/seed_manager/manager.rs")
        self.assertIn("find_matching_mnemonic", manager)
        self.assertIn("find_matching_mnemonic", seed)
        duplicate = seed[seed.index("if ad.wallet.seeds.seed_mgr.find_matching_mnemonic"):seed.index("if !commit_current_seed", seed.index("if ad.wallet.seeds.seed_mgr.find_matching_mnemonic"))]
        self.assertNotIn("activate_slot", duplicate)
        self.assertIn("Wallet already exists", duplicate)


if __name__ == "__main__":
    unittest.main()
