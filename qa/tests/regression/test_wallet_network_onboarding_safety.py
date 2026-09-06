from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps" / "signer-firmware"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class WalletNetworkOnboardingSafetyTests(unittest.TestCase):
    def test_developer_networks_are_persisted_and_legacy_wallets_default_main(self):
        production = read("apps/signer-firmware/src/runtime/navigation/production.rs")
        routes = read("apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs")
        network = read("apps/signer-firmware/src/wallet/seed_manager/network.rs")
        preferences = read("apps/signer-firmware/src/services/persistent_wallet/journal/preferences.rs")
        codec = read("apps/signer-firmware/src/services/persistent_wallet/codec.rs")

        self.assertIn('"Network",', production)
        for label in ("Mainnet", "Testnet-12", "Testnet-10"):
            self.assertIn(f'"{label}"', production)
        self.assertIn("fn route_network", routes)
        self.assertIn('Self::Mainnet => "Main"', network)
        self.assertIn('Self::Testnet12 => "Test-12"', network)
        self.assertIn('Self::Testnet10 => "Test-10"', network)
        self.assertIn("const NETWORK_SHIFT: u8 = 2", preferences)
        self.assertIn("with_wallet_network", preferences)
        self.assertIn("with_wallet_network(ad.wallet.seeds.seed_mgr.network())", read("apps/signer-firmware/src/services/persistent_wallet/device/preferences.rs"))
        # The same authenticated high nibble also includes per-wallet
        # protection while preserving old network-only tags 0..2 as LegacyStore.
        self.assertIn("const SLOT_TAG_SHIFT: u8 = 4", codec)
        self.assertIn("network.slot_tag() + NETWORK_COUNT * protection.slot_code()", codec)
        self.assertIn("let tag = value >> SLOT_TAG_SHIFT", codec)
        self.assertIn("tag % NETWORK_COUNT", codec)
        self.assertIn("tag / NETWORK_COUNT", codec)
        # Old records stored source values 1..4 with a zero high nibble, which maps to Mainnet.
        self.assertIn("0 => Some(Self::Mainnet)", network)

    def test_network_switch_clears_active_context_and_signing_uses_visible_active_slot(self):
        routes = read("apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs")
        manager = read("apps/signer-firmware/src/wallet/seed_manager/network.rs")
        session = read("apps/signer-firmware/src/services/wallet_session.rs")
        loaded = read("apps/signer-firmware/src/runtime/signing/loaded_accounts.rs")
        multisig = read("apps/signer-firmware/src/runtime/interactions/tx/multisig_setup/seed_picker.rs")
        destructive = read("apps/signer-firmware/src/services/destructive.rs")

        self.assertIn("wallet_session::clear_active_wallet(ad)", routes)
        self.assertIn("seed_mgr.set_network(network)", routes)
        self.assertIn("mark_device_preferences_dirty()", routes)
        self.assertIn("self.slots[slot_idx].network == self.selected_network", manager)
        self.assertIn("if !ad.wallet.seeds.seed_mgr.slot_visible(slot_index)", session)
        self.assertIn("seed_manager.slot_visible(active_manager_slot)", loaded)
        self.assertNotIn("for manager_index in 0..seed_manager::MAX_SLOTS", loaded)
        self.assertIn("slot_visible(slot_index)", multisig)
        self.assertIn("slot_visible(index)", destructive)

    def test_selected_network_controls_transaction_acceptance_and_address_hrp(self):
        tx = read("apps/signer-firmware/src/runtime/interactions/tx/transaction.rs")
        anti = read("apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/anti_klepto.rs")
        export = read("apps/signer-firmware/src/ui/redraw/export.rs")
        multisig_redraw = read("apps/signer-firmware/src/ui/redraw/multisig.rs")
        multisig_output = read("apps/signer-firmware/src/runtime/interactions/tx/multisig_output.rs")

        self.assertEqual(tx.count("selected_network_matches_transaction(ad)"), 2)
        self.assertIn("matches_transaction_network(ad.signing.transaction.active.network)", tx)
        pskt_context = read("apps/signer-firmware/src/runtime/interactions/tx/transaction/standard_pskt_context.rs")
        self.assertIn("selected wallet/network is therefore local signing context only", pskt_context)
        self.assertIn("seed_mgr.network().kaspa_network()", pskt_context)
        self.assertGreaterEqual(anti.count("matches_transaction_network"), 2)
        self.assertIn("seed_mgr.network().kaspa_network()", export)
        self.assertIn("encode_address_str_for_network", multisig_redraw)
        self.assertIn("seed_mgr.network().kaspa_network()", multisig_redraw)
        self.assertIn("encode_address_for_network", multisig_output)

    def test_wallet_list_puts_add_first_and_shows_pass_and_network(self):
        touch = read("apps/signer-firmware/src/runtime/interactions/seed/seed_list/list.rs")
        screen = read("apps/signer-firmware/src/ui/screens/wallet/seed_slots.rs")

        self.assertIn("let total = loaded_count + usize::from(can_add)", touch)
        self.assertIn("if can_add && item == 0", touch)
        self.assertIn("item.saturating_sub(usize::from(can_add))", touch)
        self.assertIn("if can_add && list_index == 0", screen)
        self.assertIn('draw_lato_hint(display, "Pass"', screen)
        self.assertIn("slot.network.short_label()", screen)
        self.assertIn("seed_mgr.slot_visible(index)", screen)

    def test_fresh_add_wallet_stays_staged_through_optional_entropy_and_word_ack(self):
        nav = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        generation = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        backup = read("apps/signer-firmware/src/runtime/interactions/export/seed_backup.rs")
        ack = read("apps/signer-firmware/src/runtime/interactions/persistence/onboarding/recovery.rs")

        self.assertIn("ad.wallet.seeds.begin_pending_add_wallet(action == 2)", nav)
        self.assertNotIn("pending_add_wallet_restore: bool", read("apps/signer-firmware/src/runtime/data/wallet.rs"))
        self.assertIn("route!(StorageSeedDiceChoice)", generation)
        staged_branch = passphrase.split("if ad.wallet.seeds.has_pending_add_wallet()", 1)[1].split("if !commit_current_seed", 1)[0]
        self.assertIn("route!(SeedBackup { word_idx: 0 })", staged_branch)
        self.assertNotIn("seed_mgr.store", staged_branch)
        self.assertIn("pub(crate) fn commit_staged_add_wallet", passphrase)

        pending_backup = backup.split("if ad.wallet.seeds.has_pending_add_wallet()", 1)[1]
        self.assertIn("StorageRecoveryAcknowledgement", pending_backup)
        self.assertIn("word_idx: ad.wallet.seeds.word_count.saturating_sub(1)", ack)
        # The per-wallet protection choice follows acknowledgement;
        # the seed remains staged and is committed only after that choice.
        self.assertIn("StorageProtectionChoice", ack)
        pending_ack = ack.split("if ad.wallet.seeds.has_pending_add_wallet()", 1)[1].split("if intent.is_seed_onboarding", 1)[0]
        self.assertNotIn("commit_staged_add_wallet", pending_ack)
        self.assertIn("I BACKED UP MY WORDS", read("apps/signer-firmware/src/ui/screens/device/persistence.rs"))


    def test_add_wallet_restore_is_staged_and_named(self):
        nav = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        words = read("apps/signer-firmware/src/runtime/interactions/seed/import/word_flow.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        naming = read("apps/signer-firmware/src/runtime/interactions/seed/wallet_name.rs")
        self.assertIn("ad.wallet.seeds.begin_pending_add_wallet(action == 2)", nav)
        self.assertNotIn("pending_add_wallet_restore: bool", read("apps/signer-firmware/src/runtime/data/wallet.rs"))
        self.assertIn("enter_passphrase(ad, word_count)", words)
        self.assertIn("WalletNameEntry { purpose: 3 }", passphrase)
        self.assertIn("3 => name_imported_wallet", naming)
        self.assertIn("route!(StorageFinalizeChoice)", naming)


    def test_restore_wallet_opens_simple_source_menu_before_any_import(self):
        nav = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        menus = read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
        routes = read("apps/signer-firmware/src/runtime/navigation/menu_reducer/routes.rs")
        onboarding = read("apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs")

        restore_branch = nav.split("let destination = if action == 2", 1)[1].split("} else {", 1)[0]
        self.assertIn("route!(StorageSeedSourceChoice)", restore_branch)
        self.assertNotIn("ChooseWordCount", restore_branch)
        for index, label in enumerate(("Words", "SeedQR", "SD", "Advanced")):
            self.assertIn(f'StorageSeedSourceChoice, {index}, "{label}"', menus)
        for index, label in enumerate(("Compact SeedQR", "Plain-text SeedQR", "Steganographic", "Raw Private Key")):
            self.assertIn(f'AdvancedRestoreMenu, {index}, "{label}"', menus)
        self.assertIn("(StorageSeedSourceChoice, 0) => RestoreWord { word_idx: 0 }", routes)
        self.assertIn("(StorageSeedSourceChoice, 1) => ScanQR", routes)
        self.assertIn("(StorageSeedSourceChoice, 2) => SdWalletBackupFileList", routes)
        self.assertIn("(StorageSeedSourceChoice, 3) => AdvancedRestoreMenu", routes)
        self.assertIn("pending_add_wallet_is_restore()", onboarding)
        self.assertIn("route!(AddWalletChoice)", onboarding)

    def test_restore_sources_share_staged_name_and_persistence_policy(self):
        qr = read("apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/seed.rs")
        raw = read("apps/signer-firmware/src/runtime/interactions/seed/import/private_key.rs")
        sd = read("apps/signer-firmware/src/runtime/interactions/sd/backup/import.rs")
        stego_finish = read("apps/signer-firmware/src/runtime/interactions/stego/import_finish.rs")
        stego_decrypt = read("apps/signer-firmware/src/runtime/interactions/stego/import_decrypt.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        installed = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase/installed.rs")
        manager = read("apps/signer-firmware/src/wallet/seed_manager/manager.rs")
        matching = read("apps/signer-firmware/src/wallet/seed_manager/matching.rs")

        self.assertIn("pub(super) fn process_plain_words", qr)
        self.assertIn("split_ascii_whitespace", qr)
        self.assertIn("let Ok(index) = offline_signer::derivation::bip39::word_to_index(word) else", qr)
        self.assertNotIn("let Some(index) = offline_signer::derivation::bip39::word_to_index(word) else", qr)
        self.assertIn("restore_scan_active(ad)", qr)
        self.assertIn("decode_and_install_transient", raw)
        self.assertIn("mark_pending_add_wallet_installed", raw)
        self.assertIn("WalletNameEntry { purpose: 3 }", raw)
        self.assertIn("install_account_xprv_transient", sd)
        self.assertIn("mark_pending_add_wallet_installed", sd)
        self.assertIn("WalletNameEntry { purpose: 3 }", sd)
        self.assertIn("restore_staging_active(ad)", stego_finish)
        self.assertIn("stage_bip39_passphrase(passphrase)", stego_finish)
        self.assertIn("route!(PassphraseChoice)", stego_decrypt)
        self.assertIn("pending_add_wallet_has_installed_source()", passphrase)
        self.assertIn("installed::commit_add_wallet", passphrase)
        self.assertIn("installed::finish_session_wallet", passphrase)
        self.assertIn("installed::apply_pending_wallet_name(ad, slot);", passphrase)
        self.assertIn("pub(super) fn apply_pending_wallet_name", installed)
        self.assertIn("promote_transient", installed)
        self.assertIn("pub fn store_account_key_transient", manager)
        self.assertIn("pub fn store_raw_key_transient", matching)
        self.assertIn("if slot.transient { continue; }", read("apps/signer-firmware/src/services/persistent_wallet/codec.rs"))

    def test_import_never_enters_recovery_word_backup(self):
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        redraw = read("apps/signer-firmware/src/ui/redraw/wallet/words.rs")
        branch = passphrase.split("if ad.wallet.seeds.has_pending_add_wallet() || imported_onboarding {", 1)[1].split("if !commit_current_seed", 1)[0]
        self.assertIn("pending_add_wallet_is_restore() || imported_onboarding", branch)
        self.assertIn("route!(WalletNameEntry { purpose: 3 })", branch)
        self.assertIn("route!(SeedBackup { word_idx: 0 })", branch)
        self.assertIn("ad.wallet.seeds.pending_add_wallet_is_restore() || imported_onboarding", redraw)
        self.assertIn("ad.storage.persistence.onboarding_imported_mnemonic", redraw)

    def test_session_only_wallet_is_not_serialized(self):
        manager = read("apps/signer-firmware/src/wallet/seed_manager/manager.rs")
        mnemonic_store = read("apps/signer-firmware/src/wallet/seed_manager/mnemonic_store.rs")
        codec = read("apps/signer-firmware/src/services/persistent_wallet/codec.rs")
        journal = read("apps/signer-firmware/src/services/persistent_wallet/journal.rs")
        finalize = read("apps/signer-firmware/src/runtime/interactions/persistence/onboarding/finalize.rs")
        seed_controller = read("apps/signer-firmware/src/runtime/interactions/seed.rs")
        self.assertIn("pub fn store_transient", mnemonic_store)
        self.assertIn("persistent_active", manager)
        self.assertIn("if slot.transient { continue; }", codec)
        self.assertIn("manager.persistent_active()", codec)
        self.assertIn("slot.is_empty() || slot.transient", journal)
        self.assertIn("commit_staged_session_wallet", finalize)
        self.assertIn("commit_staged_session_wallet,", seed_controller)

    def test_manual_restore_routes_passphrase_then_name_then_finalize(self):
        restore = read("apps/signer-firmware/src/runtime/interactions/seed/import/restore.rs")
        onboarding = read("apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        naming = read("apps/signer-firmware/src/runtime/interactions/seed/wallet_name.rs")
        policy = read("apps/signer-firmware/src/runtime/navigation/onboarding.rs")
        nav_policy = read("apps/signer-firmware/src/runtime/navigation/policy.rs")
        self.assertIn("route!(PassphraseChoice)", restore)
        self.assertIn("route!(PassphraseChoice)", onboarding)
        self.assertIn("route!(WalletNameEntry { purpose: 3 })", passphrase)
        self.assertIn("route!(StorageFinalizeChoice)", naming)
        self.assertIn("WalletNameEntry { purpose: 0 | 3 } => Some(SeedEntry)", policy)
        self.assertNotIn("WalletNameEntry { purpose: 0 } => Some(Persistence)", policy)
        self.assertIn("(WalletNameEntry { purpose: 3 }, StorageFinalizeChoice)", nav_policy)
        self.assertIn("(StorageFinalizeChoice, WalletNameEntry { purpose: 3 })", nav_policy)
        self.assertIn("(StorageFinalizeChoice, SeedList)", nav_policy)

if __name__ == "__main__":
    unittest.main()
