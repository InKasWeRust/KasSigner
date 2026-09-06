#!/usr/bin/env python3
"""Regression guards for device-bound wallet persistence and retired weak backups."""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def read_persistence_controller() -> str:
    return "\n".join(read(path) for path in (
        "apps/signer-firmware/src/runtime/interactions/persistence.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/finalize.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/recovery.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/credential.rs",
    ))


def read_device_redraw() -> str:
    return "\n".join(read(path) for path in (
        "apps/signer-firmware/src/ui/redraw/device.rs",
        "apps/signer-firmware/src/ui/redraw/device/onboarding.rs",
    ))


class DeviceBoundStorageTests(unittest.TestCase):
    def test_mock_hmac_kdf_vector_uses_argon2_stretched_known_answer(self) -> None:
        # The Argon2 output below is a host-generated Argon2id v=19 KAT for
        # PasswordKdfPurpose::PersistentWallet, password ``correct7horse``,
        # salt 00..0f, m=2048 KiB, t=3, p=1. This test independently
        # reproduces the device-HMAC and final SHA-256 layers without invoking
        # the retired generic PBKDF2 password policy.
        salt = bytes(range(16))
        header = b"KSWLT003-test-header"
        device_secret = bytes(range(0xA0, 0xC0))
        stretched = bytes.fromhex(
            "1a75f025090764e027c8a16ea3bca0e5"
            "ee3107a12adb6e6f3e99a38717880ce2"
        )
        params = bytes((3, 2, 1, 2))  # format, device KDF, internal purpose, password
        context = hashlib.sha256(
            b"KasSigner/device-bound-wallet/context/v1"
            + params
            + salt
            + len(header).to_bytes(4, "little")
            + header
        ).digest()
        challenge = context + stretched + params
        request = hashlib.sha256(
            b"KasSigner/device-bound-wallet/device-mix/v1"
            + len(challenge).to_bytes(4, "little")
            + challenge
        ).digest()
        device_mix = hmac.new(device_secret, request, hashlib.sha256).digest()
        key = hashlib.sha256(
            b"KasSigner/device-bound-wallet/aes-256-gcm/v1"
            + context
            + stretched
            + device_mix
        ).hexdigest()
        self.assertEqual(
            key,
            "e8ad51481e6901fc9dd19f986074c1f82925ebe43de4936f384e3d0e6e880ba9",
        )
        rust_test = read(
            "crates/offline-signer/src/crypto/unit_tests/device_bound_storage_tests.rs"
        ).replace(" ", "").replace("\n", "")
        for chunk in (
            "0xe8,0xad,0x51,0x48",
            "0x29,0x25,0xeb,0xe4",
            "0x38,0x4e,0x3d,0x0e,0x6e,0x88,0x0b,0xa9",
        ):
            self.assertIn(chunk, rust_test)
        self.assertIn(
            "deterministic_argon2_device_kdf_vector_matches_independent_host_result",
            rust_test,
        )

    def test_hardware_boundary_exposes_hmac_operation_not_raw_key(self) -> None:
        core = read("crates/offline-signer/src/crypto/device_bound_storage.rs")
        firmware = read("apps/signer-firmware/src/services/persistent_wallet/crypto.rs")
        trait = core.split("pub trait HardwareHmac", 1)[1].split("}", 1)[0]
        self.assertIn("fn hmac_sha256", trait)
        for forbidden in ("key(", "secret(", "export", "raw_key", "read_key"):
            self.assertNotIn(forbidden, trait)
        self.assertIn("Efuse::read_field_le(RD_DIS)", firmware)
        self.assertIn("HmacPurpose::ToUser", firmware)
        self.assertIn("PERSISTENT_KEY_SLOTS: [u8; 3] = [3, 4, 5]", firmware)
        self.assertNotIn("Efuse::read_field_le(KEY", firmware)

    def test_device_bound_tests_cover_required_failure_modes(self) -> None:
        tests = read(
            "crates/offline-signer/src/crypto/unit_tests/device_bound_storage_tests.rs"
        )
        for contract in (
            "deterministic_argon2_device_kdf_vector_matches_independent_host_result",
            "kdf_domain_separates_internal_sd_header_salt_and_credential_kind",
            "unsupported_format_or_kdf_parameters_fail_closed_without_hmac_use",
            "same_device_roundtrip_succeeds_and_tampering_fails_with_zeroized_plaintext",
            "wrong_password_and_wrong_device_are_rejected",
            "altered_authenticated_header_is_rejected",
            "missing_hmac_service_fails_closed_and_zeroizes_buffers",
            "fresh_salt_and_nonce_are_generated_for_each_container",
            "entropy_failure_or_all_zero_material_fails_closed_and_clears_outputs",
            "ciphertext[5] ^= 0x80",
            "changed_salt[7] ^= 0x01",
        ):
            self.assertIn(contract, tests)

    def test_current_seed_and_xprv_backups_are_device_bound_not_password_only(self) -> None:
        backup = ROOT / "apps/signer-firmware/src/services/backup"
        self.assertTrue((backup / "container.rs").exists())
        self.assertFalse((backup / "legacy.rs").exists())
        facade = read("apps/signer-firmware/src/services/backup/mod.rs")
        self.assertIn("Device-bound removable wallet backups", facade)
        self.assertIn("Historical password-only wallet", facade)

        container = read("apps/signer-firmware/src/services/backup/container.rs")
        framing = read("crates/offline-signer/src/crypto/container_framing.rs")
        container_contract = container + "\n" + framing
        for required in (
            'KASDB005', 'KASDB004',
            "KDF_ID_DEVICE_HMAC_SHA256",
            "PasswordKdfPurpose::DeviceBoundBackup",
            "BackupReaderKdf::Argon2id", "BackupReaderKdf::LegacyPbkdf2",
            "StoragePurpose::SdSeedBackup",
            "StoragePurpose::SdXprvBackup",
        ):
            self.assertIn(required, container_contract)
        for old_magic in (r"KAS\x01", r"KAS\x02", r"KAX\x02", r"KAR\x02"):
            self.assertNotIn(old_magic, container)

        for relative in ("seed.rs", "xprv.rs"):
            source = read(f"apps/signer-firmware/src/services/backup/{relative}")
            self.assertIn("BackupDevice", source)
            self.assertIn("container::", source)
            self.assertNotIn("BackupError::DeviceBoundStorageRequired", source)
            self.assertNotIn("Aes256Gcm", source)
        self.assertFalse((backup / "raw.rs").exists())
        self.assertNotIn("encrypt_raw_progress", facade)
        self.assertNotIn("decrypt_raw_progress", facade)

        tests = read("apps/signer-firmware/src/services/unit_tests/backup_tests.rs")
        for required in (
            "current_device_bound_backup_uses_argon2_metadata",
            "historical_deployed_legacy_device_bound_reader_is_magic_selected_only",
            "wrong_password", "bad_kdf", "AuthenticationFailed",
        ):
            self.assertIn(required, tests)

    def test_current_backup_and_touch_seed_states_are_present(self) -> None:
        state = read("apps/signer-firmware/src/runtime/input/state.rs")
        navigation = read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
        routing = read("apps/signer-firmware/src/runtime/interactions/sd/common/routing.rs")
        for current in (
            "TouchEntropy",
            "SdBackupWarning",
            "SdSeedFilename",
            "SdSeedExportPassphrase",
            "SdWalletBackupFileList",
            "SdWalletBackupImportPassphrase",
        ):
            self.assertIn(current, state)
        for label in ('"Touch Seed"', '"Backup to SD"', '"Encrypt to SD"', '"Seed / XPrv Backup"'):
            self.assertIn(label, navigation)
        self.assertIn("handle_seed_backup_export_passphrase", routing)
        self.assertIn("handle_wallet_backup_import_passphrase", routing)

    def test_device_bound_backup_firmware_facades_match_live_contexts(self) -> None:
        common = read("apps/signer-firmware/src/runtime/interactions/sd/common/mod.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/sd/common/passphrase.rs")
        signing = read("apps/signer-firmware/src/runtime/signing.rs")
        derivation = read("apps/signer-firmware/src/runtime/signing/derivation.rs")
        routes = read("apps/signer-firmware/src/runtime/event_loop/touch_routes.rs")
        browser = read("apps/signer-firmware/src/runtime/interactions/sd/imports/file_browser.rs")

        self.assertIn("run_device_bound_passphrase_workflow", common)
        self.assertNotIn("run_passphrase_workflow", common)
        self.assertNotIn("fn run_passphrase_workflow", passphrase)
        self.assertIn("pub(crate) use derivation::zeroize_seed;", signing)
        self.assertIn("pub(crate) use crate::services::wallet_keys::{derive_slot_seed_with_checkpoint, zeroize_seed};", derivation)
        self.assertNotIn("{derive_seed, derive_slot_seed, zeroize_seed}", derivation)
        self.assertIn("derive_slot_seed_with_checkpoint(slot, checkpoint)", derivation)
        self.assertEqual(routes.count("backup_device: &mut $persistent_wallet"), 2)
        self.assertIn("is_back, .. } = ctx", browser)

    def test_recovery_acknowledgement_is_ui_and_service_enforced(self) -> None:
        ui = read("apps/signer-firmware/src/ui/screens/device/persistence.rs")
        for text in (
            "Recovery words are your",
            "permanent portable backup.",
            "I BACKED UP MY WORDS",
        ):
            self.assertIn(text, ui)
        self.assertNotIn("Recovery words are your permanent portable backup.", ui)
        state = read("apps/signer-firmware/src/runtime/data/storage/persistence.rs")
        controller = read_persistence_controller()
        service = read("apps/signer-firmware/src/services/persistent_wallet/mod.rs")
        service_save = read("apps/signer-firmware/src/services/persistent_wallet/save/mod.rs")
        advanced = read("apps/signer-firmware/src/services/persistent_wallet/advanced.rs")
        self.assertIn("recovery_words_acknowledged: bool", state)
        self.assertIn("recovery_words_acknowledged = true", controller)
        self.assertIn("onboarding_mnemonic_ready", controller)
        self.assertIn("RecoveryAcknowledgementRequired", service)
        self.assertIn("if !recovery_words_acknowledged", service + service_save)
        self.assertIn("if !recovery_words_acknowledged", advanced)

    def test_device_bound_onboarding_establishes_words_before_ack_and_credential(self) -> None:
        app_state = read("apps/signer-firmware/src/runtime/input/state.rs")
        controller = read_persistence_controller()
        onboarding = read("apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs")
        wallet_name = read("apps/signer-firmware/src/runtime/interactions/seed/wallet_name.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        seed_backup = read("apps/signer-firmware/src/runtime/interactions/export/seed_backup.rs")
        ui = read("apps/signer-firmware/src/ui/screens/device/persistence.rs")
        matrix = read("apps/signer-firmware/src/runtime/navigation/onboarding.rs")

        for state in ("StorageSeedSourceChoice", "StorageSeedDiceChoice", "StorageSeedDiceCountChoice", "StorageSeedTouchChoice", "StorageSeedWordCountChoice { action: u8 }", "WalletNameEntry { purpose: u8 }"):
            self.assertIn(state, app_state)
        self.assertNotIn("StorageSeedCreationMethodChoice", app_state)
        self.assertIn("route!(WalletNameEntry { purpose: 0 })", onboarding)
        self.assertIn("route!(StorageSeedSourceChoice)", onboarding)
        self.assertIn("route!(StorageSeedWordCountChoice { action: 0 })", wallet_name)
        self.assertIn("WalletNameEntry { purpose: 0 } => matches!(to, StorageModeChoice | StorageSeedWordCountChoice { action: 0 })", matrix)
        for label in ('"Create Wallet"', '"Restore Wallet"', '"Save Securely on Device"', '"Use for This Session Only"', '"Hardware + camera are always used."', '"No Dice"', '"Add Dice Rolls"', '"ADD TOUCH"', '"No Touch Entropy"', '"Add Touch Entropy"'):
            self.assertIn(label, ui)
        self.assertNotIn("ad.export.seed_backup_return = AppState::StorageRecoveryAcknowledgement", passphrase)
        self.assertIn("device_storage_intent", seed_backup)
        self.assertIn("ReturnScope::SeedBackup", seed_backup)


    def test_empty_wallet_startup_can_only_enter_storage_choice(self) -> None:
        startup = read("apps/signer-firmware/src/services/persistent_wallet/startup.rs")
        service = read("apps/signer-firmware/src/services/persistent_wallet/mod.rs")
        service_save = read("apps/signer-firmware/src/services/persistent_wallet/save/mod.rs")
        self.assertIn("None => self.initialize_empty(ad)", startup)
        self.assertIn("self.initialize_choice(ad)", startup)
        empty = startup.split("fn initialize_empty", 1)[1].split("fn initialize_choice", 1)[0]
        self.assertNotIn("MainMenu", empty)
        self.assertIn("Ok(StartupState::ChoiceRequired) => StartupDisposition::ChoiceRequired", service)
        self.assertIn("StartupDisposition::ChoiceRequired => enter_storage_choice(ad)", read("apps/signer-firmware/src/runtime/interactions/persistence.rs"))

    def test_always_start_fresh_requires_mnemonic_onboarding_before_home(self) -> None:
        state = read("apps/signer-firmware/src/runtime/data/storage/persistence.rs")
        startup = read("apps/signer-firmware/src/services/persistent_wallet/startup.rs")
        onboarding = read("apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs")
        wallet_name = read("apps/signer-firmware/src/runtime/interactions/seed/wallet_name.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        persistence = read_persistence_controller()

        self.assertIn("StartFresh", state)
        self.assertIn("is_seed_onboarding", state)
        empty = startup[startup.index("fn initialize_empty"):startup.index("fn initialize_choice")]
        choice = startup[startup.index("fn initialize_choice"):]
        self.assertIn("self.initialize_choice(ad)", empty)
        self.assertIn("Ok(StartupState::ChoiceRequired)", choice)
        mode = onboarding[onboarding.index("fn apply_mode_choice"):onboarding.index("#[cfg(feature = \"workflow-test-auto\")]", onboarding.index("fn apply_mode_choice"))]
        self.assertIn("route!(WalletNameEntry { purpose: 0 })", mode)
        self.assertNotIn("MainMenu", mode)
        self.assertIn("route!(StorageSeedWordCountChoice { action: 0 })", wallet_name)
        self.assertIn("DeviceStorageIntent::StartFresh", passphrase)
        self.assertIn("route!(SeedBackup { word_idx: 0 })", passphrase)
        seed_backup = read("apps/signer-firmware/src/runtime/interactions/export/seed_backup.rs")
        self.assertIn("route!(StorageRecoveryAcknowledgement)", seed_backup)
        self.assertNotIn("complete_start_fresh(ad)", passphrase)
        self.assertIn("DeviceStorageIntent::StartFresh | DeviceStorageIntent::CreateInternal =>", persistence)
        self.assertIn("complete_start_fresh(ad)", persistence)

    def test_device_bound_dice_is_additive_after_mandatory_hardware_camera_entropy(self) -> None:
        wallet_name = read("apps/signer-firmware/src/runtime/interactions/seed/wallet_name.rs")
        generation = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs")
        additive = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation/additive.rs")
        dice = read("apps/signer-firmware/src/runtime/interactions/menu/seed_tools/dice.rs")
        mixer = read("apps/signer-firmware/src/services/entropy/mixer.rs")
        wallet = read("apps/signer-firmware/src/runtime/data/wallet.rs") + read("apps/signer-firmware/src/runtime/data/wallet/seed_session.rs")

        self.assertIn("route!(StorageSeedWordCountChoice { action: 0 })", wallet_name)
        for state in ("StorageSeedDiceChoice", "StorageSeedDiceCountChoice", "StorageSeedTouchChoice"):
            self.assertIn(state, generation)
        for name in ("NO_DICE_BUTTON_Y", "ADD_DICE_BUTTON_Y", "NO_TOUCH_BUTTON_Y", "ADD_TOUCH_BUTTON_Y"):
            self.assertIn(name, additive)
        for target in (25, 50, 100, 200):
            self.assertIn(f"DICE_{target}_BUTTON_Y", additive)
        production_generation = generation[generation.index("fn generate_random_seed("):]
        collect_at = production_generation.index("crate::services::entropy::collect(")
        stage_at = production_generation.index("stage_seed_entropy(&mut pool, word_count)")
        dice_choice_at = production_generation.index("StorageSeedDiceChoice", stage_at)
        self.assertLess(collect_at, stage_at)
        self.assertLess(stage_at, dice_choice_at)
        self.assertIn("pending_seed_entropy_valid", wallet)
        self.assertIn("mix_dice_into_staged", dice)
        self.assertIn('b"KasSigner/additive-dice/v1"', mixer)
        self.assertIn("!(1..=6).contains(roll)", mixer)

    def test_proportional_font_rendering_batches_each_glyph_instead_of_each_pixel(self) -> None:
        fonts = read("apps/signer-firmware/src/ui/prop_fonts.rs")
        draw_start = fonts.index("pub fn draw_prop_text<")
        opaque_start = fonts.index("pub fn draw_prop_text_opaque<")
        transparent = fonts[draw_start:opaque_start]

        self.assertNotIn("display.draw_iter(core::iter::once", transparent)
        self.assertIn("let pixels = (0..height as usize).flat_map", transparent)
        self.assertIn("display.draw_iter(pixels)", transparent)
        self.assertIn("data.get(byte_off).copied().unwrap_or(0)", transparent)

        opaque = fonts[opaque_start:]
        self.assertIn("let cell_width = cw.saturating_add(1)", opaque)
        self.assertIn("(0..cell_width).map", opaque)
        self.assertIn("display.fill_contiguous(&area, pixel_iter)", opaque)
        self.assertNotIn("let gap_area = Rectangle::new", opaque)

        receive = read("apps/signer-firmware/src/ui/screens/wallet/address/receive.rs")
        self.assertIn("draw_lato_title_opaque", receive)
        address_lines = receive[receive.index("fn draw_address_lines"):receive.index("fn draw_address_index_button")]
        self.assertIn("draw_lato_title_opaque(", address_lines)
        self.assertNotIn("draw_lato_title(&mut self.display, line", address_lines)

    def test_device_bound_word_count_render_is_fixed_and_font_measurement_is_panic_safe(self) -> None:
        redraw = read_device_redraw()
        keyboard = read("apps/signer-firmware/src/ui/screens/wallet/keyboard.rs")
        fonts = read("apps/signer-firmware/src/ui/prop_fonts.rs")

        self.assertIn("draw_storage_seed_word_count_screen()", redraw)
        self.assertNotIn("word_count_title(action)", redraw)
        self.assertIn('self.draw_word_count_choices("MNEMONIC LENGTH")', keyboard)
        self.assertIn("pub fn draw_choose_wc_screen(&mut self, action: u8)", keyboard)
        self.assertIn("let title = signer_firmware_core::presentation::render::word_count_title(action);", keyboard)
        self.assertIn("text.as_bytes().iter().take(256)", fonts)
        self.assertIn(".get((ch - first_char) as usize)", fonts)
        self.assertIn("w = w.saturating_add(advance)", fonts)
        self.assertIn("w.saturating_sub", fonts)
        self.assertNotIn("w += (height / 3) as i32", fonts)

        widths_match = re.search(
            r"pub const OSWALD_BOLD_22_WIDTHS: \[u8; 95\] = \[(.*?)\];",
            fonts,
            re.S,
        )
        self.assertIsNotNone(widths_match)
        widths = [int(value) for value in re.findall(r"\d+", widths_match.group(1))]
        header_width = sum(widths[ord(char) - 32] + 1 for char in "MNEMONIC LENGTH") - 1
        self.assertEqual(header_width, 185)
        self.assertLess(header_width, 300)


    def test_mnemonic_passphrase_is_explicitly_optional_and_explained(self) -> None:
        state = read("apps/signer-firmware/src/runtime/input/state.rs")
        controller = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase_choice.rs")
        entry = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        redraw = read("apps/signer-firmware/src/ui/redraw/wallet/input.rs")
        ui = read("apps/signer-firmware/src/ui/screens/wallet/keyboard.rs")
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        nav_back = read("apps/signer-firmware/src/runtime/navigation/back.rs")
        persistence = read_persistence_controller()
        self.assertIn("PassphraseChoice", state)
        self.assertIn("PassphraseEntry", state)
        self.assertIn('"BIP39 Pass."', ui)
        self.assertIn('"Optional extra secret for your words."', ui)
        self.assertIn('"It creates a different wallet."', ui)
        self.assertIn('"Keep the passphrase to restore later."', ui)
        self.assertIn('"No Passphrase"', ui)
        self.assertIn('"Use Passphrase"', ui)
        self.assertIn("store_seed_with_passphrase", controller)
        self.assertIn("route!(PassphraseEntry)", controller)
        self.assertIn("draw_passphrase_choice_screen", redraw)
        self.assertIn("pub(super) fn store_seed_with_passphrase", entry)
        self.assertIn("PassphraseEntry", nav_back)
        self.assertIn("PassphraseEntry => PassphraseChoice", nav_back)
        self.assertIn("pp_input.reset()", nav_back)
        self.assertIn("zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices)", persistence)
        self.assertIn("runtime::navigation::handle_back($ad)", dispatch)
        fonts = read("apps/signer-firmware/src/ui/prop_fonts.rs")
        widths_match = re.search(r"pub const LATO_15_WIDTHS: \[u8; 95\] = \[(.*?)\];", fonts, re.S)
        self.assertIsNotNone(widths_match)
        widths = [int(value) for value in re.findall(r"\d+", widths_match.group(1))]
        for line in (
            "Optional extra secret for your words.",
            "It creates a different wallet.",
            "Keep the passphrase to restore later.",
        ):
            measured = sum(widths[ord(char) - 32] + 1 for char in line) - 1
            self.assertLessEqual(measured, 300, line)

    def test_all_mnemonic_acquisition_paths_stop_at_passphrase_choice(self) -> None:
        paths = [
            "apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs",
            "apps/signer-firmware/src/runtime/interactions/menu/seed_tools/dice.rs",
            "apps/signer-firmware/src/runtime/interactions/seed/import/word_flow.rs",
            "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/seed.rs",
            "apps/signer-firmware/src/runtime/event_loop/touch_entropy.rs",
        ]
        for path in paths:
            source = read(path)
            self.assertIn("PassphraseChoice", source, path)
            self.assertNotIn("state = AppState::PassphraseEntry", source, path)
            self.assertNotIn("state = crate::runtime::input::AppState::PassphraseEntry", source, path)

    def test_device_bound_centered_hints_fit_the_320px_display(self) -> None:
        ui = read("apps/signer-firmware/src/ui/screens/device/persistence.rs")
        fonts = read("apps/signer-firmware/src/ui/prop_fonts.rs")
        widths_match = re.search(
            r"pub const LATO_12_WIDTHS: \[u8; 95\] = \[(.*?)\];",
            fonts,
            re.S,
        )
        self.assertIsNotNone(widths_match)
        widths = [int(value) for value in re.findall(r"\d+", widths_match.group(1))]
        self.assertEqual(len(widths), 95)

        def measured_width(text: str) -> int:
            total = sum(widths[ord(char) - 32] + 1 for char in text)
            return max(total - 1, 0)

        hints = re.findall(r'draw_centered_hint\("([^"]+)"', ui)
        self.assertGreater(len(hints), 10)
        for hint in hints:
            self.assertLessEqual(
                measured_width(hint),
                300,
                f"centered persistence hint clips the 320px display: {hint!r}",
            )

    def test_storage_setup_credentials_are_visible_but_unlock_remains_masked(self) -> None:
        ui = read("apps/signer-firmware/src/ui/screens/device/persistence.rs")
        redraw = read_device_redraw()
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        controller = read_persistence_controller()
        self.assertIn("draw_visible_credential", ui)
        self.assertIn("draw_visible_pin", ui)
        self.assertNotIn("Credential is hidden while typing", ui)
        self.assertIn('draw_storage_pin_entry(&ad.wallet.seeds.pp_input, "CREATE PIN", true)', redraw)
        self.assertIn('draw_storage_pin_entry(&ad.wallet.seeds.pp_input, "CONFIRM PIN", true)', redraw)
        self.assertIn("unlock_feedback.pin_title()", redraw)
        self.assertIn("false,", redraw.split("unlock_feedback.pin_title()", 1)[1].split("),", 1)[0])
        self.assertIn("accepted", navigation)
        self.assertIn("credential keys may click once", navigation)
        self.assertIn("tap_uses_router_click", dispatch)
        self.assertIn("crate::services::audio::click();", controller)
        self.assertIn("if !matches!(action, KeyAction::None | KeyAction::Ok) { crate::services::audio::click(); }", controller)
        self.assertIn("if !matches!(action, PinPadAction::Submit) { crate::services::audio::click(); }", controller)

    def test_initial_wallet_resolver_hides_back_until_a_wallet_is_active(self) -> None:
        seed_ui = read("apps/signer-firmware/src/ui/screens/wallet/seed_management.rs")
        navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        self.assertIn("if seed_mgr.active_slot().is_some() {", seed_ui)
        conditional = seed_ui[seed_ui.index("if seed_mgr.active_slot().is_some() {"):]
        active_branch, inactive_and_rest = conditional.split("} else {", 1)
        inactive_branch = inactive_and_rest.split("}", 1)[0]
        self.assertIn("self.clear_keep_nav();", active_branch)
        self.assertIn("self.clear_screen();", inactive_branch)
        self.assertNotIn("self.draw_back_button();", seed_ui.split("pub fn draw_seed_list_screen", 1)[1].split("// ═", 1)[0])
        self.assertIn("ad.navigation.app.state == AppState::SeedList", navigation)
        self.assertIn("ad.wallet.seeds.seed_mgr.active_slot().is_none()", navigation)

    def test_credential_audio_resume_does_not_drop_ordinary_pin_clicks(self) -> None:
        sound = read("apps/signer-firmware/src/hw/m5stack/sound.rs")
        controller = read_persistence_controller()
        resume_at = sound.index("pub fn resume_runtime_cues()")
        resume = sound[resume_at:sound.index("/// UI/domain sound APIs", resume_at)]
        self.assertIn("CUES_SUSPENDED.swap(false, Ordering::AcqRel)", resume)
        self.assertIn("discard_pending();", resume)
        self.assertNotIn("discard_pending();\n    CUES_SUSPENDED.store(false", resume)
        self.assertIn("if !matches!(action, PinPadAction::Submit) { crate::services::audio::click(); }", controller)
        self.assertIn("if !matches!(action, KeyAction::None | KeyAction::Ok) { crate::services::audio::click(); }", controller)

    def test_device_bound_pin_uses_dedicated_bounded_numeric_keypad(self) -> None:
        ui = read("apps/signer-firmware/src/ui/screens/device/persistence.rs")
        controller = read_persistence_controller()
        self.assertIn("PIN_PAD_X", ui)
        self.assertIn("PIN_PAD_Y", ui)
        self.assertIn('["1", "2", "3"]', ui)
        self.assertIn('["4", "5", "6"]', ui)
        self.assertIn('["7", "8", "9"]', ui)
        self.assertIn('["DEL", "0", "OK"]', ui)
        self.assertIn("PinPadAction::Digit", ui)
        self.assertIn("PinPadAction::Backspace", ui)
        self.assertIn("PinPadAction::Submit", ui)
        self.assertIn("return edit_pin_secret(input, ad, display)", controller)
        self.assertIn("pp.len < 12", controller)
        self.assertIn("update_storage_pin_value", controller)
        self.assertIn("update_storage_pin_value", ui)
        pin_body = controller.split("fn edit_pin_secret", 1)[1].split("fn edit_password_secret", 1)[0]
        self.assertNotIn("hit_test(", pin_body)
        self.assertNotIn("KeyboardMode::Numeric", pin_body)

    def test_m5stack_touch_recovers_missed_release_and_missed_press_edges(self) -> None:
        touch = read("apps/signer-firmware/src/hw/m5stack/touch/mod.rs")
        gate = read("crates/signer-firmware-core/src/input/touch/contact_gate.rs")
        tests = read("apps/signer-firmware/src/hw/m5stack/touch/unit_tests/mod.rs")
        self.assertIn("touch::contact_gate::ContactGate", touch)
        self.assertNotIn("ImmediateTouchTracker as TouchTracker", touch)
        self.assertIn("TouchEventType::PressDown => self.observe_press_down", gate)
        self.assertIn("TouchEventType::Contact => self.observe_contact", gate)
        self.assertIn("event == TouchEventType::LiftUp", gate)
        self.assertNotIn("navigation_changed", gate)
        self.assertNotIn("MISSED_RELEASE_REARM_SAMPLES", gate)
        self.assertIn("if !self.is_down", gate)
        self.assertIn("clearly new PressDown recovers after a missed release", tests)
        self.assertIn("held-contact samples never synthesize duplicate taps", tests)

    def test_device_bound_key_is_preflighted_before_seed_or_credential_setup(self) -> None:
        controller = read_persistence_controller()
        service = read("apps/signer-firmware/src/services/persistent_wallet/mod.rs")
        service_save = read("apps/signer-firmware/src/services/persistent_wallet/save/mod.rs")
        self.assertIn("pub fn device_key_available(&mut self) -> bool", service)
        self.assertIn("self.crypto.available_key_slot().is_some()", service)
        finalize_at = controller.index("fn handle_finalize_choice")
        preflight_at = controller.index("if !persistence.device_key_available()", finalize_at)
        credential_at = controller.index("enter_credential_type_choice(ad)", preflight_at)
        self.assertLess(preflight_at, credential_at)
        self.assertIn('show_rejection(display, delay, "Device key not provisioned"', controller)
        self.assertIn('"Device key not provisioned"', service)
        self.assertNotIn('"Device-bound storage key unavailable"', service)

        fonts = read("apps/signer-firmware/src/ui/prop_fonts.rs")
        title_match = re.search(r"pub const LATO_BOLD_18_WIDTHS: \[u8; 95\] = \[(.*?)\];", fonts, re.S)
        self.assertIsNotNone(title_match)
        title_widths = [int(value) for value in re.findall(r"\d+", title_match.group(1))]
        width = max(sum(title_widths[ord(char) - 32] + 1 for char in "Device key not provisioned") - 1, 0)
        self.assertLessEqual(width, 300)

    def test_seed_onboarding_navigation_cannot_escape_into_unrelated_menus(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        backup = read("apps/signer-firmware/src/runtime/interactions/export/seed_backup.rs")
        persistence = read_persistence_controller()
        persistence_navigation = read("apps/signer-firmware/src/runtime/interactions/persistence.rs")
        state_navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        self.assertNotIn("let is_home = (52..=82).contains(&x)", dispatch)
        self.assertIn("pub(crate) fn home(ad: &mut AppData)", state_navigation)
        self.assertIn("cancel_seed_onboarding(ad)", state_navigation)
        self.assertIn("UiEvent::Route(route!(StorageModeChoice))", state_navigation)
        start_fresh = passphrase.index("DeviceStorageIntent::StartFresh")
        backup_state = passphrase.index("route!(SeedBackup { word_idx: 0 })", start_fresh)
        self.assertNotIn("device_storage_intent =", passphrase[start_fresh:backup_state])
        self.assertIn("device_storage_intent.is_seed_onboarding()", backup)
        self.assertIn("DeviceStorageIntent::StartFresh", backup)
        self.assertIn("route!(StorageRecoveryAcknowledgement)", backup)
        self.assertNotIn("complete_start_fresh(ad)", backup)
        self.assertIn("complete_start_fresh(ad)", persistence)
        self.assertIn("pub(crate) fn complete_start_fresh", persistence_navigation)

    def test_cores3_entropy_retries_healthy_windows_and_stops_continuous_camera_dma(self) -> None:
        imu = read("apps/signer-firmware/src/hw/m5stack/imu.rs")
        camera = read("apps/signer-firmware/src/services/entropy/camera/mod.rs")
        camera_dvp = read("apps/signer-firmware/src/services/entropy/camera/dvp.rs")
        shared_dvp = read("apps/signer-firmware/src/hw/shared/dvp.rs")
        rejected = imu.index("BMI270 health sample rejected")
        self.assertNotIn("READY.store(false", imu[rejected - 300:rejected + 300])
        self.assertIn("seed windows will retry", imu)
        self.assertNotIn("delay.delay_millis(40);", camera)
        self.assertIn("MAX_CAMERA_HEALTH_WINDOWS", camera)
        self.assertIn("should_retry_camera_window", camera)
        self.assertIn("receive_full_frame", camera_dvp)
        self.assertIn("transfer.is_done()", shared_dvp)
        self.assertIn("transfer.wait()", shared_dvp)
        self.assertIn("transfer.stop()", shared_dvp)
        self.assertIn("partial transfer is stopped and must not be consumed", shared_dvp)
        mix_frames_sig = camera[camera.index("pub(crate) fn mix_frames"):camera.index(") -> CameraEntropyReport")]
        self.assertEqual(mix_frames_sig.count("delay: &mut Delay"), 1)

    def test_camera_entropy_failure_is_recoverable_without_weakening_health_policy(self) -> None:
        state = read("apps/signer-firmware/src/runtime/input/state.rs")
        routing = read("apps/signer-firmware/src/runtime/input/routing.rs")
        navigation = read("apps/signer-firmware/src/runtime/navigation/onboarding.rs")
        generation = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs")
        camera = read("apps/signer-firmware/src/services/entropy/camera/mod.rs")
        shared_camera = read("crates/signer-firmware-core/src/entropy/frame_noise.rs")
        screens = read("apps/signer-firmware/src/ui/screens/wallet/seed_generation.rs")
        geometry = read("apps/signer-firmware/src/ui/screens/wallet/mod.rs")
        redraw = read_device_redraw()
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        click_policy = read("apps/signer-firmware/src/runtime/navigation/mod.rs")

        self.assertIn("SeedEntropyUnavailable { word_count: u8 }", state)
        self.assertIn("SeedEntropyUnavailable { .. }", routing)
        self.assertIn("SeedEntropyUnavailable { .. }", navigation)
        self.assertIn("Some(Generation)", navigation)
        self.assertIn("StorageSeedDiceChoice | SeedEntropyUnavailable", navigation)
        self.assertIn("SeedEntropyUnavailable { word_count: retry_count }", navigation)

        self.assertIn("MAX_CAMERA_HEALTH_WINDOWS: u8 = 3", shared_camera)
        self.assertIn("const RETRY_SETTLE_MS: u32 = 150;", camera)
        self.assertIn("Camera entropy auto-retry {}/{}", camera)
        self.assertIn("CameraEntropyTracker::new()", camera)
        self.assertIn("delay.delay_millis(RETRY_SETTLE_MS);", camera)
        self.assertIn("if report.healthy() { break; }", camera)

        camera_reject = generation[generation.index("if error == crate::services::entropy::EntropyError::CameraUnavailable"):]
        camera_reject = camera_reject[:camera_reject.index("if error == crate::services::entropy::EntropyError::ImuUnavailable")]
        self.assertIn("clear_pending_seed_entropy()", camera_reject)
        self.assertIn("SeedEntropyUnavailable { word_count }", camera_reject)
        self.assertNotIn("show_rejection", camera_reject)
        self.assertIn("Camera entropy user retry", generation)
        self.assertIn("generate_random_seed(", generation[generation.index("fn handle_entropy_recovery"):])
        self.assertIn("Camera entropy user cancel", generation)
        self.assertIn("route!(StorageSeedWordCountChoice { action: 0 })", generation[generation.index("fn handle_entropy_recovery"):])
        self.assertIn("route!(SeedToolsMenu)", generation[generation.index("fn handle_entropy_recovery"):])

        self.assertIn("pub fn draw_camera_entropy_recovery", screens)
        self.assertIn('"Not enough changing image detail."', screens)
        self.assertIn('"Uncover camera and use brighter light."', screens)
        self.assertIn('"Move the signer slightly, then retry."', screens)
        self.assertIn('"TRY AGAIN"', screens)
        self.assertIn('"CANCEL"', screens)
        self.assertIn("entropy_recovery_choice_at", geometry)
        self.assertIn("ENTROPY_RECOVERY_BUTTON_Y", screens)
        self.assertIn("SeedEntropyUnavailable { .. }", redraw)
        self.assertIn("draw_camera_entropy_recovery()", redraw)

        self.assertIn("let entropy_recovery_ack = matches!(", dispatch)
        self.assertIn("entropy_recovery_choice_at(x, y)", dispatch)
        router_click = click_policy.split("pub(crate) fn tap_uses_router_click", 1)[1].split("/// Fail closed", 1)[0]
        self.assertIn("SeedEntropyUnavailable { .. }", router_click)

    def test_imported_mnemonic_skips_redundant_word_by_word_backup_review(self) -> None:
        state = read("apps/signer-firmware/src/runtime/data/storage/persistence.rs")
        controller = read_persistence_controller()
        passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        self.assertIn("onboarding_imported_mnemonic", state)
        self.assertIn("onboarding_imported_mnemonic = true", controller)
        self.assertIn("onboarding_imported_mnemonic = false", controller)
        imported_at = passphrase.index("if ad.storage.persistence.onboarding_imported_mnemonic")
        imported_branch = passphrase[imported_at:passphrase.index("        _ => {}", imported_at)]
        self.assertIn("recovery_words_acknowledged = true", imported_branch)
        self.assertIn("route!(StorageFinalizeChoice)", imported_branch)
        self.assertNotIn("route!(StorageRecoveryAcknowledgement)", imported_branch)
        self.assertNotIn("route!(SeedBackup { word_idx: 0 })", imported_branch)
        self.assertIn("route!(WalletNameEntry { purpose: 3 })", passphrase)
        self.assertIn("I BACKED UP MY WORDS", read("apps/signer-firmware/src/ui/screens/device/persistence.rs"))

    def test_legacy_storage_formats_are_explicit_and_portable_recovery_is_password_only(self) -> None:
        recovery = read("SECURITY.md")
        stego = read("docs/security/STEGANOGRAPHY.md")
        self.assertIn("mnemonic recovery words", recovery)
        self.assertIn("work only with the KasSigner device that created them", recovery)
        self.assertIn("current JPEG steganographic wallet backup", stego)
        self.assertIn("Historical Base64/password-only JPEG payload formats remain unsupported", stego)
        self.assertIn("JPEG + Password", stego)
        self.assertIn("offline password-guessing target", stego)
        self.assertIn("Argon2id", stego)
        self.assertIn("There is no generic KDF probing", stego)
        self.assertNotIn("128-bit recovery key", stego)
        self.assertNotIn("password and then the recovery key", stego)
        readme = read("README.md")
        self.assertIn("## Steganographic Backup: A beautiful way", readme)
        self.assertNotIn("## Historical JPEG wallet backups — retired", readme)
        self.assertNotIn("services/backup/legacy.rs` decrypts", recovery)


    def test_cores3_audio_uses_temporary_boot_clocks_and_owned_runtime_device(self) -> None:
        boot = read("apps/signer-firmware/src/boot/m5stack/mod.rs")
        audio = read("apps/signer-firmware/src/boot/m5stack/audio.rs")
        startup_audio = read("apps/signer-firmware/src/runtime/event_loop/runner/startup_audio.rs")
        runner = read("apps/signer-firmware/src/runtime/event_loop/runner.rs")
        sound = read("apps/signer-firmware/src/hw/m5stack/sound.rs")
        self.assertNotIn("core::mem::forget", boot + audio + sound)
        self.assertIn("tx.write_dma_circular(&*buffer)", audio)
        self.assertEqual(audio.count("write_dma_circular"), 1)
        self.assertIn("clocks.stop()", audio)
        init = audio[audio.index("pub(crate) fn initialize"):audio.index("fn enable_amplifier_power")]
        power = audio[audio.index("fn enable_amplifier_power"):audio.index("fn finish_audio_ready")]
        self.assertIn("delay.delay_millis(100)", power)
        self.assertLess(init.index("enable_amplifier_power(i2c, delay)"), init.index("tx.write_dma_circular(&*buffer)"))
        self.assertLess(init.index("tx.write_dma_circular(&*buffer)"), init.index("init_aw88298"))
        self.assertLess(audio.index("clocks.stop()"), audio.index("RuntimeAudio::new"))
        self.assertNotIn("play_boot_chime(", audio)
        self.assertIn("audio.play_boot_chime()", startup_audio)
        self.assertLess(runner.index("startup_audio::apply_audio_preference"), runner.index("startup_ui::render"))
        self.assertIn("pub(crate) struct RuntimeAudio", sound)
        self.assertIn("tx: SoundTx", sound)
        self.assertIn("const SOUND_DMA_BYTES: usize = 4 * 4092;", sound)
        self.assertIn("type SoundBuffer = [u8; SOUND_DMA_BYTES];", sound)
        self.assertIn("esp_hal::dma_buffers!(0, 4 * 4092)", boot)
        self.assertIn("buffer: &'static mut SoundBuffer", sound)
        self.assertIn("self.tx.write_dma_circular(&words)", sound)
        self.assertIn("SOUND_DMA_TIMEOUT", sound)
        self.assertIn("play_bounded_dma(transfer, used)", sound)
        self.assertIn("PENDING_CUE", sound)
        self.assertNotIn("AtomicPtr", sound)
        self.assertNotIn("StaticCell<SoundTx>", sound)
        self.assertNotIn("unsafe {", sound)
        self.assertNotIn("MaybeUninit", sound)
        self.assertNotIn("write_words(&buffer[..used])", sound)
        self.assertIn("pub(crate) fn play_boot_chime", sound)
        self.assertIn("transfer.push_with", sound)
        self.assertIn("fill_stereo_boot_chime_chunk", sound)
        core_audio = read("crates/signer-firmware-core/src/presentation/audio.rs")
        self.assertIn("pub const BOOT_CHIME_VOLUME: u8 = 18;", core_audio)
        self.assertIn("pub const BOOT_CHIME_BASE_AMPLITUDE: i16 = 6_000;", core_audio)
        self.assertIn("pub const BOOT_CHIME_AMPLITUDE: i16 = 423;", core_audio)
        self.assertIn("(800, 100)", core_audio)
        self.assertIn("(1_200, 100)", core_audio)
        self.assertIn("(1_600, 150)", core_audio)
        self.assertNotIn("BOOT_CHIME_GAP_MS", core_audio)
        self.assertLess(boot.index("m5stack::display::initialize"), boot.index("m5stack::audio::initialize"))

    def test_cores3_entropy_compile_interfaces_are_pinned(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        collection = read("apps/signer-firmware/src/services/entropy/collection.rs")
        m5_imu = read("apps/signer-firmware/src/hw/m5stack/imu.rs")
        self.assertNotIn("$crate::shared_signer", dispatch)
        navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        persistence_controller = read_persistence_controller()
        self.assertIn("cancel_seed_onboarding(ad)", navigation)
        self.assertIn("shared_signer::bytes::zeroize_u16", persistence_controller)
        self.assertIn("output: &mut [u8; imu::SEED_SAMPLE_BYTES]", collection)
        self.assertIn("const BMI270_DRIVER_BUFFER_BYTES: usize = 512;", m5_imu)
        self.assertIn("Bmi2::<_, _, BMI270_DRIVER_BUFFER_BYTES>::new_i2c(", m5_imu)
        self.assertIn(
            "        &mut *i2c,\n        &mut *delay,\n        I2cAddr::Alternative,\n        Burst::new(255),",
            m5_imu,
        )
        self.assertIn("Burst::new(255)", m5_imu)
        self.assertNotIn("Burst::Other", m5_imu)
        self.assertIn("bmi.init(&config::BMI270_CONFIG_FILE)", m5_imu)
        self.assertNotIn("bmi.init(&config::BMI270_CONFIG_FILE,", m5_imu)
        self.assertNotIn("config_buf", m5_imu)
        entropy_imu = read("apps/signer-firmware/src/services/entropy/imu.rs")
        gc0308 = read("apps/signer-firmware/src/hw/m5stack/cameras/gc0308/initialization.rs")
        camera_entropy = read("apps/signer-firmware/src/services/entropy/camera/mod.rs")
        self.assertIn('#[cfg(feature = "m5stack")]\npub(super) const SEED_SAMPLE_BYTES: usize = 33;', entropy_imu)
        self.assertIn("const NOISE_REMOVAL_ENABLE: u8 = 1 << 2;", gc0308)
        self.assertIn("prior & !NOISE_REMOVAL_ENABLE", gc0308)
        self.assertIn("end_entropy_capture(i2c, prior)", camera_entropy)
        signature = camera_entropy[camera_entropy.index("pub(crate) fn mix_frames"):camera_entropy.index(") -> CameraEntropyReport")]
        self.assertIn('#[cfg(feature = "m5stack")] i2c:', signature)
        self.assertNotIn('i2c: &mut esp_hal::i2c::master::I2c', signature.replace('#[cfg(feature = "m5stack")] i2c: &mut esp_hal::i2c::master::I2c', ''))
        mix_call = collection[collection.index("let camera_report = camera::mix_frames("):collection.index("    );", collection.index("let camera_report = camera::mix_frames("))]
        self.assertIn('#[cfg(feature = "m5stack")]\n        i2c,', mix_call)

    def test_fat32_formatter_allocator_and_power_loss_contracts_are_hardened(self) -> None:
        formatter = read("apps/signer-firmware/src/hw/shared/storage/fat32/format.rs")
        geometry = read("apps/signer-firmware/src/hw/shared/storage/fat32/format/geometry.rs")
        format_io = read("apps/signer-firmware/src/hw/shared/storage/fat32/format/io.rs")
        allocation = read("apps/signer-firmware/src/hw/shared/storage/fat32/allocation.rs")
        cache = read("apps/signer-firmware/src/hw/shared/storage/fat32/allocation/cache.rs")
        directory = read("apps/signer-firmware/src/hw/shared/storage/fat32/directory/helpers.rs")
        files = read("apps/signer-firmware/src/hw/shared/storage/fat32/files.rs")
        file_helpers = read("apps/signer-firmware/src/hw/shared/storage/fat32/files/helpers.rs")
        sd_backend = read("apps/signer-firmware/src/services/persistent_wallet/sd_backend.rs")
        shared_write = read("apps/signer-firmware/src/runtime/interactions/sd/common/shared.rs")

        self.assertIn("let card_sectors = sd_sector_count()?;", formatter)
        self.assertIn("format_geometry(card_sectors.min(MAX_FORMAT_SECTORS))?", formatter)
        self.assertNotIn("fat_size = 1024", formatter + geometry)
        self.assertNotIn("0x00F00000", formatter + geometry)
        self.assertIn("required_fat_size(total_sectors, sectors_per_cluster)?", geometry)
        self.assertIn("for index in 0..geometry.fat_size", format_io)
        self.assertIn("sd_write_block(card_type, fat1 + index, sector)?", format_io)
        self.assertIn("sd_write_block(card_type, fat2 + index, sector)?", format_io)
        self.assertNotIn("let _ = sd_write_block", format_io)
        self.assertIn("BACKUP_BOOT_SECTOR + FSINFO_SECTOR", format_io)
        self.assertIn("liveness();", format_io)

        self.assertIn("fat32.next_free_cluster", allocation)
        self.assertIn("fat32.cluster_count.saturating_add(2)", cache)
        self.assertNotIn("total_sectors - fat32.data_start_sector", cache)
        self.assertIn("struct FatSectorCache", cache)
        self.assertIn("for copy in 0..u32::from(self.fat32.num_fats)", cache)
        self.assertEqual(cache.count("sd_read_block("), 1)
        self.assertIn("update_fsinfo_hint", cache)
        self.assertIn("if sd_read_block(card_type, sector, &mut buf).is_err()", directory)

        delete = files[files.index("pub fn delete_file"):files.index("pub fn overwrite_file")]
        self.assertLess(delete.index("mark_dir_entry_deleted"), delete.index("release_chain"))
        replace = file_helpers[file_helpers.index("pub(super) fn replace_existing_file"):]
        committed = replace[replace.index("let new_entry = file_entry"): ]
        final_release = committed.rfind("release_chain(card_type, fat32, old_entry.first_cluster())")
        self.assertGreater(final_release, committed.index("replace_dir_entry_at"))
        self.assertRegex(
            sd_backend,
            re.compile(r"overwrite_file\s*\(\s*card\s*,\s*&fat\s*,\s*&SLOT_FILES\[index\]\s*,\s*&envelope\.0\s*\)\?"),
        )
        write_slot = sd_backend[sd_backend.index("pub(super) fn write_slot"):sd_backend.index("pub(super) fn read_slot")]
        self.assertNotIn("delete_file", write_slot)
        self.assertIn("storage_device::overwrite_file", shared_write)

        m5_capacity = read("apps/signer-firmware/src/hw/m5stack/storage/transport/capacity.rs")
        waveshare_capacity = read("apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/capacity.rs")
        card = read("crates/signer-firmware-core/src/storage/card.rs")
        self.assertIn("CMD9", m5_capacity)
        self.assertIn("sdhost_send_cmd(\n        9,", waveshare_capacity)
        waveshare_init = read("apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/initialization.rs")
        identify = waveshare_init[waveshare_init.index("fn identify_and_select_card"):waveshare_init.index("fn assign_relative_address")]
        prepare = identify[identify.index("fn identify_card"): ]
        self.assertIn("let rca = identify_card()?;", identify)
        self.assertIn("select_card(rca)", identify)
        self.assertIn("capture_sector_count(rca)?;", prepare)
        self.assertIn("pub fn csd_sector_count", card)

    def test_cores3_bmi270_enters_normal_mode_and_waits_for_real_gyro_startup(self) -> None:
        imu = read("apps/signer-firmware/src/hw/m5stack/imu.rs")
        self.assertIn("const REG_ACC_CONF: u8 = 0x40;", imu)
        self.assertIn("const REG_GYR_CONF: u8 = 0x42;", imu)
        self.assertIn("const REG_GYR_RANGE: u8 = 0x43;", imu)
        self.assertIn("const REG_PWR_CONF: u8 = 0x7C;", imu)
        self.assertIn("const REG_PWR_CTRL: u8 = 0x7D;", imu)
        self.assertIn("const ACC_CONF_NORMAL_100HZ: u8 = 0xA8;", imu)
        self.assertIn("const GYR_CONF_NORMAL_200HZ: u8 = 0xA9;", imu)
        self.assertIn("const GYR_RANGE_ENTROPY_250DPS: u8 = 0x03;", imu)
        shared_health = read("apps/signer-firmware/src/hw/shared/imu_health.rs")
        self.assertIn("const HEALTHY_DISTINCT_PCT: u32 = 60;", shared_health)
        self.assertIn("crate::hw::shared::imu_health::axis_distinct(bytes)", imu)
        self.assertIn("const PWR_CONF_NORMAL: u8 = 0x02;", imu)
        self.assertIn("const PWR_CTRL_NORMAL: u8 = 0x06;", imu)
        self.assertNotIn("PWR_CTRL_GYRO_ONLY", imu)
        self.assertIn("const GYRO_STARTUP_MS: u32 = 350;", imu)
        self.assertIn("const GYRO_SAMPLE_INTERVAL_MS: u32 = 6;", imu)
        self.assertIn("bmi.set_pwr_ctrl(PwrCtrl {", imu)
        self.assertIn("gyr_en: true", imu)
        self.assertIn("acc_en: true", imu)
        self.assertIn("temp_en: false", imu)
        self.assertIn("write_normal_mode(i2c)", imu)
        self.assertIn("normal_mode_matches(i2c)", imu)
        self.assertIn("write_named_reg(i2c, REG_GYR_RANGE, GYR_RANGE_ENTROPY_250DPS, \"GYR_RANGE\")", imu)
        self.assertIn("Some(GYR_RANGE_ENTROPY_250DPS)", imu)
        self.assertIn("BMI270 mode readback PWR_CTRL={:?} ACC_CONF={:?} GYR_CONF={:?} GYR_RANGE={:?} PWR_CONF={:?}", imu)
        self.assertIn("delay.delay_millis(GYRO_STARTUP_MS)", imu)
        self.assertIn("delay.delay_millis(GYRO_SAMPLE_INTERVAL_MS)", imu)
        self.assertIn("fatal_error(i2c)", imu)
        self.assertNotIn("delay.delay_millis(20);", imu)

    def test_device_bound_setup_navigation_has_single_click_feedback(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        controller = read_persistence_controller()
        self.assertNotIn("silent_seed_setup", dispatch)
        self.assertNotIn(
            "AppState::StorageSeedSourceChoice\n                        | $crate::runtime::input::AppState::StoragePinEntry",
            dispatch,
        )
        self.assertNotIn("let is_home = (52..=82).contains(&x) && y <= 34;", dispatch)
        self.assertNotIn("cancel_seed_onboarding($ad)", dispatch)
        pin = controller.split("fn edit_pin_secret", 1)[1].split("fn edit_password_secret", 1)[0]
        password = controller.split("fn edit_password_secret", 1)[1].split("const fn setup_entry_is_visible", 1)[0]
        self.assertEqual(pin.count("crate::services::audio::click();"), 1)
        self.assertEqual(password.count("crate::services::audio::click();"), 1)
        self.assertIn("tap_uses_router_click", dispatch)
        self.assertIn("credential keys may click once", navigation)

    def test_imu_rejection_is_actionable_on_screen(self) -> None:
        generation = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs")
        errors = read("apps/signer-firmware/src/ui/screens/signing/errors.rs")
        self.assertIn("draw_entropy_error_screen", generation)
        self.assertIn('"Retry seed generation"', generation)
        self.assertIn("crate::services::audio::error();", generation)
        self.assertIn("pub fn draw_entropy_error_screen", errors)
        self.assertIn("self.draw_error_surface(reason, Some(hint), ErrorAction::None)", errors)
        self.assertIn("draw_lato_title(", errors)
        self.assertIn("draw_lato_body(", errors)

if __name__ == "__main__":
    unittest.main()
