"""Focused firmware source-contract checks."""
from source_contract_support import read, require

def check_storage_facades(errors: list[str]) -> None:
    ws_boot = read(
        "apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/boot.rs"
    )
    require(
        errors,
        "gpio::{func_in_sel_addr" in ws_boot,
        "Waveshare SDHOST boot must import func_in_sel_addr from gpio",
    )
    registers_group = ws_boot.split("use super::super::registers::{", 1)[1].split(
        "};", 1
    )[0]
    require(
        errors,
        "func_in_sel_addr" not in registers_group,
        "Waveshare SDHOST boot imports func_in_sel_addr from the wrong owner",
    )

    for path in (
        "apps/signer-firmware/src/hw/waveshare/storage/mod.rs",
        "apps/signer-firmware/src/hw/m5stack/storage/mod.rs",
    ):
        source = read(path)
        require(
            errors,
            "pub(crate) use transport::{fast_read_multi_block, fast_write_multi_block, sd_sector_count, sd_write_block};" in source,
            f"{path}: shared FAT32 block I/O façade must be crate-visible",
        )
        require(
            errors,
            "pub(super) use transport::{fast_read_multi_block" not in source,
            f"{path}: shared FAT32 block I/O façade is too private",
        )
        require(
            errors,
            "find_fat32_partition" not in source,
            f"{path}: duplicate FAT32 partition wrapper must not return",
        )
        for internal in (
            "allocate_chain",
            "allocate_cluster",
            "create_file_progress",
            "read_file_progress",
            "write_fat_entry",
        ):
            require(
                errors,
                internal not in source,
                f"{path}: internal FAT32 helper leaked through board facade: {internal}",
            )

    for path, contract in (
        (
            "apps/signer-firmware/src/hw/waveshare/storage/transport/mod.rs",
            "pub(crate) use sdhost::{fast_read_multi_block, fast_write_multi_block, sd_sector_count, sd_write_block};",
        ),
        (
            "apps/signer-firmware/src/hw/m5stack/storage/transport/mod.rs",
            "pub(crate) use multi_block::{fast_read_multi_block, fast_write_multi_block};",
        ),
    ):
        source = read(path)
        require(errors, contract in source, f"{path}: block I/O transport visibility regressed")

    fat32 = read("apps/signer-firmware/src/hw/shared/storage/fat32/mod.rs")
    require(
        errors,
        "pub use files::{create_file, create_file_progress" not in fat32,
        "FAT32 façade leaks the internal progress writer",
    )

    screens = read("apps/signer-firmware/src/ui/screens.rs")
    require(
        errors,
        "embedded_iconoir::prelude::*" not in screens,
        "screen façade must not wildcard-re-export the Iconoir prelude",
    )

    wallet_backup_list = read("apps/signer-firmware/src/runtime/interactions/sd/backup/import.rs")
    require(
        errors,
        "common::context::{SdIoContext, SdListContext}" in wallet_backup_list,
        "SD wallet-backup list must import contexts from the owning context module",
    )
    require(
        errors,
        "FileListWorkflow, SdIoContext, SdListContext" not in wallet_backup_list,
        "SD wallet-backup list must not rely on stale parent-facade context re-exports",
    )

    for path in (
        "apps/signer-firmware/src/runtime/interactions/sd/backup/xprv/mod.rs",
        "apps/signer-firmware/src/runtime/interactions/sd/exports/kspt_export/mod.rs",
    ):
        source = read(path)
        require(
            errors,
            "pub(super) use" not in source,
            f"{path}: SD dispatcher re-exports must be crate-visible",
        )
        require(
            errors,
            "pub(crate) use" in source,
            f"{path}: missing crate-visible SD dispatcher re-export",
        )

def check_mutable_sector_slice_contract(errors: list[str]) -> None:
    paths = (
        "apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/multi_block.rs",
        "apps/signer-firmware/src/hw/m5stack/storage/transport/multi_block.rs",
    )
    for path in paths:
        source = read(path)
        require(
            errors,
            "output[..512].try_into()" not in source
            and "output[start..end].try_into()" not in source,
            f"{path}: mutable block reads must not convert an immutable slice",
        )
        require(
            errors,
            "(&mut output[" in source,
            f"{path}: mutable block reads must explicitly borrow a mutable slice",
        )

def check_sd_persistence_security_contract(errors: list[str]) -> None:
    persistence = read("apps/signer-firmware/src/services/persistent_wallet/mod.rs") + read("apps/signer-firmware/src/services/persistent_wallet/save/mod.rs")
    require(
        errors,
        "SdCard = 3" in persistence,
        "persistent-wallet storage mode must retain the encrypted SD backend",
    )
    require(
        errors,
        "RecoveryAcknowledgementRequired" in persistence
        and "if !recovery_words_acknowledged" in persistence,
        "device-bound storage creation must fail closed without recovery-word acknowledgement",
    )
    startup = read("apps/signer-firmware/src/services/persistent_wallet/startup.rs")
    require(
        errors,
        "StartupState::UnlockRequired(anchor.credential_kind)" in startup,
        "SD persistence must require PIN/password unlock during startup",
    )

    core = read("crates/offline-signer/src/crypto/device_bound_storage.rs")
    for contract in (
        'b"KasSigner/device-bound-wallet/context/v1"',
        'b"KasSigner/device-bound-wallet/device-mix/v1"',
        'b"KasSigner/device-bound-wallet/aes-256-gcm/v1"',
        "pub trait HardwareHmac",
        "HardwareHmacUnavailable",
        "seal_in_place",
        "open_in_place",
        "zeroize_buf(plaintext)",
        "zeroize_buf(ciphertext)",
    ):
        require(errors, contract in core, f"device-bound storage core missing: {contract}")
    for forbidden in ("raw_hmac_key", "read_hmac_key", "export_hmac_key", "device_secret("):
        require(
            errors,
            forbidden not in core,
            f"device-bound storage core must not expose raw hardware key material: {forbidden}",
        )

    crypto = read("apps/signer-firmware/src/services/persistent_wallet/crypto.rs")
    for contract in (
        'const CURRENT_MAGIC: [u8; 8] = *b"KSWLT004";',
        'const LEGACY_MAGIC: [u8; 8] = *b"KSWLT003";',
        "KDF_ID_DEVICE_HMAC_SHA256",
        "Efuse::read_field_le(RD_DIS)",
        "HmacPurpose::ToUser",
        "PERSISTENT_KEY_SLOTS: [u8; 3] = [3, 4, 5]",
        "StoragePurpose::InternalWallet",
        "StoragePurpose::SdWallet",
        "DeviceKeyMissing",
    ):
        require(errors, contract in crypto, f"device-bound firmware HMAC contract missing: {contract}")
    for forbidden in ("Efuse::read_field_le(KEY", "read_key", "key_bytes", "software_device_key"):
        require(
            errors,
            forbidden not in crypto,
            f"persistent-wallet firmware must not read/export raw eFuse HMAC key: {forbidden}",
        )

    backend = read("apps/signer-firmware/src/services/persistent_wallet/sd_backend.rs")
    for contract in (
        "crypto.seal_sd(",
        "crypto.open_sd(",
        'const CURRENT_MAGIC: [u8; 4] = *b"KSW4";',
        "KasSigner device-bound SD wallet slot A v4",
        "KasSigner device-bound SD wallet slot B v4",
        "KasSigner device-bound SD wallet slot A v3",
        "KasSigner device-bound SD wallet slot B v3",
        "overwrite_file(",
        "&SLOT_FILES[index]",
        "&envelope.0",
    ):
        require(errors, contract in backend, f"device-bound SD backend missing: {contract}")
    for forbidden in ("Aes256Gcm", "derive_sd_storage_key", "copy_from_slice(credential_key)"):
        require(errors, forbidden not in backend, f"SD backend duplicated/weakened KDF: {forbidden}")

    journal = "\n".join(read(path) for path in (
        "apps/signer-firmware/src/services/persistent_wallet/journal.rs",
        "apps/signer-firmware/src/services/persistent_wallet/journal/config.rs",
    ))
    require(
        errors,
        "const CONFIG_VERSION: u8 = 8;" in journal
        and "const V7_COMPAT_VERSION: u8 = 7;" in journal
        and "const V6_COMPAT_VERSION: u8 = 6;" in journal
        and "const V5_COMPAT_VERSION: u8 = 5;" in journal
        and "record.0[8] = CONFIG_VERSION;" in journal
        and "WALLET_LABELS_OFFSET" in journal
        and "CONFIG_DIGEST_START" in journal,
        "persistent config writer must remain current v8 while explicitly reading v7/v6/v5",
    )
    require(
        errors,
        "const LEGACY_CONFIG_VERSION: u8 = 3;" in journal
        and "const V471_V475_COMPAT_VERSION: u8 = 4;" in journal
        and "const V5_COMPAT_VERSION: u8 = 5;" in journal
        and "const V7_COMPAT_VERSION: u8 = 7;" in journal
        and "const V6_COMPAT_VERSION: u8 = 6;" in journal
        and "CONFIG_VERSION | V7_COMPAT_VERSION | V6_COMPAT_VERSION | V5_COMPAT_VERSION | LEGACY_CONFIG_VERSION | V471_V475_COMPAT_VERSION" in journal
        and "let legacy_kdf = matches!(version, LEGACY_CONFIG_VERSION | V471_V475_COMPAT_VERSION);" in journal,
        "persistent config must preserve explicit v3/v4 PBKDF2 plus v5/v6/v7 compatibility beside current v8 preferences/activation metadata",
    )
    for forbidden in ("read_legacy_config", "restore_latest_legacy", "try_pbkdf2", "fallback_pbkdf2"):
        require(errors, forbidden not in journal, f"generic persistent-wallet legacy fallback returned: {forbidden}")

    advanced = read("apps/signer-firmware/src/services/persistent_wallet/advanced.rs")
    require(
        errors,
        "pub fn enable_sd_storage(" in advanced
        and "recovery_words_acknowledged: bool" in advanced
        and "RecoveryAcknowledgementRequired" in advanced,
        "Advanced Settings SD activation must require recovery-word acknowledgement",
    )
    require(
        errors,
        "journal::erase_wallet(&mut self.flash)?;" in advanced,
        "SD migration must erase internal wallet ciphertext after the SD copy is committed",
    )
    require(
        errors,
        "disable_sd" not in advanced and "disable_sd_storage" not in advanced,
        "device-bound SD persistence must not gain a bypass/disable API",
    )
    require(
        errors,
        "if self.mode == Some(StorageMode::SdCard) { return Err(PersistError::AdvancedAlreadyEnabled); }" in persistence,
        "SD persistence must remain irreversible through the persistence service API",
    )

    unlock = read("apps/signer-firmware/src/services/persistent_wallet/unlock/mod.rs") + read("apps/signer-firmware/src/services/persistent_wallet/unlock/asynchronous.rs")
    require(
        errors,
        "self.unlock_from_sd(kind, secret, ad, i2c, delay, liveness)" in unlock,
        "SD persistence unlock must authenticate through the user credential path",
    )
    require(
        errors,
        "Err(PersistError::SdStorageCorrupt)" in unlock,
        "SD persistence corruption must fail closed",
    )
    kdf = read("apps/signer-firmware/src/services/persistent_wallet/kdf/mod.rs")
    require(
        errors,
        "kdf::derive(" in unlock
        and "liveness();" in kdf
        and "derive_legacy_32_progress" in kdf,
        "saved-wallet KDF must bracket Argon2 with liveness and preserve cooperative legacy PBKDF2 checkpoints",
    )

    event_persistence = read("apps/signer-firmware/src/runtime/event_loop/persistence.rs")
    require(
        errors,
        "$crate::services::device_wipe::zeroize_volatile($ad);" in event_persistence
        and "$crate::runtime::navigation::route!(StorageSdFailure)" in event_persistence,
        "runtime SD persistence failures must zeroize volatile secrets and fail closed",
    )

    state = read("apps/signer-firmware/src/runtime/input/state.rs")
    require(
        errors,
        "StorageSeedSourceChoice" in state
        and "StorageRecoveryAcknowledgement" in state
        and "StorageSdFailure" in state
        and "AdvancedSdStorageWarning" in state
        and "StorageSeedDiceChoice" in state
        and "StorageSeedDiceCountChoice" in state
        and "StorageSeedCreationMethodChoice" not in state
        and "PassphraseChoice" in state,
        "firmware state machine must include recovery acknowledgement and fail-closed states",
    )
    persistence_ui = read("apps/signer-firmware/src/ui/screens/device/persistence.rs")
    for contract in (
        "WELCOME",
        "Create Wallet",
        "Restore Wallet",
        "Save Securely on Device",
        "Use for This Session Only",
        "Recovery words are your",
        "permanent portable backup.",
        "I BACKED UP MY WORDS",
        "Hardware + camera are always used.",
        "No Dice",
        "Add Dice Rolls",
        "25 Rolls",
        "50 Rolls",
        "100 Rolls",
        "200 Rolls",
    ):
        require(errors, contract in persistence_ui, f"device-bound storage recovery UI missing: {contract}")
    persistence_controller = "\n".join(read(path) for path in (
        "apps/signer-firmware/src/runtime/interactions/persistence.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/recovery.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/finalize.rs",
        "apps/signer-firmware/src/runtime/interactions/persistence/credential.rs",
    ))
    seed_passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
    wallet_name = read("apps/signer-firmware/src/runtime/interactions/seed/wallet_name.rs")
    require(
        errors,
        "AppState::StorageSeedSourceChoice" in persistence_controller
        and "onboarding_mnemonic_ready" in persistence_controller
        and "route!(WalletNameEntry { purpose: 0 })" in persistence_controller
        and "route!(StorageSeedWordCountChoice { action: 0 })" in wallet_name
        and "route!(RestoreWord { word_idx: 0 })" in persistence_controller
        and "StorageFinalizeChoice" in persistence_controller,
        "device-bound onboarding must establish/import a mnemonic before acknowledgement",
    )
    seed_generation = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs")
    additive_entropy = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation/additive.rs")
    entropy_mixer = read("apps/signer-firmware/src/services/entropy/mixer.rs")
    dice_controller = read("apps/signer-firmware/src/runtime/interactions/menu/seed_tools/dice.rs")
    touch_entropy = read("apps/signer-firmware/src/runtime/event_loop/touch_entropy.rs")
    require(
        errors,
        "crate::services::entropy::collect(" in seed_generation
        and "stage_seed_entropy(&mut pool, word_count)" in seed_generation
        and "StorageSeedDiceChoice" in seed_generation
        and "StorageSeedDiceCountChoice" in seed_generation
        and "StorageSeedTouchChoice" in seed_generation
        and "NO_DICE_BUTTON_Y" in additive_entropy
        and "ADD_DICE_BUTTON_Y" in additive_entropy
        and "NO_TOUCH_BUTTON_Y" in additive_entropy
        and "ADD_TOUCH_BUTTON_Y" in additive_entropy
        and "mix_dice_into_staged" in seed_generation
        and "crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedTouchChoice))" in additive_entropy
        and 'b"KasSigner/additive-dice/v1"' in entropy_mixer
        and 'b"KasSigner/additive-touch/v1"' in entropy_mixer
        and "hasher.update(&*pool)" in entropy_mixer
        and "hasher.update(rolls)" in entropy_mixer
        and "mix_additive_touch" in touch_entropy
        and "pending_seed_entropy_valid" in dice_controller,
        "optional dice and touch entropy must remain additive after mandatory checked hardware/camera entropy",
    )
    require(
        errors,
        "device_key_available()" in persistence_controller
        and 'show_rejection(display, delay, "Device key not provisioned"' in persistence_controller
        and "DeviceStorageIntent::CreateInternal" in persistence_controller
        and "enter_credential_type_choice(ad)" in persistence_controller,
        "device-bound storage must preflight the read-protected HMAC key before credential setup",
    )
    startup = read("apps/signer-firmware/src/services/persistent_wallet/startup.rs")
    persistent_service = read("apps/signer-firmware/src/services/persistent_wallet/mod.rs")
    persistence_state = read("apps/signer-firmware/src/runtime/data/storage/persistence.rs")
    seed_backup = read("apps/signer-firmware/src/runtime/interactions/export/seed_backup.rs")
    require(
        errors,
        "DeviceStorageIntent::StartFresh" in persistence_controller
        and "route!(WalletNameEntry { purpose: 0 })" in persistence_controller
        and "route!(StorageSeedWordCountChoice { action: 0 })" in wallet_name
        and "StorageSeedSourceChoice" in persistence_controller
        and "StorageFinalizeChoice" in persistence_controller
        and "SeedSourceRequired" not in startup
        and "fn initialize_empty(&mut self, ad: &mut AppData)" in startup
        and "self.initialize_choice(ad)" in startup
        and "StartFresh" in persistence_state
        and "is_seed_onboarding" in persistence_state,
        "empty-wallet startup must require wallet onboarding before the terminal storage choice",
    )
    require(
        errors,
        "onboarding_imported_mnemonic" in persistence_controller
        and "onboarding_imported_mnemonic" in seed_passphrase
        and "route!(WalletNameEntry { purpose: 3 })" in seed_passphrase
        and "route!(StorageFinalizeChoice)" in seed_passphrase
        and "recovery_words_acknowledged = true" in seed_passphrase
        and "route!(SeedBackup { word_idx: 0 })" in seed_passphrase
        and "route!(StorageRecoveryAcknowledgement)" in seed_backup
        and "ad.export.seed_backup_return = AppState::StorageRecoveryAcknowledgement" not in seed_passphrase,
        "generated mnemonics must use backup acknowledgement while imported mnemonics skip redisplay and proceed through passphrase, naming, and storage choice",
    )
    event_dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
    navigation = read("apps/signer-firmware/src/runtime/interactions/persistence.rs")
    state_navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
    require(
        errors,
        "pub(crate) fn home(ad: &mut AppData)" in state_navigation
        and "cancel_seed_onboarding(ad)" in state_navigation
        and "UiEvent::Route(route!(StorageModeChoice))" in state_navigation
        and "device_storage_intent.is_seed_onboarding()" in seed_backup
        and "route!(StorageRecoveryAcknowledgement)" in seed_backup
        and "complete_start_fresh(ad)" not in seed_backup
        and "DeviceStorageIntent::StartFresh" in persistence_controller
        and ("super::complete_start_fresh(ad);" in persistence_controller or "super::super::complete_start_fresh(ad);" in persistence_controller)
        and "pub(crate) fn complete_start_fresh" in navigation
        and "complete_start_fresh" not in read("apps/signer-firmware/src/services/persistent_wallet/mod.rs"),
        "seed onboarding navigation must remain context-bound through recovery acknowledgement until an explicit terminal transition",
    )
    device_redraw = "\n".join(read(path) for path in ("apps/signer-firmware/src/ui/redraw/device.rs", "apps/signer-firmware/src/ui/redraw/device/onboarding.rs"))
    wallet_keyboard = read("apps/signer-firmware/src/ui/screens/wallet/keyboard.rs")
    prop_fonts = read("apps/signer-firmware/src/ui/prop_fonts.rs")
    require(
        errors,
        "draw_storage_seed_word_count_screen()" in device_redraw
        and "word_count_title(action)" not in device_redraw
        and 'self.draw_word_count_choices("MNEMONIC LENGTH")' in wallet_keyboard,
        "device-bound word-count redraw must use the fixed local header path",
    )
    require(
        errors,
        "text.as_bytes().iter().take(256)" in prop_fonts
        and "w = w.saturating_add(advance)" in prop_fonts
        and ".get((ch - first_char) as usize)" in prop_fonts,
        "proportional-font measurement must be bounded and panic-safe",
    )
    require(
        errors,
        "draw_storage_pin_entry" in persistence_ui
        and "PIN_PAD_X" in persistence_ui
        and "PIN_PAD_Y" in persistence_ui
        and "PinPadAction::Submit" in persistence_ui
        and "edit_pin_secret" in persistence_controller
        and "pin_pad_action(input.x, input.y)" in persistence_controller
        and "pp.len < 12" in persistence_controller
        and "update_storage_pin_value" in persistence_controller
        and "update_storage_pin_value" in persistence_ui,
        "PIN create/confirm/unlock must use the dedicated bounded persistence keypad",
    )
    require(
        errors,
        'draw_storage_pin_entry(&ad.wallet.seeds.pp_input, "CREATE PIN", true)' in device_redraw
        and 'draw_storage_pin_entry(&ad.wallet.seeds.pp_input, "CONFIRM PIN", true)' in device_redraw
        and "unlock_feedback.pin_title()" in device_redraw
        and "start_credential_operation(" in persistence_controller
        and "operation_kind(kind, true), unlock_state(kind)" in persistence_controller
        and "draw_unlock_wait_screen" not in persistence_controller
        and 'draw_wait_screen("Unlocking wallet...")' in read("apps/signer-firmware/src/ui/redraw/presentation/mod.rs")
        and "KASSIGNER_PIN_FLOW: LOADING RENDERED {}" in read("apps/signer-firmware/src/runtime/presentation/mod.rs"),
        "PIN setup must remain visible while unlock transitions through a rendered static wait operation",
    )
    passphrase_choice = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase_choice.rs")
    wallet_redraw = read("apps/signer-firmware/src/ui/redraw/wallet/input.rs")
    require(
        errors,
        '"BIP39 Pass."' in wallet_keyboard
        and '"No Passphrase"' in wallet_keyboard
        and '"Use Passphrase"' in wallet_keyboard
        and '"Optional extra secret for your words."' in wallet_keyboard
        and "store_seed_with_passphrase" in passphrase_choice
        and "route!(PassphraseEntry)" in passphrase_choice
        and "draw_passphrase_choice_screen" in wallet_redraw,
        "mnemonic installation must make the optional BIP39 passphrase an explicit explained choice",
    )
    require(
        errors,
        prop_fonts.count("text.as_bytes().iter().take(256)") >= 3
        and "widths[idx]" not in prop_fonts[prop_fonts.index("pub fn draw_prop_text"):prop_fonts.index("// ═════════", prop_fonts.index("pub fn draw_prop_text"))],
        "proportional-font drawing and measurement must all be bounded and table-checked",
    )

