// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Seed passphrase workflow.

mod installed;

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::{AppData, RedrawFlag, display, sound};
use crate::runtime::interactions::keyboard::{KeyboardAction, handle_passphrase_keyboard};
use crate::runtime::input::AppState;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::PassphraseEntry { return None; }

    let mut needs_redraw = RedrawFlag::default();
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
        needs_redraw.set(true);
    } else if handle_passphrase_keyboard(
        &mut ad.wallet.seeds.pp_input,
        boot_display,
        x,
        y,
    ) == KeyboardAction::Submitted
    {
        store_seed_with_passphrase(ad, boot_display, delay);
        needs_redraw.set(true);
    }

    Some(needs_redraw.value())
}

pub(super) fn store_seed_with_passphrase(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    // Add Wallet stays transactional until the user chooses persistence policy.
    // Generated mnemonics still enter recovery-word acknowledgement. Restored
    // mnemonics follow the deliberate order: words -> BIP39 passphrase ->
    // wallet name -> Save Securely / Session Only, without ever echoing words.
    let imported_onboarding = ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        && ad.storage.persistence.onboarding_imported_mnemonic;
    if ad.wallet.seeds.has_pending_add_wallet() || imported_onboarding {
        ad.wallet.seeds.stage_pending_bip39_passphrase();
        let route = if ad.wallet.seeds.pending_add_wallet_is_restore() || imported_onboarding {
            crate::runtime::navigation::route!(WalletNameEntry { purpose: 3 })
        } else {
            crate::runtime::navigation::route!(SeedBackup { word_idx: 0 })
        };
        crate::runtime::effects::route(ad, route);
        return;
    }

    if !commit_current_seed(ad, boot_display, delay) { return; }
    finish_seed_commit_navigation(ad);
}

/// Commit a restored first-wallet mnemonic only after the user has chosen
/// a storage policy. Until this point the mnemonic, optional BIP39 passphrase,
/// and wallet name remain staged in RAM so Back navigation can edit them.
pub(crate) fn commit_staged_onboarding_import(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    let imported_onboarding = ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        && ad.storage.persistence.onboarding_imported_mnemonic;
    if !imported_onboarding || !matches!(ad.wallet.seeds.word_count, 12 | 24) {
        return false;
    }
    if !commit_current_seed(ad, boot_display, delay) {
        return false;
    }
    ad.storage.persistence.recovery_words_acknowledged = true;
    true
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_commit_staged_onboarding_import(ad: &mut AppData) -> bool {
    let imported_onboarding = ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        && ad.storage.persistence.onboarding_imported_mnemonic;
    if !imported_onboarding || !matches!(ad.wallet.seeds.word_count, 12 | 24) {
        return false;
    }
    let passphrase_len = usize::from(ad.wallet.seeds.pending_bip39_passphrase_len);
    let Some(slot_index) = ad.wallet.seeds.seed_mgr.store(
        &ad.wallet.seeds.mnemonic_indices,
        ad.wallet.seeds.word_count,
        &ad.wallet.seeds.pending_bip39_passphrase[..passphrase_len],
        passphrase_len as u8,
    ) else {
        return false;
    };
    let name_len = usize::from(ad.wallet.seeds.pending_wallet_name_len)
        .min(crate::wallet::seed_manager::WALLET_NAME_MAX);
    if name_len > 0 {
        let mut name = [0u8; crate::wallet::seed_manager::WALLET_NAME_MAX];
        name[..name_len].copy_from_slice(&ad.wallet.seeds.pending_wallet_name[..name_len]);
        let _ = ad.wallet.seeds.seed_mgr.set_slot_name(slot_index, &name[..name_len]);
        shared_signer::bytes::zeroize_bytes(&mut name);
    }
    if crate::services::wallet_session::activate_slot(ad, slot_index).is_err() {
        ad.wallet.seeds.seed_mgr.delete(slot_index);
        return false;
    }
    ad.wallet.seeds.clear_pending_wallet_name();
    ad.wallet.seeds.clear_pending_bip39_passphrase();
    ad.storage.persistence.recovery_words_acknowledged = true;
    true
}

/// Commit a generated Add Wallet mnemonic only after recovery-word acknowledgement.
pub(crate) fn commit_staged_add_wallet(
    ad: &mut AppData,
    persistence: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    if !ad.wallet.seeds.has_pending_add_wallet() || !ad.wallet.seeds.pending_wallet_activation_ready() {
        return false;
    }
    let reserved = usize::from(ad.wallet.seeds.pending_add_wallet_slot);
    if reserved >= crate::wallet::seed_manager::MAX_SLOTS { return false; }
    let protection = ad.wallet.seeds.pending_wallet_protection;
    let salt = ad.wallet.seeds.pending_wallet_activation_salt;
    let verifier = ad.wallet.seeds.pending_wallet_activation_verifier;
    if ad.wallet.seeds.pending_add_wallet_has_installed_source() {
        return installed::commit_add_wallet(
            ad, persistence, boot_display, delay, reserved, protection, salt, verifier,
        );
    }
    let bip39_len = usize::from(ad.wallet.seeds.pending_bip39_passphrase_len);
    if ad.wallet.seeds.seed_mgr.find_matching_mnemonic(
        &ad.wallet.seeds.mnemonic_indices,
        ad.wallet.seeds.word_count,
        &ad.wallet.seeds.pending_bip39_passphrase[..bip39_len],
    ).is_some() {
        ad.wallet.seeds.clear_pending_add_wallet();
        show_rejection(boot_display, delay, "Wallet already exists", 1_500, ErrorSound::Silent);
        super::seed_list::return_after_add_wallet(ad);
        return false;
    }
    if !commit_current_seed(ad, boot_display, delay) { return false; }
    let slot = usize::from(ad.wallet.seeds.seed_mgr.active);
    if slot != reserved || !ad.wallet.seeds.seed_mgr.set_slot_protection(slot, protection) {
        if slot == reserved { ad.wallet.seeds.seed_mgr.delete(slot); }
        crate::services::wallet_session::clear_active_wallet(ad);
        show_rejection(boot_display, delay, "Wallet creation failed", 1_800, ErrorSound::Silent);
        return false;
    }
    if let Err(error) = persistence.stage_wallet_activation_record(slot, protection, salt, verifier) {
        ad.wallet.seeds.seed_mgr.delete(slot);
        crate::services::wallet_session::clear_active_wallet(ad);
        show_rejection(boot_display, delay, error.message(), 1_800, ErrorSound::Silent);
        return false;
    }

    // The per-wallet credential setup reuses persistence credential UI state.
    // Clear only that transient creation state after commit; do not disturb the
    // persistent store's advanced-security availability/mirror.
    finish_add_wallet_commit(ad);
    true
}

/// Commit a restored Add Wallet as RAM-only state for this power session.
pub(crate) fn commit_staged_session_wallet(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    if !ad.wallet.seeds.has_pending_add_wallet() || !ad.wallet.seeds.pending_add_wallet_is_restore() {
        return false;
    }
    let reserved = usize::from(ad.wallet.seeds.pending_add_wallet_slot);
    if reserved >= crate::wallet::seed_manager::MAX_SLOTS { return false; }
    if ad.wallet.seeds.pending_add_wallet_has_installed_source() {
        return installed::finish_session_wallet(ad, boot_display, delay, reserved);
    }
    let bip39_len = usize::from(ad.wallet.seeds.pending_bip39_passphrase_len);
    if ad.wallet.seeds.seed_mgr.find_matching_mnemonic(
        &ad.wallet.seeds.mnemonic_indices,
        ad.wallet.seeds.word_count,
        &ad.wallet.seeds.pending_bip39_passphrase[..bip39_len],
    ).is_some() {
        ad.wallet.seeds.clear_pending_add_wallet();
        show_rejection(boot_display, delay, "Wallet already exists", 1_500, ErrorSound::Silent);
        super::seed_list::return_after_add_wallet(ad);
        return false;
    }
    let Some(slot) = ad.wallet.seeds.seed_mgr.store_transient(
        &ad.wallet.seeds.mnemonic_indices,
        ad.wallet.seeds.word_count,
        &ad.wallet.seeds.pending_bip39_passphrase[..bip39_len],
        bip39_len as u8,
    ) else {
        show_rejection(
            boot_display,
            delay,
            crate::services::wallet_session::SLOTS_FULL_MESSAGE,
            2_000,
            ErrorSound::Silent,
        );
        return false;
    };
    if slot != reserved {
        ad.wallet.seeds.seed_mgr.delete(slot);
        show_rejection(boot_display, delay, "Wallet creation failed", 1_800, ErrorSound::Silent);
        return false;
    }
    installed::apply_pending_wallet_name(ad, slot);
    if let Err(error) = crate::services::wallet_session::activate_slot(ad, slot) {
        ad.wallet.seeds.seed_mgr.delete(slot);
        show_rejection(boot_display, delay, error.message(), 2_000, ErrorSound::Silent);
        return false;
    }
    sound::success();
    ad.wallet.seeds.finish_pending_add_wallet_commit();
    ad.wallet.seeds.clear_pending_wallet_name();
    ad.wallet.seeds.clear_pending_bip39_passphrase();
    ad.wallet.seeds.seed_list_scroll = 0;
    super::seed_list::return_after_add_wallet(ad);
    true
}

fn finish_add_wallet_commit(ad: &mut AppData) {
    ad.wallet.seeds.finish_pending_add_wallet_commit();
    ad.wallet.seeds.clear_pending_wallet_name();
    ad.wallet.seeds.clear_pending_bip39_passphrase();
    shared_signer::bytes::zeroize_bytes(&mut ad.storage.persistence.confirmation_digest);
    ad.storage.persistence.kind = None;
    ad.storage.persistence.recovery_words_acknowledged = false;
    ad.storage.persistence.confirmation_pending = false;
    ad.wallet.seeds.pp_input.reset();
    ad.wallet.seeds.seed_list_scroll = 0;
    super::seed_list::return_after_add_wallet(ad);
}

fn commit_current_seed(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    let pending_add = ad.wallet.seeds.has_pending_add_wallet();
    let imported_onboarding = ad.storage.persistence.device_storage_intent.is_seed_onboarding()
        && ad.storage.persistence.onboarding_imported_mnemonic;
    let staged_passphrase = pending_add || imported_onboarding;
    let passphrase_len = if staged_passphrase {
        usize::from(ad.wallet.seeds.pending_bip39_passphrase_len)
    } else {
        ad.wallet.seeds.pp_input.len
    };
    let passphrase = if staged_passphrase {
        &ad.wallet.seeds.pending_bip39_passphrase[..passphrase_len]
    } else {
        &ad.wallet.seeds.pp_input.buf[..passphrase_len]
    };
    let Some(slot_index) = ad.wallet.seeds.seed_mgr.store(
        &ad.wallet.seeds.mnemonic_indices,
        ad.wallet.seeds.word_count,
        passphrase,
        passphrase_len as u8,
    ) else {
        ad.wallet.seeds.pp_input.reset();
        show_rejection(
            boot_display,
            delay,
            crate::services::wallet_session::SLOTS_FULL_MESSAGE,
            2_000,
            ErrorSound::Silent,
        );
        recover_seed_setup_failure(ad);
        return false;
    };

    let name_len = usize::from(ad.wallet.seeds.pending_wallet_name_len)
        .min(crate::wallet::seed_manager::WALLET_NAME_MAX);
    if name_len > 0 {
        let mut name = [0u8; crate::wallet::seed_manager::WALLET_NAME_MAX];
        name[..name_len].copy_from_slice(&ad.wallet.seeds.pending_wallet_name[..name_len]);
        let _ = ad.wallet.seeds.seed_mgr.set_slot_name(slot_index, &name[..name_len]);
        shared_signer::bytes::zeroize_bytes(&mut name);
    }
    ad.wallet.seeds.clear_pending_wallet_name();

    if let Err(error) = crate::services::wallet_session::activate_slot(ad, slot_index) {
        ad.wallet.seeds.pp_input.reset();
        show_rejection(boot_display, delay, error.message(), 2_000, ErrorSound::Silent);
        recover_seed_setup_failure(ad);
        return false;
    }

    log!(
        "   Seed stored in slot {} (pp={})",
        slot_index,
        if passphrase_len > 0 { "yes" } else { "no" }
    );
    sound::success();
    ad.wallet.seeds.pp_input.reset();
    if staged_passphrase { ad.wallet.seeds.clear_pending_bip39_passphrase(); }
    true
}

fn finish_seed_commit_navigation(ad: &mut AppData) {
    // SeedBackup routes by onboarding intent; fresh Add Wallet commits through
    // its separate staged recovery-word acknowledgement path above.
    if ad.signing.multisig.creating.n > 0 && !ad.signing.multisig.creating.active {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigPickSeed {
            key_idx: first_empty_multisig_key(ad),
        }));
        return;
    }

    match ad.storage.persistence.device_storage_intent {
        crate::runtime::data::DeviceStorageIntent::CreateInternal => {
            ad.storage.persistence.recovery_words_acknowledged = false;
            if ad.storage.persistence.onboarding_imported_mnemonic {
                // Imported words were supplied by the user; do not re-display them
                // or require a redundant "I backed them up" acknowledgement.
                ad.storage.persistence.recovery_words_acknowledged = true;
                crate::runtime::effects::route(
                    ad,
                    crate::runtime::navigation::route!(StorageFinalizeChoice),
                );
                return;
            }
        }
        crate::runtime::data::DeviceStorageIntent::StartFresh => {
            ad.storage.persistence.recovery_words_acknowledged = false;
            if ad.storage.persistence.onboarding_imported_mnemonic {
                // Imported words were supplied by the user; do not re-display them
                // or require a redundant "I backed them up" acknowledgement.
                ad.storage.persistence.recovery_words_acknowledged = true;
                crate::runtime::effects::route(
                    ad,
                    crate::runtime::navigation::route!(StorageFinalizeChoice),
                );
                return;
            }
        }
        _ => {}
    }
    crate::runtime::effects::route(
        ad,
        crate::runtime::navigation::route!(SeedBackup { word_idx: 0 }),
    );
}

fn recover_seed_setup_failure(ad: &mut AppData) {
    if ad.wallet.seeds.has_pending_add_wallet() {
        ad.wallet.seeds.clear_pending_add_wallet();
        super::seed_list::return_after_add_wallet(ad);
        return;
    }
    if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        ad.wallet.seeds.seed_mgr.zeroize_all();
        crate::services::wallet_session::clear_active_wallet(ad);
        shared_signer::bytes::zeroize_u16(&mut ad.wallet.seeds.mnemonic_indices);
        ad.wallet.seeds.word_count = 0;
        if ad.storage.persistence.onboarding_imported_mnemonic {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedSourceChoice));
        } else {
            crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(StorageSeedWordCountChoice { action: 0 }),
            );
        }
        return;
    }
    if !crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedTool) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedToolsMenu));
    }
}

fn first_empty_multisig_key(ad: &AppData) -> u8 {
    (0..ad.signing.multisig.creating.n)
        .find(|index| ad.signing.multisig.creating.slot_empty(*index as usize))
        .unwrap_or(0)
}
