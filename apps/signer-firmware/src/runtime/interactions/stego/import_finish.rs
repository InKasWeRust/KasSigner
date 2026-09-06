// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Finalize a recovered steganographic seed, with an optional passphrase.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound, show_success};
use super::{AppData, RedrawFlag, display};
use crate::runtime::interactions::keyboard::{KeyboardAction, handle_passphrase_keyboard};
use crate::runtime::input::AppState;

pub(super) fn finish_recovery_destination(ad: &mut AppData) {
    if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageRecoveryAcknowledgement));
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
    }
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = RedrawFlag::default();
    match ad.navigation.app.state {
        AppState::StegoHintReveal => {
            if is_back {
                finish_recovery(ad, boot_display, delay, &[]);
            } else {
                ad.wallet.seeds.pp_input.reset();
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoHintPassphrase));
            }
            needs_redraw.set(true);
        }
        AppState::StegoHintPassphrase => {
            if is_back {
                finish_recovery(ad, boot_display, delay, &[]);
                needs_redraw.set(true);
            } else if handle_passphrase_keyboard(
                &mut ad.wallet.seeds.pp_input,
                boot_display,
                x,
                y,
            ) == KeyboardAction::Submitted
            {
                let passphrase_len = ad.wallet.seeds.pp_input.len.min(64);
                let mut passphrase = [0u8; 64];
                passphrase[..passphrase_len]
                    .copy_from_slice(&ad.wallet.seeds.pp_input.buf[..passphrase_len]);
                finish_recovery(ad, boot_display, delay, &passphrase[..passphrase_len]);
                shared_signer::bytes::zeroize_bytes(&mut passphrase);
                needs_redraw.set(true);
            }
        }
        _ => return None,
    }
    Some(needs_redraw.value())
}

pub(super) fn restore_staging_active(ad: &AppData) -> bool {
    ad.wallet.seeds.pending_add_wallet_is_restore()
        || (ad.storage.persistence.device_storage_intent.is_seed_onboarding()
            && ad.storage.persistence.onboarding_imported_mnemonic)
}

fn finish_recovery(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    passphrase: &[u8],
) {
    if restore_staging_active(ad) {
        ad.wallet.seeds.stage_bip39_passphrase(passphrase);
        ad.wallet.seeds.pp_input.reset();
        shared_signer::bytes::zeroize_bytes(&mut ad.stego.import.recovered_hint);
        ad.stego.import.recovered_hint_len = 0;
        crate::runtime::effects::route(
            ad,
            crate::runtime::navigation::route!(WalletNameEntry { purpose: 3 }),
        );
        return;
    }
    let stored = ad.wallet.seeds.seed_mgr.store(
        &ad.wallet.seeds.mnemonic_indices,
        ad.wallet.seeds.word_count,
        passphrase,
        passphrase.len() as u8,
    );
    ad.wallet.seeds.pp_input.reset();
    shared_signer::bytes::zeroize_bytes(&mut ad.stego.import.recovered_hint);
    ad.stego.import.recovered_hint_len = 0;

    let Some(slot_index) = stored else {
        show_rejection(boot_display, delay, crate::services::wallet_session::SLOTS_FULL_MESSAGE, 2_000, ErrorSound::Beep);
        return;
    };

    if let Err(error) = crate::services::wallet_session::activate_slot(ad, slot_index) {
        show_rejection(
            boot_display,
            delay,
            error.message(),
            2_000,
            ErrorSound::Beep,
        );
        return;
    }
    log!(
        "   Stego seed stored in slot {} (pp={})",
        slot_index,
        if passphrase.is_empty() { "no" } else { "yes" }
    );
    show_success(boot_display, delay, "Full Recovery!", 2_000);
    finish_recovery_destination(ad);
}
