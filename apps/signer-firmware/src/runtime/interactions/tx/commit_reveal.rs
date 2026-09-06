// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Commit-reveal touch workflow.

use super::{AppData, RedrawFlag, display, sound};
use crate::runtime::interactions::{
    feedback::{show_rejection, ErrorSound},
    keyboard::{KeyboardAction, handle_passphrase_keyboard}};
use shared_signer::bytes::zeroize_bytes;

const SALT_LEN: usize = 8;
const MAX_SECRET_LEN: usize = 33;

fn store_salted_secret_with_salt(ad: &mut AppData, salt: &[u8; SALT_LEN]) -> Result<(), &'static str> {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};

    let secret_len = ad.wallet.seeds.pp_input.len;
    if secret_len == 0 { return Err("Enter a message"); }
    if secret_len > MAX_SECRET_LEN { return Err("Max 33 characters"); }

    let copy_len = secret_len.min(ad.signing.commit_reveal.plaintext.len() - SALT_LEN);
    for index in (0..copy_len).rev() {
        ad.signing.commit_reveal.plaintext[SALT_LEN + index] = ad.wallet.seeds.pp_input.buf[index];
    }
    ad.signing.commit_reveal.plaintext[..SALT_LEN].copy_from_slice(salt);
    ad.signing.commit_reveal.plaintext_len = SALT_LEN + copy_len;
    type Blake2b256 = Blake2b<U32>;
    let mut hasher = Blake2b256::new();
    hasher.update(&ad.signing.commit_reveal.plaintext[..ad.signing.commit_reveal.plaintext_len]);
    ad.signing.commit_reveal.hash = hasher.finalize().into();
    Ok(())
}

fn store_salted_secret(ad: &mut AppData) -> Result<(), &'static str> {
    let mut salt = [0u8; SALT_LEN];
    crate::crypto::entropy::fill(&mut salt)
        .map_err(crate::services::entropy::EntropyError::message)?;
    let result = store_salted_secret_with_salt(ad, &salt);
    zeroize_bytes(&mut salt);
    result
}

fn handle_secret_entry(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SigningTool);
        return true;
    }
    match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::Submitted => match store_salted_secret(ad) {
            Ok(()) => {
                let _ = crate::runtime::effects::route(
                    ad,
                    crate::runtime::navigation::route!(CommitRevealPreview,),
                );
            }
            Err(message) => show_rejection(boot_display, delay, message, 1500, ErrorSound::Beep),
        },
        KeyboardAction::Edited => {}
        KeyboardAction::None => return false,
    }
    true
}

fn derive_recipient_pubkey(ad: &AppData, liveness: &mut dyn FnMut()) -> Result<[u8; 32], &'static str> {
    crate::runtime::signing::derive_active_account_key_with_checkpoint(ad, liveness)?
        .public_key_x_only()
        .map_err(|_| "Bad recipient key")
}

fn encrypt_preimage(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) -> bool {
    boot_display.draw_saving_screen("Encrypting...");
    boot_display.update_progress_bar(20);
    crate::services::timing::pause(delay, 50);
    let mut recipient_pubkey = match derive_recipient_pubkey(ad, liveness) {
        Ok(public_key) => public_key,
        Err(message) => {
            show_rejection(boot_display, delay, message, 1500, ErrorSound::Beep);
            return true;
        }
    };
    boot_display.update_progress_bar(40);
    let mut randomness = [0u8; 44];
    if let Err(error) = crate::crypto::entropy::fill(&mut randomness) {
        show_rejection(boot_display, delay, error.message(), 1_500, ErrorSound::Beep);
        zeroize_bytes(&mut recipient_pubkey);
        return true;
    }
    boot_display.update_progress_bar(60);
    let plaintext_len = ad.signing.commit_reveal.plaintext_len;
    let encryption = offline_signer::crypto::ecies::encrypt(
        &recipient_pubkey,
        &ad.signing.commit_reveal.plaintext[..plaintext_len],
        &randomness,
    );
    match encryption {
        Ok(ciphertext) => {
            ad.signing.commit_reveal.ciphertext = ciphertext;
            boot_display.update_progress_bar(100);
            sound::success();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CommitRevealResult));
        }
        Err(_) => show_rejection(boot_display, delay, "ECIES failed", 1500, ErrorSound::Beep),
    }
    zeroize_bytes(&mut randomness);
    zeroize_bytes(&mut recipient_pubkey);
    zeroize_bytes(&mut ad.signing.commit_reveal.plaintext[..plaintext_len]);
    ad.signing.commit_reveal.plaintext_len = 0;
    ad.wallet.seeds.pp_input.reset();
    true
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_store_secret(ad: &mut AppData, secret: &[u8]) -> Result<(), &'static str> {
    ad.wallet.seeds.pp_input.reset();
    if secret.len() > ad.wallet.seeds.pp_input.buf.len() { return Err("Max 33 characters"); }
    ad.wallet.seeds.pp_input.buf[..secret.len()].copy_from_slice(secret);
    ad.wallet.seeds.pp_input.len = secret.len();
    ad.wallet.seeds.pp_input.cursor = secret.len();
    store_salted_secret_with_salt(ad, &[0x42u8; SALT_LEN])?;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CommitRevealPreview));
    Ok(())
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_encrypt_preimage(ad: &mut AppData) -> Result<(), &'static str> {
    let mut liveness = || {};
    let mut recipient_pubkey = derive_recipient_pubkey(ad, &mut liveness)?;
    let randomness = [0x33u8; 44];
    let plaintext_len = ad.signing.commit_reveal.plaintext_len;
    let encryption = offline_signer::crypto::ecies::encrypt(
        &recipient_pubkey,
        &ad.signing.commit_reveal.plaintext[..plaintext_len],
        &randomness,
    );
    zeroize_bytes(&mut recipient_pubkey);
    let ciphertext = encryption.map_err(|_| "ECIES failed")?;
    ad.signing.commit_reveal.ciphertext = ciphertext;
    zeroize_bytes(&mut ad.signing.commit_reveal.plaintext[..plaintext_len]);
    ad.signing.commit_reveal.plaintext_len = 0;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CommitRevealResult));
    Ok(())
}

fn handle_preview(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CommitRevealType));
        return true;
    }
    if (60..=260).contains(&x) && (165..=201).contains(&y) {
        return encrypt_preimage(ad, boot_display, delay, liveness);
    }
    false
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let changed = match ad.navigation.app.state {
        crate::runtime::input::AppState::CommitRevealType => {
            handle_secret_entry(ad, boot_display, delay, x, y, is_back)
        }
        crate::runtime::input::AppState::CommitRevealPreview => {
            handle_preview(ad, boot_display, delay, liveness, x, y, is_back)
        }
        _ => return None,
    };
    let mut needs_redraw = RedrawFlag::default();
    needs_redraw.set(changed);
    Some(needs_redraw.value())
}
