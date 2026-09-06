// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::super::{display, sound, AppData};
use crate::runtime::input::AppState;
use shared_signer::bytes::zeroize_bytes;

pub(super) fn is_pending(ad: &AppData) -> bool {
    matches!(ad.navigation.app.state, AppState::DecryptSecretScan)
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_process(data: &[u8], ad: &mut AppData) {
    let hex = core::str::from_utf8(data).unwrap_or("").trim();
    if hex.len() < 122 || hex.len() % 2 != 0 {
        crate::runtime::effects::redraw(ad);
        return;
    }

    let Ok(mut ciphertext) = crate::services::memory::zeroed_bytes(hex.len() / 2) else { return; };
    if signer_firmware_core::qr::classification::decode_hex(hex.as_bytes(), &mut ciphertext)
        .is_err()
        || ciphertext.len() < 61
    {
        zeroize_bytes(&mut ciphertext);
        crate::runtime::effects::redraw(ad);
        return;
    }

    let mut liveness = || {};
    let decrypt_result = crate::runtime::signing::derive_active_account_key_with_checkpoint(ad, &mut liveness)
        .map_err(|_| "key derivation failed")
        .and_then(|account_key| {
            offline_signer::crypto::ecies::decrypt(account_key.private_key_bytes(), &ciphertext)
        });
    zeroize_bytes(&mut ciphertext);

    if let Ok(mut plaintext) = decrypt_result {
        let copy_len = plaintext.len().min(ad.signing.commit_reveal.plaintext.len());
        ad.signing.commit_reveal.plaintext[..copy_len].copy_from_slice(&plaintext[..copy_len]);
        ad.signing.commit_reveal.plaintext_len = copy_len;
        zeroize_bytes(&mut plaintext);
        sound::success();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DecryptSecretResult));
        crate::runtime::effects::redraw(ad);
    } else {
        crate::runtime::effects::redraw(ad);
    }
}

pub(super) fn process(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    let input_len = len.min(data.len());
    let hex = core::str::from_utf8(&data[..input_len])
        .unwrap_or("")
        .trim();
    if hex.len() < 122 || hex.len() % 2 != 0 {
        reject(ad, boot_display, delay, "Invalid ciphertext hex", 1_500);
        return;
    }

    let Ok(mut ciphertext) = crate::services::memory::zeroed_bytes(hex.len() / 2) else { return; };
    if signer_firmware_core::qr::classification::decode_hex(hex.as_bytes(), &mut ciphertext).is_err()
        || ciphertext.len() < 61
    {
        zeroize_bytes(&mut ciphertext);
        reject(ad, boot_display, delay, "Bad hex data", 1_500);
        return;
    }

    let decrypt_result = crate::runtime::signing::derive_active_account_key_with_checkpoint(ad, liveness)
        .map_err(|_| "key derivation failed")
        .and_then(|account_key| {
            offline_signer::crypto::ecies::decrypt(
                account_key.private_key_bytes(),
                &ciphertext,
            )
        });
    zeroize_bytes(&mut ciphertext);

    match decrypt_result {
        Ok(mut plaintext) => {
            let copy_len = plaintext
                .len()
                .min(ad.signing.commit_reveal.plaintext.len());
            ad.signing.commit_reveal.plaintext[..copy_len]
                .copy_from_slice(&plaintext[..copy_len]);
            ad.signing.commit_reveal.plaintext_len = copy_len;
            zeroize_bytes(&mut plaintext);
            sound::success();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DecryptSecretResult));
            crate::runtime::effects::redraw(ad);
        }
        Err(error) => {
            let message = match error {
                "ciphertext too short" => "Data too short",
                "bad ephemeral pubkey" | "invalid ephemeral point" => "Bad ciphertext",
                "bad private key" => "Key error",
                "decryption failed" => "Wrong key or corrupt",
                _ => "Decrypt failed",
            };
            reject(ad, boot_display, delay, message, 2_000);
        }
    }
}

fn reject(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    message: &str,
    duration_ms: u32,
) {
    show_rejection(boot_display, delay, message, duration_ms, ErrorSound::Beep);
    crate::runtime::effects::redraw(ad);
}
