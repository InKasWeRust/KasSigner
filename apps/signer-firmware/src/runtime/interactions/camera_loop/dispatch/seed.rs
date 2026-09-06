// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use super::super::{AppData, seed_manager, sound, validate_mnemonic};

pub(super) fn process_seedqr(data: &[u8], ad: &mut AppData) {
    // Standard SeedQR — numeric digit string (48=12w, 96=24w)
    let mut import_indices = [0u16; 24];
    let wc = seed_manager::decode_seedqr(data, &mut import_indices);
    finish_seed_import(ad, import_indices, wc, "SeedQR");
}

pub(super) fn process_raw_entropy(data: &[u8], ad: &mut AppData) {
    // CompactSeedQR — raw entropy (16=12w, 32=24w)
    let mut import_indices = [0u16; 24];
    let wc = seed_manager::decode_compact_seedqr(data, &mut import_indices);
    finish_seed_import(ad, import_indices, wc, "CompactSeedQR");
}

fn finish_seed_import(ad: &mut AppData, indices: [u16; 24], word_count: u8, format_name: &str) {
    if word_count == 0 || !validate_mnemonic(&indices, word_count) {
        log!("   → {}: invalid checksum", format_name);
        sound::error();
        return;
    }

    ad.wallet.seeds.mnemonic_indices = indices;
    ad.wallet.seeds.word_count = word_count;
    log!("   → {} imported ({} words) → passphrase choice", format_name, word_count);
    sound::qr_decoded();
    #[cfg(feature = "waveshare")]
    crate::services::camera_device::stop();
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
    crate::runtime::effects::redraw(ad);
}


pub(super) fn process_plain_words(data: &[u8], ad: &mut AppData) -> bool {
    if !restore_scan_active(ad) { return false; }
    let Ok(text) = core::str::from_utf8(data) else { return false; };
    let mut indices = [0u16; 24];
    let mut count = 0usize;
    for word in text.split_ascii_whitespace() {
        if count >= indices.len() { return false; }
        let Ok(index) = offline_signer::derivation::bip39::word_to_index(word) else {
            return false;
        };
        indices[count] = index;
        count += 1;
    }
    if !matches!(count, 12 | 24) { return false; }
    let word_count = count as u8;
    if !validate_mnemonic(&indices, word_count) { return false; }
    finish_seed_import(ad, indices, word_count, "Plain-text SeedQR");
    true
}

fn restore_scan_active(ad: &AppData) -> bool {
    ad.wallet.seeds.pending_add_wallet_is_restore()
        || (ad.storage.persistence.device_storage_intent.is_seed_onboarding()
            && ad.storage.persistence.onboarding_imported_mnemonic)
}
