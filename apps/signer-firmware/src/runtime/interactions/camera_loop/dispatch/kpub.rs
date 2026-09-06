// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Watch-account QR import with decode-only legacy Base58 compatibility.

use super::super::{sound, AppData};

fn decode_payload(
    data: &[u8],
    length: usize,
    output: &mut [u8; offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN],
) -> bool {
    let input = &data[..length.min(data.len())];
    if let Some(raw) = kassigner_protocol::wire::qr_payload::unwrap_v1_raw(input) {
        if raw.len() == output.len() {
            output.copy_from_slice(raw);
            return offline_signer::derivation::xpub::import_kpub_raw(output).is_ok();
        }
        return false;
    }
    offline_signer::derivation::xpub::decode_kpub_compatible(input, output).is_ok()
}

pub(super) fn matches(data: &[u8], length: usize) -> bool {
    let mut payload = [0u8; offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN];
    decode_payload(data, length, &mut payload)
}

pub(super) fn process(
    data: &[u8],
    length: usize,
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    let mut payload = [0u8; offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN];
    if !decode_payload(data, length, &mut payload) {
        sound::error();
        return;
    }

    if ad.signing.multisig.creating.n > 0 && !ad.signing.multisig.creating.active {
        import_multisig_cosigner(&payload, ad, checkpoint);
    } else {
        store_scanned_account_key(&payload, ad);
    }
}

fn import_multisig_cosigner(
    payload: &[u8; offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN],
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    let mut canonical = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let Ok(length) = offline_signer::derivation::xpub::encode_kpub_text(payload, &mut canonical) else {
        sound::error(); return;
    };
    let Some(parts) = offline_signer::derivation::xpub::parse_kpub_parts(&canonical[..length]) else {
        sound::error(); return;
    };
    let key_index = (0..ad.signing.multisig.creating.n)
        .find(|index| ad.signing.multisig.creating.slot_empty(*index as usize))
        .unwrap_or(0);
    if !ad.signing.multisig.creating.set_cosigner(key_index as usize, &parts) {
        sound::error(); return;
    }
    log!("   → multisig kpub imported for key {}/{}", key_index + 1, ad.signing.multisig.creating.n);
    sound::qr_decoded();
    crate::runtime::interactions::tx::advance_after_cosigner(ad, key_index + 1, checkpoint);
    crate::runtime::effects::redraw(ad);
}

fn store_scanned_account_key(
    payload: &[u8; offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN],
    ad: &mut AppData,
) {
    let mut encoded = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let Ok(length) = offline_signer::derivation::xpub::encode_kpub_text(payload, &mut encoded) else {
        sound::error();
        return;
    };
    ad.export.kpub_data[..length].copy_from_slice(&encoded[..length]);
    ad.export.kpub_len = length;
    log!("   → account key scanned, normalized to kpub1");
    sound::qr_decoded();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(KpubScannedPopup));
    crate::runtime::effects::redraw(ad);
}
