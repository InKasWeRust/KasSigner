// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::super::{AppData, display, sound};

fn display_response(response: &[u8], count: usize, ad: &mut AppData) {
    let response_len = 5 + count * 64;
    if crate::runtime::qr_presentation::present_payload(
        ad,
        &response[..response_len],
        crate::runtime::navigation::continuation!(MainMenu),
    ).is_err() {
        crate::runtime::effects::home(ad);
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
    let count = match validate_request(data, len) {
        Ok(count) => count,
        Err(message) => {
            log!("   → STLH: {}", message);
            sound::error();
            return;
        }
    };
    if ad.wallet.seeds.seed_mgr.active_slot().is_none() {
        show_rejection(boot_display, delay, "Load seed first", 1500, ErrorSound::Beep);
        crate::runtime::effects::redraw(ad);
        return;
    }

    log!("   → STLH: {} R values to scan", count);
    #[cfg(feature = "waveshare")]
    crate::services::camera_device::stop();
    boot_display.draw_loading_screen("Stealth scanning...");

    let keys = match derive_stealth_keys(ad, liveness) {
        Ok(keys) => keys,
        Err(message) => {
            show_rejection(boot_display, delay, message, 1500, ErrorSound::Beep);
            crate::runtime::effects::redraw(ad);
            return;
        }
    };
    boot_display.update_progress_bar(30);
    let response = match build_response(data, count, &keys, boot_display) {
        Ok(response) => response,
        Err(message) => {
            show_rejection(boot_display, delay, message, 1_500, ErrorSound::Beep);
            crate::runtime::effects::redraw(ad);
            return;
        }
    };
    boot_display.update_progress_bar(100);
    display_response(&response, count, ad);
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_validate_request(
    data: &[u8],
    length: usize,
) -> Result<usize, &'static str> {
    validate_request(data, length)
}

fn validate_request(data: &[u8], length: usize) -> Result<usize, &'static str> {
    if length < 5 || data.len() < 5 {
        return Err("request too short");
    }
    let count = usize::from(data[4]);
    let expected = 5usize.saturating_add(count.saturating_mul(32));
    if count == 0 || count > 64 || length < expected || data.len() < expected {
        return Err("bad count or payload length");
    }
    Ok(count)
}

struct StealthKeys {
    scan_scalar: k256::Scalar,
    spend_public_key: [u8; 32],
}

fn derive_stealth_keys(ad: &AppData, liveness: &mut (impl FnMut() + ?Sized)) -> Result<StealthKeys, &'static str> {
    use k256::elliptic_curve::ScalarPrimitive;

    let account_key = crate::runtime::signing::derive_active_account_key_with_checkpoint(ad, liveness)?;
    let scan_branch = offline_signer::derivation::bip32::derive_child(&account_key, 2)
        .map_err(|_| "Scan branch failed")?;
    let scan_key = offline_signer::derivation::bip32::derive_child(&scan_branch, 0)
        .map_err(|_| "Scan key failed")?;
    let scan_primitive = ScalarPrimitive::<k256::Secp256k1>::from_slice(
        scan_key.private_key_bytes(),
    )
    .map_err(|_| "Invalid scan key")?;
    Ok(StealthKeys {
        scan_scalar: k256::Scalar::from(scan_primitive),
        spend_public_key: xonly_public_key(account_key.private_key_bytes())?,
    })
}

fn xonly_public_key(private_key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    use k256::elliptic_curve::ScalarPrimitive;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let primitive = ScalarPrimitive::<k256::Secp256k1>::from_slice(private_key)
        .map_err(|_| "Invalid account key")?;
    let point = (k256::ProjectivePoint::GENERATOR * k256::Scalar::from(primitive)).to_affine();
    let encoded = point.to_encoded_point(true);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&encoded.as_bytes()[1..33]);
    Ok(xonly)
}

fn build_response(
    data: &[u8],
    count: usize,
    keys: &StealthKeys,
    boot_display: &mut display::BootDisplay<'_>,
) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let response_len = count.checked_mul(64).and_then(|n| n.checked_add(5)).ok_or("Response too large")?;
    let mut response = crate::services::memory::zeroed_bytes(response_len).map_err(|_| "Not enough memory")?;
    response[..4].copy_from_slice(b"STLR");
    response[4] = count as u8;
    for index in 0..count {
        let request_offset = 5 + index * 32;
        let output_offset = 5 + index * 64;
        if let Some((public_key, tweak)) = scan_candidate(
            &data[request_offset..request_offset + 32],
            keys,
        ) {
            response[output_offset..output_offset + 32].copy_from_slice(&public_key);
            response[output_offset + 32..output_offset + 64].copy_from_slice(&tweak);
        }
        boot_display.update_progress_bar(30 + ((index + 1) * 60 / count) as u8);
    }
    Ok(response)
}

fn scan_candidate(candidate: &[u8], keys: &StealthKeys) -> Option<([u8; 32], [u8; 32])> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};

    let ephemeral = parse_xonly_public_key(candidate)?;
    let shared = (ephemeral.to_projective() * keys.scan_scalar)
        .to_affine()
        .to_encoded_point(true);
    let mut hasher = Sha256::new();
    hasher.update(b"KasStealth");
    hasher.update(&shared.as_bytes()[1..33]);
    hasher.update(0u32.to_be_bytes());
    let tweak_hash: [u8; 32] = hasher.finalize().into();
    let tweak_primitive = scalar_primitive(&tweak_hash)?;
    let spend = parse_xonly_public_key(&keys.spend_public_key)?;
    let one_time = (spend.to_projective()
        + k256::ProjectivePoint::GENERATOR * k256::Scalar::from(tweak_primitive))
        .to_affine()
        .to_encoded_point(true);
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&one_time.as_bytes()[1..33]);
    Some((public_key, tweak_hash))
}

fn parse_xonly_public_key(value: &[u8]) -> Option<k256::PublicKey> {
    if value.len() != 32 {
        return None;
    }
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(value);
    k256::PublicKey::from_sec1_bytes(&compressed).ok()
}

fn scalar_primitive(
    value: &[u8; 32],
) -> Option<k256::elliptic_curve::ScalarPrimitive<k256::Secp256k1>> {
    use k256::elliptic_curve::ScalarPrimitive;

    // A SHA-256 digest is a 256-bit integer. Since the secp256k1 group order
    // is only slightly below 2^256, canonical reduction requires at most one
    // subtraction. Never truncate or shift the digest: doing so changes the
    // protocol and creates a biased, incompatible tweak.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ];

    let mut reduced = *value;
    if reduced >= ORDER {
        let mut borrow = 0u16;
        for index in (0..32).rev() {
            let minuend = u16::from(reduced[index]);
            let subtrahend = u16::from(ORDER[index]) + borrow;
            if minuend >= subtrahend {
                reduced[index] = (minuend - subtrahend) as u8;
                borrow = 0;
            } else {
                reduced[index] = (minuend + 256 - subtrahend) as u8;
                borrow = 1;
            }
        }
    }
    if reduced.iter().all(|byte| *byte == 0) {
        return None;
    }
    ScalarPrimitive::<k256::Secp256k1>::from_slice(&reduced).ok()
}
