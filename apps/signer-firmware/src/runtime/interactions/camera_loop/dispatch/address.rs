// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use super::super::{AppData, sound};

pub(super) fn process(data: &[u8], len: usize, ad: &mut AppData) {
    // Kaspa address — lowercase and store
    let copy_len = len.min(data.len()).min(ad.qr.scan.address.len());
    for i in 0..copy_len {
        ad.qr.scan.address[i] = if data[i] >= b'A' && data[i] <= b'Z' {
            data[i] + 32
        } else {
            data[i]
        };
    }
    ad.qr.scan.address_length = copy_len;

    let valid = offline_signer::address::validate_kaspa_address(
        &ad.qr.scan.address[..ad.qr.scan.address_length]);
    ad.qr.scan.address_valid = valid;
    if valid {
        log!("   → Valid Kaspa address");
        sound::qr_decoded();
    } else {
        log!("   → Kaspa address (invalid checksum)");
        sound::error();
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowAddress));
    crate::runtime::effects::redraw(ad);
}
