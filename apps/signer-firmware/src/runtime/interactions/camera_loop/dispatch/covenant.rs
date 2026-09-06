// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use super::super::{AppData, display};

pub(super) fn process_raw(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    // Raw binary COVB/COVI (from multi-frame assembly). Store directly.
    let n = len.min(data.len()).min(ad.qr.outgoing.buffer.len());
    ad.qr.outgoing.buffer[..n].copy_from_slice(&data[..n]);
    ad.qr.outgoing.covenant_backup_length = n;
    ad.wallet.seeds.pp_input.reset();
    boot_display.clear_screen();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CovBackupName));
    crate::runtime::effects::redraw(ad);
    log!("   → COVB raw: {} bytes", n);
}

pub(super) fn process_hex(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    // Hex-encoded COVB/COVI (from single-frame KasSee export QR).
    let input = &data[..len.min(data.len())];
    let Ok(n) = signer_firmware_core::qr::classification::decode_hex(input, &mut ad.qr.outgoing.buffer) else {
        log!("   → COVB hex decode rejected after classification");
        return;
    };
    ad.qr.outgoing.covenant_backup_length = n;
    ad.wallet.seeds.pp_input.reset();
    boot_display.clear_screen();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CovBackupName));
    crate::runtime::effects::redraw(ad);
    log!("   → COVB: {} hex → {} bytes", len, n);
}
