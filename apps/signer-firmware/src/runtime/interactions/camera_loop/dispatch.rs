// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Ordered decoded-payload routing.
//!
//! Each payload family owns its validation and workflow. This router retains
//! the original precedence and the stable camera-controller call surface.

use super::{AppData, display, sound};
use signer_firmware_core::qr::classification::{classify_qr_payload, QrPayloadKind};

mod address;
mod anti_klepto;
mod covenant;
mod covenant_sign;
mod descriptor;
mod private_swap;
mod kpub;
mod pairing;
mod text;
mod secret;
mod seed;
mod stealth;
mod transaction;

#[inline(never)]
pub(super) fn process_confirmed_qr(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    sound::qr_decoded();
    if process_pending(data, len, ad, boot_display, delay, liveness) { return; }
    dispatch_payload(
        classify_qr_payload(data, len), data, len, ad, boot_display, delay, i2c, liveness,
    );
}

fn process_pending(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut (impl FnMut() + ?Sized),
) -> bool {
    if text::message::is_pending(ad) {
        text::message::process(data, len, ad, boot_display, delay);
        return true;
    }
    if secret::is_pending(ad) {
        secret::process(data, len, ad, boot_display, delay, liveness);
        return true;
    }
    false
}

fn dispatch_payload(
    kind: QrPayloadKind,
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    if dispatch_identity(kind, data, len, ad, i2c, liveness) { return; }
    if dispatch_transaction(kind, data, ad, liveness) { return; }
    if dispatch_seed(kind, data, ad) { return; }
    if dispatch_platform(kind, data, len, ad, boot_display, delay, liveness) { return; }
    if dispatch_covenant(kind, data, len, ad, boot_display, liveness) { return; }
    dispatch_last(kind, data, len, ad, liveness);
}

fn dispatch_identity(
    kind: QrPayloadKind, data: &[u8], len: usize, ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) -> bool {
    match kind {
        QrPayloadKind::AntiKlepto => anti_klepto::process(data, len, ad, i2c, liveness),
        QrPayloadKind::KaspaAddress => address::process(data, len, ad),
        _ => return false,
    }
    true
}

fn dispatch_transaction(
    kind: QrPayloadKind, data: &[u8], ad: &mut AppData,
    liveness: &mut (impl FnMut() + ?Sized),
) -> bool {
    match kind {
        QrPayloadKind::CompactKspt => transaction::process_kspt(data, ad, liveness),
        QrPayloadKind::StandardPskt => transaction::process_standard_pskt(data, ad, liveness),
        _ => return false,
    }
    true
}


#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_process_seed_payload(data: &[u8], compact: bool, ad: &mut AppData) {
    if compact {
        seed::process_raw_entropy(data, ad);
    } else {
        seed::process_seedqr(data, ad);
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_process_transaction_payload(
    data: &[u8],
    standard_pskt: bool,
    ad: &mut AppData,
) {
    if standard_pskt {
        crate::runtime::interactions::tx::workflow_load_standard_transaction(data, ad);
    } else {
        crate::runtime::interactions::tx::workflow_load_compact_transaction(data, ad);
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_process_kpub_payload(data: &[u8], ad: &mut AppData) {
    kpub::process(data, data.len(), ad, &mut || {});
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_process_anti_klepto_payload(data: &[u8], ad: &mut AppData) {
    anti_klepto::workflow_process(data, ad);
}

fn dispatch_seed(kind: QrPayloadKind, data: &[u8], ad: &mut AppData) -> bool {
    match kind {
        QrPayloadKind::SeedQr => seed::process_seedqr(data, ad),
        QrPayloadKind::RawSeedEntropy => seed::process_raw_entropy(data, ad),
        _ => return false,
    }
    true
}

fn dispatch_platform(
    kind: QrPayloadKind, data: &[u8], len: usize, ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>, delay: &mut esp_hal::delay::Delay,
    liveness: &mut (impl FnMut() + ?Sized),
) -> bool {
    match kind {
        QrPayloadKind::StealthRequest => stealth::process(data, len, ad, boot_display, delay, liveness),
        QrPayloadKind::PairingRequest => pairing::process(data, len, ad, boot_display, delay, liveness),
        QrPayloadKind::FirmwareUpdate => {
            log!("   → Firmware update QR ignored; use Settings -> Advanced -> Firmware Update and USB");
            sound::error();
        },
        _ => return false,
    }
    true
}

fn dispatch_covenant(
    kind: QrPayloadKind, data: &[u8], len: usize, ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) -> bool {
    match kind {
        QrPayloadKind::CovenantRaw => covenant::process_raw(data, len, ad, boot_display),
        QrPayloadKind::CovenantHex => covenant::process_hex(data, len, ad, boot_display),
        QrPayloadKind::CovenantSignRaw => covenant_sign::process_raw(data, len, ad, liveness),
        QrPayloadKind::CovenantSignHex => covenant_sign::process_hex(data, len, ad, liveness),
        QrPayloadKind::PrivateSwapRaw => private_swap::process_raw(data, len, ad, liveness),
        QrPayloadKind::PrivateSwapHex => private_swap::process_hex(data, len, ad, liveness),
        _ => return false,
    }
    true
}

fn dispatch_last(
    kind: QrPayloadKind,
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    match kind {
        QrPayloadKind::Unknown => dispatch_unknown(data, len, ad, liveness),
        _ => {}
    }
}

fn dispatch_unknown(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    if seed::process_plain_words(&data[..len.min(data.len())], ad) {
        return;
    }
    if descriptor::matches(data, len) {
        descriptor::process(data, len, ad, liveness);
    } else if kpub::matches(data, len) {
        kpub::process(data, len, ad, liveness);
    } else {
        log!("   → Unknown QR format ({} bytes)", len);
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_validate_stealth_request(
    data: &[u8],
    length: usize,
) -> Result<usize, &'static str> {
    stealth::workflow_validate_request(data, length)
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_process_pending_payload(data: &[u8], ad: &mut AppData) -> bool {
    if text::message::is_pending(ad) {
        text::message::workflow_process(data, ad);
        return true;
    }
    if secret::is_pending(ad) {
        secret::workflow_process(data, ad);
        return true;
    }
    false
}
