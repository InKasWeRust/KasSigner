// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Watch-only export workflows.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    runtime::interactions::menu_selection::selected_visible_item,
    hw::display,
    runtime::{data::AppData, input::AppState},
};
use super::{context::ExportStorageContext, TouchInput};


pub(super) fn handle_pure(
    ad: &mut AppData, list_zones: &[crate::hw::touch::TouchZone; 4], x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::WatchOnlyMenu { return None; }
    if is_back { ad.navigation.watch_only_menu.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportChoice)); return Some(true); }
    match selected_visible_item(&ad.navigation.watch_only_menu, list_zones, x, y) {
        None => Some(false),
        Some(_) => None,
    }
}

pub(super) fn handle(context: ExportStorageContext<'_, '_, '_>) -> Option<bool> {
    let ExportStorageContext {
        ad, boot_display, delay, liveness, i2c, sd_card_type, list_zones, input, ..
    } = context;
    let TouchInput { x, y, is_back } = input;
    if ad.navigation.app.state != AppState::WatchOnlyMenu {
        return None;
    }
    if is_back {
        ad.navigation.watch_only_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportChoice));
        return Some(true);
    }

    let Some(item) = selected_visible_item(&ad.navigation.watch_only_menu, list_zones, x, y)
    else {
        return Some(false);
    };
    match item {
        0 => export_as_qr(ad, boot_display, delay, liveness),
        1 => export_to_sd(ad, boot_display, delay, liveness, i2c, sd_card_type),
        2 => export_multisig_kpub_qr(ad, boot_display, delay, liveness),
        _ => return Some(false),
    }
    Some(true)
}

fn export_as_qr(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) {
    boot_display.draw_saving_screen("Deriving kpub...");
    if derive_watch_account(ad, boot_display, delay, liveness) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
    }
}

fn export_to_sd(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::services::storage_device::SdCardType>,
) {
    if sd_card_type.is_none() {
        show_rejection(boot_display, delay, "No SD card", 1_500, ErrorSound::Silent);
        return;
    }

    boot_display.draw_saving_screen("Deriving kpub...");
    if !derive_watch_account(ad, boot_display, delay, liveness) {
        return;
    }
    let next = crate::runtime::interactions::sd::scan_auto_increment(i2c, delay, b"KP", b"TXT");
    let filename = crate::runtime::interactions::sd::format_auto_name(b"KP", next, b"TXT");
    super::derivation::prepare_filename(ad, filename);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKpubFilename));
}

fn export_multisig_kpub_qr(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) {
    let _ = prepare_multisig_kpub_qr(ad, boot_display, delay, liveness);
}

pub(crate) fn prepare_multisig_kpub_qr(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) -> bool {
    liveness();
    let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else {
        show_rejection(boot_display, delay, "No active wallet", 1_500, ErrorSound::Silent);
        return false;
    };
    if slot.is_account_key() {
        show_rejection(boot_display, delay, "xprv slot has no 45' key", 2_000, ErrorSound::Silent);
        return false;
    }
    if !slot.is_mnemonic() {
        show_rejection(boot_display, delay, "Mnemonic wallet required", 2_000, ErrorSound::Silent);
        return false;
    }

    // CoreS3 production and runtime-HIL use the cooperative Core0/Core1 path.
    // Controller-only workflow tests retain the bounded synchronous fixture so
    // host/state tests do not require Core1 ownership.
    #[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
    {
        ad.export.kpub_len = 0;
        ad.export.kpub_progress = 0;
        #[cfg(feature = "m5stack")]
        ad.export.reset_multisig_kpub_work();
        let index = match ad.navigation.app.state {
            AppState::MultisigMenu => 1,
            AppState::WatchOnlyMenu => 2,
            _ => return false,
        };
        return crate::runtime::effects::menu_select(ad, index);
    }

    #[cfg(all(feature = "workflow-test-auto", not(feature = "workflow-runtime-auto")))]
    {
        if crate::runtime::interactions::feedback::physical_presentation_enabled() {
            boot_display.draw_saving_screen("Deriving multisig kpub...");
        }
        let Ok(mut seed) = crate::services::wallet_keys::derive_slot_seed_with_checkpoint(slot, liveness) else {
            show_rejection(boot_display, delay, "45' key derivation failed", 2_000, ErrorSound::Silent);
            return false;
        };
        let mut encoded = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
        let result = offline_signer::derivation::xpub::derive_and_serialize_multisig_kpub(
            &seed.bytes, &mut encoded,
        );
        crate::runtime::signing::zeroize_seed(&mut seed.bytes);
        match result {
            Ok(length) => {
                ad.export.kpub_data[..length].copy_from_slice(&encoded[..length]);
                ad.export.kpub_len = length;
                shared_signer::bytes::zeroize_bytes(&mut encoded);
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
                true
            }
            Err(_) => {
                shared_signer::bytes::zeroize_bytes(&mut encoded);
                show_rejection(boot_display, delay, "45' key derivation failed", 2_000, ErrorSound::Silent);
                false
            }
        }
    }
}

fn derive_watch_account(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) -> bool {
    if super::derivation::derive_watch_account(ad, liveness).is_ok() {
        return true;
    }
    show_rejection(boot_display, delay, "Account-key derivation failed", 2_000, ErrorSound::Silent);
    false
}
