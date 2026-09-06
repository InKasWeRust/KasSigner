// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::{AppData, display, sdcard, sound, stego};
use crate::{
    runtime::interactions::{
        feedback::{show_rejection, show_success, ErrorSound},
        keyboard::{handle_passphrase_keyboard, KeyboardAction},
    },
    runtime::input::AppState,
    services::backup::BackupDevice,
};
use shared_signer::{bytes::zeroize_bytes, bytes::zeroize_u16};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn BackupDevice,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::StegoImportPass => handle_descriptor_entry(
            ad, boot_display, delay, liveness, i2c, backup_device, x, y, is_back,
        ),
        AppState::StegoImportPortablePassword => {
            handle_portable_password(ad, boot_display, delay, liveness, i2c, x, y, is_back)
        }
        _ => None,
    }
}

fn handle_descriptor_entry(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn BackupDevice,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        clear_import_secret(ad);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportDescChoice));
        return Some(true);
    }
    Some(match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::Submitted => identify_and_open(ad, boot_display, delay, liveness, i2c, backup_device),
        KeyboardAction::Edited | KeyboardAction::None => false,
    })
}

fn identify_and_open(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn BackupDevice,
) -> bool {
    boot_display.draw_loading_screen("Decrypting...");
    boot_display.update_progress_bar(10);
    liveness();
    let jpeg = match read_selected_image(ad, i2c, delay) {
        Ok(image) => image,
        Err(_) => {
            show_rejection(boot_display, delay, "JPEG read failed", 2_000, ErrorSound::Beep);
            return true;
        }
    };
    liveness();
    let descriptor_len = ad.wallet.seeds.pp_input.len.min(96);
    if descriptor_len == 0 {
        show_rejection(boot_display, delay, "Descriptor required", 1_700, ErrorSound::Beep);
        return true;
    }
    ad.stego.import.clear_descriptor();
    ad.stego.import.descriptor_buf[..descriptor_len]
        .copy_from_slice(&ad.wallet.seeds.pp_input.buf[..descriptor_len]);
    ad.stego.import.descriptor_len = descriptor_len;
    ad.wallet.seeds.pp_input.reset();
    ad.stego.import.carrier = None;

    let mut fallback_payload = [0u8; 256];
    let mut fallback_len = 0usize;
    let mut fallback_carrier = None;

    if extract_descriptor_payload(ad, jpeg.as_bytes()) {
        if open_device_bound(ad, boot_display, delay, stego::StegoCarrier::Descriptor, backup_device) {
            liveness();
            clear_import_secret(ad);
            return true;
        }
        fallback_len = ad.stego.import.embedded_payload_len;
        fallback_payload[..fallback_len]
            .copy_from_slice(&ad.stego.import.embedded_payload[..fallback_len]);
        fallback_carrier = Some(stego::StegoCarrier::Descriptor);
    }

    zeroize_bytes(&mut ad.stego.import.embedded_payload);
    liveness();
    ad.stego.import.embedded_payload_len = stego::extract_picture(
        jpeg.as_bytes(),
        &ad.stego.import.descriptor_buf[..descriptor_len],
        &mut ad.stego.import.embedded_payload,
    ).unwrap_or(0);
    if ad.stego.import.embedded_payload_len == stego::STEGO_PAYLOAD_SIZE {
        if open_device_bound(ad, boot_display, delay, stego::StegoCarrier::Picture, backup_device) {
            liveness();
            zeroize_bytes(&mut fallback_payload);
            clear_import_secret(ad);
            return true;
        }
        if fallback_carrier.is_none() {
            fallback_carrier = Some(stego::StegoCarrier::Picture);
        }
    }

    if let Some(carrier) = fallback_carrier {
        if carrier == stego::StegoCarrier::Descriptor {
            zeroize_bytes(&mut ad.stego.import.embedded_payload);
            ad.stego.import.embedded_payload[..fallback_len]
                .copy_from_slice(&fallback_payload[..fallback_len]);
            ad.stego.import.embedded_payload_len = fallback_len;
        }
        zeroize_bytes(&mut fallback_payload);
        ad.stego.import.carrier = Some(carrier);
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportPortablePassword));
        return true;
    }

    zeroize_bytes(&mut fallback_payload);
    clear_import_secret(ad);
    show_rejection(boot_display, delay, "Wrong descriptor or backup", 2_500, ErrorSound::Beep);
    true
}

fn handle_portable_password(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        clear_import_secret(ad);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportDescChoice));
        return Some(true);
    }
    Some(match handle_passphrase_keyboard(&mut ad.wallet.seeds.pp_input, boot_display, x, y) {
        KeyboardAction::None => false,
        KeyboardAction::Edited => true,
        KeyboardAction::Submitted => {
            let password_len = ad.wallet.seeds.pp_input.len;
            if let Err(message) = stego::validate_portable_password(
                &ad.wallet.seeds.pp_input.buf[..password_len],
            ) {
                show_rejection(boot_display, delay, message, 1_700, ErrorSound::Beep);
                return Some(true);
            }
            ad.stego.session.portable.set_password(&ad.wallet.seeds.pp_input.buf[..password_len]);
            ad.wallet.seeds.pp_input.reset();
            let opened = open_portable(ad, boot_display, delay)
                || try_alternate_picture_portable(ad, boot_display, delay, liveness, i2c);
            if !opened {
                ad.stego.session.portable.clear();
                show_rejection(boot_display, delay, "Wrong password or damaged backup", 2_000, ErrorSound::Beep);
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportPortablePassword));
            }
            opened
        }
    })
}

fn read_selected_image(
    ad: &AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) -> Result<crate::services::memory::psram::PsramAllocation, &'static str> {
    let filename = ad.stego.import.jpeg_names[ad.stego.import.jpeg_selected as usize];
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        let (entry, _, _) = sdcard::find_file_in_root(card, &fat32, &filename)?;
        let size = entry.file_size as usize;
        if size == 0 || size > 2_000_000 { return Err("JPEG size unsupported"); }
        const IMPORT_HEADROOM: usize = 1_310_720;
        let mut jpeg = crate::services::memory::psram::PsramAllocation::allocate_with_reserve(size, 8, IMPORT_HEADROOM)
            .map_err(|_| "Not enough PSRAM for JPEG import")?;
        let length = sdcard::read_file(card, &fat32, &entry, jpeg.as_mut_bytes())?;
        if length != size || length < 4 || !jpeg.as_bytes()[..length].starts_with(&[0xFF, 0xD8]) {
            return Err("Invalid JPEG read");
        }
        Ok(jpeg)
    })
}

fn extract_descriptor_payload(ad: &mut AppData, jpeg: &[u8]) -> bool {
    zeroize_bytes(&mut ad.stego.import.embedded_payload);
    ad.stego.import.embedded_payload_len = 0;
    let Some((offset, length)) = stego::find_exif_app1(jpeg) else { return false; };
    let extracted = stego::extract_user_comment(
        &jpeg[offset..offset + length],
        &mut ad.stego.import.embedded_payload,
    );
    ad.stego.import.embedded_payload_len = extracted;
    extracted == stego::STEGO_PAYLOAD_SIZE
}

fn open_device_bound(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    carrier: stego::StegoCarrier,
    backup_device: &mut dyn BackupDevice,
) -> bool {
    let descriptor_len = ad.stego.import.descriptor_len;
    let mut indices = [0u16; 24];
    let mut hint = [0u8; 64];
    let result = stego::unpack_device_bound_payload(
        carrier,
        &ad.stego.import.embedded_payload[..ad.stego.import.embedded_payload_len],
        &ad.stego.import.descriptor_buf[..descriptor_len],
        backup_device,
        &mut indices,
        &mut hint,
    );
    commit_recovery(ad, boot_display, delay, carrier, result, &mut indices, &mut hint)
}

fn try_alternate_picture_portable(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> bool {
    if ad.stego.import.carrier != Some(stego::StegoCarrier::Descriptor) { return false; }
    let mut descriptor_payload = [0u8; 256];
    let descriptor_payload_len = ad.stego.import.embedded_payload_len;
    descriptor_payload[..descriptor_payload_len]
        .copy_from_slice(&ad.stego.import.embedded_payload[..descriptor_payload_len]);
    let jpeg = match read_selected_image(ad, i2c, delay) {
        Ok(image) => image,
        Err(_) => {
            zeroize_bytes(&mut descriptor_payload);
            return false;
        }
    };
    zeroize_bytes(&mut ad.stego.import.embedded_payload);
    liveness();
    ad.stego.import.embedded_payload_len = stego::extract_picture(
        jpeg.as_bytes(),
        &ad.stego.import.descriptor_buf[..ad.stego.import.descriptor_len],
        &mut ad.stego.import.embedded_payload,
    ).unwrap_or(0);
    ad.stego.import.carrier = Some(stego::StegoCarrier::Picture);
    if ad.stego.import.embedded_payload_len == stego::STEGO_PAYLOAD_SIZE
        && open_portable(ad, boot_display, delay)
    {
        zeroize_bytes(&mut descriptor_payload);
        return true;
    }
    zeroize_bytes(&mut ad.stego.import.embedded_payload);
    ad.stego.import.embedded_payload[..descriptor_payload_len]
        .copy_from_slice(&descriptor_payload[..descriptor_payload_len]);
    ad.stego.import.embedded_payload_len = descriptor_payload_len;
    ad.stego.import.carrier = Some(stego::StegoCarrier::Descriptor);
    zeroize_bytes(&mut descriptor_payload);
    false
}

fn open_portable(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    let Some(carrier) = ad.stego.import.carrier else { return false; };
    let descriptor_len = ad.stego.import.descriptor_len;
    let mut indices = [0u16; 24];
    let mut hint = [0u8; 64];
    let result = stego::unpack_portable_payload(
        carrier,
        &ad.stego.import.embedded_payload[..ad.stego.import.embedded_payload_len],
        &ad.stego.import.descriptor_buf[..descriptor_len],
        ad.stego.session.portable.password(),
        &mut indices,
        &mut hint,
    );
    let opened = commit_recovery(ad, boot_display, delay, carrier, result, &mut indices, &mut hint);
    if opened { clear_import_secret(ad); }
    opened
}

fn commit_recovery(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    carrier: stego::StegoCarrier,
    result: Result<(u8, usize), &'static str>,
    indices: &mut [u16; 24],
    hint: &mut [u8; 64],
) -> bool {
    let (word_count, hint_len) = match result {
        Ok(value) => value,
        Err(_) => {
            zeroize_u16(indices);
            zeroize_bytes(hint);
            return false;
        }
    };
    ad.wallet.seeds.mnemonic_indices = *indices;
    zeroize_u16(indices);
    ad.wallet.seeds.word_count = word_count;
    zeroize_bytes(&mut ad.stego.import.recovered_hint);
    ad.stego.import.recovered_hint[..hint_len].copy_from_slice(&hint[..hint_len]);
    ad.stego.import.recovered_hint_len = hint_len;
    zeroize_bytes(hint);
    ad.stego.import.carrier = Some(carrier);
    log!("   Stego import OK: {} words via {}", word_count, carrier.label());
    finish_recovery(ad, boot_display, delay);
    true
}

fn clear_import_secret(ad: &mut AppData) {
    ad.stego.session.portable.clear();
    ad.stego.import.clear_descriptor();
    zeroize_bytes(&mut ad.stego.import.embedded_payload);
    ad.stego.import.embedded_payload_len = 0;
}

fn finish_recovery(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    if ad.stego.import.recovered_hint_len > 0 {
        sound::success();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoHintReveal));
        return;
    }
    if super::import_finish::restore_staging_active(ad) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
        return;
    }
    if let Some(slot) = ad.wallet.seeds.seed_mgr.store(
        &ad.wallet.seeds.mnemonic_indices,
        ad.wallet.seeds.word_count,
        &[],
        0,
    ) {
        match crate::services::wallet_session::activate_slot(ad, slot) {
            Ok(()) => show_success(boot_display, delay, "Seed Recovered!", 2_000),
            Err(error) => show_rejection(boot_display, delay, error.message(), 2_000, ErrorSound::Beep),
        }
        super::import_finish::finish_recovery_destination(ad);
    } else {
        show_rejection(
            boot_display,
            delay,
            crate::services::wallet_session::SLOTS_FULL_MESSAGE,
            2_000,
            ErrorSound::Beep,
        );
    }
}

#[cfg(feature = "workflow-test-auto")]
mod workflow;
#[cfg(feature = "workflow-test-auto")]
pub(crate) use workflow::{workflow_open_payload, workflow_stage_portable_payload};
