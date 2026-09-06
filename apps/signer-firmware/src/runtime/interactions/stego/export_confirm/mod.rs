// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

mod carrier;

use super::{AppData, display, sound};
use crate::{
    runtime::interactions::feedback::{show_rejection, ErrorSound},
    runtime::input::AppState,
    services::{backup::BackupDevice, stego},
};
use shared_signer::{bytes::zeroize_bytes, bytes::zeroize_u16};

#[inline(never)]
pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn BackupDevice,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::StegoJpegConfirm { return None; }
    if is_back {
        clear_portable_secret(ad);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPpAsk));
        return Some(true);
    }
    if !(182..=225).contains(&y) { return Some(false); }
    if (20..=150).contains(&x) {
        clear_hint(ad);
        clear_portable_secret(ad);
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
        return Some(true);
    }
    if (170..=300).contains(&x) {
        confirm_export(ad, boot_display, delay, i2c, backup_device);
        return Some(true);
    }
    Some(false)
}

#[inline(never)]
fn confirm_export(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    backup_device: &mut dyn BackupDevice,
) {
    let Some((mut indices, word_count)) = active_seed(ad) else {
        reject(ad, boot_display, delay, "No mnemonic loaded");
        return;
    };
    let descriptor_len = ad.stego.export_flow.jpeg_desc_len;
    if descriptor_len == 0 || descriptor_len > 96 {
        zeroize_u16(&mut indices);
        reject(ad, boot_display, delay, "Invalid image descriptor");
        return;
    }

    boot_display.draw_loading_screen("Encrypting...");
    let mut payload = [0u8; stego::STEGO_PAYLOAD_SIZE];
    let carrier = ad.stego.export_flow.carrier;
    let descriptor = &ad.stego.export_flow.jpeg_desc_buf[..descriptor_len];
    let hint = &ad.stego.hint.buffer[..ad.stego.hint.length];
    let portable_password = ad.stego.session.portable.password();
    let result = stego::pack_payload(
        ad.stego.export_flow.security,
        carrier,
        &indices,
        word_count,
        hint,
        descriptor,
        portable_password,
        backup_device,
        &mut payload,
    ).and_then(|payload_length| {
        sound::task_done();
        carrier::write(ad, delay, i2c, &payload[..payload_length])
    });
    zeroize_u16(&mut indices);
    zeroize_bytes(&mut payload);
    clear_hint(ad);
    clear_portable_secret(ad);

    boot_display.update_progress_bar(100);
    if result.is_ok() {
        ad.stego.session.result_ok = true;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoResult));
        sound::success();
    } else if let Err(message) = result {
        reject(ad, boot_display, delay, message);
    }
}

fn active_seed(ad: &AppData) -> Option<([u16; 24], u8)> {
    let slot = ad.wallet.seeds.seed_mgr.active_slot()?;
    let word_count = slot.mnemonic_word_count()?;
    Some((slot.indices, word_count))
}

fn clear_hint(ad: &mut AppData) {
    zeroize_bytes(&mut ad.stego.hint.buffer);
    ad.stego.hint.length = 0;
}

fn clear_portable_secret(ad: &mut AppData) {
    ad.wallet.seeds.pp_input.reset();
    ad.stego.session.portable.clear();
    ad.stego.export_flow.clear_portable_confirmation();
}

fn reject(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    message: &str,
) {
    clear_portable_secret(ad);
    show_rejection(boot_display, delay, message, 1_500, ErrorSound::Beep);
    crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
}
