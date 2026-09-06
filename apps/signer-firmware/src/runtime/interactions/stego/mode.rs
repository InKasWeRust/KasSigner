// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::{display, sdcard, AppData, RedrawFlag};
use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    runtime::input::AppState,
    services::{stego::{StegoCarrier, StegoSecurity}, storage_files},
};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<sdcard::SdCardType>,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let changed = match ad.navigation.app.state {
        AppState::StegoModeSelect => handle_carrier_select(ad, boot_display, delay, sd_card_type, x, y, is_back),
        AppState::StegoSecuritySelect => handle_security_select(
            ad, boot_display, delay, i2c, sd_card_type, x, y, is_back,
        ),
        AppState::StegoResult => {
            ad.wallet.seeds.pp_input.reset();
            ad.stego.export_flow.clear_portable_confirmation();
            ad.stego.session.portable.clear();
            crate::runtime::effects::home(ad);
            true
        }
        _ => return None,
    };
    let mut redraw = RedrawFlag::default();
    redraw.set(changed);
    Some(redraw.value())
}


fn handle_carrier_select(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    sd_card_type: &Option<sdcard::SdCardType>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
        return true;
    }
    if !(15..=305).contains(&x) { return false; }
    let carrier = if (60..=126).contains(&y) {
        StegoCarrier::Descriptor
    } else if (136..=202).contains(&y) {
        StegoCarrier::Picture
    } else {
        return false;
    };
    if ad.wallet.seeds.seed_mgr.active_slot().and_then(|slot| slot.mnemonic_word_count()).is_none() {
        show_rejection(boot_display, delay, "No mnemonic loaded", 1_500, ErrorSound::Silent);
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
        return true;
    }
    if sd_card_type.is_none() {
        show_rejection(boot_display, delay, "No SD card", 1_500, ErrorSound::Silent);
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
        return true;
    }
    ad.stego.export_flow.carrier = carrier;
    ad.stego.export_flow.security = StegoSecurity::DeviceBound;
    ad.stego.export_flow.clear_portable_confirmation();
    ad.stego.session.portable.clear();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoSecuritySelect));
    true
}

fn handle_security_select(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<sdcard::SdCardType>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoModeSelect));
        return true;
    }
    if !(15..=305).contains(&x) { return false; }
    let security = if (60..=126).contains(&y) {
        StegoSecurity::DeviceBound
    } else if (136..=202).contains(&y) {
        StegoSecurity::Portable
    } else {
        return false;
    };
    if sd_card_type.is_none() {
        show_rejection(boot_display, delay, "No SD card", 1_500, ErrorSound::Silent);
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
        return true;
    }
    ad.stego.export_flow.security = security;
    ad.stego.export_flow.clear_portable_confirmation();
    ad.stego.session.portable.clear();
    scan_jpegs(ad, boot_display, delay, i2c)
}

fn scan_jpegs(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> bool {
    boot_display.draw_loading_screen("Scanning SD...");
    boot_display.update_progress_bar(50);
    crate::services::timing::pause(delay, 50);
    let result = storage_files::scan_jpeg_files(
        &mut ad.stego.export_flow.jpeg_file_names,
        &mut ad.stego.export_flow.jpeg_display_names,
        &mut ad.stego.export_flow.jpeg_display_lens,
        &mut ad.stego.export_flow.jpeg_file_count,
        delay,
        i2c,
    );
    if !matches!(result, Ok(count) if count > 0) {
        show_rejection(boot_display, delay, "No .JPG files on SD", 2_000, ErrorSound::Beep);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoSecuritySelect));
        return true;
    }
    ad.stego.export_flow.jpeg_selected = 0;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPick));
    true
}


#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_select_security_with_jpegs(
    ad: &mut AppData,
    security: StegoSecurity,
    names: &[[u8; 11]],
) -> bool {
    if names.is_empty() || names.len() > ad.stego.export_flow.jpeg_file_names.len() {
        return false;
    }
    ad.stego.export_flow.security = security;
    ad.stego.export_flow.clear_portable_confirmation();
    ad.stego.session.portable.clear();
    ad.stego.export_flow.jpeg_file_names.fill([0; 11]);
    ad.stego.export_flow.jpeg_display_names.fill([0; 32]);
    ad.stego.export_flow.jpeg_display_lens.fill(0);
    for (index, name) in names.iter().enumerate() {
        ad.stego.export_flow.jpeg_file_names[index] = *name;
        let end = name.iter().position(|byte| *byte == b' ').unwrap_or(name.len());
        ad.stego.export_flow.jpeg_display_names[index][..end].copy_from_slice(&name[..end]);
        ad.stego.export_flow.jpeg_display_lens[index] = end as u8;
    }
    ad.stego.export_flow.jpeg_file_count = names.len() as u8;
    ad.stego.export_flow.jpeg_selected = 0;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPick));
    true
}
