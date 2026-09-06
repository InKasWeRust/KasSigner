// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// Watch-only account-key QR export.

use crate::runtime::data::AppData;


pub(super) fn handle_pure(ad: &mut AppData, x: u16, is_back: bool) -> Option<bool> {
    use crate::runtime::input::AppState;
    match ad.navigation.app.state {
        AppState::ExportKpub => Some(handle_export_screen(ad)),
        AppState::KpubScannedPopup => {
            if is_back { crate::runtime::effects::home(ad); }
            else if x < 160 { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub)); }
            else { ad.wallet.seeds.pp_input.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKpubFilename)); }
            Some(true)
        }
        AppState::ExportKpubPopup if is_back => { crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::KpubExport); Some(true) }
        AppState::ExportKpubPopup if (165..=290).contains(&x) => { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub)); Some(true) }
        AppState::ExportKpubPopup if !(30..=155).contains(&x) => Some(false),
        _ => None,
    }
}


fn handle_export_screen(ad: &mut AppData) -> bool {
    if ad.export.kpub_len == 0 {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::KpubExport);
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpubPopup));
    }
    true
}

pub(super) fn handle(
    ad: &mut AppData,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16,
    is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = super::RedrawFlag::default();

    match ad.navigation.app.state {
        crate::runtime::input::AppState::ExportKpub => {
            if ad.export.kpub_len == 0 {
                crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::KpubExport);
            } else {
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpubPopup));
            }
            needs_redraw.mark();
        }
        crate::runtime::input::AppState::KpubScannedPopup => {
            if is_back {
                crate::runtime::effects::home(ad);
            } else if x < 160 {
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
            } else {
                ad.wallet.seeds.pp_input.reset();
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKpubFilename));
            }
            needs_redraw.mark();
        }
        crate::runtime::input::AppState::ExportKpubPopup => {
            if is_back {
                crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::KpubExport);
                needs_redraw.mark();
            } else if (30..=155).contains(&x) {
                let next = crate::runtime::interactions::sd::scan_auto_increment(i2c, delay, b"KP", b"TXT");
                let name = crate::runtime::interactions::sd::format_auto_name(b"KP", next, b"TXT");
                super::derivation::prepare_filename(ad, name);
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKpubFilename));
                needs_redraw.mark();
            } else if (165..=290).contains(&x) {
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
                needs_redraw.mark();
            }
        }
        _ => return None,
    }

    Some(needs_redraw.value())
}
