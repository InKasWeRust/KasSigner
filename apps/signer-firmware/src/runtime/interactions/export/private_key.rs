// Address private-key export controller facade.

mod derivation;
mod index_input;

use crate::{hw::display, runtime::{data::AppData, input::AppState}};


pub(super) fn handle_pure(ad: &mut AppData) -> Option<bool> {
    if ad.navigation.app.state != AppState::ExportPrivKey { return None; }
    shared_signer::bytes::zeroize_bytes(&mut ad.export.export_key_hex);
    crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::KeyExport);
    Some(true)
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::ExportPrivKeyIndex => Some(index_input::handle(
            ad,
            boot_display,
            delay,
            liveness,
            x,
            y,
            is_back,
        )),
        AppState::ExportPrivKey => {
            shared_signer::bytes::zeroize_bytes(&mut ad.export.export_key_hex);
            crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::KeyExport);
            Some(true)
        }
        _ => None,
    }
}
