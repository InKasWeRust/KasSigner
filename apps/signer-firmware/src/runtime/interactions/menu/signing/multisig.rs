use crate::hw::{display, touch};
use crate::runtime::data::AppData;
use crate::runtime::input::AppState;

use super::common::selected_item;

pub(super) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::MultisigMenu { return None; }
    if is_back { return Some(route_back(ad)); }
    match selected_item(&ad.navigation.multisig_menu, list_zones, x, y) {
        Some(0) => Some(start_multisig_creation(ad)),
        Some(1) => None,
        Some(_) | None => Some(false),
    }
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back { return route_back(ad); }
    match selected_item(&ad.navigation.multisig_menu, list_zones, x, y) {
        Some(0) => start_multisig_creation(ad),
        Some(1) => export_multisig_kpub(ad, boot_display, delay, liveness),
        _ => false,
    }
}

fn route_back(ad: &mut AppData) -> bool {
    ad.navigation.multisig_menu.reset();
    crate::runtime::effects::back(ad);
    true
}

fn start_multisig_creation(ad: &mut AppData) -> bool {
    ad.signing.multisig.threshold = 2;
    ad.signing.multisig.participant_count = 3;
    ad.signing.multisig.creating = offline_signer::transaction::model::MultisigConfig::new();
    let _ = crate::runtime::effects::menu_select(ad, 0);
    true
}

fn export_multisig_kpub(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) -> bool {
    let _ = crate::runtime::interactions::export::prepare_multisig_kpub_qr(ad, boot_display, delay, liveness);
    true
}
