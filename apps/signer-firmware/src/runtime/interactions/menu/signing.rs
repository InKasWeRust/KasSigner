// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use crate::hw::{display, touch};
use crate::runtime::data::AppData;
use crate::runtime::input::AppState;

mod common;
pub(super) mod multisig;
pub(super) mod single_sig;


/// Route signing-menu choices that only mutate navigation/application state.
pub(super) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up: &touch::TouchZone,
    page_down: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    single_sig::handle_pure(ad, list_zones, page_up, page_down, x, y, is_back)
        .or_else(|| multisig::handle_pure(ad, list_zones, x, y, is_back))
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
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::SingleSigMenu => Some(single_sig::handle(
            ad,
            boot_display,
            delay,
            liveness,
            list_zones,
            x,
            y,
            is_back,
        )),
        AppState::MultisigMenu => Some(multisig::handle(
            ad, boot_display, delay, liveness, list_zones, x, y, is_back,
        )),
        _ => None,
    }
}
