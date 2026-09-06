// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
// menu controller — seed-tools facade.
pub(crate) mod address;
mod dice;
mod menu;

use super::{AppData, display, touch};
use crate::runtime::input::AppState;


/// Route Seed Tools choices that only mutate navigation/application state.
pub(super) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    menu::handle_pure(ad, list_zones, page_up_zone, page_down_zone, x, y, is_back)
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let redraw = match ad.navigation.app.state {
        AppState::SeedToolsMenu => menu::handle(
            ad,
            boot_display,
            delay,
            liveness,
            list_zones,
            page_up_zone,
            page_down_zone,
            x,
            y,
            is_back,
        ),
        AppState::DiceRoll => dice::handle(ad, boot_display, x, y, is_back),
        _ => return None,
    };
    Some(redraw)
}

/// Handle the dice collector when it is owned by first-wallet onboarding.
pub(crate) fn handle_onboarding_dice(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    dice::handle(ad, boot_display, x, y, is_back)
}
