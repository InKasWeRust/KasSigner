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

// controllers/menu.rs — Touch handlers for MainMenu and Wallet navigation

use crate::{runtime::interactions::TouchInput, runtime::data::AppData, hw::display, hw::touch};
use esp_hal::{dma::DmaRxBuf, lcd_cam::cam::Camera as DvpCamera};

pub(crate) mod primary;
pub(crate) mod seed_tools;
pub(crate) mod seed_generation;
mod import_export;
mod signing;
mod qr;
pub struct MenuTouchContext<'ctx, 'display, 'hal, 'camera> {
    pub ad: &'ctx mut AppData,
    pub boot_display: &'ctx mut display::BootDisplay<'display>,
    pub delay: &'ctx mut esp_hal::delay::Delay,
    pub liveness: &'ctx mut dyn FnMut(),
    pub i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub sd_card_type: &'ctx Option<crate::services::storage_device::SdCardType>,
    pub dvp_camera_opt: &'ctx mut Option<DvpCamera<'camera>>,
    pub cam_dma_buf_opt: &'ctx mut Option<DmaRxBuf>,
    pub list_zones: &'ctx [touch::TouchZone; 4],
    pub page_up_zone: &'ctx touch::TouchZone,
    pub page_down_zone: &'ctx touch::TouchZone,
    pub input: TouchInput,
}

/// Route navigation-only Main/Seeds/Tools states without hardware ownership.
pub fn handle_navigation_touch(
    ad: &mut AppData, grid_zones: &[touch::TouchZone; 4], list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone, page_down_zone: &touch::TouchZone, input: TouchInput,
) -> Option<bool> {
    primary::handle_navigation_touch(ad, grid_zones, list_zones, page_up_zone, page_down_zone, input)
}

/// Dedicated hardware-free Home dispatcher shared by production and connected E2E.
pub fn handle_root_touch(ad: &mut AppData, x: u16, y: u16) -> bool {
    primary::handle_root_touch(ad, x, y)
}

/// Handle hardware-owning menu families only after navigation-only menus have
/// declined the event.
#[inline(never)]
pub fn handle_menu_touch(context: MenuTouchContext<'_, '_, '_, '_>) -> Option<bool> {
    let MenuTouchContext {
        ad,
        boot_display,
        delay,
        liveness,
        i2c,
        sd_card_type,
        dvp_camera_opt,
        cam_dma_buf_opt,
        list_zones,
        page_up_zone,
        page_down_zone,
        input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    if let Some(result) = seed_tools::handle(ad, boot_display, delay, liveness, list_zones, page_up_zone, page_down_zone, x, y, is_back) { return Some(result); }
    if let Some(result) = seed_generation::handle(ad, boot_display, delay, liveness, i2c, sd_card_type, dvp_camera_opt, cam_dma_buf_opt, x, y, is_back) { return Some(result); }
    if let Some(result) = import_export::handle(ad, boot_display, delay, i2c, list_zones, x, y, is_back) { return Some(result); }
    if let Some(result) = signing::handle(ad, boot_display, delay, liveness, list_zones, x, y, is_back) { return Some(result); }
    if let Some(result) = qr::handle(ad, x, y, is_back) { return Some(result); }
    None
}
/// Narrow signing-menu fallback for display/progress-owning actions.
pub fn handle_signing_feedback_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    list_zones: &[touch::TouchZone; 4],
    input: TouchInput,
) -> Option<bool> {
    if !matches!(ad.navigation.app.state,
        crate::runtime::input::AppState::SingleSigMenu | crate::runtime::input::AppState::MultisigMenu
    ) { return None; }
    let TouchInput { x, y, is_back } = input;
    signing::handle(ad, boot_display, delay, liveness, list_zones, x, y, is_back)
}
#[cfg(feature = "workflow-test-auto")]
pub(crate) fn handle_connected_root_probe(ad: &mut AppData, x: u16, y: u16) -> bool {
    handle_root_touch(ad, x, y)
}
