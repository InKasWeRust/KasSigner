// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use super::{touch, AppData};
use crate::runtime::input::AppState;

mod production;

pub(super) fn handle(
    ad: &mut AppData,
    grid_zones: &[touch::TouchZone; 4],
    list_zones: &[touch::TouchZone; 4],
    page_up: &touch::TouchZone,
    page_down: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if let Some(result) = production::handle(
        ad, list_zones, page_up, page_down, x, y, is_back,
    ) { return Some(result); }
    match ad.navigation.app.state {
        AppState::MainMenu => Some(handle_main_menu(ad, grid_zones, x, y)),
        AppState::SeedToolsMenu => super::seed_tools::handle_pure(
            ad, list_zones, page_up, page_down, x, y, is_back,
        ),
        AppState::ImportExportChoice | AppState::ImportMenu => {
            super::import_export::handle_pure(ad, list_zones, x, y, is_back)
        }
        AppState::SingleSigMenu | AppState::MultisigMenu => {
            super::signing::handle_pure(ad, list_zones, page_up, page_down, x, y, is_back)
        }
        AppState::ShowQR | AppState::Rejected => {
            super::qr::handle(ad, x, y, is_back)
        }
        _ => None,
    }
}


pub(super) fn handle_navigation_touch(
    ad: &mut AppData,
    grid_zones: &[touch::TouchZone; 4],
    list_zones: &[touch::TouchZone; 4],
    page_up: &touch::TouchZone,
    page_down: &touch::TouchZone,
    input: super::TouchInput,
) -> Option<bool> {
    let super::TouchInput { x, y, is_back } = input;
    handle(ad, grid_zones, list_zones, page_up, page_down, x, y, is_back)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_wallet_select(ad: &mut AppData, item: usize) -> bool {
    production::workflow_wallet_select(ad, item)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_wallet_details_edit(ad: &mut AppData) -> bool {
    production::workflow_wallet_details_edit(ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_wallet_details_delete(ad: &mut AppData) -> bool {
    production::workflow_wallet_details_delete(ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_wallet_backup_methods_select(ad: &mut AppData, item: usize) -> bool {
    production::workflow_wallet_backup_methods_select(ad, item)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_advanced_select(ad: &mut AppData, item: usize) -> bool {
    production::workflow_advanced_select(ad, item)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_owner_firmware_select(ad: &mut AppData, item: usize) -> bool {
    production::workflow_owner_firmware_select(ad, item)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_owner_firmware_back(ad: &mut AppData) -> bool {
    production::workflow_owner_firmware_back(ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_backup_recovery_select(ad: &mut AppData, item: usize) -> bool {
    production::workflow_backup_recovery_select(ad, item)
}

pub(super) fn handle_root_touch(ad: &mut AppData, x: u16, y: u16) -> bool {
    log!("   NAV root pure controller BEGIN");
    handle_main_menu(ad, &crate::ui::layout::HOME_GRID_ZONES, x, y)
}

pub(super) fn handle_main_menu(
    ad: &mut AppData,
    grid_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
) -> bool {
    log!("   NAV root tap ({}, {})", x, y);
    debug_assert_eq!(*grid_zones, crate::ui::layout::HOME_GRID_ZONES);
    let Some((index, next)) = crate::runtime::navigation::main_menu_target_at(x, y) else {
        return false;
    };
    log!("   NAV root tile {} -> {:?}", index, next);
    let Some(committed) = crate::runtime::effects::root(ad, index) else {
        log!("   NAV root commit rejected for tile {}", index);
        return false;
    };
    debug_assert_eq!(committed, next);
    true
}

