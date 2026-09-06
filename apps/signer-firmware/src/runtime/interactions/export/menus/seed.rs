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

// Seed backup and QR export menus.

use crate::{
    runtime::interactions::{
        feedback::{show_rejection, ErrorSound, RedrawFlag},
        menu_selection::{handle_paged_menu_touch, selected_visible_item, PagedMenuAction},
    },
    hw::touch,
    runtime::{data::AppData, input::AppState},
};
use super::super::{context::ExportMenuContext, TouchInput};


pub(crate) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    input: TouchInput,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::SeedBackupMenu => handle_seed_backup_pure(ad, list_zones, input),
        AppState::QrExportMenu => handle_qr_export_pure(
            ad, list_zones, page_up_zone, page_down_zone, input,
        ),
        _ => None,
    }
}

fn handle_seed_backup_pure(
    ad: &mut AppData, list_zones: &[touch::TouchZone; 4], input: TouchInput,
) -> Option<bool> {
    if input.is_back {
        ad.navigation.seed_backup_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportChoice));
        return Some(true);
    }
    let Some(item) = selected_visible_item(
        &ad.navigation.seed_backup_menu, list_zones, input.x, input.y,
    ) else { return Some(false); };
    let has_words = ad.wallet.seeds.active_source.mnemonic_word_count().is_some();
    match item {
        0 if has_words => {
            let _ = crate::runtime::effects::menu_select(ad, 0);
            Some(true)
        }
        1 => { ad.navigation.qr_export_menu.reset(); let _ = crate::runtime::effects::menu_select(ad, 1); Some(true) }
        2 if has_words => {
            ad.wallet.seeds.pp_input.reset();
            let _ = crate::runtime::effects::menu_select(ad, 2);
            Some(true)
        }
        0 | 2 => None,
        _ => Some(false),
    }
}

fn handle_qr_export_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    input: TouchInput,
) -> Option<bool> {
    if input.is_back {
        ad.navigation.qr_export_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedBackupMenu));
        return Some(true);
    }
    let Some(word_count) = ad.wallet.seeds.active_source.mnemonic_word_count() else {
        return Some(false);
    };
    match handle_paged_menu_touch(
        &mut ad.navigation.qr_export_menu, list_zones, page_up_zone, page_down_zone, input.x, input.y,
    ) {
        PagedMenuAction::PageChanged => Some(true),
        PagedMenuAction::Selected(0) => { let _ = crate::runtime::effects::menu_select(ad, 0); Some(true) }
        PagedMenuAction::Selected(1) => { let _ = crate::runtime::effects::menu_select(ad, 1); Some(true) }
        PagedMenuAction::Selected(2) if word_count <= 12 => { let _ = crate::runtime::effects::menu_select(ad, 2); Some(true) }
        PagedMenuAction::Selected(_) | PagedMenuAction::None => Some(false),
    }
}

pub(crate) fn handle(context: ExportMenuContext<'_, '_>) -> Option<bool> {
    let ExportMenuContext {
        ad, boot_display, delay, list_zones, page_up_zone, page_down_zone, input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    let mut needs_redraw = RedrawFlag::default();

    match ad.navigation.app.state {
        AppState::SeedBackupMenu => handle_seed_backup_menu(
            ad,
            boot_display,
            delay,
            list_zones,
            x,
            y,
            is_back,
            &mut needs_redraw,
        ),
        AppState::QrExportMenu => handle_qr_export_menu(
            ad,
            list_zones,
            page_up_zone,
            page_down_zone,
            x,
            y,
            is_back,
            &mut needs_redraw,
        ),
        _ => return None,
    }

    Some(needs_redraw.value())
}

fn handle_seed_backup_menu(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
    needs_redraw: &mut RedrawFlag,
) {
    if is_back {
        ad.navigation.seed_backup_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportChoice));
        needs_redraw.mark();
        return;
    }

    let Some(item) = selected_visible_item(&ad.navigation.seed_backup_menu, list_zones, x, y)
    else {
        return;
    };
    needs_redraw.mark();
    match item {
        0 => {
            if !ad.wallet.seeds.active_source.mnemonic_word_count().is_some() {
                show_rejection(
                    boot_display,
                    delay,
                    "No seed phrase (xprv)",
                    1_500,
                    ErrorSound::Silent,
                );
            } else {
                let _ = crate::runtime::effects::menu_select(ad, 0);
            }
        }
        1 => {
            ad.navigation.qr_export_menu.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(QrExportMenu));
        }
        2 => {
            if ad.wallet.seeds.active_source.mnemonic_word_count().is_none() {
                show_rejection(boot_display, delay, "No seed phrase (xprv)", 1_500, ErrorSound::Silent);
            } else {
                ad.wallet.seeds.pp_input.reset();
                let _ = crate::runtime::effects::menu_select(ad, 2);
            }
        }
        _ => {}
    }
}

fn handle_qr_export_menu(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
    needs_redraw: &mut RedrawFlag,
) {
    if is_back {
        ad.navigation.qr_export_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedBackupMenu));
        needs_redraw.mark();
        return;
    }

    let Some(word_count) = ad.wallet.seeds.active_source.mnemonic_word_count() else {
        return;
    };

    match handle_paged_menu_touch(
        &mut ad.navigation.qr_export_menu,
        list_zones,
        page_up_zone,
        page_down_zone,
        x,
        y,
    ) {
        PagedMenuAction::PageChanged => needs_redraw.mark(),
        PagedMenuAction::Selected(item) => {
            needs_redraw.mark();
            match item {
                0 => { let _ = crate::runtime::effects::menu_select(ad, 0); }
                1 => { let _ = crate::runtime::effects::menu_select(ad, 1); }
                2 if word_count <= 12 => {
                    let _ = crate::runtime::effects::menu_select(ad, 2);
                }
                _ => {}
            }
        }
        PagedMenuAction::None => {}
    }
}
