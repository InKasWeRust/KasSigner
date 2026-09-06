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

// Top-level export menu.

use crate::{
    runtime::interactions::{
        feedback::RedrawFlag,
        menu_selection::{handle_paged_menu_touch, PagedMenuAction},
    },
    runtime::input::AppState,
};
use super::super::{context::ExportMenuContext, TouchInput};


pub(crate) fn handle_pure(
    ad: &mut crate::runtime::data::AppData,
    list_zones: &[crate::hw::touch::TouchZone; 4],
    page_up_zone: &crate::hw::touch::TouchZone,
    page_down_zone: &crate::hw::touch::TouchZone,
    input: TouchInput,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::ExportChoice { return None; }
    let TouchInput { x, y, is_back } = input;
    if is_back { ad.navigation.export_menu.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList)); return Some(true); }
    match handle_paged_menu_touch(&mut ad.navigation.export_menu, list_zones, page_up_zone, page_down_zone, x, y) {
        PagedMenuAction::PageChanged => Some(true),
        PagedMenuAction::Selected(item) => {
            match item {
                0 => ad.navigation.seed_backup_menu.reset(),
                1 => ad.navigation.watch_only_menu.reset(),
                2 => ad.navigation.signing_keys_menu.reset(),
                3 => { ad.stego.session.result_ok = false; }
                _ => return Some(false),
            }
            let _ = crate::runtime::effects::menu_select(ad, item);
            Some(true)
        }
        PagedMenuAction::None => Some(false),
    }
}

pub(crate) fn handle(context: ExportMenuContext<'_, '_>) -> Option<bool> {
    let ExportMenuContext {
        ad, boot_display: _, delay: _, list_zones, page_up_zone, page_down_zone, input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    if ad.navigation.app.state != AppState::ExportChoice {
        return None;
    }

    let mut needs_redraw = RedrawFlag::default();
    if is_back {
        ad.navigation.export_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
        needs_redraw.mark();
        return Some(needs_redraw.value());
    }

    match handle_paged_menu_touch(
        &mut ad.navigation.export_menu,
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
                0 => ad.navigation.seed_backup_menu.reset(),
                1 => ad.navigation.watch_only_menu.reset(),
                2 => ad.navigation.signing_keys_menu.reset(),
                3 => {
                    ad.stego.session.result_ok = false;
                }
                _ => return Some(needs_redraw.value()),
            }
            let _ = crate::runtime::effects::menu_select(ad, item);
        }
        PagedMenuAction::None => {}
    }

    Some(needs_redraw.value())
}

