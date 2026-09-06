// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Signing-key export menu.

use crate::{
    runtime::interactions::menu_selection::selected_visible_item,
    hw::touch,
    runtime::{data::AppData, input::AppState},
};

pub(crate) fn handle(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::SigningKeysMenu {
        return None;
    }
    if is_back {
        ad.navigation.signing_keys_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportChoice));
        return Some(true);
    }

    let Some(item) = selected_visible_item(&ad.navigation.signing_keys_menu, list_zones, x, y)
    else {
        return Some(false);
    };
    match item {
        0 => ad.navigation.xprv_export_menu.reset(),
        1 => ad.wallet.addresses.input_len = 0,
        _ => return Some(false),
    }
    Some(crate::runtime::effects::menu_select(ad, item))
}
