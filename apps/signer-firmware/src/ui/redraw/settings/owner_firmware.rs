// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Redraw for owner-authority warning and confirmation states.

use super::super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        AppState::OwnerKeyWarning => boot_display.draw_owner_key_warning(),
        AppState::OwnerInstallWarning => boot_display.draw_owner_install_warning(),
        AppState::OwnerKeyConfirm => {
            boot_display.draw_owner_confirm(&ad.wallet.seeds.pp_input, true, ad.pop_it.error);
        }
        AppState::OwnerInstallConfirm => {
            boot_display.draw_owner_confirm(&ad.wallet.seeds.pp_input, false, ad.pop_it.error);
        }
        _ => return false,
    }
    true
}
