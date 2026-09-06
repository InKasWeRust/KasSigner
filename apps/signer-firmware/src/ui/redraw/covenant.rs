// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0-only

//! Screen redraw handlers for universal covenant-signing states.

use super::display;
use crate::runtime::input::AppState;

pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        AppState::CovenantSignReview => boot_display.draw_covenant_sign_review(ad),
        AppState::CovenantSignOpaqueWarning => boot_display.draw_covenant_opaque_warning(ad),
        AppState::CovenantSignOpaqueConfirm => boot_display.draw_covenant_opaque_confirm(ad),
        AppState::CovenantKeyResult | AppState::CovenantKeyResultQr => {
            boot_display.draw_covenant_key_result(ad);
        }
        AppState::CovenantSignResult | AppState::CovenantSignResultQr => {
            boot_display.draw_covenant_sign_result(ad);
        }
        AppState::PrivateSwapReview => boot_display.draw_private_swap_review(ad),
        AppState::PrivateSwapKeyResult | AppState::PrivateSwapKeyResultQr => boot_display.draw_private_swap_key_result(ad),
        AppState::PrivateSwapResult | AppState::PrivateSwapResultQr => boot_display.draw_private_swap_result(ad),
        _ => return false,
    }
    true
}
