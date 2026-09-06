// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Screen redraw adapters for wallet-owned states.

use super::display;

mod bip85;
mod input;
mod inventory;
mod words;

pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    inventory::redraw(ad, boot_display)
        || words::redraw(ad, boot_display)
        || input::redraw(ad, boot_display)
        || bip85::redraw(ad, boot_display)
}
