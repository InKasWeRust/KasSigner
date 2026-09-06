// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Board-independent display presentation.
//!
//! Hardware display modules own only transport construction and optional
//! framebuffer mirroring. This module owns colors, typography, icons, boot
//! screens, navigation overlays, and security-oriented presentation helpers.

mod boot;
pub(crate) use boot::draw_security_badge;
pub(crate) mod icon_data;
mod icons;
mod palette;
mod typography;

pub use palette::DISPLAY_H;
pub(crate) use icons::draw_menu_icon;
pub(crate) use palette::{
    COLOR_BG, COLOR_CARD, COLOR_CARD_BORDER, COLOR_DANGER, COLOR_GREEN_BTN, COLOR_HINT,
    COLOR_ORANGE, COLOR_RED_BTN, COLOR_TEXT, COLOR_TEXT_DIM, KASPA_ACCENT, KASPA_TEAL,
};
pub(crate) use typography::*;
