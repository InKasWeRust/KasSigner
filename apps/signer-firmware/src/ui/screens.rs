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


// ui/screens.rs — Stable screen-rendering module root.
//
// Screen implementations are grouped by responsibility under ui/screens/.
// BootDisplay method names and signatures remain unchanged for callers.

pub(super) use embedded_graphics::{
    prelude::*,
    pixelcolor::Rgb565,
    primitives::{
        Circle, CornerRadii, Line, PrimitiveStyle, Rectangle, RoundedRectangle, Triangle,
    },
    image::Image,
};
pub(super) use embedded_iconoir::icons::size24px;
pub(super) use crate::hw::display::BootDisplay;
pub(super) use crate::ui::display::*;
pub(super) use crate::hw::sound;

mod components;
pub(crate) use components::qr_brightness::{
    QR_BRIGHTNESS_MINUS_ZONE, QR_BRIGHTNESS_PLUS_ZONE,
};
pub(crate) mod device;
mod dialogs;
mod navigation;
mod security;
mod signing;
mod storage;
mod wallet;
pub(crate) use wallet::word_count_choice_at;
pub(crate) use wallet::{entropy_recovery_choice_at, EntropyRecoveryChoice};
