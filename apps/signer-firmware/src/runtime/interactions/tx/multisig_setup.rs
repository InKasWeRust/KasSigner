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
// tx controller — multisig setup workflow facade.
mod configuration;
mod key_source;
pub(crate) mod seed_picker;

use super::{AppData, display};
use crate::runtime::input::AppState;

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let redraw = match ad.navigation.app.state {
        AppState::MultisigChooseMN => configuration::handle(ad, x, y, is_back),
        AppState::MultisigAddKey { key_idx } => {
            key_source::handle(ad, boot_display, delay, key_idx, x, y, is_back)
        }
        AppState::MultisigPickSeed { key_idx } => {
            seed_picker::handle(ad, boot_display, delay, liveness, key_idx, x, y, is_back)
        }
        _ => return None,
    };
    Some(redraw)
}
