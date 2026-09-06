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

// controllers/seed.rs — Touch handlers for seed management states
//

use crate::runtime::interactions::feedback::RedrawFlag;
use crate::runtime::interactions::TouchInput;
use crate::{runtime::data::AppData, hw::display, services::audio as sound};

mod bip85;
mod import;
mod passphrase;
mod passphrase_choice;
mod seed_list;
mod wallet_name;
mod delete_seed;

pub(crate) use passphrase::{
    commit_staged_add_wallet,
    commit_staged_onboarding_import,
    commit_staged_session_wallet,
};
#[cfg(feature = "workflow-test-auto")]
pub(crate) use passphrase::workflow_commit_staged_onboarding_import;

pub fn handle_inventory_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    input: TouchInput,
) -> Option<bool> {
    if !matches!(ad.navigation.app.state,
        crate::runtime::input::AppState::SeedList
    ) { return None; }
    let TouchInput { x, y, is_back } = input;
    seed_list::handle(ad, boot_display, delay, x, y, is_back, liveness)
}

/// Route navigation-only seed screens before the capability-rich generic
/// Seed controller. Keeping Add Wallet here gives its two choice buttons the
/// same deterministic pre-dispatch path as the other hardware-free menus.
pub fn handle_navigation_touch(ad: &mut AppData, input: TouchInput) -> Option<bool> {
    let TouchInput { x, y, is_back } = input;
    seed_list::handle_add_wallet_choice(ad, x, y, is_back)
}

/// Handle touch events for seed management screens (BIP85, import, passphrase).
#[inline(never)]
pub fn handle_seed_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    input: TouchInput,
) -> Option<bool> {
    let TouchInput { x, y, is_back } = input;
    if let Some(result) = bip85::handle(ad, boot_display, delay, liveness, x, y, is_back) { return Some(result); }
    if let Some(result) = import::handle(ad, boot_display, delay, x, y, is_back) { return Some(result); }
    if let Some(result) = wallet_name::handle(ad, boot_display, delay, x, y, is_back) { return Some(result); }
    if let Some(result) = passphrase_choice::handle(ad, boot_display, delay, x, y, is_back) { return Some(result); }
    if let Some(result) = passphrase::handle(ad, boot_display, delay, x, y, is_back) { return Some(result); }
    if let Some(result) = delete_seed::handle(ad, x, y, is_back) { return Some(result); }
    None
}
