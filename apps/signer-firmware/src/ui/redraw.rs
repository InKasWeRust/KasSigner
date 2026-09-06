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

// ui/redraw.rs — Screen redraw dispatch for all AppState variants
//
// All draw_*_screen() calls dispatched by AppState.
// Called from main loop when needs_redraw is true.

use crate::{hw::battery, hw::display, hw::sound, hw::sdcard, wallet::seed_manager};

mod presentation;
mod navigation;
mod device;
mod wallet;
mod storage;
mod export;
mod settings;
mod signing;
mod messages;
mod covenant;
mod multisig;
mod stego;
mod system;

/// Redraw the current screen based on AppState. Called when needs_redraw is set.
pub fn redraw_screen(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<sdcard::SdCardType>,
) {
    let _ = crate::runtime::navigation::reconcile(ad);
    crate::runtime::qr_presentation::prepare_navigation(ad);
    sound::stop_ticking();
    if presentation::redraw(ad, boot_display) { return; }
    let handled = navigation::redraw(ad, boot_display, i2c)
        || device::redraw(ad, boot_display)
        || wallet::redraw(ad, boot_display)
        || storage::redraw(ad, boot_display, sd_card_type)
        || export::redraw(ad, boot_display)
        || settings::redraw(ad, boot_display)
        || signing::redraw(ad, boot_display)
        || messages::redraw(ad, boot_display)
        || covenant::redraw(ad, boot_display)
        || multisig::redraw(ad, boot_display)
        || stego::redraw(ad, boot_display)
        || system::redraw(ad, boot_display);
    super::runtime_evidence::record(ad.navigation.app.state, handled);
    if crate::runtime::navigation::home_shortcut_visible(ad) {
        boot_display.draw_home_button();
    }
    #[cfg(feature = "m5stack")]
    if crate::ui::layout::audio_toggle_visible(ad.navigation.app.state) {
        boot_display.draw_audio_toggle(ad.navigation.app.state, ad.settings.audio_muted());
    }
}
