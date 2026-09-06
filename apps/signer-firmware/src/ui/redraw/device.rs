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
// Screen redraw — device states.
use super::display;
mod onboarding;
pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    if onboarding::redraw(ad, boot_display) { return true; }
    redraw_device_runtime(ad, boot_display)
}

fn redraw_device_runtime(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    use crate::runtime::input::AppState;
    match ad.navigation.app.state {
        AppState::StoragePinEntry => boot_display.draw_storage_pin_entry(&ad.wallet.seeds.pp_input, "CREATE PIN", true),
        AppState::StoragePinConfirm => boot_display.draw_storage_pin_entry(&ad.wallet.seeds.pp_input, "CONFIRM PIN", true),
        AppState::StoragePasswordEntry => boot_display.draw_storage_secret_entry(&ad.wallet.seeds.pp_input, "CREATE PASSWORD", false, true),
        AppState::StoragePasswordConfirm => boot_display.draw_storage_secret_entry(&ad.wallet.seeds.pp_input, "CONFIRM PASSWORD", false, true),
        AppState::StorageUnlockPin => boot_display.draw_storage_pin_entry(
            &ad.wallet.seeds.pp_input, ad.storage.persistence.unlock_feedback.pin_title(), false,
        ),
        AppState::StorageUnlockPassword => boot_display.draw_storage_secret_entry(
            &ad.wallet.seeds.pp_input, ad.storage.persistence.unlock_feedback.password_title(), false, false,
        ),
        AppState::StorageSdFailure => boot_display.draw_fatal_error_screen("Device-bound SD storage unavailable", "Use this signer/card and reboot"),
        AppState::ScanQR => {
            // Scanner entry/rendering is owned by the camera event-loop stage.
            // Keeping hardware-backed camera UI out of generic redraw prevents
            // duplicate lifecycle work during a navigation commit.
        }
        #[cfg(feature = "waveshare")]
        AppState::CameraSettings => redraw_camera_settings(ad, boot_display),
        _ => return false,
    }
    true
}

#[cfg(feature = "waveshare")]
fn redraw_camera_settings(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    use embedded_graphics::prelude::*;
    use embedded_graphics::primitives::{Rectangle, PrimitiveStyle};
    Rectangle::new(Point::new(0, 0), embedded_graphics::geometry::Size::new(320, 240))
        .into_styled(PrimitiveStyle::with_fill(crate::ui::display::COLOR_BG))
        .draw(&mut boot_display.display).ok();
    boot_display.draw_cam_tune_overlay(ad.camera.cam_tune_param, &ad.camera.cam_tune_vals);
}

