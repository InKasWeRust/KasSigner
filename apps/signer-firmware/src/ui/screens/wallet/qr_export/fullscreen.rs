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


use super::super::super::{
    components::qr_renderer::{QrRenderOptions, QrScreenOptions},
    BootDisplay, DISPLAY_H,
};

impl<'a> BootDisplay<'a> {
    /// Draw SeedQR export screen (QR with title)
    /// Draw a full-screen QR code with title. Reusable for any data.
    pub fn draw_qr_fullscreen(&mut self, data: &[u8]) {
        self.draw_qr_screen_with_options(data, QrScreenOptions {
            region: QrRenderOptions {
                x: 38,
                y: 4,
                width: 238,
                height: DISPLAY_H as i32 - 8,
                quiet_zone: 4,
            },
            max_payload_bytes: Some(134),
            stop_sound: true,
            error_title: "QR Error",
            too_large_title: "QR Error — too large",
        });
    }
}
