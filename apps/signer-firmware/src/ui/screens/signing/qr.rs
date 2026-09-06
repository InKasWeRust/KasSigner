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


use super::super::{
    components::qr_renderer::{QrRenderOptions, QrScreenOptions},
    BootDisplay, COLOR_DANGER, DISPLAY_H, KASPA_TEAL, draw_lato_title,
    draw_oswald_header, measure_header, measure_title,
};

impl<'a> BootDisplay<'a> {
    /// Draw QR code screen
    pub fn draw_qr_screen(&mut self, data: &[u8]) {
        self.draw_qr_screen_with_options(data, QrScreenOptions {
            region: QrRenderOptions {
                x: 38,
                y: 4,
                width: 238,
                height: DISPLAY_H as i32 - 8,
                quiet_zone: 4,
            },
            max_payload_bytes: None,
            stop_sound: false,
            error_title: "QR Error",
            too_large_title: "QR Error — too large",
        });
        // Shared QR chrome restores the same explicit top-left Back control used by production.
    }

    /// Watch-only account QR with explicit navigation chrome. The QR is kept
    /// below the top rail so Back and the global post-Home Home shortcut remain
    /// visible and cannot be mistaken for QR modules.
    pub fn draw_kpub_qr_screen(&mut self, data: &[u8]) {
        self.draw_qr_screen_with_options(data, QrScreenOptions {
            region: QrRenderOptions {
                x: 0,
                y: 40,
                width: 280,
                height: DISPLAY_H as i32 - 40,
                quiet_zone: 4,
            },
            max_payload_bytes: None,
            stop_sound: false,
            error_title: "QR Error",
            too_large_title: "QR Error — too large",
        });
        self.draw_back_button();
        let title = "CONNECT KASSEE";
        let width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - width) / 2, 28, KASPA_TEAL);
    }

    /// Left-aligned full-height QR, reserving the right 80 px strip
    /// for the multisig info column (sig status at top, frame counter
    /// at bottom). Used by the signed-KSPT ShowQR flow where we need
    /// to display both pieces of info without clipping the QR pixels.
    ///
    /// Layout:
    ///   Back rail:       x=0..34
    ///   QR zone:         x=38..239, y=2..237
    ///   Info column:     x=240..316 (76 px wide)
    ///     MS badge:      y≈30..90  (2 lines: "MS" header + "P/R")
    ///     FR# badge:     y≈172..236 (2 lines: "FRAMES" header + "F/N")
    ///
    /// The ms/frame overlays (draw_sig_status + draw_frame_counter)
    /// render into this reserved column — they target the same x range
    /// when the layout intent is "info column" rather than "corner badge".
    pub fn draw_qr_screen_left(&mut self, data: &[u8]) {
        if !self.draw_encoded_qr(data, QrRenderOptions {
            x: 38,
            y: 2,
            width: 202,
            height: DISPLAY_H as i32 - 4,
            quiet_zone: 6,
        }) {
            let width = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - width) / 2, 120, COLOR_DANGER);
        }
    }

}
