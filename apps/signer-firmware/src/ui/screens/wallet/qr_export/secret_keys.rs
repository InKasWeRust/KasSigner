use embedded_graphics::prelude::DrawTarget;
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
    BootDisplay,
    COLOR_BG,
    COLOR_DANGER,
    COLOR_TEXT,
    components::qr_renderer::QrRenderOptions,
    Rgb565,
    draw_lato_hint,
    draw_lato_title,
    measure_hint,
    measure_title};

impl<'a> BootDisplay<'a> {
    /// Draw kpub export screen — shows the kpub string as a QR code
    /// for importing into Kaspium/KasWare as a watch-only wallet.
    /// Draw export private key screen — shows hex string + QR
    /// WARNING: This shows sensitive key material on screen!
    pub fn draw_export_privkey_screen(&mut self, hex_str: &[u8; 64]) {
        self.display.clear(COLOR_BG).ok();

        let warn_color = Rgb565::new(31, 24, 0); // amber
        let tw = measure_hint("! PRIVATE KEY !");
        draw_lato_hint(&mut self.display, "! PRIVATE KEY !", (320 - tw) / 2, 14, warn_color);

        // Show hex as QR code.
        self.draw_encoded_qr(
            hex_str,
            QrRenderOptions { x: 81, y: 20, width: 158, height: 160, quiet_zone: 4 },
        );

        // Show first 32 and last 32 hex chars — centered
        if let Ok(s1) = core::str::from_utf8(&hex_str[..32]) {
            let w1 = measure_hint(s1);
            draw_lato_hint(&mut self.display, s1, (320 - w1) / 2, 195, COLOR_TEXT);
        }
        if let Ok(s2) = core::str::from_utf8(&hex_str[32..64]) {
            let w2 = measure_hint(s2);
            draw_lato_hint(&mut self.display, s2, (320 - w2) / 2, 210, COLOR_TEXT);
        }

        let bw = measure_hint("Tap to dismiss — KEEP SECRET");
        draw_lato_hint(&mut self.display, "Tap to dismiss — KEEP SECRET", (320 - bw) / 2, 232, warn_color);
    }

    /// Draw export choice screen — uses same paged list layout as draw_menu_screen
    pub fn draw_export_choice_screen(&mut self, menu: &crate::runtime::input::Menu) {
        self.update_menu_content("EXPORT WALLET", menu);
    }

    /// Draw xprv export screen — shows xprv as QR with warning
    pub fn draw_export_xprv_screen(&mut self, xprv_str: &[u8], xprv_len: usize) {
        self.display.clear(COLOR_BG).ok();

        let warn_color = Rgb565::new(31, 24, 0);
        let tw = measure_hint("! xprv — KEEP SECRET !");
        draw_lato_hint(&mut self.display, "! xprv — KEEP SECRET !", (320 - tw) / 2, 14, warn_color);

        if !self.draw_encoded_qr(
            &xprv_str[..xprv_len],
            QrRenderOptions { x: 61, y: 20, width: 198, height: 200, quiet_zone: 4 },
        ) {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }

        let hw = measure_hint("Tap to dismiss");
        draw_lato_hint(&mut self.display, "Tap to dismiss", (320 - hw) / 2, 232, warn_color);
    }

}
