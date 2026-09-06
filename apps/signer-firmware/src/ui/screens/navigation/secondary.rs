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
    BootDisplay,
    COLOR_BG,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    DrawTarget,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rgb565,
    draw_lato_body,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    measure_body,
    measure_header,
    measure_hint,
    measure_title};

impl<'a> BootDisplay<'a> {
    /// Draw QR Export sub-menu — dims "Plain Words QR" when seed is 24 words
    pub fn draw_qr_export_menu(&mut self, menu: &crate::runtime::input::Menu, word_count: u8) {
        self.clear_keep_nav();

        let tw = measure_header("QR EXPORT");
        draw_oswald_header(&mut self.display, "QR EXPORT", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let max_visible = crate::runtime::input::Menu::MAX_VISIBLE;
        let visible_count = max_visible.min(menu.count.saturating_sub(menu.scroll));
        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let card_w: u32 = 232;
        let start_y: i32 = 46;
        let start_x: i32 = 44;

        let mut drawn: u8 = 0;

        for i in 0..visible_count {
            let item_idx = menu.scroll + i;
            if item_idx >= menu.count { break; }

            // Plain-word QR is intentionally unavailable for 24-word seeds.
            if item_idx == 2 && word_count > 12 {
                continue;
            }

            let y = start_y + (drawn as i32) * (card_h + card_gap);
            let label = menu.items[item_idx as usize];

            self.draw_navigation_card(label, start_x, y, card_w, card_h as u32);
            drawn += 1;
        }

    }

    /// Draw about screen
    pub fn draw_about_screen(&mut self) {
        use embedded_graphics::image::{Image, ImageRawLE};

        self.display.clear(COLOR_BG).ok();

        // Logo shifted up 20px for visual balance; Back is overlaid after the full-screen image.
        static LOGO_DATA: &[u8] = include_bytes!("../../../../assets/logo_320x240.raw");
        let raw_img: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
        Image::new(&raw_img, Point::new(0, -20))
            .draw(&mut self.display).ok();

        // Version
        let mut vbuf = [0u8; 12];
        let vlen = crate::services::fw_update::format_version(
            crate::services::fw_update::CURRENT_VERSION, &mut vbuf[1..]);
        vbuf[0] = b'v';
        let vtxt = core::str::from_utf8(&vbuf[..vlen + 1]).unwrap_or("v?");
        let vw = measure_title(vtxt);
        draw_lato_title(&mut self.display, vtxt, (320 - vw) / 2, 122, COLOR_TEXT);

        // Tagline
        let s1 = "Secure Hardware Wallet for Kaspa";
        draw_lato_body(&mut self.display, s1, (320 - measure_body(s1)) / 2, 146, COLOR_TEXT_DIM);

        // Tech line
        let s2 = "100% Rust | Air-Gapped | no_std";
        draw_lato_body(&mut self.display, s2, (320 - measure_body(s2)) / 2, 166, COLOR_TEXT_DIM);

        // Board name
        #[cfg(feature = "waveshare")]
        let s3 = "Waveshare ESP32-S3-Touch-LCD-2";
        #[cfg(feature = "m5stack")]
        let s3 = "M5Stack CoreS3 Lite";
        draw_lato_hint(&mut self.display, s3, (320 - measure_hint(s3)) / 2, 186, COLOR_TEXT_DIM);

        // kaspa.org
        let s4 = "kaspa.org";
        draw_lato_hint(&mut self.display, s4, (320 - measure_hint(s4)) / 2, 206, KASPA_TEAL);

        // The logo is a full-screen image, so draw Back last rather than relying
        // on clear_keep_nav() to preserve it underneath the image.
        self.draw_back_button();
    }

    #[cfg(feature = "developer-ui")]
    /// Draw real development diagnostics; unlike About, this keeps Back visible.
    pub fn draw_diagnostic_info(&mut self) {
        self.clear_keep_nav();
        let title = "DIAGNOSTIC INFO";
        draw_oswald_header(&mut self.display, title, (320 - measure_header(title)) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let trust = match crate::services::verify::boot_security::level() {
            crate::services::verify::boot_security::BootSecurityLevel::HardwareEnforced => "HARDWARE SECURE BOOT",
            crate::services::verify::boot_security::BootSecurityLevel::SoftwareVerified => "SOFTWARE VERIFIED",
            crate::services::verify::boot_security::BootSecurityLevel::None => "NOT VERIFIED",
        };
        draw_lato_body(&mut self.display, "Trust", 26, 70, COLOR_TEXT_DIM);
        draw_lato_body(&mut self.display, trust, 118, 70, COLOR_TEXT);
        draw_lato_body(&mut self.display, "Profile", 26, 94, COLOR_TEXT_DIM);
        draw_lato_body(&mut self.display, if cfg!(feature = "production") { "PRODUCTION" } else { "DEVELOPMENT" }, 118, 94, COLOR_TEXT);
        draw_lato_body(&mut self.display, "Signer", 26, 118, COLOR_TEXT_DIM);
        draw_lato_body(&mut self.display, if cfg!(feature = "production") { "RELEASE KEY" } else { "DEV TEST KEY" }, 118, 118, COLOR_TEXT);
        draw_lato_body(&mut self.display, "Secure Boot eFuse", 26, 142, COLOR_TEXT_DIM);
        draw_lato_body(&mut self.display, if crate::services::verify::boot_security::secure_boot_enabled() { "ON" } else { "OFF" }, 188, 142, COLOR_TEXT);
        #[cfg(feature = "provisioning-ui")]
        {
            draw_lato_body(&mut self.display, "Pop It", 26, 166, COLOR_TEXT_DIM);
            let pop_it = if crate::services::verify::boot_security::secure_boot_enabled() {
                "COMPLETE"
            } else if crate::services::verify::boot_security::dev_pop_it_indicator_demo_active() {
                "DEMO TEAL"
            } else if cfg!(feature = "secure-provisioning-core") {
                "AVAILABLE"
            } else {
                "DEMO AVAILABLE"
            };
            draw_lato_body(&mut self.display, pop_it, 118, 166, COLOR_TEXT);
        }
        let mut version: heapless::String<24> = heapless::String::new();
        let _ = core::fmt::Write::write_fmt(
            &mut version,
            format_args!("Version {}", env!("CARGO_PKG_VERSION")),
        );
        draw_lato_hint(&mut self.display, version.as_str(), 26, 206, COLOR_TEXT_DIM);
    }

    /// Draw the post-Home navigation shortcut as a pure overlay.
    pub fn draw_home_button(&mut self) {
        use embedded_graphics::image::{Image, ImageRawLE};

        static ICON_HOME: &[u8] = include_bytes!("../../../../assets/icon_home_24.raw");
        let raw_icon: ImageRawLE<Rgb565> = ImageRawLE::new(ICON_HOME, 24);
        Image::new(&raw_icon, Point::new(284, 3))
            .draw(&mut self.display)
            .ok();
    }

}
