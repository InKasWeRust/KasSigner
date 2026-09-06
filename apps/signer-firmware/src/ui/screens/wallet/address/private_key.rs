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
    COLOR_TEXT,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Size,
    draw_lato_18,
    draw_oswald_header,
    measure_header,
};

impl<'a> BootDisplay<'a> {
    /// Draw private key import screen with hex keypad
    pub fn draw_import_privkey_screen(&mut self, hex_chars: &[u8], hex_len: u8) {
        self.clear_keep_nav();

        // Header
        let tw = measure_header("IMPORT KEY");
        draw_oswald_header(&mut self.display, "IMPORT KEY", (320 - tw) / 2, 26, COLOR_TEXT);
        Line::new(Point::new(20, 36), Point::new(300, 36))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        self.draw_private_key_input_area(hex_chars, hex_len);

        // Unified keyboard (Hex mode)
        crate::ui::keyboard::draw_keyboard(
            &mut self.display,
            crate::ui::keyboard::KeyboardMode::Hex,
            0,
        );
    }

    /// Partial redraw: only the hex input text + cursor. Keyboard stays static.
    pub fn update_import_privkey_input(&mut self, hex_chars: &[u8], hex_len: u8) {
        // Clear input area (y=40..70)
        Rectangle::new(Point::new(0, 40), Size::new(320, 30))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display)
            .ok();

        self.draw_private_key_input_area(hex_chars, hex_len);
    }

    fn draw_private_key_input_area(&mut self, hex_chars: &[u8], hex_len: u8) {
        let length = (hex_len as usize).min(hex_chars.len());
        let start = length.saturating_sub(28);
        let mut display = heapless::String::<34>::new();
        if start > 0 {
            core::fmt::Write::write_str(&mut display, "..").ok();
        }
        for &byte in &hex_chars[start..length] {
            core::fmt::Write::write_char(&mut display, byte as char).ok();
        }

        let text_x = 10;
        let text_y = 62;
        let drawn_width = if display.is_empty() {
            0
        } else {
            draw_lato_18(&mut self.display, &display, text_x, text_y, COLOR_TEXT)
        };
        let cursor_x = text_x + drawn_width;
        Line::new(
            Point::new(cursor_x, text_y - 15),
            Point::new(cursor_x, text_y + 1),
        )
        .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
        .draw(&mut self.display)
        .ok();
    }
}
