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
use super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD_BORDER,
    COLOR_ORANGE,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    CornerRadii,
    Drawable,
    KASPA_ACCENT,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    RoundedRectangle,
    Size,
    draw_lato_body,
    draw_lato_title,
    draw_oswald_header,
    measure_body,
    measure_header,
    measure_title,
};
impl<'a> BootDisplay<'a> {
    // ─── Commit-Reveal Screens ───

    pub fn draw_commit_reveal_preview(&mut self, message: &str, hash: &[u8; 32]) {
        self.clear_keep_nav();
        let tw = measure_header("COMMIT SECRET");
        draw_oswald_header(&mut self.display, "COMMIT SECRET", (320 - tw) / 2, 28, KASPA_TEAL);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        self.draw_centered_wrapped_title(message, 48, 22, 18, 118);

        // BLAKE2B hash (teal)
        let hex_chars = b"0123456789abcdef";
        let mut hash_label = [0u8; 20]; // "BLAKE2B: xxxxxxxx..."
        hash_label[0..9].copy_from_slice(b"BLAKE2B: ");
        for i in 0..4 {
            hash_label[9 + i * 2] = hex_chars[(hash[i] >> 4) as usize];
            hash_label[9 + i * 2 + 1] = hex_chars[(hash[i] & 0x0f) as usize];
        }
        hash_label[17] = b'.';
        hash_label[18] = b'.';
        hash_label[19] = b'.';
        let hash_str = core::str::from_utf8(&hash_label).unwrap_or("???");
        let hw = measure_body(hash_str);
        draw_lato_body(&mut self.display, hash_str, (320 - hw) / 2, 140, COLOR_ORANGE);

        // ENCRYPT & EXPORT button
        let btn_w: u32 = 200;
        let btn_h: u32 = 36;
        let btn_x: i32 = (320 - btn_w as i32) / 2;
        let btn_y: i32 = 165;
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(
            Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, btn_h)), btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let bw = measure_title("ENCRYPT & EXPORT");
        draw_lato_title(&mut self.display, "ENCRYPT & EXPORT", btn_x + (btn_w as i32 - bw) / 2, btn_y + 26, COLOR_BG);
    }

    pub fn draw_commit_reveal_result(&mut self, hash: &[u8; 32], ct_len: usize) {
        self.clear_keep_nav();
        let tw = measure_header("COMMITTED");
        draw_oswald_header(&mut self.display, "COMMITTED", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // BLAKE2B label
        let lw = measure_body("BLAKE2B Hash:");
        draw_lato_body(&mut self.display, "BLAKE2B Hash:", (320 - lw) / 2, 55, COLOR_TEXT_DIM);

        // Hash in orange, body font, 2 rows of 32 hex chars
        let hex_chars = b"0123456789abcdef";
        for row in 0..2u8 {
            let mut hex_line = [0u8; 32];
            for i in 0..16 {
                let byte_idx = row as usize * 16 + i;
                hex_line[i * 2] = hex_chars[(hash[byte_idx] >> 4) as usize];
                hex_line[i * 2 + 1] = hex_chars[(hash[byte_idx] & 0x0f) as usize];
            }
            let line_str = core::str::from_utf8(&hex_line).unwrap_or("?");
            let row_y = 62 + row as i32 * 20;
            let lw2 = measure_body(line_str);
            draw_lato_body(&mut self.display, line_str, (320 - lw2) / 2, row_y + 16, COLOR_ORANGE);
        }

        // Encryption status
        let info_str = if ct_len > 0 { "Secret encrypted (ECIES)" } else { "Encryption failed" };
        let sw = measure_body(info_str);
        draw_lato_body(&mut self.display, info_str, (320 - sw) / 2, 118, COLOR_TEXT_DIM);

        // Separator
        Line::new(Point::new(30, 132), Point::new(290, 132))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();

        // SHOW QR button at bottom
        let btn_w: u32 = 200;
        let btn_h: u32 = 36;
        let btn_x: i32 = (320 - btn_w as i32) / 2;
        let btn_y: i32 = 150;
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(
            Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, btn_h)), btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
            .draw(&mut self.display).ok();
        let qw = measure_title("SHOW QR");
        draw_lato_title(&mut self.display, "SHOW QR", btn_x + (btn_w as i32 - qw) / 2, btn_y + 26, COLOR_BG);
    }
    pub fn draw_decrypt_secret_result(&mut self, plaintext: &str) {
        self.clear_keep_nav();
        let tw = measure_header("DECRYPTED");
        draw_oswald_header(&mut self.display, "DECRYPTED", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Plaintext in title font (bigger), up to 4 lines
        let chars_per_line: usize = 18;
        let pt_bytes = plaintext.as_bytes();
        for line_idx in 0..4u8 {
            let start = line_idx as usize * chars_per_line;
            if start >= pt_bytes.len() { break; }
            let end = (start + chars_per_line).min(pt_bytes.len());
            let line = &plaintext[start..end];
            let row_y = 44 + line_idx as i32 * 24;
            let lw = measure_title(line);
            draw_lato_title(&mut self.display, line, (320 - lw) / 2, row_y + 20, COLOR_TEXT);
        }

        // Export as QR button at bottom
        let btn_w: u32 = 180;
        let btn_h: u32 = 36;
        let btn_x: i32 = (320 - btn_w as i32) / 2;
        let btn_y: i32 = 150;
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(
            Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, btn_h)), btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
            .draw(&mut self.display).ok();
        let qw = measure_title("Export as QR");
        draw_lato_title(&mut self.display, "Export as QR", btn_x + (btn_w as i32 - qw) / 2, btn_y + 26, COLOR_BG);
    }
}
