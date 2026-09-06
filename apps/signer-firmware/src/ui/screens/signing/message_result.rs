// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD_BORDER, COLOR_TEXT_DIM, CornerRadii, Drawable,
    KASPA_ACCENT, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle,
    RoundedRectangle, Size, draw_lato_hint, draw_lato_title, draw_oswald_header,
    measure_header, measure_hint, measure_title,
};

impl<'a> BootDisplay<'a> {
    /// Draw sign message result — signature hex + save option
    pub fn draw_sign_msg_result(&mut self, sig: &[u8; 64], msg_hash: &[u8; 32]) {
        self.clear_keep_nav();
        let tw = measure_header("SIGNATURE");
        draw_oswald_header(&mut self.display, "SIGNATURE", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // R label + 2 rows of 32 hex chars
        let hex_chars = b"0123456789abcdef";
        let rw = measure_hint("R (nonce):");
        draw_lato_hint(&mut self.display, "R (nonce):", (320 - rw) / 2, 48, COLOR_TEXT_DIM);

        for row in 0..2u8 {
            let mut hex_line = [0u8; 32];
            for i in 0..16 {
                let byte_idx = row as usize * 16 + i;
                hex_line[i * 2] = hex_chars[(sig[byte_idx] >> 4) as usize];
                hex_line[i * 2 + 1] = hex_chars[(sig[byte_idx] & 0x0f) as usize];
            }
            let line_str = core::str::from_utf8(&hex_line).unwrap_or("?");
            let row_y = 52 + row as i32 * 16;
            let lw = measure_hint(line_str);
            draw_lato_hint(&mut self.display, line_str, (320 - lw) / 2, row_y + 14, KASPA_ACCENT);
        }

        // S label + 2 rows
        let sw2 = measure_hint("S (scalar):");
        draw_lato_hint(&mut self.display, "S (scalar):", (320 - sw2) / 2, 98, COLOR_TEXT_DIM);

        for row in 0..2u8 {
            let mut hex_line = [0u8; 32];
            for i in 0..16 {
                let byte_idx = 32 + row as usize * 16 + i;
                hex_line[i * 2] = hex_chars[(sig[byte_idx] >> 4) as usize];
                hex_line[i * 2 + 1] = hex_chars[(sig[byte_idx] & 0x0f) as usize];
            }
            let line_str = core::str::from_utf8(&hex_line).unwrap_or("?");
            let row_y = 102 + row as i32 * 16;
            let lw = measure_hint(line_str);
            draw_lato_hint(&mut self.display, line_str, (320 - lw) / 2, row_y + 14, KASPA_ACCENT);
        }

        // Separator
        Line::new(Point::new(30, 145), Point::new(290, 145))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();

        // SAVE TO SD button (left half)
        let btn_w: u32 = 130;
        let btn_h: u32 = 36;
        let btn_x: i32 = 20;
        let btn_y: i32 = 155;
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let save_rect = Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, btn_h));
        RoundedRectangle::new(save_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let sw = measure_title("SAVE SD");
        draw_lato_title(
            &mut self.display,
            "SAVE SD",
            btn_x + (btn_w as i32 - sw) / 2,
            btn_y + 26,
            COLOR_BG,
        );

        // SHOW QR button (right half) — oracle attestation QR
        let qr_btn_x: i32 = 170;
        let qr_rect = Rectangle::new(Point::new(qr_btn_x, btn_y), Size::new(btn_w, btn_h));
        RoundedRectangle::new(qr_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
            .draw(&mut self.display).ok();
        let qw = measure_title("SHOW QR");
        draw_lato_title(
            &mut self.display,
            "SHOW QR",
            qr_btn_x + (btn_w as i32 - qw) / 2,
            btn_y + 26,
            COLOR_BG,
        );

        // Show msg_hash (1 row, truncated)
        let hw = measure_hint("MSG HASH:");
        draw_lato_hint(&mut self.display, "MSG HASH:", (320 - hw) / 2, 200, COLOR_TEXT_DIM);
        let mut hash_hex = [0u8; 64];
        for i in 0..32 {
            hash_hex[i * 2] = hex_chars[(msg_hash[i] >> 4) as usize];
            hash_hex[i * 2 + 1] = hex_chars[(msg_hash[i] & 0x0f) as usize];
        }
        // Show first 32 chars on row 1, next 32 on row 2
        let h1 = core::str::from_utf8(&hash_hex[..32]).unwrap_or("?");
        let h2 = core::str::from_utf8(&hash_hex[32..]).unwrap_or("?");
        let hw1 = measure_hint(h1);
        draw_lato_hint(&mut self.display, h1, (320 - hw1) / 2, 218, KASPA_ACCENT);
        let hw2 = measure_hint(h2);
        draw_lato_hint(&mut self.display, h2, (320 - hw2) / 2, 234, KASPA_ACCENT);
    }
}
