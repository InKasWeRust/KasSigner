// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_ORANGE, CornerRadii, Drawable,
    KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, Rectangle, RoundedRectangle,
    Size, draw_lato_body, draw_lato_title, draw_oswald_header, measure_body,
    measure_header, measure_title,
};

impl<'a> BootDisplay<'a> {
    /// Draw sign message preview — show message text + SIGN button
    pub fn draw_sign_msg_preview(&mut self, message: &str) {
        self.draw_signing_preview_chrome("SIGN MESSAGE");

        self.draw_centered_wrapped_title(message, 48, 26, 20, 128);

        // SHA256 hash preview — orange, body font
        let msg_bytes = message.as_bytes();
        let msg_hash = offline_signer::crypto::message::message_digest(msg_bytes);
        let hex_chars = b"0123456789abcdef";
        let mut hash_buf = [0u8; 24]; // "SHA256: xxxxxxxx..."
        hash_buf[0..8].copy_from_slice(b"DOMAIN: ");
        for i in 0..6 {
            hash_buf[8 + i * 2] = hex_chars[(msg_hash[i] >> 4) as usize];
            hash_buf[8 + i * 2 + 1] = hex_chars[(msg_hash[i] & 0x0f) as usize];
        }
        hash_buf[20] = b'.';
        hash_buf[21] = b'.';
        hash_buf[22] = b'.';
        hash_buf[23] = b' ';
        let hash_str = core::str::from_utf8(&hash_buf[..23]).unwrap_or("???");
        let hw = measure_body(hash_str);
        draw_lato_body(
            &mut self.display,
            hash_str,
            (320 - hw) / 2,
            155,
            COLOR_ORANGE,
        );

        self.draw_sign_button();
    }

    fn draw_signing_preview_chrome(&mut self, title: &str) {
        self.clear_keep_nav();
        let width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - width) / 2, 28, KASPA_TEAL);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();
    }

    fn draw_sign_button(&mut self) {
        let width: u32 = 140;
        let height: u32 = 36;
        let x = (320 - width as i32) / 2;
        let y = 185;
        let rectangle = Rectangle::new(Point::new(x, y), Size::new(width, height));
        RoundedRectangle::new(rectangle, CornerRadii::new(Size::new(8, 8)))
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display)
            .ok();
        let label_width = measure_title("SIGN");
        draw_lato_title(
            &mut self.display,
            "SIGN",
            x + (width as i32 - label_width) / 2,
            y + 26,
            COLOR_BG,
        );
    }
}
