// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
    COLOR_CARD_BORDER,
    COLOR_HINT,
    COLOR_ORANGE,
    COLOR_TEXT,
    CornerRadii,
    Drawable,
    KASPA_ACCENT,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    RoundedRectangle,
    Size,
    draw_lato_body,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    measure_body,
    measure_header,
    measure_hint,
    measure_title,
};

impl<'a> BootDisplay<'a> {
/// Draw steganography JPEG file picker
    pub fn draw_stego_jpeg_pick(&mut self, disp_names: &[[u8; 32]; 8], disp_lens: &[u8; 8], count: u8, selected: u8) {
        self.draw_stego_file_picker("SELECT JPEG", disp_names, disp_lens, count, Some(selected), true);
    }

/// Draw steganography JPEG confirm overwrite screen
    pub fn draw_stego_jpeg_confirm(&mut self, filename: &str, description: &str, has_pp: bool, security: &str) {
        self.clear_keep_nav();
        let tw = measure_header("CONFIRM OVERWRITE");
        draw_oswald_header(&mut self.display, "CONFIRM OVERWRITE", (320 - tw) / 2, 30, COLOR_ORANGE);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_ORANGE, 1))
            .draw(&mut self.display).ok();

        let tw1 = measure_body("This will modify:");
        draw_lato_body(&mut self.display, "This will modify:", (320 - tw1) / 2, 65, COLOR_TEXT);
        let fw = measure_title(filename);
        draw_lato_title(&mut self.display, filename, (320 - fw) / 2, 88, KASPA_TEAL);

        let dw1 = measure_body("Descriptor:");
        draw_lato_body(&mut self.display, "Descriptor:", (320 - dw1) / 2, 115, COLOR_TEXT);
        let show_len = description.len().min(35);
        let desc_show = &description[..show_len];
        let dw2 = measure_body(desc_show);
        draw_lato_body(&mut self.display, desc_show, (320 - dw2) / 2, 135, KASPA_ACCENT);

        let security_line: heapless::String<40> = {
            let mut text = heapless::String::new();
            let detail = if security == "Portable" {
                "Restore: JPEG + Password"
            } else {
                "Original device required"
            };
            core::fmt::Write::write_str(&mut text, detail).ok();
            text
        };
        let sw = measure_body(security_line.as_str());
        draw_lato_body(&mut self.display, security_line.as_str(), (320 - sw) / 2, 154, KASPA_TEAL);

        if has_pp {
            let pw = measure_body("Hint: HIDDEN");
            draw_lato_body(&mut self.display, "Hint: HIDDEN", (320 - pw) / 2, 171, Rgb565::new(0, 50, 0));
        } else {
            let pw = measure_hint("Hint: not included");
            draw_lato_hint(&mut self.display, "Hint: not included", (320 - pw) / 2, 171, COLOR_HINT);
        }

        // CANCEL / CONFIRM buttons
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let cancel_rect = Rectangle::new(Point::new(20, 190), Size::new(130, 32));
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let cw = measure_body("CANCEL");
        draw_lato_body(&mut self.display, "CANCEL", 20 + (130 - cw) / 2, 212, COLOR_TEXT);

        let confirm_rect = Rectangle::new(Point::new(170, 190), Size::new(130, 32));
        RoundedRectangle::new(confirm_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let ow = measure_body("OVERWRITE");
        draw_lato_body(&mut self.display, "OVERWRITE", 170 + (130 - ow) / 2, 212, COLOR_BG);

    }

}
