// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
    COLOR_CARD_BORDER,
    COLOR_HINT,
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
    draw_lato_hint,
    draw_oswald_header,
    measure_body,
    measure_header,
    measure_hint,
};

impl<'a> BootDisplay<'a> {
/// Draw .TXT file picker with LFN display names — standard template layout
    pub fn draw_stego_txt_pick(&mut self, disp_names: &[[u8; 32]; 8], disp_lens: &[u8; 8], count: u8) {
        self.draw_stego_file_picker("SELECT TXT", disp_names, disp_lens, count, None, false);
    }

/// Draw descriptor preview and make its non-secret role explicit
    pub fn draw_stego_desc_preview(&mut self, desc: &str) {
        self.clear_keep_nav();
        let tw = measure_header("DESCRIPTOR PREVIEW");
        draw_oswald_header(&mut self.display, "DESCRIPTOR PREVIEW", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Show descriptor text (wrap at ~32 chars per line, max 3 lines, centered)
        let len = desc.len();
        let line1_end = len.min(32);
        let l1w = measure_body(&desc[..line1_end]);
        draw_lato_body(&mut self.display, &desc[..line1_end], (320 - l1w) / 2, 55, KASPA_ACCENT);

        if len > 32 {
            let line2_end = len.min(64);
            let l2w = measure_body(&desc[32..line2_end]);
            draw_lato_body(&mut self.display, &desc[32..line2_end], (320 - l2w) / 2, 73, KASPA_ACCENT);
        }
        if len > 64 {
            let line3_end = len.min(96);
            // Truncate with ".." if there's more
            if len > 96 {
                let mut trunc = [0u8; 34];
                let copy = 30.min(line3_end - 64);
                trunc[..copy].copy_from_slice(&desc.as_bytes()[64..64 + copy]);
                trunc[copy] = b'.';
                trunc[copy + 1] = b'.';
                if let Ok(s) = core::str::from_utf8(&trunc[..copy + 2]) {
                    let l3w = measure_body(s);
                    draw_lato_body(&mut self.display, s, (320 - l3w) / 2, 91, KASPA_ACCENT);
                }
            } else {
                let l3w = measure_body(&desc[64..line3_end]);
                draw_lato_body(&mut self.display, &desc[64..line3_end], (320 - l3w) / 2, 91, KASPA_ACCENT);
            }
        }

        // The descriptor is deliberately public carrier text, not a password.
        let vw = measure_hint("VISIBLE CARRIER TEXT - NOT A PASSWORD");
        draw_lato_hint(&mut self.display, "VISIBLE CARRIER TEXT - NOT A PASSWORD", (320 - vw) / 2, 118, COLOR_HINT);

        // Character count
        let mut len_buf: heapless::String<16> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut len_buf, format_args!("{len} characters")).ok();
        let lw = measure_hint(len_buf.as_str());
        draw_lato_hint(&mut self.display, len_buf.as_str(), (320 - lw) / 2, 136, COLOR_HINT);

        // Hint text
        let hw = measure_hint("Descriptor mode also writes it to EXIF.");
        draw_lato_hint(&mut self.display, "Descriptor mode also writes it to EXIF.", (320 - hw) / 2, 150, COLOR_TEXT_DIM);

        // EDIT / USE buttons
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let edit_rect = Rectangle::new(Point::new(20, 185), Size::new(130, 40));
        RoundedRectangle::new(edit_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(edit_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let ew = measure_body("EDIT");
        draw_lato_body(&mut self.display, "EDIT", 20 + (130 - ew) / 2, 211, COLOR_TEXT);

        let use_rect = Rectangle::new(Point::new(170, 185), Size::new(130, 40));
        RoundedRectangle::new(use_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let uw = measure_body("USE");
        draw_lato_body(&mut self.display, "USE", 170 + (130 - uw) / 2, 211, COLOR_BG);

    }

}
