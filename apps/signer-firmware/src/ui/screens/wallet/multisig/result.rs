// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

use super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
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
    RoundedRectangle,
    Size,
    draw_lato_body,
    draw_lato_title,
    draw_oswald_header,
    measure_body,
    measure_header,
    measure_title,
};

fn format_small(prefix: &str, value: u32) -> heapless::String<12> {
    let mut text = heapless::String::new();
    core::fmt::Write::write_fmt(&mut text, format_args!("{prefix}{value}")).ok();
    text
}

fn draw_nav_button<D>(display: &mut D, x: i32, width: u32, text: &str)
where
    D: embedded_graphics::draw_target::DrawTarget<Color = embedded_graphics::pixelcolor::Rgb565>,
{
    let corner = CornerRadii::new(Size::new(6, 6));
    let rect = Rectangle::new(Point::new(x, 210), Size::new(width, 28));
    RoundedRectangle::new(rect, corner).into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(display).ok();
    RoundedRectangle::new(rect, corner).into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(display).ok();
    let tw = measure_title(text);
    draw_lato_title(display, text, x + (width as i32 - tw) / 2, 230, KASPA_TEAL);
}

impl<'a> BootDisplay<'a> {
/// Draw multisig result screen — shows M-of-N label + P2SH address. Tap for QR.
    pub fn draw_multisig_result(&mut self, label: &str, address: &str, addr_index: u32, sig_chain: Option<(u8, u8)>) {
        self.clear_keep_nav();

        let tw = measure_header("MULTISIG WALLET");
        draw_oswald_header(&mut self.display, "MULTISIG WALLET", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // "2-of-3 multisig · #N" combined label — shows M-of-N context AND
        // the current address index in a single line.
        let mut info: heapless::String<32> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut info,
            format_args!("{label} multisig · #{addr_index}")).ok();
        let iw = measure_body(info.as_str());
        draw_lato_body(&mut self.display, &info, (320 - iw) / 2, 52, KASPA_ACCENT);

        // Address text — title font, centered, 25 chars/line.
        // Shrunk vertical band to make room for the bottom nav row.
        let bytes = address.as_bytes();
        let total_len = bytes.len();
        let chars_per_line: usize = 25;
        let line_h: i32 = 26;
        let num_lines = ((total_len + chars_per_line - 1) / chars_per_line) as i32;
        let text_block_h = num_lines * line_h;
        let avail_top: i32 = 60;
        let avail_bottom: i32 = 195; // was 225; shrunk to reserve y=210..238 for nav
        let start_y = avail_top + (avail_bottom - avail_top - text_block_h) / 2;
        let mut y_pos = start_y;
        let mut offset: usize = 0;
        while offset < total_len && y_pos < avail_bottom {
            let end = core::cmp::min(offset + chars_per_line, total_len);
            if let Ok(line) = core::str::from_utf8(&bytes[offset..end]) {
                let lw = measure_title(line);
                draw_lato_title(&mut self.display, line, (320 - lw) / 2, y_pos, COLOR_TEXT);
            }
            y_pos += line_h;
            offset = end;
        }

        // Bottom nav: [<] [#N] [>] — mirrors singlesig draw_address_screen.
        // Hit zones for touch handler: y=210..238
        //   [<]  x=10..60
        //   [#N] x=110..210  (opens numeric index picker)
        //   [>]  x=260..310
        let btn_corner = CornerRadii::new(Size::new(6, 6));

        let btn_l = Rectangle::new(Point::new(10, 210), Size::new(50, 28));
        RoundedRectangle::new(btn_l, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_l, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let lw = measure_title("<");
        draw_lato_title(&mut self.display, "<", 10 + (50 - lw) / 2, 230, KASPA_TEAL);

        if let Some((sig, chain)) = sig_chain {
            draw_nav_button(&mut self.display, 66, 40, &format_small("S", u32::from(sig)));
            draw_lato_title(&mut self.display, "/", 108, 230, KASPA_ACCENT);
            draw_nav_button(&mut self.display, 118, 40, &format_small("C", u32::from(chain)));
            draw_lato_title(&mut self.display, "/", 160, 230, KASPA_ACCENT);
            draw_nav_button(&mut self.display, 170, 80, &format_small("#", addr_index));
        } else {
            draw_nav_button(&mut self.display, 110, 100, &format_small("#", addr_index));
        }

        let btn_r = Rectangle::new(Point::new(260, 210), Size::new(50, 28));
        RoundedRectangle::new(btn_r, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_r, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let rw = measure_title(">");
        draw_lato_title(&mut self.display, ">", 260 + (50 - rw) / 2, 230, KASPA_TEAL);

    }

/// Draw multisig wallet descriptor text screen.
    /// Shows the descriptor in format: multi(M, pubkey1_hex, ..., pubkeyN_hex)
    /// This allows companion wallets to reconstruct the same multisig address.
    pub fn draw_multisig_descriptor(&mut self, n: u8, pubkeys: &[[u8; 32]], label: &str) {
        self.clear_keep_nav();

        let tw = measure_header("DESCRIPTOR");
        draw_oswald_header(&mut self.display, "DESCRIPTOR", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // "2-of-3 multisig" label
        let mut info: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut info, format_args!("{label} multisig")).ok();
        let iw = measure_body(info.as_str());
        draw_lato_body(&mut self.display, &info, (320 - iw) / 2, 55, KASPA_ACCENT);

        // Show each pubkey truncated — using title font (bold, readable)
        let hex_chars = b"0123456789abcdef";
        let mut y_pos: i32 = 79;
        for i in 0..n.min(5) as usize {
            let pk = &pubkeys[i];
            let mut line: heapless::String<28> = heapless::String::new();
            core::fmt::Write::write_fmt(&mut line, format_args!("{}: ", i + 1)).ok();
            // First 3 bytes hex
            for j in 0..3 {
                line.push(hex_chars[(pk[j] >> 4) as usize] as char).ok();
                line.push(hex_chars[(pk[j] & 0x0f) as usize] as char).ok();
            }
            line.push_str("..").ok();
            // Last 3 bytes hex
            for j in 29..32 {
                line.push(hex_chars[(pk[j] >> 4) as usize] as char).ok();
                line.push(hex_chars[(pk[j] & 0x0f) as usize] as char).ok();
            }
            let color = if i == 0 { KASPA_ACCENT } else { COLOR_TEXT };
            draw_lato_title(&mut self.display, &line, 30, y_pos, color);
            y_pos += 22;
        }

        // === QR button (left) — y=195..225, x=10..150 ===
        let btn_corner = CornerRadii::new(Size::new(8, 8));
        let qr_rect = Rectangle::new(Point::new(10, 195), Size::new(140, 30));
        RoundedRectangle::new(qr_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let qw = measure_title("SHOW QR");
        draw_lato_title(&mut self.display, "SHOW QR", 10 + (140 - qw) / 2, 217, COLOR_BG);

        // === SD CARD button (right) — y=195..225, x=160..310 ===
        let sd_rect = Rectangle::new(Point::new(170, 195), Size::new(140, 30));
        RoundedRectangle::new(sd_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let sw = measure_title("SD CARD");
        draw_lato_title(&mut self.display, "SD CARD", 170 + (140 - sw) / 2, 217, COLOR_BG);

    }

}
