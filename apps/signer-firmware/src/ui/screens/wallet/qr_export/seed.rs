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
    COLOR_HINT,
    components::qr_renderer::QrRenderOptions,
    DrawTarget,
    Drawable,
    KASPA_TEAL,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    Size,
    Triangle,
    draw_lato_hint,
    draw_lato_title,
    measure_hint,
    measure_title};

impl<'a> BootDisplay<'a> {
    pub fn draw_export_seed_qr_screen(&mut self, data: &[u8], word_count: u8) {
        let mut title: heapless::String<32> = heapless::String::new();
        let grid = if word_count <= 12 { "25x25" } else { "29x29" };
        core::fmt::Write::write_fmt(
            &mut title,
            format_args!("SeedQR {grid} ({word_count}w)"),
        )
        .ok();
        self.draw_seed_qr_payload(data, title.as_str(), true);
    }

    /// Draw CompactSeedQR screen (21x21 for 12w, 25x25 for 24w)
    pub fn draw_export_compact_seedqr_screen(&mut self, data: &[u8], word_count: u8) {
        let size = if word_count == 12 { "21x21" } else { "25x25" };
        let mut title: heapless::String<32> = heapless::String::new();
        core::fmt::Write::write_fmt(
            &mut title,
            format_args!("CompactSeedQR {size} ({word_count}w)"),
        )
        .ok();
        self.draw_seed_qr_payload(data, title.as_str(), false);
    }

    /// Draw Plain Words QR export — BIP39 words as space-separated text QR
    pub fn draw_export_plain_words_qr(&mut self, indices: &[u16; 24], word_count: u8) {
        self.display.clear(COLOR_BG).ok();
        let mut title_buf: heapless::String<32> = heapless::String::new();
        core::fmt::Write::write_fmt(
            &mut title_buf,
            format_args!("Plain Text ({word_count} words)"),
        )
        .ok();
        let tw = measure_hint(title_buf.as_str());
        draw_lato_hint(&mut self.display, &title_buf, (320 - tw) / 2, 14, KASPA_TEAL);

        let hw = measure_hint("Tap to go back");
        draw_lato_hint(&mut self.display, "Tap to go back", (320 - hw) / 2, 238, COLOR_HINT);

        // Build QR content
        let mut words_buf = [0u8; 256];
        let mut pos = 0usize;
        for (index, word_index) in indices
            .iter()
            .take(usize::from(word_count))
            .enumerate()
        {
            let word = offline_signer::derivation::bip39::index_to_word(*word_index);
            let bytes = word.as_bytes();
            if pos + bytes.len() + usize::from(index > 0) > words_buf.len() {
                break;
            }
            if index > 0 {
                words_buf[pos] = b' ';
                pos += 1;
            }
            words_buf[pos..pos + bytes.len()].copy_from_slice(bytes);
            pos += bytes.len();
        }

        if !self.draw_encoded_qr(
            &words_buf[..pos],
            QrRenderOptions { x: 56, y: 20, width: 208, height: 210, quiet_zone: 4 },
        ) {
            let ew = measure_title("QR Error — too large");
            draw_lato_title(
                &mut self.display,
                "QR Error — too large",
                (320 - ew) / 2,
                120,
                COLOR_DANGER,
            );
        }
    }

    /// Draw zoomed SeedQR grid view for manual card filling.
    /// Shows a 7x7 window into the QR, with row/col labels and navigation arrows.
    pub fn draw_seedqr_grid(&mut self, data: &[u8], pan_x: u8, pan_y: u8, numeric: bool) {
        self.clear_keep_nav();

        let qr_result = if numeric {
            crate::qr::encoder::encode_numeric(data)
        } else {
            crate::qr::encoder::encode(data)
        };
        if let Ok(qr) = qr_result {
            let qr_size = qr.size;
            let view_cells: u8 = 7;
            let cell_px: i32 = 24;

            let grid_x0: i32 = 70;
            let grid_y0: i32 = 38;

            // Title with position info
            let mut pos_buf: heapless::String<32> = heapless::String::new();
            core::fmt::Write::write_fmt(&mut pos_buf,
                format_args!("Grid {},{} of {}x{}", pan_x + 1, pan_y + 1, qr_size, qr_size)).ok();
            let tw = measure_hint(pos_buf.as_str());
            draw_lato_hint(&mut self.display, &pos_buf, (320 - tw) / 2, 18, KASPA_TEAL);

            // Column labels at top
            for c in 0..view_cells {
                let col = pan_x + c;
                if col >= qr_size { break; }
                let cx = grid_x0 + c as i32 * cell_px + cell_px / 2;
                let mut lbl: heapless::String<4> = heapless::String::new();
                core::fmt::Write::write_fmt(&mut lbl, format_args!("{}", col + 1)).ok();
                let lw = measure_hint(lbl.as_str());
                draw_lato_hint(&mut self.display, &lbl, cx - lw / 2, grid_y0 - 3, KASPA_TEAL);
            }

            // Row labels on left
            for r in 0..view_cells {
                let row = pan_y + r;
                if row >= qr_size { break; }
                let ry = grid_y0 + r as i32 * cell_px + cell_px / 2 + 4;
                let letter = if row < 26 { (b'A' + row) as char } else { '?' };
                let mut lbl: heapless::String<4> = heapless::String::new();
                core::fmt::Write::write_fmt(&mut lbl, format_args!("{letter}")).ok();
                draw_lato_hint(&mut self.display, &lbl, grid_x0 - 16, ry, KASPA_TEAL);
            }

            // Draw cells
            for r in 0..view_cells {
                let row = pan_y + r;
                if row >= qr_size { continue; }
                for c in 0..view_cells {
                    let col = pan_x + c;
                    if col >= qr_size { continue; }

                    let cx = grid_x0 + c as i32 * cell_px;
                    let cy = grid_y0 + r as i32 * cell_px;

                    let is_black = qr.get(col, row);
                    let fill = if is_black { Rgb565::new(0, 0, 0) } else { Rgb565::new(31, 63, 31) };
                    Rectangle::new(Point::new(cx, cy), Size::new(cell_px as u32, cell_px as u32))
                        .into_styled(PrimitiveStyle::with_fill(fill))
                        .draw(&mut self.display).ok();
                    Rectangle::new(Point::new(cx, cy), Size::new(cell_px as u32, cell_px as u32))
                        .into_styled(PrimitiveStyle::with_stroke(Rgb565::new(8, 20, 8), 1))
                        .draw(&mut self.display).ok();
                }
            }

            self.draw_seedqr_navigation(qr_size, pan_x, pan_y, view_cells);

        } else {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }

    }

    fn draw_seedqr_navigation(&mut self, qr_size: u8, pan_x: u8, pan_y: u8, view_cells: u8) {
        let max_pan = qr_size.saturating_sub(view_cells);
        let teal_dark = Rgb565::new(0, 20, 10);
        let lx = 18i32;
        let ly_top = 80i32;
        let ly_bot = 160i32;

        let left_color = if pan_x > 0 { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(lx - 12, ly_top),
            Point::new(lx + 12, ly_top - 15),
            Point::new(lx + 12, ly_top + 15),
        )
        .into_styled(PrimitiveStyle::with_fill(left_color))
        .draw(&mut self.display)
        .ok();

        let right_color = if pan_x < max_pan { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(lx + 12, ly_bot),
            Point::new(lx - 12, ly_bot - 15),
            Point::new(lx - 12, ly_bot + 15),
        )
        .into_styled(PrimitiveStyle::with_fill(right_color))
        .draw(&mut self.display)
        .ok();

        let rx = 302i32;
        let ry_top = 80i32;
        let ry_bot = 160i32;
        let up_color = if pan_y > 0 { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(rx, ry_top - 12),
            Point::new(rx - 15, ry_top + 12),
            Point::new(rx + 15, ry_top + 12),
        )
        .into_styled(PrimitiveStyle::with_fill(up_color))
        .draw(&mut self.display)
        .ok();

        let down_color = if pan_y < max_pan { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(rx, ry_bot + 12),
            Point::new(rx - 15, ry_bot - 12),
            Point::new(rx + 15, ry_bot - 12),
        )
        .into_styled(PrimitiveStyle::with_fill(down_color))
        .draw(&mut self.display)
        .ok();
    }

}
