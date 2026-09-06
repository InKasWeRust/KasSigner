use embedded_iconoir::prelude::IconoirNewIcon;
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
    COLOR_CARD,
    COLOR_CARD_BORDER,
    COLOR_RED_BTN,
    COLOR_TEXT,
    CornerRadii,
    Drawable,
    Image,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    RoundedRectangle,
    Size,
    Triangle,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    measure_header,
    size24px};

impl<'a> BootDisplay<'a> {
    /// Draw SD file list for restore — shows up to 8 backup files found on SD
    /// Draw SD file list. If `seed_fps` is provided (up to 4 fingerprints from loaded seeds),
    /// files whose name matches a fingerprint will show the slot label (e.g. "Seed #1").
    pub fn draw_sd_file_list_ex(
        &mut self, files: &[[u8; 11]], count: u8, scroll: u8,
        seed_fps: &[[u8; 4]; 4], seed_count: u8,
    ) {
        self.clear_keep_nav();

        let tw = measure_header("SELECT BACKUP");
        draw_oswald_header(&mut self.display, "SELECT BACKUP", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let max_visible: u8 = 4;
        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let start_y: i32 = 46;
        let start_x: i32 = 44;
        let card_w: u32 = 232;
        let card_corner = CornerRadii::new(Size::new(6, 6));
        let teal_dark = Rgb565::new(0b00001, 0b000100, 0b00010);

        let n = count.min(16);

        for vis in 0..max_visible {
            let abs = vis + scroll;
            let row_y = start_y + (vis as i32) * (card_h + card_gap);
            let slot_rect = Rectangle::new(Point::new(start_x, row_y), Size::new(card_w, card_h as u32));

            if abs < n {
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                    .draw(&mut self.display).ok();

                // File icon
                let icon = size24px::docs::Folder::new(COLOR_TEXT);
                Image::new(&icon, Point::new(start_x + 6, row_y + 9)).draw(&mut self.display).ok();

                let mut disp = [0u8; 13];
                let dlen = crate::hw::sdcard::format_83_display(&files[abs as usize], &mut disp);

                // Check if this file matches a loaded seed (for sub-label)
                let file_fp = extract_fingerprint_from_filename(&files[abs as usize]);
                let mut matched_seed: Option<usize> = None;
                if let Some(fp) = file_fp {
                    for s in 0..seed_count as usize {
                        if seed_fps[s][0] == fp[0] && seed_fps[s][1] == fp[1] {
                            matched_seed = Some(s);
                            break;
                        }
                    }
                }

                // Draw filename — centered vertically if no seed label, shifted up if label present
                let name_y = if matched_seed.is_some() { row_y + 18 } else { row_y + 28 };
                if let Ok(name_str) = core::str::from_utf8(&disp[..dlen]) {
                    draw_lato_title(&mut self.display, name_str, start_x + 36, name_y, COLOR_TEXT);
                }

                // Draw seed label if matched
                if let Some(s) = matched_seed {
                    let mut label: heapless::String<12> = heapless::String::new();
                    let _ = core::fmt::Write::write_fmt(&mut label, format_args!("Seed #{}", s + 1));
                    draw_lato_hint(&mut self.display, label.as_str(), start_x + 36, row_y + 36, KASPA_TEAL);
                }

                // Delete button — trash icon on right edge of card
                let del_rect = Rectangle::new(Point::new(start_x + card_w as i32 - 44, row_y + 3), Size::new(38, 36));
                let del_corner = CornerRadii::new(Size::new(4, 4));
                RoundedRectangle::new(del_rect, del_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
                    .draw(&mut self.display).ok();
                use embedded_graphics::image::ImageRawLE;
                let trash_raw: ImageRawLE<Rgb565> = ImageRawLE::new(
                    crate::ui::display::icon_data::ICON_TRASH, crate::ui::display::icon_data::ICON_TRASH_W);
                Image::new(&trash_raw, Point::new(start_x + card_w as i32 - 35, row_y + 9)).draw(&mut self.display).ok();
            } else {
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                    .draw(&mut self.display).ok();
            }
        }

        // Arrows — teal when scrollable, dark when not
        let arrow_cy = start_y + (max_visible as i32 * (card_h + card_gap) - card_gap) / 2;
        let left_color = if scroll > 0 { KASPA_TEAL } else { teal_dark };
        let right_color = if (scroll + max_visible) < n { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(5, arrow_cy), Point::new(30, arrow_cy - 17), Point::new(30, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(left_color))
            .draw(&mut self.display).ok();
        Triangle::new(
            Point::new(315, arrow_cy), Point::new(290, arrow_cy - 17), Point::new(290, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(right_color))
            .draw(&mut self.display).ok();

    }
}

/// Extract the 2-byte fingerprint prefix from an SD backup filename.
/// Filenames are "SDxxxx" or "XPxxxx" where xxxx = 4 hex chars.
/// Returns Some([hi, lo]) or None if format doesn't match.
fn extract_fingerprint_from_filename(name: &[u8; 11]) -> Option<[u8; 2]> {
    // Must start with "SD" or "XP"
    if !((name[0] == b'S' && name[1] == b'D') || (name[0] == b'X' && name[1] == b'P')) {
        return None;
    }
    let h0 = shared_signer::bytes::decode_hex_nibble(name[2])?;
    let l0 = shared_signer::bytes::decode_hex_nibble(name[3])?;
    let h1 = shared_signer::bytes::decode_hex_nibble(name[4])?;
    let l1 = shared_signer::bytes::decode_hex_nibble(name[5])?;
    Some([(h0 << 4) | l0, (h1 << 4) | l1])
}
