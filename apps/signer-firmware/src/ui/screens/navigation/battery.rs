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
    COLOR_DANGER,
    COLOR_ORANGE,
    COLOR_TEXT,
    Drawable,
    KASPA_TEAL,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Size,
    draw_lato_hint,
    measure_hint,
};

impl<'a> BootDisplay<'a> {
    /// Call after drawing the title bar.
    pub fn draw_battery_icon(&mut self, percentage: u8, charging: bool) {
        // Battery outline: 24x12, vertically centered with header (header center ~y=21)
        let bx: i32 = 238;
        let by: i32 = 15;
        let bw: u32 = 24;
        let bh: u32 = 12;

        // Outline — white
        Rectangle::new(Point::new(bx, by), Size::new(bw, bh))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT, 1))
            .draw(&mut self.display).ok();
        // Tip
        Rectangle::new(Point::new(bx + bw as i32, by + 3), Size::new(2, 6))
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

        // Fill level
        let inner_w = bw - 2;
        let fill_w = (percentage as u32 * inner_w / 100).max(1);
        let fill_color = if charging {
            KASPA_TEAL
        } else if percentage <= 15 {
            COLOR_DANGER
        } else if percentage <= 30 {
            COLOR_ORANGE
        } else {
            KASPA_TEAL
        };
        Rectangle::new(Point::new(bx + 1, by + 1), Size::new(fill_w, bh - 2))
            .into_styled(PrimitiveStyle::with_fill(fill_color))
            .draw(&mut self.display).ok();

        // Percentage text — white, shifted left
        let mut pct_buf: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut pct_buf,
            format_args!("{}%", percentage.min(100))).ok();
        let pct_w = measure_hint(pct_buf.as_str());
        let tx = bx - pct_w - 6;
        draw_lato_hint(&mut self.display, &pct_buf, tx, by + 11, COLOR_TEXT);

        // Charging indicator
        if charging {
            draw_lato_hint(&mut self.display, "+", bx + 7, by + 11, KASPA_TEAL);
        }
    }
}
