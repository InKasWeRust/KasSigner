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
    COLOR_HINT,
    COLOR_TEXT,
    CornerRadii,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    RoundedRectangle,
    Size,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    measure_header,
    measure_hint,
    measure_title};

impl<'a> BootDisplay<'a> {
    /// Draw address index picker with numeric keypad.
    /// `input_val` is the current typed number string, `cursor` shows blinking state.
    pub fn draw_addr_index_screen(&mut self, input_str: &str) {
        self.clear_keep_nav();

        let btn_bg = Rgb565::new(2, 8, 2);

        let tw = measure_header("GO TO ADDRESS #");
        draw_oswald_header(&mut self.display, "GO TO ADDRESS #", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Input display box: x=80..240, y=42..70
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let input_rect = Rectangle::new(Point::new(80, 42), Size::new(160, 28));
        RoundedRectangle::new(input_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(input_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let display_str = if input_str.is_empty() { "_" } else { input_str };
        let dw = measure_title(display_str);
        draw_lato_title(&mut self.display, display_str, (320 - dw) / 2, 62, COLOR_TEXT);

        // Numeric keypad: 3x4 grid
        let labels = ["1","2","3","4","5","6","7","8","9","C","0","GO"];
        for row in 0..4u16 {
            for col in 0..3u16 {
                let i = (row * 3 + col) as usize;
                let bx = 55 + col as i32 * 75;
                let by = 76 + row as i32 * 34;
                Rectangle::new(Point::new(bx, by), Size::new(65, 30))
                    .into_styled(PrimitiveStyle::with_fill(btn_bg))
                    .draw(&mut self.display).ok();
                let stroke_w = if labels[i] == "GO" { 2 } else { 1 };
                Rectangle::new(Point::new(bx, by), Size::new(65, 30))
                    .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, stroke_w))
                    .draw(&mut self.display).ok();
                let lbl_color = if labels[i] == "GO" { KASPA_TEAL } else { COLOR_TEXT };
                let lw = measure_title(labels[i]);
                draw_lato_title(&mut self.display, labels[i], bx + (65 - lw) / 2, by + 22, lbl_color);
            }
        }

        let hw = measure_hint("Type index, tap GO");
        draw_lato_hint(&mut self.display, "Type index, tap GO", (320 - hw) / 2, 228, COLOR_HINT);

    }

    /// Partial redraw: only the input display box for address index picker.
    pub fn update_addr_index_input(&mut self, input_str: &str) {
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let input_rect = Rectangle::new(Point::new(80, 42), Size::new(160, 28));
        RoundedRectangle::new(input_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(input_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let display_str = if input_str.is_empty() { "_" } else { input_str };
        let dw = measure_title(display_str);
        draw_lato_title(&mut self.display, display_str, (320 - dw) / 2, 62, COLOR_TEXT);
    }
}
