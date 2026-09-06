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
    COLOR_BG,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    DrawTarget,
    Drawable,
    KASPA_ACCENT,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Size,
    draw_lato_body,
    draw_oswald_header,
    measure_body,
    measure_header,
};

impl<'a> BootDisplay<'a> {
    /// Draw a loading surface for work that has no honest incremental progress.
    /// This intentionally omits the progress track and ticking sound.
    pub fn draw_loading_wait_screen(&mut self, message: &str) {
        self.display.clear(COLOR_BG).ok();

        let title = "LOADING";
        let title_width = measure_header(title);
        draw_oswald_header(
            &mut self.display,
            title,
            (320 - title_width) / 2,
            90,
            KASPA_TEAL,
        );

        let message_width = measure_body(message);
        draw_lato_body(
            &mut self.display,
            message,
            (320 - message_width) / 2,
            125,
            COLOR_TEXT_DIM,
        );

        let wait = "Please wait...";
        let wait_width = measure_body(wait);
        draw_lato_body(
            &mut self.display,
            wait,
            (320 - wait_width) / 2,
            158,
            COLOR_TEXT,
        );
    }

    pub fn draw_signing_screen(&mut self, current_input: usize, total_inputs: usize) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("SIGNING");
        draw_oswald_header(&mut self.display, "SIGNING", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        use core::fmt::Write;
        let mut progress = heapless::String::<32>::new();
        write!(&mut progress, "Input {}/{}", current_input + 1, total_inputs).ok();
        let pw = measure_body(progress.as_str());
        draw_lato_body(&mut self.display, progress.as_str(), (320 - pw) / 2, 100, COLOR_TEXT);

        // Progress bar
        let bar_width = if total_inputs > 0 {
            (240 * (current_input + 1) / total_inputs) as u32
        } else {
            0
        };
        Rectangle::new(Point::new(40, 130), Size::new(240, 20))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT, 1))
            .draw(&mut self.display).ok();
        Rectangle::new(Point::new(40, 130), Size::new(bar_width, 20))
            .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
            .draw(&mut self.display).ok();

        let wait = "Please wait...";
        let ww = measure_body(wait);
        draw_lato_body(&mut self.display, wait, (320 - ww) / 2, 178, COLOR_TEXT);
    }

}
