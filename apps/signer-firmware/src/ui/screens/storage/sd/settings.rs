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

use crate::ui::prop_fonts;

use super::super::super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
    COLOR_DANGER,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    CornerRadii,
    DrawTarget,
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
    /// Draw SD card settings screen
    pub fn draw_sdcard_settings(&mut self, card_present: bool, card_locked: bool, card_type_str: &str) {
        self.clear_keep_nav();


        // Header — uniform y=30
        let tw = measure_header("SD CARD");
        draw_oswald_header(&mut self.display, "SD CARD", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        if card_present {
            // Card type + status — centered
            let cw = measure_body(card_type_str);
            draw_lato_body(&mut self.display, card_type_str, (320 - cw) / 2, 65, COLOR_TEXT);
            let status = if card_locked { "Password locked" } else { "Card detected" };
            let status_color = if card_locked { COLOR_DANGER } else { KASPA_TEAL };
            let sw = measure_body(status);
            draw_lato_body(&mut self.display, status, (320 - sw) / 2, 85, status_color);

            // Buttons — rounded, centered
            let btn_corner = CornerRadii::new(Size::new(6, 6));
            if card_locked {
                let locked_hint = "Unlock keeps data / Format erases all";
                let lw = measure_hint(locked_hint);
                draw_lato_hint(&mut self.display, locked_hint, (320 - lw) / 2, 101, COLOR_TEXT_DIM);
                self.draw_sd_action_button(15, 115, "Unlock", KASPA_TEAL);
                self.draw_sd_action_button(165, 115, "Format", COLOR_DANGER);
                return;
            }

            let btn1 = Rectangle::new(Point::new(15, 105), Size::new(140, 34));
            RoundedRectangle::new(btn1, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(btn1, btn_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();
            let fw = measure_body("Format FAT32");
            draw_lato_body(&mut self.display, "Format FAT32", 15 + (140 - fw) / 2, 127, COLOR_TEXT);

            let btn2 = Rectangle::new(Point::new(165, 105), Size::new(140, 34));
            RoundedRectangle::new(btn2, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(btn2, btn_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();
            let rw = measure_body("Test R/W");
            draw_lato_body(&mut self.display, "Test R/W", 165 + (140 - rw) / 2, 127, COLOR_TEXT);

            // Hints — centered
            let h1 = "Use Tools menu to import";
            draw_lato_hint(&mut self.display, h1, (320 - prop_fonts::measure_prop_text(h1,
                &prop_fonts::LATO_12_WIDTHS, prop_fonts::LATO_12_FIRST,
                prop_fonts::LATO_12_LAST, prop_fonts::LATO_12_HEIGHT)) / 2, 170, COLOR_TEXT_DIM);
            let h2 = "Use Seeds > Export to backup";
            draw_lato_hint(&mut self.display, h2, (320 - prop_fonts::measure_prop_text(h2,
                &prop_fonts::LATO_12_WIDTHS, prop_fonts::LATO_12_FIRST,
                prop_fonts::LATO_12_LAST, prop_fonts::LATO_12_HEIGHT)) / 2, 188, COLOR_TEXT_DIM);
        } else {
            let s1 = "No SD card detected";
            draw_lato_body(&mut self.display, s1, (320 - measure_body(s1)) / 2, 100, COLOR_TEXT_DIM);
            let s2 = "Insert a microSD card";
            draw_lato_body(&mut self.display, s2, (320 - measure_body(s2)) / 2, 125, COLOR_TEXT_DIM);
        }
    }

    fn draw_sd_action_button(&mut self, x: i32, y: i32, label: &str, stroke: Rgb565) {
        let rect = Rectangle::new(Point::new(x, y), Size::new(140, 34));
        let corners = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_stroke(stroke, 1)).draw(&mut self.display).ok();
        let width = measure_body(label);
        draw_lato_body(&mut self.display, label, x + (140 - width) / 2, y + 22, COLOR_TEXT);
    }

    pub fn draw_sdcard_unlocking(&mut self) {
        self.draw_sdcard_operation("Unlocking SD...");
    }

    /// Draw SD card formatting progress.
    pub fn draw_sdcard_formatting(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let title = "Formatting SD...";
        let title_width = measure_title(title);
        draw_lato_title(&mut self.display, title, (320 - title_width) / 2, 90, KASPA_TEAL);
        let wait = "Locked erase may take hours";
        let wait_width = measure_body(wait);
        draw_lato_body(&mut self.display, wait, (320 - wait_width) / 2, 125, COLOR_TEXT_DIM);
        let warning = "Do not remove power or card";
        let warning_width = measure_body(warning);
        draw_lato_body(&mut self.display, warning, (320 - warning_width) / 2, 150, COLOR_DANGER);
    }

    /// Draw SD card format complete
    pub fn draw_sdcard_format_done(&mut self, success: bool) {
        use embedded_graphics::image::{Image, ImageRawLE};

        if success {
            static LOGO_DATA: &[u8] = include_bytes!("../../../../../assets/logo_320x240.raw");
            let raw_img: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
            Image::new(&raw_img, Point::zero())
                .draw(&mut self.display).ok();

            let tw = measure_title("!! Format Complete !!");
            draw_lato_title(&mut self.display, "!! Format Complete !!", (320 - tw) / 2, 170, KASPA_TEAL);
        } else {
            self.display.clear(COLOR_BG).ok();
            let mw = measure_title("Format Failed");
            draw_lato_title(&mut self.display, "Format Failed", (320 - mw) / 2, 120, COLOR_DANGER);
        }
    }

    /// Draw SD card R/W test in progress.
    pub fn draw_sdcard_testing(&mut self) {
        self.draw_sdcard_operation("Testing R/W...");
    }

    fn draw_sdcard_operation(&mut self, title: &str) {
        self.display.clear(COLOR_BG).ok();
        let title_width = measure_title(title);
        draw_lato_title(
            &mut self.display,
            title,
            (320 - title_width) / 2,
            100,
            KASPA_TEAL,
        );
        let warning = "Do not remove card";
        let warning_width = measure_body(warning);
        draw_lato_body(
            &mut self.display,
            warning,
            (320 - warning_width) / 2,
            135,
            COLOR_TEXT_DIM,
        );
    }

    /// Draw SD card R/W test result (multi-line)
    pub fn draw_sdcard_test_result(&mut self, lines: &[&str], success: bool) {
        use embedded_graphics::image::{Image, ImageRawLE};

        if success {
            static LOGO_DATA: &[u8] = include_bytes!("../../../../../assets/logo_320x240.raw");
            let raw_img: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
            Image::new(&raw_img, Point::zero())
                .draw(&mut self.display).ok();

            let tw = measure_title("!! Test PASSED !!");
            draw_lato_title(&mut self.display, "!! Test PASSED !!", (320 - tw) / 2, 168, KASPA_TEAL);

            for (i, line) in lines.iter().enumerate() {
                let lw = measure_body(line);
                draw_lato_body(&mut self.display, line, (320 - lw) / 2, 195 + i as i32 * 18, COLOR_TEXT);
            }
        } else {
            self.display.clear(COLOR_BG).ok();
            let hw = measure_header("Test FAILED");
            draw_oswald_header(&mut self.display, "Test FAILED", (320 - hw) / 2, 30, COLOR_DANGER);
            Line::new(Point::new(20, 40), Point::new(300, 40))
                .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 1))
                .draw(&mut self.display).ok();

            for (i, line) in lines.iter().enumerate() {
                let lw = measure_body(line);
                draw_lato_body(&mut self.display, line, (320 - lw) / 2, 60 + i as i32 * 20, COLOR_TEXT);
            }
        }
    }
}
