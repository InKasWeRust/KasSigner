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
    COLOR_CARD,
    COLOR_DANGER,
    COLOR_RED_BTN,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    CornerRadii,
    DrawTarget,
    Drawable,
    KASPA_ACCENT,
    KASPA_TEAL,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    RoundedRectangle,
    Size,
    draw_lato_body,
    draw_oswald_header,
    measure_body,
    measure_header,
    sound,
};

impl<'a> BootDisplay<'a> {
    // ═══════════════════════════════════════════════════════════════
    /// Draw mnemonic word display (one word at a time for secure backup)
    pub fn draw_word_screen(&mut self, word_num: u8, total_words: u8, word: &str) {
        self.draw_mnemonic_word("WORD", word_num, total_words, word);
    }

    /// Draw a single dice face: teal rounded rect with black dots
    fn draw_dice_face(&mut self, x: i32, y: i32, w: u32, h: u32, val: u8) {
        use embedded_graphics::primitives::Circle;
        let corner = CornerRadii::new(Size::new(8, 8));
        // Teal background
        RoundedRectangle::new(
            Rectangle::new(Point::new(x, y), Size::new(w, h)), corner
        ).into_styled(PrimitiveStyle::with_fill(KASPA_TEAL)).draw(&mut self.display).ok();

        // Dot positions relative to dice face center
        let cx = x + w as i32 / 2;
        let cy = y + h as i32 / 2;
        let dx = w as i32 / 4; // horizontal offset from center
        let dy = h as i32 / 4; // vertical offset from center
        let r = (w.min(h) / 10).max(2); // dot radius

        let dot = |sx: &mut Self, px: i32, py: i32| {
            Circle::new(Point::new(px - r as i32, py - r as i32), r * 2)
                .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                .draw(&mut sx.display).ok();
        };

        match val {
            1 => { dot(self, cx, cy); }
            2 => { dot(self, cx - dx, cy - dy); dot(self, cx + dx, cy + dy); }
            3 => { dot(self, cx - dx, cy - dy); dot(self, cx, cy); dot(self, cx + dx, cy + dy); }
            4 => { dot(self, cx - dx, cy - dy); dot(self, cx + dx, cy - dy);
                   dot(self, cx - dx, cy + dy); dot(self, cx + dx, cy + dy); }
            5 => { dot(self, cx - dx, cy - dy); dot(self, cx + dx, cy - dy);
                   dot(self, cx, cy);
                   dot(self, cx - dx, cy + dy); dot(self, cx + dx, cy + dy); }
            6 => { dot(self, cx - dx, cy - dy); dot(self, cx + dx, cy - dy);
                   dot(self, cx - dx, cy);      dot(self, cx + dx, cy);
                   dot(self, cx - dx, cy + dy); dot(self, cx + dx, cy + dy); }
            _ => {}
        }
    }

    /// Touch Seed collection canvas. The screen is drawn once; accepted
    /// movement points and progress are painted incrementally so rendering does
    /// not dominate the timing transcript.
    pub fn draw_touch_entropy_screen(&mut self, count: usize, target: usize) {
        self.clear_keep_nav();

        let mut title_buf: heapless::String<30> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("TOUCH {count}/{target}")).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 25, COLOR_TEXT);

        Rectangle::new(Point::new(30, 35), Size::new(260, 8))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let progress_w = if target > 0 { (260 * count / target).min(260) } else { 0 };
        if progress_w > 0 {
            Rectangle::new(Point::new(30, 35), Size::new(progress_w as u32, 8))
                .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
                .draw(&mut self.display).ok();
        }

        let msg = "Draw here. Keep moving.";
        let sw = measure_body(msg);
        draw_lato_body(&mut self.display, msg, (320 - sw) / 2, 62, COLOR_TEXT_DIM);
        Rectangle::new(Point::new(20, 75), Size::new(280, 140))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT_DIM, 1))
            .draw(&mut self.display).ok();
    }

    /// Paint only the newly accepted touch point and new progress segment.
    pub fn draw_touch_entropy_point(&mut self, x: u16, y: u16, count: usize, target: usize) {
        if (21..299).contains(&x) && (76..214).contains(&y) {
            Rectangle::new(Point::new(x as i32 - 1, y as i32 - 1), Size::new(3, 3))
                .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
                .draw(&mut self.display).ok();
        }
        let now = if target > 0 { (260 * count / target).min(260) } else { 0 };
        let previous = if target > 0 {
            (260 * count.saturating_sub(1) / target).min(260)
        } else {
            0
        };
        if now > previous {
            Rectangle::new(
                Point::new(30 + previous as i32, 35),
                Size::new((now - previous) as u32, 8),
            )
            .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
            .draw(&mut self.display).ok();
        }
    }

    /// Persistent fail-closed recovery screen after all automatic camera-health windows fail.
    pub fn draw_camera_entropy_recovery(&mut self) {
        self.clear_keep_nav();

        let title = "CAMERA ENTROPY";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, COLOR_DANGER);

        for (text, y) in [
            ("Not enough changing image detail.", 66),
            ("Uncover camera and use brighter light.", 88),
            ("Move the signer slightly, then retry.", 110),
            ("3 automatic checks were rejected.", 136),
        ] {
            let w = measure_body(text);
            draw_lato_body(&mut self.display, text, (320 - w) / 2, y, COLOR_TEXT_DIM);
        }

        let corners = CornerRadii::new(Size::new(7, 7));
        let retry = Rectangle::new(
            Point::new(super::ENTROPY_RECOVERY_LEFT_X as i32, super::ENTROPY_RECOVERY_BUTTON_Y as i32),
            Size::new(super::ENTROPY_RECOVERY_BUTTON_WIDTH as u32, super::ENTROPY_RECOVERY_BUTTON_HEIGHT as u32),
        );
        let cancel = Rectangle::new(
            Point::new(super::ENTROPY_RECOVERY_RIGHT_X as i32, super::ENTROPY_RECOVERY_BUTTON_Y as i32),
            Size::new(super::ENTROPY_RECOVERY_BUTTON_WIDTH as u32, super::ENTROPY_RECOVERY_BUTTON_HEIGHT as u32),
        );
        RoundedRectangle::new(retry, corners)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL)).draw(&mut self.display).ok();
        RoundedRectangle::new(cancel, corners)
            .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN)).draw(&mut self.display).ok();
        for (label, x) in [
            ("TRY AGAIN", super::ENTROPY_RECOVERY_LEFT_X),
            ("CANCEL", super::ENTROPY_RECOVERY_RIGHT_X),
        ] {
            let w = measure_body(label);
            draw_lato_body(
                &mut self.display,
                label,
                x as i32 + (super::ENTROPY_RECOVERY_BUTTON_WIDTH as i32 - w) / 2,
                super::ENTROPY_RECOVERY_BUTTON_Y as i32 + 29,
                COLOR_BG,
            );
        }
    }

    /// Draw dice roll screen
    pub fn draw_dice_screen(&mut self, count: usize, target: usize) {
        self.clear_keep_nav();

        // Title
        let mut title_buf: heapless::String<30> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("DICE {count}/{target}")).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 25, COLOR_TEXT);

        // Progress bar
        let progress_w = if target > 0 { (260 * count / target).min(260) } else { 0 };
        Rectangle::new(Point::new(30, 35), Size::new(260, 8))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        if progress_w > 0 {
            Rectangle::new(Point::new(30, 35), Size::new(progress_w as u32, 8))
                .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
                .draw(&mut self.display).ok();
        }

        let sw = measure_body("Tap the dice value you rolled:");
        draw_lato_body(&mut self.display, "Tap the dice value you rolled:", (320 - sw) / 2, 62, COLOR_TEXT);

        // Dice buttons: 2 rows x 3 cols — gray button bg + square teal dice centered
        let dice_x: [i32; 3] = [10, 110, 210];
        let dice_y: [i32; 2] = [70, 135];
        let dw: u32 = 95;
        let dh: u32 = 58;
        let btn_corner = CornerRadii::new(Size::new(6, 6));

        for val in 1u8..=6 {
            let row = ((val - 1) / 3) as usize;
            let col = ((val - 1) % 3) as usize;
            let bx = dice_x[col] + 2;
            let by = dice_y[row] + 2;
            let bw = dw - 4;
            let bh = dh - 4;

            // Gray button background
            RoundedRectangle::new(
                Rectangle::new(Point::new(bx, by), Size::new(bw, bh)), btn_corner
            ).into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();

            // Square teal dice centered in button — slightly smaller
            let dice_sz = bh.min(bw) - 10; // square, 10px margin
            let dice_x0 = bx + (bw as i32 - dice_sz as i32) / 2;
            let dice_y0 = by + (bh as i32 - dice_sz as i32) / 2;
            self.draw_dice_face(dice_x0, dice_y0, dice_sz, dice_sz, val);
        }

        // Undo button — centered at bottom
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let undo_w: u32 = 120;
        let undo_x = (320 - undo_w as i32) / 2;
        let undo_rect = Rectangle::new(Point::new(undo_x, 200), Size::new(undo_w, 38));
        RoundedRectangle::new(undo_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
            .draw(&mut self.display).ok();
        let uw = measure_body("UNDO");
        draw_lato_body(&mut self.display, "UNDO", undo_x + (undo_w as i32 - uw) / 2, 225, COLOR_TEXT);

    }

    /// Partial redraw: only the dice count header + progress bar.
    /// Everything else (dice buttons, undo, back) is static.
    pub fn update_dice_progress(&mut self, count: usize, target: usize) {
        // Clear header area — preserve back icon (x=0..34) and home icon (x=286..320)
        Rectangle::new(Point::new(34, 0), Size::new(252, 32))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // Redraw title
        let mut title_buf: heapless::String<30> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("DICE {count}/{target}")).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 25, COLOR_TEXT);

        // Clear + redraw progress bar
        Rectangle::new(Point::new(30, 35), Size::new(260, 8))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        Rectangle::new(Point::new(30, 35), Size::new(260, 8))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let progress_w = if target > 0 { (260 * count / target).min(260) } else { 0 };
        if progress_w > 0 {
            Rectangle::new(Point::new(30, 35), Size::new(progress_w as u32, 8))
                .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
                .draw(&mut self.display).ok();
        }
    }

    /// Draw "saving to flash" progress screen.
    pub fn draw_saving_screen(&mut self, message: &str) {
        self.draw_progress_screen("SAVING", message);
    }

    /// Draw a loading/processing screen with a progress track for operations
    /// that can report meaningful incremental progress.
    pub fn draw_loading_screen(&mut self, message: &str) {
        self.draw_progress_screen("LOADING", message);
    }


    /// Draw a static wait surface for deliberately opaque operations such as
    /// Argon2 wallet unlock. Do not imply measurable progress when the worker
    /// cannot expose an honest percentage.
    pub fn draw_wait_screen(&mut self, message: &str) {
        self.display.clear(COLOR_BG).ok();
        let title = "LOADING";
        let title_width = measure_header(title);
        draw_oswald_header(
            &mut self.display,
            title,
            (320 - title_width) / 2,
            82,
            KASPA_TEAL,
        );
        let message_width = measure_body(message);
        draw_lato_body(
            &mut self.display,
            message,
            (320 - message_width) / 2,
            119,
            COLOR_TEXT,
        );
        let wait = "PLEASE WAIT";
        let wait_width = measure_body(wait);
        draw_lato_body(
            &mut self.display,
            wait,
            (320 - wait_width) / 2,
            148,
            COLOR_TEXT_DIM,
        );
        let hint = "This can take up to 30 secs";
        let hint_width = measure_body(hint);
        draw_lato_body(
            &mut self.display,
            hint,
            (320 - hint_width) / 2,
            174,
            COLOR_TEXT_DIM,
        );
    }

    fn draw_progress_screen(&mut self, title: &str, message: &str) {
        self.display.clear(COLOR_BG).ok();
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
        Rectangle::new(Point::new(40, 145), Size::new(240, 10))
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display)
            .ok();
        sound::start_ticking();
    }

    /// Redraw the progress bar for an absolute percentage. Clearing the track
    /// first keeps multi-stage operations honest when a new stage restarts at
    /// a lower percentage instead of leaving stale fill pixels behind.
    pub fn update_progress_bar(&mut self, pct: u8) {
        Rectangle::new(Point::new(40, 145), Size::new(240, 10))
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        let fill = (pct as u32).min(100) * 240 / 100;
        if fill > 0 {
            Rectangle::new(Point::new(40, 145), Size::new(fill, 10))
                .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
                .draw(&mut self.display).ok();
        }
    }
    /// Draw word import keyboard screen (a-z + backspace + suggestions)
    pub fn draw_import_word_screen(
        &mut self,
        word_idx: u8,
        word_count: u8,
        word_input: &crate::wallet::mnemonic::WordInput,
    ) {
        self.clear_keep_nav();

        let mut title_buf: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("IMPORT {}/{}", word_idx + 1, word_count)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 24, COLOR_TEXT);

        self.draw_import_keyboard_full(word_input);
    }

    pub fn draw_restore_word_screen(
        &mut self,
        word_idx: u8,
        word_input: &crate::wallet::mnemonic::WordInput,
    ) {
        self.clear_keep_nav();
        let mut title: heapless::String<28> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title, format_args!("RECOVERY WORD {}", word_idx + 1)).ok();
        let tw = measure_header(title.as_str());
        draw_oswald_header(&mut self.display, &title, (320 - tw) / 2, 24, COLOR_TEXT);
        self.draw_import_keyboard_full(word_input);
    }

    /// Partial redraw: only title + input/suggestions area.
    /// Keyboard stays static, back/home icons preserved.
    pub fn update_import_word_header(
        &mut self,
        word_idx: u8,
        word_count: u8,
        word_input: &crate::wallet::mnemonic::WordInput,
    ) {
        // Clear header through separator line (preserve back/home icons)
        Rectangle::new(Point::new(34, 0), Size::new(252, 36))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        let mut title_buf: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("IMPORT {}/{}", word_idx + 1, word_count)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 24, COLOR_TEXT);

        // Redraw input + suggestions (no keyboard)
        self.draw_import_keyboard(word_input);
    }

    /// Partial redraw for calc last word: title + input/suggestions.
    pub fn update_calc_last_word_header(
        &mut self,
        word_idx: u8,
        word_count: u8,
        word_input: &crate::wallet::mnemonic::WordInput,
    ) {
        Rectangle::new(Point::new(34, 0), Size::new(252, 36))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        let entering = if word_count == 12 { 11u8 } else { 23u8 };
        let mut title_buf: heapless::String<30> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("CALC LAST {}/{}", word_idx + 1, entering)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 24, COLOR_TEXT);

        self.draw_import_keyboard(word_input);
    }
}
