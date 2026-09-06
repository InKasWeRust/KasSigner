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


use super::{
    WORD_COUNT_12_Y, WORD_COUNT_24_Y, WORD_COUNT_BUTTON_HEIGHT,
    WORD_COUNT_BUTTON_WIDTH, WORD_COUNT_BUTTON_X,
};

use super::super::{
    BootDisplay,
    COLOR_BG,
    COLOR_CARD,
    COLOR_DANGER,
    COLOR_TEXT,
    CornerRadii,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    RoundedRectangle,
    Size,
    draw_lato_18,
    draw_lato_22_opaque,
    draw_lato_body,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    measure_18,
    measure_22,
    measure_body,
    measure_header,
    measure_title,
};

impl<'a> BootDisplay<'a> {
    pub fn draw_calc_last_word_screen(
        &mut self,
        word_idx: u8,
        word_count: u8,
        word_input: &crate::wallet::mnemonic::WordInput,
    ) {
        self.clear_keep_nav();

        let entering = if word_count == 12 { 11u8 } else { 23u8 };
        let mut title_buf: heapless::String<30> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("CALC LAST {}/{}", word_idx + 1, entering)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 24, COLOR_TEXT);

        self.draw_import_keyboard_full(word_input);
    }

    /// Draw just the input area (prefix, cursor, suggestions) — no keyboard redraw
    pub fn draw_import_keyboard(&mut self, word_input: &crate::wallet::mnemonic::WordInput) {
        // Flicker-free partial redraw of the input + chips area (y=38..98).
        // No full pre-clear — glyphs are painted opaque, and we clear only the
        // narrow tail/chip regions that may hold stale pixels from a longer
        // previous frame.

        // Teal separator (static across keypresses)
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Input prefix area
        let prefix = word_input.prefix_str();
        let text_x: i32 = 80;
        let text_y: i32 = 62;

        // Paint prefix with opaque background — no pre-clear needed
        let drawn_w = if !prefix.is_empty() {
            draw_lato_22_opaque(&mut self.display, prefix, text_x, text_y, COLOR_TEXT, COLOR_BG)
        } else {
            0
        };

        // Cursor position
        let cursor_x = text_x + drawn_w;
        // Clear everything right of the cursor up to the right edge of the input band
        // (y=40..68). This erases stale pixels from a longer previous prefix AND
        // any previous inline match text drawn after the cursor.
        if cursor_x < 320 {
            Rectangle::new(
                Point::new(cursor_x, 40),
                Size::new((320 - cursor_x) as u32, 28),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        }
        // Clear the left margin area before text_x (may hold stale left-aligned content)
        Rectangle::new(Point::new(0, 40), Size::new(text_x as u32, 28))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        embedded_graphics::primitives::Line::new(
            Point::new(cursor_x, text_y - 19),
            Point::new(cursor_x, text_y + 2),
        ).into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Match result inline after cursor — opaque paint so no prior text shows through
        if word_input.match_count == 1 {
            if let Some(idx) = word_input.matched_index {
                let word = offline_signer::derivation::bip39::index_to_word(idx);
                let mut match_buf: heapless::String<24> = heapless::String::new();
                core::fmt::Write::write_fmt(&mut match_buf,
                    format_args!("= {word}")).ok();
                draw_lato_22_opaque(&mut self.display, &match_buf, cursor_x + 6, text_y, KASPA_TEAL, COLOR_BG);
            }
        }

        // Suggestion chips area (y=72..95): clear it first, then redraw chips.
        // Height 24 stops before keyboard top row at y=96.
        Rectangle::new(Point::new(0, 72), Size::new(320, 24))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        let chip_y: i32 = 72;
        if word_input.num_suggestions > 1 {
            let chip_corner = CornerRadii::new(Size::new(5, 5));
            for i in 0..(word_input.num_suggestions as usize).min(3) {
                let w = offline_signer::derivation::bip39::index_to_word(word_input.suggestions[i]);
                let sx = 4 + (i as i32) * 106;
                let chip_rect = Rectangle::new(Point::new(sx, chip_y), Size::new(102, 24));
                RoundedRectangle::new(chip_rect, chip_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(chip_rect, chip_corner)
                    .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                    .draw(&mut self.display).ok();
                let wlen = w.len().min(10);
                let tw = measure_18(&w[..wlen]);
                draw_lato_18(&mut self.display, &w[..wlen], sx + (102 - tw) / 2, chip_y + 18, COLOR_TEXT);
            }
        } else if word_input.match_count == 0 && !prefix.is_empty() {
            let nw = measure_body("No matches");
            draw_lato_body(&mut self.display, "No matches", (320 - nw) / 2, chip_y + 18, COLOR_DANGER);
        }

        self.draw_back_button();
    }

    /// Draw import keyboard with full keyboard layout (call on first draw or word change)
    pub(super) fn draw_import_keyboard_full(&mut self, word_input: &crate::wallet::mnemonic::WordInput) {
        self.draw_import_keyboard(word_input);
        crate::ui::keyboard::draw_keyboard(&mut self.display, crate::ui::keyboard::KeyboardMode::Alpha, 0);
    }

    /// Draw the generic seed-tools word-count screen (12 or 24).
    ///
    /// Keep only the compact action byte live across the display clear.  The
    /// title reference is selected afterwards so a renderer call never has to
    /// preserve a dynamic string fat pointer across the clear transaction.
    pub fn draw_choose_wc_screen(&mut self, action: u8) {
        self.clear_keep_nav();
        let title = signer_firmware_core::presentation::render::word_count_title(action);
        self.draw_word_count_choices(title);
    }

    /// Device-bound onboarding deliberately uses a local fixed header.
    pub fn draw_storage_seed_word_count_screen(&mut self) {
        self.clear_keep_nav();
        self.draw_word_count_choices("MNEMONIC LENGTH");
    }

    fn draw_word_count_choices(&mut self, title: &str) {
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let btn_corner = CornerRadii::new(Size::new(8, 8));

        // 12 Words button: y=70..130
        let btn12 = Rectangle::new(
            Point::new(WORD_COUNT_BUTTON_X as i32, WORD_COUNT_12_Y as i32),
            Size::new(WORD_COUNT_BUTTON_WIDTH as u32, WORD_COUNT_BUTTON_HEIGHT as u32),
        );
        RoundedRectangle::new(btn12, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn12, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let w12 = measure_title("12 Words");
        draw_lato_title(
            &mut self.display,
            "12 Words",
            WORD_COUNT_BUTTON_X as i32 + (WORD_COUNT_BUTTON_WIDTH as i32 - w12) / 2,
            WORD_COUNT_12_Y as i32 + 38,
            COLOR_TEXT,
        );

        // 24 Words button: y=150..210
        let btn24 = Rectangle::new(
            Point::new(WORD_COUNT_BUTTON_X as i32, WORD_COUNT_24_Y as i32),
            Size::new(WORD_COUNT_BUTTON_WIDTH as u32, WORD_COUNT_BUTTON_HEIGHT as u32),
        );
        RoundedRectangle::new(btn24, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn24, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let w24 = measure_title("24 Words");
        draw_lato_title(
            &mut self.display,
            "24 Words",
            WORD_COUNT_BUTTON_X as i32 + (WORD_COUNT_BUTTON_WIDTH as i32 - w24) / 2,
            WORD_COUNT_24_Y as i32 + 38,
            COLOR_TEXT,
        );
    }

    pub fn draw_passphrase_choice_screen(&mut self) {
        self.clear_keep_nav();
        let title = "BIP39 Pass.";
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let lines = [
            ("Optional extra secret for your words.", 62),
            ("It creates a different wallet.", 78),
            ("Keep the passphrase to restore later.", 94),
        ];
        for (text, y) in lines {
            let w = measure_body(text);
            draw_lato_body(&mut self.display, text, (320 - w) / 2, y, COLOR_TEXT);
        }
        self.draw_passphrase_choice_button(18, 126, 284, "No Passphrase");
        self.draw_passphrase_choice_button(18, 176, 284, "Use Passphrase");
    }

    fn draw_passphrase_choice_button(&mut self, x: i32, y: i32, width: u32, label: &str) {
        let rect = Rectangle::new(Point::new(x, y), Size::new(width, 35));
        let corners = CornerRadii::new(Size::new(7, 7));
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(&mut self.display).ok();
        let w = measure_title(label);
        draw_lato_title(&mut self.display, label, x + (width as i32 - w) / 2, y + 24, COLOR_TEXT);
    }

    /// Full passphrase screen including keyboard layout (for initial draw or page change)
    pub fn draw_passphrase_screen_full(&mut self, pp_input: &crate::wallet::seed_manager::PassphraseInput) {
        self.draw_keyboard_screen_full(pp_input, "PASSPHRASE");
    }

    /// Draw keyboard screen with custom title (for password, passphrase, description entry)
    /// Draw the input-text strip (header already drawn; keyboard below untouched).
    ///
    /// Flicker-free: no pre-clear of the text area. Text is painted with
    /// `draw_lato_22_opaque` which writes each glyph cell as one
    /// `fill_contiguous` burst (BG + FG pixels in a single SPI transaction).
    /// Unchanged glyphs transition same-to-same (invisible to the eye), so
    /// only the character(s) that actually changed visibly update.
    ///
    /// The only explicit clear is the TAIL region past the new text's right
    /// edge — needed when text shrinks (backspace). That's a narrow fill
    /// for short text, zero-width when text fills the strip.
    ///
    /// Strip bounds: y=38..68, x=0..320. Input text starts at `text_x`;
    /// the leading column before `text_x` holds the scroll indicator when
    /// `vis_start > 0`.
    pub fn draw_keyboard_screen(&mut self, pp_input: &crate::wallet::seed_manager::PassphraseInput) {
        let pp = pp_input.as_str();
        let max_vis: usize = 22;
        let cursor = pp_input.cursor.min(pp_input.len);
        let text_x: i32 = 10;
        let text_y: i32 = 64;
        const STRIP_Y: i32 = 38;
        const STRIP_H: u32 = 30;
        const STRIP_W: u32 = 320;

        // Visible window: always left-aligned, scroll only when cursor exceeds it
        let vis_start = if cursor <= max_vis {
            0
        } else {
            cursor - max_vis
        };
        let vis_end = (vis_start + max_vis).min(pp.len());
        let vis_text = &pp[vis_start..vis_end];

        // Leading scroll-indicator column: clear when unused (to erase a prior '‹'),
        // leave alone when still in use (we'll draw '‹' back at the end).
        if vis_start == 0 {
            Rectangle::new(Point::new(0, STRIP_Y), Size::new(text_x as u32, STRIP_H))
                .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                .draw(&mut self.display).ok();
        }

        // Opaque text paint — each glyph cell is a single fill_contiguous SPI burst.
        // No pre-clear of the text column; glyphs overdraw previous content cleanly.
        let drawn_w = if !vis_text.is_empty() {
            draw_lato_22_opaque(&mut self.display, vis_text, text_x, text_y, COLOR_TEXT, COLOR_BG)
        } else {
            0
        };

        // Tail clear — from the right edge of the new text to the strip right edge.
        // Needed when text shrinks (backspace removed chars that are still visible past
        // the new end). For a growing text this is just unused background space.
        let tail_x = text_x + drawn_w;
        if tail_x < STRIP_W as i32 {
            Rectangle::new(
                Point::new(tail_x, STRIP_Y),
                Size::new((STRIP_W as i32 - tail_x) as u32, STRIP_H),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        }

        // Cursor: vertical teal line at the post-cursor position. When cursor is
        // at text end, cursor_x == text_x + drawn_w — the tail clear just wiped
        // that area, so drawing the cursor here is on fresh BG. When cursor is
        // interior (cursor-left/right used), the opaque glyph paint already
        // covered any stale cursor pixels.
        let cursor_in_window = cursor - vis_start;
        let cursor_x = if cursor_in_window > 0 {
            let before = &pp[vis_start..vis_start + cursor_in_window];
            text_x + measure_22(before)
        } else {
            text_x
        };
        embedded_graphics::primitives::Line::new(
            Point::new(cursor_x, text_y - 19),
            Point::new(cursor_x, text_y + 2),
        ).into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display).ok();

        // Scroll indicator: '‹' when text before window
        if vis_start > 0 {
            // Clear the 10px leading column first (it may hold a stale '‹' or be empty)
            Rectangle::new(Point::new(0, STRIP_Y), Size::new(text_x as u32, STRIP_H))
                .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                .draw(&mut self.display).ok();
            draw_lato_hint(&mut self.display, "\u{2039}", 2, 56, KASPA_TEAL);
        }
    }

    /// Draw the full keyboard screen including keyboard layout (call on first draw or page change)
    pub fn draw_keyboard_screen_full(&mut self, pp_input: &crate::wallet::seed_manager::PassphraseInput, title: &str) {
        self.clear_keep_nav();

        // Header — compact (only drawn on full redraw, not per-keypress)
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 26, COLOR_TEXT);
        Line::new(Point::new(20, 36), Point::new(300, 36))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();


        // Input text + cursor (partial redraw area)
        self.draw_keyboard_screen(pp_input);

        crate::ui::keyboard::draw_keyboard(&mut self.display, crate::ui::keyboard::KeyboardMode::Full, pp_input.page);
    }

    /// Redraw only the keyboard keys (for page toggle — no screen clear, no header, no text)
    pub fn draw_keyboard_keys_only(&mut self, pp_input: &crate::wallet::seed_manager::PassphraseInput) {
        crate::ui::keyboard::draw_keyboard(&mut self.display, crate::ui::keyboard::KeyboardMode::Full, pp_input.page);
    }

}
