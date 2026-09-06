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
    COLOR_CARD_BORDER,
    COLOR_DANGER,
    COLOR_ORANGE,
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
    draw_lato_title,
    draw_oswald_header,
    measure_body,
    measure_header,
    measure_title,
};

impl<'a> BootDisplay<'a> {
    /// Draw seed list screen showing all populated slots + controls
    /// Layout: title, up to 4 slot rows, "New" button at bottom
    /// Each slot: wallet name + [12w/24w/KEY/xprv] + passphrase/network metadata.
    /// Active slot has teal highlight
    pub fn draw_seed_list_screen(&mut self, seed_mgr: &crate::wallet::seed_manager::SeedManager, scroll: u8) {
        // clear_keep_nav() redraws the Back icon by design. Startup WALLETS is
        // a required-selection surface with no valid parent, so it must clear
        // the entire screen instead of preserving/drawing navigation chrome.
        if seed_mgr.active_slot().is_some() {
            self.clear_keep_nav();
        } else {
            self.clear_screen();
        }
        let tw = measure_header("WALLETS");
        draw_oswald_header(&mut self.display, "WALLETS", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        self.draw_seed_slot_list(
            seed_mgr,
            scroll,
            super::seed_slots::SeedSlotListConfig {
                start_y: 46,
                include_add_slot: true,
                active_fill: COLOR_CARD_BORDER,
                active_border: KASPA_TEAL,
                active_text: KASPA_TEAL,
            },
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Confirm Seed Deletion Screen
    // ═══════════════════════════════════════════════════════════════

    /// Draw the wallet-delete confirmation with a bounded, allocation-free
    /// presentation path. The CoreS3 trace that entered this state
    /// stalled during the generic destructive-popup redraw, so this critical
    /// wallet path deliberately avoids dynamic subject formatting and keeps
    /// every draw primitive explicit.
    pub fn draw_confirm_delete_screen(&mut self, fp_str: &str, source: crate::wallet::seed_manager::WalletSource) {
        self.clear_keep_nav();

        let title = "DELETE WALLET?";
        let title_width = measure_header(title);
        draw_oswald_header(
            &mut self.display,
            title,
            (320 - title_width) / 2,
            30,
            COLOR_ORANGE,
        );
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 1))
            .draw(&mut self.display).ok();

        let fingerprint_width = measure_title(fp_str);
        draw_lato_title(
            &mut self.display,
            fp_str,
            (320 - fingerprint_width) / 2,
            72,
            COLOR_TEXT,
        );
        let source_label = source.deletion_label();
        let source_width = measure_body(source_label);
        draw_lato_body(
            &mut self.display,
            source_label,
            (320 - source_width) / 2,
            94,
            COLOR_TEXT_DIM,
        );

        for (line, y) in [
            ("This action is irreversible.", 119),
            ("Without a backup, your funds", 140),
            ("will be permanently lost.", 159),
        ] {
            let width = measure_body(line);
            draw_lato_body(&mut self.display, line, (320 - width) / 2, y, COLOR_TEXT);
        }

        let cancel = Rectangle::new(Point::new(30, 185), Size::new(120, 40));
        cancel
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display).ok();
        let cancel_width = measure_title("CANCEL");
        draw_lato_title(
            &mut self.display,
            "CANCEL",
            30 + (120 - cancel_width) / 2,
            212,
            KASPA_TEAL,
        );

        let delete = Rectangle::new(Point::new(170, 185), Size::new(120, 40));
        delete
            .into_styled(PrimitiveStyle::with_fill(COLOR_DANGER))
            .draw(&mut self.display).ok();
        let delete_width = measure_title("DELETE");
        draw_lato_title(
            &mut self.display,
            "DELETE",
            170 + (120 - delete_width) / 2,
            212,
            COLOR_TEXT,
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // BIP85 Child Mnemonic Screens
    // ═══════════════════════════════════════════════════════════════

    /// Draw BIP85 index input screen with +/- buttons
    pub fn draw_bip85_index_screen(&mut self, index: u8, word_count: u8) {
        self.clear_keep_nav();

        // Header
        let tw = measure_header("BIP85 CHILD");
        draw_oswald_header(&mut self.display, "BIP85 CHILD", (320 - tw) / 2, 28, COLOR_TEXT);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Word count subtitle centered
        let mut wc_buf: heapless::String<20> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut wc_buf, format_args!("{word_count}-word child")).ok();
        let wcw = measure_body(wc_buf.as_str());
        draw_lato_body(&mut self.display, &wc_buf, (320 - wcw) / 2, 58, COLOR_TEXT_DIM);

        // "Child Index" label centered — orange
        let lbl = "Child Index";
        let lw = measure_body(lbl);
        let orange = Rgb565::new(0b11111, 0b101000, 0b00000);
        draw_lato_body(&mut self.display, lbl, (320 - lw) / 2, 85, orange);

        // [-] index [+] row — centered horizontally
        // Layout: [-](40px) gap(10) index(50px) gap(10) [+](40px) = 150px total
        // Center: (320 - 150) / 2 = 85
        let row_x = 85i32;
        let row_y = 98i32;
        let btn_sz = 40u32;
        let btn_h = 34u32;
        let btn_corner = CornerRadii::new(Size::new(6, 6));

        // [-] button
        let btn_m = Rectangle::new(Point::new(row_x, row_y), Size::new(btn_sz, btn_h));
        RoundedRectangle::new(btn_m, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(btn_m, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(&mut self.display).ok();
        let mw = measure_title("-");
        draw_lato_title(&mut self.display, "-", row_x + (btn_sz as i32 - mw) / 2, row_y + 24, COLOR_TEXT);

        // Index value — white, large, centered
        let mut idx_buf: heapless::String<4> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut idx_buf, format_args!("{index}")).ok();
        let idx_x = row_x + btn_sz as i32 + 10;
        let iw = measure_header(idx_buf.as_str());
        draw_oswald_header(&mut self.display, &idx_buf, idx_x + (50 - iw) / 2, row_y + 26, COLOR_TEXT);

        // [+] button
        let plus_x = idx_x + 60;
        let btn_p = Rectangle::new(Point::new(plus_x, row_y), Size::new(btn_sz, btn_h));
        RoundedRectangle::new(btn_p, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(btn_p, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(&mut self.display).ok();
        let pw = measure_title("+");
        draw_lato_title(&mut self.display, "+", plus_x + (btn_sz as i32 - pw) / 2, row_y + 24, COLOR_TEXT);

        // Derive button — teal filled, narrow, centered
        let derive_w: u32 = 140;
        let derive_h: u32 = 32;
        let derive_x = (320 - derive_w as i32) / 2;
        let derive_y = 150i32;
        let derive_rect = Rectangle::new(Point::new(derive_x, derive_y), Size::new(derive_w, derive_h));
        RoundedRectangle::new(derive_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL)).draw(&mut self.display).ok();
        let dw = measure_title("DERIVE");
        draw_lato_title(&mut self.display, "DERIVE", derive_x + (derive_w as i32 - dw) / 2, derive_y + 22, COLOR_BG);

    }

    /// Partial redraw: only the index number between [-] and [+] buttons.
    pub fn update_bip85_index(&mut self, index: u8) {
        // Clear index area: x=135..185, y=98..132
        Rectangle::new(Point::new(135, 98), Size::new(50, 34))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();
        // Redraw index value
        let mut idx_buf: heapless::String<4> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut idx_buf, format_args!("{index}")).ok();
        let iw = measure_header(idx_buf.as_str());
        draw_oswald_header(&mut self.display, &idx_buf, 135 + (50 - iw) / 2, 124, COLOR_TEXT);
    }

    /// Draw BIP85 deriving progress screen
    pub fn draw_bip85_deriving(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("DERIVING");
        draw_oswald_header(&mut self.display, "DERIVING", (320 - tw) / 2, 100, KASPA_TEAL);
        let sw = measure_body("Generating child seed...");
        draw_lato_body(&mut self.display, "Generating child seed...", (320 - sw) / 2, 130, COLOR_TEXT_DIM);
    }

    /// Draw a BIP85 child mnemonic word.
    pub fn draw_bip85_word_screen(&mut self, word_num: u8, total_words: u8, word: &str) {
        self.draw_mnemonic_word("BIP85", word_num, total_words, word);
    }

}
