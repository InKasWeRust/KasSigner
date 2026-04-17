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

// ui/screens.rs — Screen drawing methods for all AppState variants
//
// This file extends BootDisplay (defined in hw/display.rs) with all
// screen-specific rendering methods. Separated for maintainability.


use embedded_graphics::{
    prelude::*,
    pixelcolor::Rgb565,
    primitives::{PrimitiveStyle, Rectangle, RoundedRectangle, Line, Triangle, Circle, CornerRadii},
    image::Image,
};
use embedded_iconoir::prelude::*;
use embedded_iconoir::icons::size24px;
use crate::hw::display::*;
use crate::hw::sound;
use crate::ui::prop_fonts;
use crate::wallet;

impl<'a> BootDisplay<'a> {

    /// Draw the "Sign TX" guided instruction screen.
    pub fn draw_sign_tx_guide(&mut self, seed_loaded: bool, addr_str: &str, _addr_index: u16) {
        self.display.clear(COLOR_BG).ok();

        // Title
        let tw = measure_header("SIGN TRANSACTION");
        draw_oswald_header(&mut self.display, "SIGN TRANSACTION", (320 - tw) / 2, 28, KASPA_TEAL);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        if !seed_loaded {
            // No seed warning — large centered
            let w = measure_header("Load a seed first");
            draw_oswald_header(&mut self.display, "Load a seed first", (320 - w) / 2, 110, COLOR_DANGER);
            let w2 = measure_body("Go to Seeds menu to create or import");
            draw_lato_body(&mut self.display, "Go to Seeds menu to create or import", (320 - w2) / 2, 140, COLOR_TEXT_DIM);
        } else {
            // Active address display (centered, no label)
            {
                if addr_str.len() > 24 {
                    let mut buf = [0u8; 32];
                    let front = 14.min(addr_str.len());
                    let back = 8.min(addr_str.len());
                    let mut pos = 0;
                    for &b in &addr_str.as_bytes()[..front] { buf[pos] = b; pos += 1; }
                    buf[pos] = b'.'; pos += 1;
                    buf[pos] = b'.'; pos += 1;
                    buf[pos] = b'.'; pos += 1;
                    for &b in &addr_str.as_bytes()[addr_str.len() - back..] { buf[pos] = b; pos += 1; }
                    let s = core::str::from_utf8(&buf[..pos]).unwrap_or("???");
                    let sw = measure_title(s);
                    draw_lato_title(&mut self.display, s, (320 - sw) / 2, 58, COLOR_ORANGE);
                } else {
                    let sw = measure_title(addr_str);
                    draw_lato_title(&mut self.display, addr_str, (320 - sw) / 2, 58, COLOR_ORANGE);
                }
            }

            // Separator
            Line::new(Point::new(30, 68), Point::new(290, 68))
                .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                .draw(&mut self.display).ok();

            // Step-by-step guide — centered, regular weight, no numbers
            let steps: [&str; 4] = [
                "Open your Kaspa wallet",
                "Import the kpub",
                "Create a Send transaction",
                "Show the KSPT QR code",
            ];
            let step_h: i32 = 26;
            let block_h = steps.len() as i32 * step_h;
            let avail_top: i32 = 92;
            let avail_bot: i32 = 192;
            let start_sy = avail_top + (avail_bot - avail_top - block_h) / 2;
            for (i, step) in steps.iter().enumerate() {
                let sy = start_sy + i as i32 * step_h;
                let sw = measure_18(step);
                draw_lato_18(&mut self.display, step, (320 - sw) / 2, sy, COLOR_TEXT);
            }

            // "SCAN KSPT" button — moved down
            let btn_w: u32 = 200;
            let btn_h: u32 = 36;
            let btn_x: i32 = (320 - btn_w as i32) / 2;
            let btn_y: i32 = 194;
            let btn_rect = Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, btn_h));
            let btn_corner = CornerRadii::new(Size::new(8, 8));
            RoundedRectangle::new(btn_rect, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
                .draw(&mut self.display).ok();
            let lw = measure_title("SCAN KSPT");
            draw_lato_title(&mut self.display, "SCAN KSPT", btn_x + (btn_w as i32 - lw) / 2, btn_y + 26, COLOR_BG);
        }

        self.draw_back_button();
    }

    /// Draw sign message choice screen — type manually or load from SD
    pub fn draw_sign_msg_choice(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("SIGN MESSAGE");
        draw_oswald_header(&mut self.display, "SIGN MESSAGE", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let sw = measure_body("Sign any text with your key");
        draw_lato_body(&mut self.display, "Sign any text with your key", (320 - sw) / 2, 60, COLOR_TEXT_DIM);

        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let start_y: i32 = 70;
        let start_x: i32 = 44;
        let card_w: u32 = 232;
        let card_corner = CornerRadii::new(Size::new(6, 6));

        let r0 = Rectangle::new(Point::new(start_x, start_y), Size::new(card_w, card_h as u32));
        RoundedRectangle::new(r0, card_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(r0, card_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let kb_icon = size24px::editor::EditPencil::new(KASPA_TEAL);
        Image::new(&kb_icon, Point::new(start_x + 6, start_y + 9)).draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "Type manually", start_x + 42, start_y + 28, COLOR_TEXT);

        let r1_y = start_y + card_h + card_gap;
        let r1 = Rectangle::new(Point::new(start_x, r1_y), Size::new(card_w, card_h as u32));
        RoundedRectangle::new(r1, card_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(r1, card_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let sd_icon = size24px::docs::Page::new(KASPA_TEAL);
        Image::new(&sd_icon, Point::new(start_x + 6, r1_y + 9)).draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "Load .TXT from SD", start_x + 42, r1_y + 28, COLOR_TEXT);

        self.draw_back_button();
    }

    /// Draw sign message preview — show message text + SIGN button
    pub fn draw_sign_msg_preview(&mut self, message: &str) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("SIGN MESSAGE");
        draw_oswald_header(&mut self.display, "SIGN MESSAGE", (320 - tw) / 2, 28, KASPA_TEAL);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Message text — white, title font, up to 3 lines ~20 chars each
        let msg_bytes = message.as_bytes();
        let chars_per_line: usize = 20;
        for line_idx in 0..3u8 {
            let start = line_idx as usize * chars_per_line;
            if start >= msg_bytes.len() { break; }
            let end = (start + chars_per_line).min(msg_bytes.len());
            let line = &message[start..end];
            let row_y = 48 + line_idx as i32 * 26;
            let lw = measure_title(line);
            draw_lato_title(&mut self.display, line, (320 - lw) / 2, row_y + 20, COLOR_TEXT);
        }
        if msg_bytes.len() > chars_per_line * 3 {
            let tw2 = measure_body("...");
            draw_lato_body(&mut self.display, "...", (320 - tw2) / 2, 128, COLOR_TEXT_DIM);
        }

        // SHA256 hash preview — orange, body font
        let msg_hash = wallet::hmac::sha256(&msg_bytes[..msg_bytes.len().min(128)]);
        let hex_chars = b"0123456789abcdef";
        let mut hash_buf = [0u8; 24]; // "SHA256: xxxxxxxx..."
        hash_buf[0..8].copy_from_slice(b"SHA256: ");
        for i in 0..6 {
            hash_buf[8 + i * 2] = hex_chars[(msg_hash[i] >> 4) as usize];
            hash_buf[8 + i * 2 + 1] = hex_chars[(msg_hash[i] & 0x0f) as usize];
        }
        hash_buf[20] = b'.';
        hash_buf[21] = b'.';
        hash_buf[22] = b'.';
        hash_buf[23] = b' ';
        let hash_str = core::str::from_utf8(&hash_buf[..23]).unwrap_or("???");
        let hw = measure_body(hash_str);
        draw_lato_body(&mut self.display, hash_str, (320 - hw) / 2, 155, COLOR_ORANGE);

        // SIGN button (centered, teal)
        let btn_w: u32 = 140;
        let btn_h: u32 = 36;
        let btn_x: i32 = (320 - btn_w as i32) / 2;
        let btn_y: i32 = 185;
        let btn_rect = Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, btn_h));
        let btn_corner = CornerRadii::new(Size::new(8, 8));
        RoundedRectangle::new(btn_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let lw = measure_title("SIGN");
        draw_lato_title(&mut self.display, "SIGN", btn_x + (btn_w as i32 - lw) / 2, btn_y + 26, COLOR_BG);

        self.draw_back_button();
    }

    /// Draw sign message result — signature hex + save option
    pub fn draw_sign_msg_result(&mut self, sig: &[u8; 64]) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("SIGNATURE");
        draw_oswald_header(&mut self.display, "SIGNATURE", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // R label + 2 rows of 32 hex chars
        let hex_chars = b"0123456789abcdef";
        let rw = measure_hint("R (nonce):");
        draw_lato_hint(&mut self.display, "R (nonce):", (320 - rw) / 2, 48, COLOR_TEXT_DIM);

        for row in 0..2u8 {
            let mut hex_line = [0u8; 32];
            for i in 0..16 {
                let byte_idx = row as usize * 16 + i;
                hex_line[i * 2] = hex_chars[(sig[byte_idx] >> 4) as usize];
                hex_line[i * 2 + 1] = hex_chars[(sig[byte_idx] & 0x0f) as usize];
            }
            let line_str = core::str::from_utf8(&hex_line).unwrap_or("?");
            let row_y = 52 + row as i32 * 16;
            let lw = measure_hint(line_str);
            draw_lato_hint(&mut self.display, line_str, (320 - lw) / 2, row_y + 14, KASPA_ACCENT);
        }

        // S label + 2 rows
        let sw2 = measure_hint("S (scalar):");
        draw_lato_hint(&mut self.display, "S (scalar):", (320 - sw2) / 2, 98, COLOR_TEXT_DIM);

        for row in 0..2u8 {
            let mut hex_line = [0u8; 32];
            for i in 0..16 {
                let byte_idx = 32 + row as usize * 16 + i;
                hex_line[i * 2] = hex_chars[(sig[byte_idx] >> 4) as usize];
                hex_line[i * 2 + 1] = hex_chars[(sig[byte_idx] & 0x0f) as usize];
            }
            let line_str = core::str::from_utf8(&hex_line).unwrap_or("?");
            let row_y = 102 + row as i32 * 16;
            let lw = measure_hint(line_str);
            draw_lato_hint(&mut self.display, line_str, (320 - lw) / 2, row_y + 14, KASPA_ACCENT);
        }

        // Separator
        Line::new(Point::new(30, 145), Point::new(290, 145))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();

        // SAVE TO SD button (centered, teal)
        let btn_w: u32 = 200;
        let btn_h: u32 = 36;
        let btn_x: i32 = (320 - btn_w as i32) / 2;
        let btn_y: i32 = 155;
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let save_rect = Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, btn_h));
        RoundedRectangle::new(save_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let sw = measure_title("SAVE TO SD");
        draw_lato_title(&mut self.display, "SAVE TO SD", btn_x + (btn_w as i32 - sw) / 2, btn_y + 26, COLOR_BG);

        // Tap hint
        let cw = measure_hint("Tap anywhere to continue");
        draw_lato_hint(&mut self.display, "Tap anywhere to continue", (320 - cw) / 2, 210, COLOR_HINT);

        self.draw_back_button();
    }

        /// Draw a transaction review page (amount, fee, addresses).
pub fn draw_tx_page(&mut self, tx: &crate::wallet::transaction::Transaction, page: u8,
        receive_pks: &[[u8; 32]; 20], change_pks: &[[u8; 32]; 5]) {
        self.display.clear(COLOR_BG).ok();

        use core::fmt::Write;

        let total_pages = 1 + tx.num_outputs as u8; // summary + outputs

        if page == 0 {
            // Summary page
            let tw = measure_header("TX REVIEW");
            draw_oswald_header(&mut self.display, "TX REVIEW", (320 - tw) / 2, 30, COLOR_TEXT);
            Line::new(Point::new(20, 40), Point::new(300, 40))
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();

            // Total amount
            let total: u64 = (0..tx.num_outputs)
                .map(|i| tx.outputs[i].value)
                .sum();
            let kas = total / 100_000_000;
            let sompi = total % 100_000_000;
            let mut amount_text = heapless::String::<32>::new();
            write!(&mut amount_text, "{kas}.{sompi:08} KAS").ok();

            draw_lato_body(&mut self.display, "Total:", 30, 75, COLOR_TEXT);
            draw_lato_title(&mut self.display, amount_text.as_str(), 30, 100, COLOR_ORANGE);

            // Fee
            let total_in: u64 = (0..tx.num_inputs)
                .map(|i| tx.inputs[i].utxo_entry.amount)
                .sum();
            let fee = total_in.saturating_sub(total);
            let fee_kas = fee / 100_000_000;
            let fee_sompi = fee % 100_000_000;
            let mut fee_text = heapless::String::<32>::new();
            write!(&mut fee_text, "Fee: {fee_kas}.{fee_sompi:08} KAS").ok();
            draw_lato_body(&mut self.display, fee_text.as_str(), 30, 135, COLOR_TEXT);

            // Inputs/outputs count
            let mut info_text = heapless::String::<48>::new();
            write!(&mut info_text, "{} input(s) -> {} output(s)",
                tx.num_inputs, tx.num_outputs).ok();
            draw_lato_body(&mut self.display, info_text.as_str(), 30, 160, COLOR_TEXT);

            // KRC-20 token detection
            let krc20 = crate::features::krc20::detect_krc20(tx);
            if krc20.detected {
                let mut token_text = heapless::String::<48>::new();
                write!(&mut token_text, "KRC-20 {} {}", krc20.op_str(), krc20.ticker_str()).ok();
                draw_lato_title(&mut self.display, token_text.as_str(), 30, 182, COLOR_ORANGE);
                if krc20.amount_len > 0 {
                    let mut amt_text = heapless::String::<40>::new();
                    write!(&mut amt_text, "Amount: {}", krc20.amount_str()).ok();
                    draw_lato_body(&mut self.display, amt_text.as_str(), 30, 200, KASPA_ACCENT);
                }
            }

            // Multisig detection: check first input for multisig script
            use crate::wallet::transaction::{detect_script_type, ScriptType, parse_multisig_script};
            let script = &tx.inputs[0].utxo_entry.script_public_key;
            let st = detect_script_type(&script.script, script.script_len);
            if st == ScriptType::Multisig {
                if let Some(ms) = parse_multisig_script(&script.script, script.script_len) {
                    let mut ms_text = heapless::String::<32>::new();
                    write!(&mut ms_text, "{}-of-{} MULTISIG", ms.m, ms.n).ok();
                    draw_lato_title(&mut self.display, ms_text.as_str(), 30, 190, KASPA_ACCENT);

                    // Show existing signature count
                    let sig_count = tx.inputs[0].sig_count;
                    if sig_count > 0 {
                        let mut sig_text = heapless::String::<24>::new();
                        write!(&mut sig_text, "Sigs: {}/{}", sig_count, ms.m).ok();
                        draw_lato_body(&mut self.display, sig_text.as_str(), 30, 210, COLOR_ORANGE);
                    }
                }
            }
        } else {
            // Output page
            let out_idx = (page - 1) as usize;
            if out_idx < tx.num_outputs {
                let output = &tx.outputs[out_idx];
                let spk = &output.script_public_key;

                // Detect if this output goes to our receive or change address
                let mut is_own = false;
                let mut is_change = false;
                if spk.script_len == 34 && spk.script[0] == 0x20 && spk.script[33] == 0xAC {
                    // P2PK: extract 32-byte pubkey from script[1..33]
                    let mut out_pk = [0u8; 32];
                    out_pk.copy_from_slice(&spk.script[1..33]);
                    for pk in receive_pks.iter() {
                        if *pk != [0u8; 32] && *pk == out_pk { is_own = true; break; }
                    }
                    if !is_own {
                        for pk in change_pks.iter() {
                            if *pk != [0u8; 32] && *pk == out_pk { is_change = true; break; }
                        }
                    }
                }

                // Title with CHANGE/OWN label
                let mut title = heapless::String::<32>::new();
                if is_change {
                    write!(&mut title, "OUTPUT {out_idx} (CHANGE)").ok();
                } else if is_own {
                    write!(&mut title, "OUTPUT {out_idx} (OWN)").ok();
                } else {
                    write!(&mut title, "OUTPUT {out_idx}").ok();
                }

                let title_color = if is_change || is_own { KASPA_TEAL } else { COLOR_TEXT };
                let tw = measure_header(title.as_str());
                draw_oswald_header(&mut self.display, title.as_str(), (320 - tw) / 2, 30, title_color);
                Line::new(Point::new(20, 40), Point::new(300, 40))
                    .into_styled(PrimitiveStyle::with_stroke(
                        if is_change || is_own { KASPA_TEAL } else { KASPA_TEAL }, 1))
                    .draw(&mut self.display).ok();

                // Amount
                let kas = output.value / 100_000_000;
                let sompi = output.value % 100_000_000;
                let mut amount_text = heapless::String::<32>::new();
                write!(&mut amount_text, "{kas}.{sompi:08} KAS").ok();
                let amount_color = if is_change { COLOR_TEXT_DIM } else { COLOR_ORANGE };
                draw_lato_title(&mut self.display, amount_text.as_str(), 30, 65, amount_color);

                // Encode actual Kaspa address if P2PK
                if spk.script_len == 34 && spk.script[0] == 0x20 && spk.script[33] == 0xAC {
                    let mut out_pk = [0u8; 32];
                    out_pk.copy_from_slice(&spk.script[1..33]);
                    let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                    let addr = wallet::address::encode_address_str(
                        &out_pk, wallet::address::AddressType::P2PK, &mut addr_buf);

                    // Wrap address at 25 chars/line
                    let bytes = addr.as_bytes();
                    let total_len = bytes.len();
                    let chars_per_line: usize = 25;
                    let line_h: i32 = 22;
                    let mut y_pos: i32 = 90;
                    let mut offset: usize = 0;
                    while offset < total_len && y_pos < 195 {
                        let end = core::cmp::min(offset + chars_per_line, total_len);
                        if let Ok(line) = core::str::from_utf8(&bytes[offset..end]) {
                            let lw = measure_body(line);
                            draw_lato_body(&mut self.display, line, (320 - lw) / 2, y_pos, COLOR_TEXT);
                        }
                        y_pos += line_h;
                        offset = end;
                    }
                } else {
                    // Non-P2PK: show raw script hex
                    let mut addr_text = heapless::String::<48>::new();
                    write!(&mut addr_text, "Script: ").ok();
                    let show_bytes = core::cmp::min(8, spk.script_len);
                    for i in 0..show_bytes {
                        write!(&mut addr_text, "{:02x}", spk.script[i]).ok();
                    }
                    write!(&mut addr_text, "...").ok();
                    draw_lato_body(&mut self.display, addr_text.as_str(), 30, 100, COLOR_TEXT);
                }
            }
        }

        // Page indicator at bottom
        let mut page_text = heapless::String::<32>::new();
        write!(&mut page_text, "Page {}/{}", page + 1, total_pages).ok();
        let pw = measure_body(page_text.as_str());
        draw_lato_body(&mut self.display, page_text.as_str(), (320 - pw) / 2, 225, COLOR_TEXT_DIM);
        self.draw_back_button();
    }

    /// Draw signing progress
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
    }

    /// Draw QR code screen
    pub fn draw_qr_screen(&mut self, data: &[u8]) {
        self.display.clear(COLOR_BG).ok();

        if let Ok(qr) = crate::qr::encoder::encode(data) {
            let qr_size = qr.size as i32;
            // Maximize QR: fill the screen minus 4px quiet zone on each side.
            // Height (240) is the limiting dimension on 320×240 displays.
            let max_px = (DISPLAY_H as i32) - 8; // 232px usable
            let scale = (max_px / qr_size).max(1);
            let total = qr_size * scale;
            let offset_x = (DISPLAY_W as i32 - total) / 2;
            let offset_y = (DISPLAY_H as i32 - total) / 2;

            Rectangle::new(
                Point::new(offset_x - 4, offset_y - 4),
                Size::new((total + 8) as u32, (total + 8) as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

            for y in 0..qr_size {
                for x in 0..qr_size {
                    if qr.get(x as u8, y as u8) {
                        Rectangle::new(
                            Point::new(offset_x + x * scale, offset_y + y * scale),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                        .draw(&mut self.display).ok();
                    }
                }
            }
        } else {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }
        // No back button on QR — tap anywhere to go back
    }

    /// Draw transaction rejected screen
    pub fn draw_rejected_screen(&mut self, reason: &str) {
        sound::stop_ticking();
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("ERROR");
        draw_oswald_header(&mut self.display, "ERROR", (320 - tw) / 2, 30, COLOR_DANGER);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 1))
            .draw(&mut self.display).ok();

        let truncated = if reason.len() > 35 { &reason[..35] } else { reason };
        let rw = measure_title(truncated);
        draw_lato_title(&mut self.display, truncated, (320 - rw) / 2, 120, COLOR_TEXT_DIM);
    }

    /// Draw 2x2 grid home menu (SeedSigner-style)
    /// Items: ["Send Demo TX", "Show Address", "Settings", "About"]
    /// Grid: [Send TX] [Address]
    ///       [Settings] [About]
    /// Touch zones: top-left(10,50,148,85) top-right(162,50,148,85)
    ///              bot-left(10,145,148,85) bot-right(162,145,148,85)
    /// Draw a small battery indicator at the top-right of the screen.
    /// Shows icon (outline + fill level) + percentage text.
    /// Call after drawing the title bar.
    pub fn draw_battery_icon(&mut self, percentage: u8, charging: bool) {
        // Battery outline: 24x12, vertically centered with header (header center ~y=21)
        let bx: i32 = 280;
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

        /// Draw the 2x2 home screen grid (Scan QR, Seeds, Tools, Settings).
pub fn draw_home_grid(&mut self) {
        use embedded_graphics::image::{Image, ImageRawLE};

        self.display.clear(COLOR_BG).ok();

        // KasSigner pill logo — top-left corner
        let logo: ImageRawLE<Rgb565> = ImageRawLE::new(
            crate::hw::icon_data::ICON_LOGO, crate::hw::icon_data::ICON_LOGO_W);
        Image::new(&logo, Point::new(2, 5))
            .draw(&mut self.display).ok();

        // Title bar — Rubik Bold header centered
        let tw = measure_header("HOME");
        draw_oswald_header(&mut self.display, "HOME", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Icon raw data (56x56 RGB565 little-endian) — converted from BMP designs
        static ICON_SCAN: &[u8] = include_bytes!("../../assets/icon_send.raw");
        static ICON_SEEDS: &[u8] = include_bytes!("../../assets/icon_addr.raw");
        static ICON_TOOLS: &[u8] = include_bytes!("../../assets/icon_settings.raw");
        static ICON_SETTINGS: &[u8] = include_bytes!("../../assets/icon_about.raw");

        let icons: [&[u8]; 4] = [ICON_SCAN, ICON_SEEDS, ICON_TOOLS, ICON_SETTINGS];
        let labels: [&str; 4] = ["Scan", "Seeds", "Tools", "Settings"];
        let positions: [(i32, i32); 4] = [
            (8, 46),    // top-left
            (164, 46),  // top-right
            (8, 143),   // bottom-left
            (164, 143), // bottom-right
        ];

        let corner = CornerRadii::new(Size::new(8, 8));

        for i in 0..4 {
            let (px, py) = positions[i];
            let card_w: u32 = 148;
            let card_h: u32 = 90;

            // Rounded card background
            RoundedRectangle::new(Rectangle::new(Point::new(px, py), Size::new(card_w, card_h)), corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(Rectangle::new(Point::new(px, py), Size::new(card_w, card_h)), corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();

            // Icon (56x56) centered horizontally in card
            let raw_icon: ImageRawLE<Rgb565> = ImageRawLE::new(icons[i], 56);
            Image::new(&raw_icon, Point::new(px + 46, py + 2))
                .draw(&mut self.display).ok();

            // Label — Lato Bold 18px centered below icon
            let label = labels[i];
            let lw = measure_title(label);
            let lx = px + (card_w as i32 - lw) / 2;
            draw_lato_title(&mut self.display, label, lx, py + 80, COLOR_TEXT);
        }
    }

    /// Draw menu screen with title and list items (for sub-menus)
    /// Layout: 40px L-strip (◀ page up), 240px content (4 rows), 40px R-strip (▶ page down)
    /// BACK button in header top-left (drawn by draw_back_button)
    pub fn draw_menu_screen(&mut self, title: &str, menu: &crate::app::input::Menu) {
        self.display.clear(COLOR_BG).ok();

        // Title — Rubik Bold header centered
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, COLOR_TEXT);

        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Menu items — 4 visible rows, 42px each, 4px gap
        let max_visible = crate::app::input::Menu::MAX_VISIBLE;
        let visible_count = max_visible.min(menu.count.saturating_sub(menu.scroll));
        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let card_w: u32 = 232; // center content area (320 - 40 - 40 - 8 margin)
        let start_y: i32 = 46;
        let start_x: i32 = 44; // 40px left strip + 4px margin

        // Near-black teal for inactive arrows/dots — max contrast with active
        let teal_dark = Rgb565::new(0b00001, 0b000100, 0b00010); // ~#081008 near-black with teal tint

        for i in 0..visible_count {
            let item_idx = menu.scroll + i;
            if item_idx >= menu.count { break; }

            let y = start_y + (i as i32) * (card_h + card_gap);
            let label = menu.items[item_idx as usize];

            let card_rect = Rectangle::new(Point::new(start_x, y), Size::new(card_w, card_h as u32));
            let card_corner = CornerRadii::new(Size::new(6, 6));
            RoundedRectangle::new(card_rect, card_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            // Teal border on all rows
            RoundedRectangle::new(card_rect, card_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();

            // Icon (24×24) at left of card, vertically centered in 42px row
            let icon_x = start_x + 8;
            let icon_y = y + 9; // (42 - 24) / 2 = 9
            let icon_pt = Point::new(icon_x, icon_y);
            draw_menu_icon(&mut self.display, label, icon_pt);

            // Lato Bold 18px label, shifted right for icon (24px icon + 8+8 margin = 40px)
            draw_lato_title(&mut self.display, label, start_x + 42, y + 28, COLOR_TEXT);
        }

        // Left strip: ◀ page-up arrow
        if menu.count > max_visible {
            let arr_color = if menu.can_page_up() { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(5, 138),    // left tip
                Point::new(30, 121),   // top-right
                Point::new(30, 155),   // bottom-right
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();
        }

        // Right strip: ▶ page-down arrow
        if menu.count > max_visible {
            let arr_color = if menu.can_page_down() { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(315, 138),  // right tip
                Point::new(290, 121),  // top-left
                Point::new(290, 155),  // bottom-left
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();
        }

        // Page dots at bottom — 7px diameter, y=232 (7px below last row bottom)
        let total_pages = menu.total_pages();
        if total_pages > 1 {
            let current_page = menu.current_page();
            let dot_d: i32 = 7;
            let dot_gap: i32 = 8;
            let total_w = (total_pages as i32) * dot_d + ((total_pages as i32) - 1) * dot_gap;
            let dot_start_x = (320 - total_w) / 2;

            for p in 0..total_pages {
                let dx = dot_start_x + (p as i32) * (dot_d + dot_gap);
                let color = if p == current_page { KASPA_ACCENT } else { teal_dark };
                Circle::new(Point::new(dx, 232), dot_d as u32)
                    .into_styled(PrimitiveStyle::with_fill(color))
                    .draw(&mut self.display).ok();
            }
        }

        self.draw_back_button();
    }

    /// Draw QR Export sub-menu — dims "Plain Words QR" when seed is 24 words
    pub fn draw_qr_export_menu(&mut self, menu: &crate::app::input::Menu, word_count: u8) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("QR EXPORT");
        draw_oswald_header(&mut self.display, "QR EXPORT", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let max_visible = crate::app::input::Menu::MAX_VISIBLE;
        let visible_count = max_visible.min(menu.count.saturating_sub(menu.scroll));
        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let card_w: u32 = 232;
        let start_y: i32 = 46;
        let start_x: i32 = 44;

        for i in 0..visible_count {
            let item_idx = menu.scroll + i;
            if item_idx >= menu.count { break; }

            // Skip "Plain Words QR" (item 2) entirely when 24 words
            if item_idx == 2 && word_count > 12 { continue; }

            let y = start_y + (i as i32) * (card_h + card_gap);
            let label = menu.items[item_idx as usize];

            let card_rect = Rectangle::new(Point::new(start_x, y), Size::new(card_w, card_h as u32));
            let card_corner = CornerRadii::new(Size::new(6, 6));
            RoundedRectangle::new(card_rect, card_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(card_rect, card_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();

            let icon_x = start_x + 8;
            let icon_y = y + 9;
            let icon_pt = Point::new(icon_x, icon_y);
            draw_menu_icon(&mut self.display, label, icon_pt);
            draw_lato_title(&mut self.display, label, start_x + 42, y + 28, COLOR_TEXT);
        }

        self.draw_back_button();
    }

    /// Draw about screen
    pub fn draw_about_screen(&mut self) {
        use embedded_graphics::image::{Image, ImageRawLE};

        self.display.clear(COLOR_BG).ok();

        // Logo shifted up 20px for visual balance (no nav buttons)
        static LOGO_DATA: &[u8] = include_bytes!("../../assets/logo_320x240.raw");
        let raw_img: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
        Image::new(&raw_img, Point::new(0, -20))
            .draw(&mut self.display).ok();

        // Version
        let mut vbuf = [0u8; 12];
        let vlen = crate::features::fw_update::format_version(
            crate::features::fw_update::CURRENT_VERSION, &mut vbuf[1..]);
        vbuf[0] = b'v';
        let vtxt = core::str::from_utf8(&vbuf[..vlen + 1]).unwrap_or("v?");
        let vw = measure_title(vtxt);
        draw_lato_title(&mut self.display, vtxt, (320 - vw) / 2, 122, COLOR_TEXT);

        // Tagline
        let s1 = "Secure Hardware Wallet for Kaspa";
        draw_lato_body(&mut self.display, s1, (320 - measure_body(s1)) / 2, 146, COLOR_TEXT_DIM);

        // Tech line
        let s2 = "100% Rust | Air-Gapped | no_std";
        draw_lato_body(&mut self.display, s2, (320 - measure_body(s2)) / 2, 166, COLOR_TEXT_DIM);

        // Board name
        #[cfg(feature = "waveshare")]
        let s3 = "Waveshare ESP32-S3-Touch-LCD-2";
        #[cfg(feature = "m5stack")]
        let s3 = "M5Stack CoreS3 Lite";
        draw_lato_hint(&mut self.display, s3, (320 - measure_hint(s3)) / 2, 186, COLOR_TEXT_DIM);

        // kaspa.org
        let s4 = "kaspa.org";
        draw_lato_hint(&mut self.display, s4, (320 - measure_hint(s4)) / 2, 206, KASPA_TEAL);
    }

    /// Draw seed info screen showing word count and address
    pub fn draw_seed_info_screen(&mut self, word_count: u8, address: &str) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("SEED INFO");
        draw_oswald_header(&mut self.display, "SEED INFO", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        use core::fmt::Write;
        let mut wc_buf: heapless::String<24> = heapless::String::new();
        write!(&mut wc_buf, "Words: {word_count}").ok();
        draw_lato_body(&mut self.display, &wc_buf, 30, 70, COLOR_TEXT);

        draw_lato_body(&mut self.display, "Status: Loaded (in RAM)", 30, 92, COLOR_TEXT);

        draw_lato_body(&mut self.display, "Address:", 30, 118, COLOR_TEXT_DIM);

        // Address — title font, centered, 25 chars/line
        let bytes = address.as_bytes();
        let total = bytes.len();
        let chars_per_line: usize = 25;
        let line_h: i32 = 26;
        let mut y: i32 = 138;
        let mut offset: usize = 0;
        while offset < total && y < 220 {
            let end = core::cmp::min(offset + chars_per_line, total);
            if let Ok(line) = core::str::from_utf8(&bytes[offset..end]) {
                let lw = measure_title(line);
                draw_lato_title(&mut self.display, line, (320 - lw) / 2, y, KASPA_TEAL);
            }
            y += line_h;
            offset = end;
        }

        let hw = measure_hint("Tap to go back");
        draw_lato_hint(&mut self.display, "Tap to go back", (320 - hw) / 2, 232, COLOR_TEXT_DIM);
        self.draw_back_button();
    }

    /// Draw address screen showing the Kaspa address string
    pub fn draw_address_screen(&mut self, address: &str, checksum_valid: bool, addr_index: Option<u16>, select_label: Option<&str>) {
        self.display.clear(COLOR_BG).ok();

        // Title
        if let Some(idx) = addr_index {
            let mut title_buf: heapless::String<24> = heapless::String::new();
            core::fmt::Write::write_fmt(&mut title_buf, format_args!("RECEIVE #{idx}")).ok();
            let tw = measure_header(title_buf.as_str());
            draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 30, COLOR_TEXT);
        } else {
            let title = if checksum_valid { "SCANNED ADDRESS" } else { "ADDRESS (INVALID)" };
            let title_color = if checksum_valid { COLOR_TEXT } else { COLOR_DANGER };
            let tw = measure_header(title);
            draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 30, title_color);
        }

        let sep_color = if checksum_valid { KASPA_TEAL } else { COLOR_DANGER };
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(sep_color, 1))
            .draw(&mut self.display).ok();

        // Address text — title font, centered, 25 chars/line, vertically centered
        let bytes = address.as_bytes();
        let total = bytes.len();
        let chars_per_line: usize = 25;
        let line_h: i32 = 26;
        let num_lines = ((total + chars_per_line - 1) / chars_per_line) as i32;
        let text_block_h = num_lines * line_h;
        let avail_top: i32 = 44;
        let avail_bottom: i32 = if select_label.is_some() { 175 } else { 205 };
        let start_y = avail_top + (avail_bottom - avail_top - text_block_h) / 2;
        let mut y = start_y;
        let mut offset: usize = 0;

        while offset < total && y < avail_bottom {
            let end = core::cmp::min(offset + chars_per_line, total);
            if let Ok(line) = core::str::from_utf8(&bytes[offset..end]) {
                let lw = measure_title(line);
                draw_lato_title(&mut self.display, line, (320 - lw) / 2, y, COLOR_TEXT);
            }
            y += line_h;
            offset = end;
        }

        if let Some(_idx) = addr_index {
            let btn_corner = CornerRadii::new(Size::new(6, 6));

            // In select mode: draw SELECT button between address and nav
            if let Some(sel_text) = select_label {
                let sel_w: u32 = 130;
                let sel_x: i32 = (320 - sel_w as i32) / 2;
                let sel_y: i32 = 150;
                let sel_h: u32 = 32;
                let sel_rect = Rectangle::new(Point::new(sel_x, sel_y), Size::new(sel_w, sel_h));
                RoundedRectangle::new(sel_rect, btn_corner)
                    .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
                    .draw(&mut self.display).ok();
                let sw = measure_title(sel_text);
                draw_lato_title(&mut self.display, sel_text, sel_x + (sel_w as i32 - sw) / 2, sel_y + 22, COLOR_BG);
            }

            // Bottom nav: [<] [#N] [>] always shown
            let btn_l = Rectangle::new(Point::new(10, 210), Size::new(50, 28));
            RoundedRectangle::new(btn_l, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(btn_l, btn_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();
            let lw = measure_title("<");
            draw_lato_title(&mut self.display, "<", 10 + (50 - lw) / 2, 230, KASPA_TEAL);

            // Center [#N] button
            let btn_c = Rectangle::new(Point::new(110, 210), Size::new(100, 28));
            RoundedRectangle::new(btn_c, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(btn_c, btn_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();
            let mut idx_label: heapless::String<8> = heapless::String::new();
            core::fmt::Write::write_fmt(&mut idx_label, format_args!("#{_idx}")).ok();
            let iw = measure_title(idx_label.as_str());
            draw_lato_title(&mut self.display, &idx_label, 110 + (100 - iw) / 2, 230, KASPA_TEAL);

            // [>] button
            let btn_r = Rectangle::new(Point::new(260, 210), Size::new(50, 28));
            RoundedRectangle::new(btn_r, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(btn_r, btn_corner)
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();
            let rw = measure_title(">");
            draw_lato_title(&mut self.display, ">", 260 + (50 - rw) / 2, 230, KASPA_TEAL);
        } else {
            let hw = measure_hint("Tap for QR | < Back");
            draw_lato_hint(&mut self.display, "Tap for QR | < Back", (320 - hw) / 2, 232, COLOR_TEXT_DIM);
        }

        self.draw_back_button();
    }

    /// Draw address index picker with numeric keypad.
    /// `input_val` is the current typed number string, `cursor` shows blinking state.
    pub fn draw_addr_index_screen(&mut self, input_str: &str) {
        self.display.clear(COLOR_BG).ok();

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

        self.draw_back_button();
    }

    /// Draw private key import screen with hex keypad
    pub fn draw_import_privkey_screen(&mut self, hex_chars: &[u8], hex_len: u8) {
        self.display.clear(COLOR_BG).ok();

        // Header
        let tw = measure_header("IMPORT KEY");
        draw_oswald_header(&mut self.display, "IMPORT KEY", (320 - tw) / 2, 26, COLOR_TEXT);
        Line::new(Point::new(20, 36), Point::new(300, 36))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Input display — lato_18, show last ~28 chars max
        let hl = hex_len as usize;
        let show_start = if hl > 28 { hl - 28 } else { 0 };
        let mut disp_buf: heapless::String<34> = heapless::String::new();
        if show_start > 0 {
            core::fmt::Write::write_str(&mut disp_buf, "..").ok();
        }
        for i in show_start..hl {
            core::fmt::Write::write_fmt(&mut disp_buf,
                format_args!("{}", hex_chars[i] as char)).ok();
        }
        let text_x: i32 = 10;
        let text_y: i32 = 62;
        let drawn_w = if !disp_buf.is_empty() {
            draw_lato_18(&mut self.display, &disp_buf, text_x, text_y, COLOR_TEXT)
        } else {
            0
        };
        // Cursor
        let cursor_x = text_x + drawn_w;
        embedded_graphics::primitives::Line::new(
            Point::new(cursor_x, text_y - 15),
            Point::new(cursor_x, text_y + 1),
        ).into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Unified keyboard (Hex mode)
        crate::ui::keyboard::draw_keyboard(&mut self.display, crate::ui::keyboard::KeyboardMode::Hex, 0);

        self.draw_back_button();
    }

    /// Draw confirm send screen with big touch-friendly buttons
    pub fn draw_confirm_send_screen(&mut self, amount_str: &str, fee_str: &str) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("CONFIRM SEND?");
        draw_oswald_header(&mut self.display, "CONFIRM SEND?", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Amount + Fee summary
        let mut line_buf: heapless::String<40> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut line_buf, format_args!("Send: {amount_str}")).ok();
        draw_lato_body(&mut self.display, &line_buf, 40, 68, COLOR_TEXT);

        let mut fee_buf: heapless::String<40> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut fee_buf, format_args!("Fee:  {fee_str}")).ok();
        draw_lato_body(&mut self.display, &fee_buf, 40, 90, COLOR_TEXT);

        // === BIG CONFIRM BUTTON (green) — y=120..170 ===
        let confirm_green = COLOR_GREEN_BTN;
        let btn_corner = CornerRadii::new(Size::new(8, 8));
        let confirm_rect = Rectangle::new(Point::new(30, 120), Size::new(260, 50));
        RoundedRectangle::new(confirm_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(confirm_green))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(confirm_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display).ok();
        let cw = measure_title("CONFIRM");
        draw_lato_title(&mut self.display, "CONFIRM", 30 + (260 - cw) / 2, 152, COLOR_TEXT);

        // === BIG CANCEL BUTTON (dark red) — y=182..227 ===
        let cancel_red = COLOR_RED_BTN;
        let cancel_rect = Rectangle::new(Point::new(30, 182), Size::new(260, 45));
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(cancel_red))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_RED_BTN, 2))
            .draw(&mut self.display).ok();
        let cw2 = measure_title("CANCEL");
        draw_lato_title(&mut self.display, "CANCEL", 30 + (260 - cw2) / 2, 212, COLOR_TEXT);
        self.draw_back_button();
    }

    /// Draw confirm send screen with multisig signature status
    pub fn draw_confirm_send_multisig(&mut self, amount_str: &str, fee_str: &str,
                                       sigs_present: u8, sigs_required: u8) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("CONFIRM MULTISIG?");
        draw_oswald_header(&mut self.display, "CONFIRM MULTISIG?", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Amount + Fee
        let mut line_buf: heapless::String<40> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut line_buf, format_args!("Send: {amount_str}")).ok();
        draw_lato_body(&mut self.display, &line_buf, 40, 62, COLOR_TEXT);

        let mut fee_buf: heapless::String<40> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut fee_buf, format_args!("Fee:  {fee_str}")).ok();
        draw_lato_body(&mut self.display, &fee_buf, 40, 82, COLOR_TEXT);

        // Signature status
        let mut sig_buf: heapless::String<32> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut sig_buf,
            format_args!("Sigs: {sigs_present}/{sigs_required} present")).ok();
        let sig_color = if sigs_present > 0 { KASPA_ACCENT } else { COLOR_TEXT_DIM };
        draw_lato_body(&mut self.display, sig_buf.as_str(), 40, 102, sig_color);

        // SIGN & PASS button (green) — y=118..158
        let btn_corner = CornerRadii::new(Size::new(8, 8));
        let confirm_rect = Rectangle::new(Point::new(30, 118), Size::new(260, 40));
        RoundedRectangle::new(confirm_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_GREEN_BTN))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(confirm_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display).ok();
        let label = "SIGN";
        let lw = measure_title(label);
        draw_lato_title(&mut self.display, label, 30 + (260 - lw) / 2, 145, COLOR_TEXT);

        // CANCEL button (red) — y=168..208
        let cancel_rect = Rectangle::new(Point::new(30, 168), Size::new(260, 40));
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_RED_BTN, 2))
            .draw(&mut self.display).ok();
        let cw = measure_title("CANCEL");
        draw_lato_title(&mut self.display, "CANCEL", 30 + (260 - cw) / 2, 195, COLOR_TEXT);

        self.draw_back_button();
    }

    // ═══════════════════════════════════════════════════════════════
    /// Draw mnemonic word display (one word at a time for secure backup)
    pub fn draw_word_screen(&mut self, word_num: u8, total_words: u8, word: &str) {
        self.display.clear(COLOR_BG).ok();

        // Title: "WORD 3/12"
        let mut title_buf: heapless::String<20> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("WORD {}/{}", word_num + 1, total_words)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 40, COLOR_TEXT);

        Line::new(Point::new(60, 55), Point::new(260, 55))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Number
        let mut num_buf: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut num_buf,
            format_args!("#{}", word_num + 1)).ok();
        let nw = measure_title(num_buf.as_str());
        draw_lato_title(&mut self.display, &num_buf, (320 - nw) / 2, 100, KASPA_TEAL);

        // Word (big, centered)
        let ww = measure_big(word);
        draw_rubik_big(&mut self.display, word, (320 - ww) / 2, 135, COLOR_TEXT);

        // Navigation hint
        let hw = measure_hint("Write it down! Tap for next.");
        draw_lato_hint(&mut self.display, "Write it down! Tap for next.", (320 - hw) / 2, 210, COLOR_HINT);

        self.draw_back_button();
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
        let r = (w.min(h) / 10).max(2);	// dot radius — slightly smaller // dot radius — slightly smaller

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

    /// Draw dice roll screen
    pub fn draw_dice_screen(&mut self, count: usize, target: usize) {
        self.display.clear(COLOR_BG).ok();

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

        self.draw_back_button();
    }

    /// Draw "saving to flash" progress screen
    pub fn draw_saving_screen(&mut self, message: &str) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("SAVING");
        draw_oswald_header(&mut self.display, "SAVING", (320 - tw) / 2, 90, KASPA_TEAL);
        let mw = measure_body(message);
        draw_lato_body(&mut self.display, message, (320 - mw) / 2, 125, COLOR_TEXT_DIM);
        // Draw empty progress bar track
        Rectangle::new(Point::new(40, 145), Size::new(240, 10))
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        sound::start_ticking();
    }

    /// Draw a loading/processing screen with a custom message
    pub fn draw_loading_screen(&mut self, message: &str) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("LOADING");
        draw_oswald_header(&mut self.display, "LOADING", (320 - tw) / 2, 90, KASPA_TEAL);
        let mw = measure_body(message);
        draw_lato_body(&mut self.display, message, (320 - mw) / 2, 125, COLOR_TEXT_DIM);
        // Draw empty progress bar track
        Rectangle::new(Point::new(40, 145), Size::new(240, 10))
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        sound::start_ticking();
    }

    /// Update just the progress bar fill (call from PBKDF2 callback). pct = 0..100
    pub fn update_progress_bar(&mut self, pct: u8) {
        let fill = (pct as u32).min(100) * 240 / 100;
        // Fill bar
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
        word_input: &crate::ui::setup_wizard::WordInput,
    ) {
        self.display.clear(COLOR_BG).ok();

        let mut title_buf: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("IMPORT {}/{}", word_idx + 1, word_count)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 24, COLOR_TEXT);

        self.draw_import_keyboard_full(word_input);
    }

    /// Draw calc last word screen
    pub fn draw_calc_last_word_screen(
        &mut self,
        word_idx: u8,
        word_count: u8,
        word_input: &crate::ui::setup_wizard::WordInput,
    ) {
        self.display.clear(COLOR_BG).ok();

        let entering = if word_count == 12 { 11u8 } else { 23u8 };
        let mut title_buf: heapless::String<30> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("CALC LAST {}/{}", word_idx + 1, entering)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 24, COLOR_TEXT);

        self.draw_import_keyboard_full(word_input);
    }

    /// Draw just the input area (prefix, cursor, suggestions) — no keyboard redraw
    pub fn draw_import_keyboard(&mut self, word_input: &crate::ui::setup_wizard::WordInput) {
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
                let word = crate::wallet::bip39::index_to_word(idx);
                let mut match_buf: heapless::String<24> = heapless::String::new();
                core::fmt::Write::write_fmt(&mut match_buf,
                    format_args!("= {word}")).ok();
                draw_lato_22_opaque(&mut self.display, &match_buf, cursor_x + 6, text_y, KASPA_TEAL, COLOR_BG);
            }
        }

        // Suggestion chips area (y=72..96): clear it first, then redraw chips.
        // This one benefits less from opaque paint because the chips have filled
        // rounded-rectangle backgrounds that already overdraw cleanly. But we
        // need to clear when chip count changes (3 → 0, etc).
        Rectangle::new(Point::new(0, 72), Size::new(320, 26))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        let chip_y: i32 = 72;
        if word_input.num_suggestions > 1 {
            let chip_corner = CornerRadii::new(Size::new(5, 5));
            for i in 0..(word_input.num_suggestions as usize).min(3) {
                let w = crate::wallet::bip39::index_to_word(word_input.suggestions[i]);
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
    fn draw_import_keyboard_full(&mut self, word_input: &crate::ui::setup_wizard::WordInput) {
        self.draw_import_keyboard(word_input);
        crate::ui::keyboard::draw_keyboard(&mut self.display, crate::ui::keyboard::KeyboardMode::Alpha, 0);
    }

    /// Draw word count choice screen (12 or 24)
    pub fn draw_choose_wc_screen(&mut self, action_name: &str) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header(action_name);
        draw_oswald_header(&mut self.display, action_name, (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let btn_corner = CornerRadii::new(Size::new(8, 8));

        // 12 Words button: y=70..130
        let btn12 = Rectangle::new(Point::new(30, 70), Size::new(260, 60));
        RoundedRectangle::new(btn12, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn12, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let w12 = measure_title("12 Words");
        draw_lato_title(&mut self.display, "12 Words", 30 + (260 - w12) / 2, 108, COLOR_TEXT);

        // 24 Words button: y=150..210
        let btn24 = Rectangle::new(Point::new(30, 150), Size::new(260, 60));
        RoundedRectangle::new(btn24, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn24, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let w24 = measure_title("24 Words");
        draw_lato_title(&mut self.display, "24 Words", 30 + (260 - w24) / 2, 188, COLOR_TEXT);

        self.draw_back_button();
    }
    /// Full passphrase screen including keyboard layout (for initial draw or page change)
    pub fn draw_passphrase_screen_full(&mut self, pp_input: &crate::ui::seed_manager::PassphraseInput) {
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
    pub fn draw_keyboard_screen(&mut self, pp_input: &crate::ui::seed_manager::PassphraseInput, _title: &str) {
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
    pub fn draw_keyboard_screen_full(&mut self, pp_input: &crate::ui::seed_manager::PassphraseInput, title: &str) {
        self.display.clear(COLOR_BG).ok();

        // Header — compact (only drawn on full redraw, not per-keypress)
        let tw = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - tw) / 2, 26, COLOR_TEXT);
        Line::new(Point::new(20, 36), Point::new(300, 36))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        self.draw_back_button();

        // Input text + cursor (partial redraw area)
        self.draw_keyboard_screen(pp_input, title);

        crate::ui::keyboard::draw_keyboard(&mut self.display, crate::ui::keyboard::KeyboardMode::Full, pp_input.page);
    }

    /// Draw seed list screen showing all populated slots + controls
    /// Layout: title, up to 4 slot rows, "New" button at bottom
    /// Each slot: [fingerprint] [12w/24w] [PP] — tap to activate
    /// Active slot has teal highlight
    pub fn draw_seed_list_screen(&mut self, seed_mgr: &crate::ui::seed_manager::SeedManager, scroll: u8) {
        self.display.clear(COLOR_BG).ok();

        // Header
        let tw = measure_header("SEEDS");
        draw_oswald_header(&mut self.display, "SEEDS", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Top buttons (y=44..72): darker teal fill, teal border, black text
        // Always show all 3 buttons — if no seed, they all go to Tools
        {
            let btn_w: u32 = 95;
            let btn_gap: i32 = 6;
            let btn_y: i32 = 44;
            let btn_h: u32 = 28;
            let btn_corner = CornerRadii::new(Size::new(6, 6));
            let teal_btn = Rgb565::new(0b00100, 0b011000, 0b01110); // ~#206858 dark teal

            let btn_labels: [&str; 3] = if let Some(slot) = seed_mgr.active_slot() {
                if slot.is_raw_key() {
                    ["", "Address", "Export"]
                } else {
                    ["Sign TX", "Address", "Export"]
                }
            } else {
                ["Sign TX", "Address", "Export"]
            };

            let active_count = btn_labels.iter().filter(|l| !l.is_empty()).count() as i32;
            let total_btn_w = active_count * btn_w as i32 + (active_count - 1) * btn_gap;
            let mut bx = (320 - total_btn_w) / 2;

            for &label in btn_labels.iter() {
                if label.is_empty() { continue; }
                let btn_rect = Rectangle::new(Point::new(bx, btn_y), Size::new(btn_w, btn_h));
                RoundedRectangle::new(btn_rect, btn_corner)
                    .into_styled(PrimitiveStyle::with_fill(teal_btn))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(btn_rect, btn_corner)
                    .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                    .draw(&mut self.display).ok();
                let lw = measure_title(label);
                draw_lato_title(&mut self.display, label, bx + (btn_w as i32 - lw) / 2, btn_y + 20, COLOR_BG);
                bx += btn_w as i32 + btn_gap;
            }
        }

        // Collect indices of non-empty slots
        let mut loaded: [usize; 16] = [0; 16];
        let mut loaded_count: usize = 0;
        for i in 0..crate::ui::seed_manager::MAX_SLOTS {
            if !seed_mgr.slots[i].is_empty() {
                loaded[loaded_count] = i;
                loaded_count += 1;
            }
        }

        // Seed rows: y=78, always draw 3 rows
        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let start_y: i32 = 78;
        let card_w: u32 = 232;
        let start_x: i32 = 44;
        let card_corner = CornerRadii::new(Size::new(6, 6));
        let max_visible: usize = 3;
        let teal_dark = Rgb565::new(0b00001, 0b000100, 0b00010);

        // Page-based scroll: scroll value is always a multiple of max_visible
        let scroll_off = scroll as usize;

        // Always draw 3 rows — filled if seed exists, dim outline if empty
        for vis in 0..max_visible {
            let row_y = start_y + (vis as i32) * (card_h + card_gap);
            let list_idx = scroll_off + vis;

            if list_idx < loaded_count {
                // Filled seed row
                let i = loaded[list_idx];
                let slot = &seed_mgr.slots[i];
                let is_active = seed_mgr.active == i as u8;

                let bg = if is_active { COLOR_CARD_BORDER } else { COLOR_CARD };
                let border = if is_active { KASPA_TEAL } else { COLOR_CARD_BORDER };
                let slot_rect = Rectangle::new(Point::new(start_x, row_y), Size::new(card_w, card_h as u32));
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(bg))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(border, 1))
                    .draw(&mut self.display).ok();

                // Fingerprint icon
                let icon_color = if is_active { KASPA_TEAL } else { COLOR_TEXT };
                let fp_icon = size24px::identity::Fingerprint::new(icon_color);
                Image::new(&fp_icon, Point::new(start_x + 6, row_y + 9)).draw(&mut self.display).ok();

                // Fingerprint hex
                let mut fp_hex = [0u8; 8];
                slot.fingerprint_hex(&mut fp_hex);
                let fp_str = core::str::from_utf8(&fp_hex).unwrap_or("????????");
                let fp_color = if is_active { KASPA_TEAL } else { COLOR_TEXT };
                draw_lato_title(&mut self.display, fp_str, start_x + 36, row_y + 28, fp_color);

                // Slot type label
                let type_str = match slot.word_count {
                    1 => "KEY", 2 => "xprv", 12 => "12w", 24 => "24w", _ => "??",
                };
                draw_lato_body(&mut self.display, type_str, start_x + 130, row_y + 28, fp_color);

                // Passphrase indicator
                if (slot.word_count == 12 || slot.word_count == 24) && slot.passphrase_len > 0 {
                    draw_lato_hint(&mut self.display, "PP", start_x + 170, row_y + 26, COLOR_ORANGE);
                }

                // Delete button — trash icon
                let del_rect = Rectangle::new(Point::new(start_x + 188, row_y + 3), Size::new(38, 36));
                let del_corner = CornerRadii::new(Size::new(4, 4));
                RoundedRectangle::new(del_rect, del_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
                    .draw(&mut self.display).ok();
                use embedded_graphics::image::ImageRawLE;
                let trash_raw: ImageRawLE<Rgb565> = ImageRawLE::new(
                    crate::hw::icon_data::ICON_TRASH, crate::hw::icon_data::ICON_TRASH_W);
                Image::new(&trash_raw, Point::new(start_x + 197, row_y + 9)).draw(&mut self.display).ok();
            } else {
                // Empty row — tappable to go to Tools menu
                let slot_rect = Rectangle::new(Point::new(start_x, row_y), Size::new(card_w, card_h as u32));
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                    .draw(&mut self.display).ok();
                let pw = measure_title("+");
                draw_lato_title(&mut self.display, "+", start_x + (card_w as i32 - pw) / 2, row_y + 28, COLOR_TEXT_DIM);
            }
        }

        // L/R strip arrows — ALWAYS visible
        // visible_total includes one extra empty row for "add new" (capped at MAX_SLOTS)
        let visible_total = (loaded_count + 1).min(crate::ui::seed_manager::MAX_SLOTS);
        let arrow_cy = start_y + (max_visible as i32 * (card_h + card_gap) - card_gap) / 2;
        let can_up = scroll_off > 0;
        let can_down = visible_total > max_visible && scroll_off + max_visible < visible_total;

        let arr_color = if can_up { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(5, arrow_cy), Point::new(30, arrow_cy - 17), Point::new(30, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(arr_color))
            .draw(&mut self.display).ok();

        let arr_color = if can_down { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(315, arrow_cy), Point::new(290, arrow_cy - 17), Point::new(290, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(arr_color))
            .draw(&mut self.display).ok();

        // Page dots — always visible if more than 1 page
        if visible_total > max_visible {
            let total_pages = ((visible_total + max_visible - 1) / max_visible) as u8;
            let current_page = (scroll_off / max_visible) as u8;
            let dot_d: i32 = 7;
            let dot_gap: i32 = 8;
            let total_w = (total_pages as i32) * dot_d + ((total_pages as i32) - 1) * dot_gap;
            let dot_start_x = (320 - total_w) / 2;
            for p in 0..total_pages {
                let dx = dot_start_x + (p as i32) * (dot_d + dot_gap);
                let color = if p == current_page { KASPA_ACCENT } else { teal_dark };
                Circle::new(Point::new(dx, 232), dot_d as u32)
                    .into_styled(PrimitiveStyle::with_fill(color))
                    .draw(&mut self.display).ok();
            }
        }

        self.draw_back_button();
    }

    /// Draw SeedQR export screen (QR with title)
    /// Draw a full-screen QR code with title. Reusable for any data.
    pub fn draw_qr_fullscreen(&mut self, data: &[u8], _title: &str) {
        self.display.clear(COLOR_BG).ok();

        // Guard: QR encoder supports V1-V6 (max 134 bytes).
        if data.len() > 134 {
            let ew = measure_title("QR Error — too large");
            draw_lato_title(&mut self.display, "QR Error — too large", (320 - ew) / 2, 120, COLOR_DANGER);
            return;
        }

        if let Ok(qr) = crate::qr::encoder::encode(data) {
            let qr_size = qr.size as i32;
            let max_px = (DISPLAY_H as i32) - 8; // 232px usable
            let scale = (max_px / qr_size).max(1);
            let total = qr_size * scale;
            let offset_x = (DISPLAY_W as i32 - total) / 2;
            let offset_y = (DISPLAY_H as i32 - total) / 2;

            Rectangle::new(
                Point::new(offset_x - 4, offset_y - 4),
                Size::new((total + 8) as u32, (total + 8) as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

            for y in 0..qr_size {
                for x in 0..qr_size {
                    if qr.get(x as u8, y as u8) {
                        Rectangle::new(
                            Point::new(offset_x + x * scale, offset_y + y * scale),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                        .draw(&mut self.display).ok();
                    }
                }
            }
        } else {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }
    }

    pub fn draw_export_seed_qr_screen(&mut self, data: &[u8], word_count: u8) {
        self.display.clear(COLOR_BG).ok();
        let mut title_buf: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("SeedQR ({word_count} words)")).ok();
        let tw = measure_hint(title_buf.as_str());
        draw_lato_hint(&mut self.display, &title_buf, (320 - tw) / 2, 14, KASPA_TEAL);

        let hw = measure_hint("Tap for grid view");
        draw_lato_hint(&mut self.display, "Tap for grid view", (320 - hw) / 2, 238, COLOR_HINT);

        if let Ok(qr) = crate::qr::encoder::encode(data) {
            let qr_size = qr.size as i32;
            let scale = (200 / qr_size).max(1);
            let total = qr_size * scale;
            let offset_x = (DISPLAY_W as i32 - total) / 2;
            let offset_y = 20 + (210 - total) / 2;

            Rectangle::new(
                Point::new(offset_x - 4, offset_y - 4),
                Size::new((total + 8) as u32, (total + 8) as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

            for y in 0..qr_size {
                for x in 0..qr_size {
                    if qr.get(x as u8, y as u8) {
                        Rectangle::new(
                            Point::new(offset_x + x * scale, offset_y + y * scale),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                        .draw(&mut self.display).ok();
                    }
                }
            }
        } else {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }
    }

    /// Draw CompactSeedQR screen (21x21 for 12w, 25x25 for 24w)
    pub fn draw_export_compact_seedqr_screen(&mut self, data: &[u8], word_count: u8) {
        self.display.clear(COLOR_BG).ok();
        let size_str = if word_count == 12 { "21x21" } else { "25x25" };
        let mut title_buf: heapless::String<32> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("CompactSeedQR {size_str} ({word_count}w)")).ok();
        let tw = measure_hint(title_buf.as_str());
        draw_lato_hint(&mut self.display, &title_buf, (320 - tw) / 2, 14, KASPA_TEAL);

        let hw = measure_hint("Tap for grid view");
        draw_lato_hint(&mut self.display, "Tap for grid view", (320 - hw) / 2, 238, COLOR_HINT);

        if let Ok(qr) = crate::qr::encoder::encode(data) {
            let qr_size = qr.size as i32;
            let scale = (200 / qr_size).max(1);
            let total = qr_size * scale;
            let offset_x = (DISPLAY_W as i32 - total) / 2;
            let offset_y = 20 + (210 - total) / 2;

            Rectangle::new(
                Point::new(offset_x - 4, offset_y - 4),
                Size::new((total + 8) as u32, (total + 8) as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

            for y in 0..qr_size {
                for x in 0..qr_size {
                    if qr.get(x as u8, y as u8) {
                        Rectangle::new(
                            Point::new(offset_x + x * scale, offset_y + y * scale),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                        .draw(&mut self.display).ok();
                    }
                }
            }
        } else {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }
    }

    /// Draw Plain Words QR export — BIP39 words as space-separated text QR
    pub fn draw_export_plain_words_qr(&mut self, indices: &[u16; 24], word_count: u8) {
        self.display.clear(COLOR_BG).ok();
        let mut title_buf: heapless::String<32> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("Plain Words ({word_count} words)")).ok();
        let tw = measure_hint(title_buf.as_str());
        draw_lato_hint(&mut self.display, &title_buf, (320 - tw) / 2, 14, KASPA_TEAL);

        let hw = measure_hint("Tap to go back");
        draw_lato_hint(&mut self.display, "Tap to go back", (320 - hw) / 2, 238, COLOR_HINT);

        // Build space-separated word string: "abandon ability able..."
        // 12 words: max ~96 bytes, 24 words: max ~192 bytes
        let mut words_buf = [0u8; 256];
        let mut pos: usize = 0;
        let wc = word_count as usize;
        for i in 0..wc {
            let word = crate::wallet::bip39::index_to_word(indices[i]);
            let wbytes = word.as_bytes();
            if pos + wbytes.len() + 1 > words_buf.len() { break; }
            if i > 0 {
                words_buf[pos] = b' ';
                pos += 1;
            }
            words_buf[pos..pos + wbytes.len()].copy_from_slice(wbytes);
            pos += wbytes.len();
        }

        if let Ok(qr) = crate::qr::encoder::encode(&words_buf[..pos]) {
            let qr_size = qr.size as i32;
            let scale = (200 / qr_size).max(1);
            let total = qr_size * scale;
            let offset_x = (DISPLAY_W as i32 - total) / 2;
            let offset_y = 20 + (210 - total) / 2;

            Rectangle::new(
                Point::new(offset_x - 4, offset_y - 4),
                Size::new((total + 8) as u32, (total + 8) as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

            for y in 0..qr_size {
                for x in 0..qr_size {
                    if qr.get(x as u8, y as u8) {
                        Rectangle::new(
                            Point::new(offset_x + x * scale, offset_y + y * scale),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                        .draw(&mut self.display).ok();
                    }
                }
            }
        } else {
            let ew = measure_title("QR Error — too large");
            draw_lato_title(&mut self.display, "QR Error — too large", (320 - ew) / 2, 120, COLOR_DANGER);
        }
    }

    /// Draw zoomed SeedQR grid view for manual card filling.
    /// Shows a 7x7 window into the QR, with row/col labels and navigation arrows.
    pub fn draw_seedqr_grid(&mut self, data: &[u8], _word_count: u8, pan_x: u8, pan_y: u8) {
        self.display.clear(COLOR_BG).ok();

        if let Ok(qr) = crate::qr::encoder::encode(data) {
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

            // Navigation triangles — same style as seeds/tools menu
            // Left strip: < (top) and > (bottom) for horizontal pan
            // Right strip: ^ (top) and v (bottom) for vertical pan
            let max_pan = qr_size.saturating_sub(view_cells);
            let teal_dark = Rgb565::new(0, 20, 10);

            // Left strip — horizontal navigation
            let lx = 18i32; // center of left strip
            let ly_top = 80i32;  // < arrow (pan left)
            let ly_bot = 160i32; // > arrow (pan right)

            // < arrow (pan left) — points left
            let arr_color = if pan_x > 0 { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(lx - 12, ly_top), Point::new(lx + 12, ly_top - 15), Point::new(lx + 12, ly_top + 15),
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();

            // > arrow (pan right) — points right
            let arr_color = if pan_x < max_pan { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(lx + 12, ly_bot), Point::new(lx - 12, ly_bot - 15), Point::new(lx - 12, ly_bot + 15),
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();

            // Right strip — vertical navigation
            let rx = 302i32; // center of right strip
            let ry_top = 80i32;  // ^ arrow (pan up)
            let ry_bot = 160i32; // v arrow (pan down)

            // ^ arrow (pan up) — points up
            let arr_color = if pan_y > 0 { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(rx, ry_top - 12), Point::new(rx - 15, ry_top + 12), Point::new(rx + 15, ry_top + 12),
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();

            // v arrow (pan down) — points down
            let arr_color = if pan_y < max_pan { KASPA_TEAL } else { teal_dark };
            Triangle::new(
                Point::new(rx, ry_bot + 12), Point::new(rx - 15, ry_bot - 12), Point::new(rx + 15, ry_bot - 12),
            ).into_styled(PrimitiveStyle::with_fill(arr_color))
                .draw(&mut self.display).ok();

        } else {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }

        self.draw_back_button();
    }

    /// Draw kpub export screen — shows the kpub string as a QR code
    /// for importing into Kaspium/KasWare as a watch-only wallet.
    /// Draw export private key screen — shows hex string + QR
    /// WARNING: This shows sensitive key material on screen!
    pub fn draw_export_privkey_screen(&mut self, hex_str: &[u8; 64]) {
        self.display.clear(COLOR_BG).ok();

        let warn_color = Rgb565::new(31, 24, 0); // amber
        let tw = measure_hint("! PRIVATE KEY !");
        draw_lato_hint(&mut self.display, "! PRIVATE KEY !", (320 - tw) / 2, 14, warn_color);

        // Show hex as QR code
        if let Ok(qr) = crate::qr::encoder::encode(hex_str) {
            let qr_size = qr.size as i32;
            let scale = (150 / qr_size).max(1);
            let total = qr_size * scale;
            let offset_x = (DISPLAY_W as i32 - total) / 2;
            let offset_y = 20 + (160 - total) / 2;

            Rectangle::new(
                Point::new(offset_x - 4, offset_y - 4),
                Size::new((total + 8) as u32, (total + 8) as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

            for y in 0..qr_size {
                for x in 0..qr_size {
                    if qr.get(x as u8, y as u8) {
                        Rectangle::new(
                            Point::new(offset_x + x * scale, offset_y + y * scale),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                        .draw(&mut self.display).ok();
                    }
                }
            }
        }

        // Show first 32 and last 32 hex chars — centered
        if let Ok(s1) = core::str::from_utf8(&hex_str[..32]) {
            let w1 = measure_hint(s1);
            draw_lato_hint(&mut self.display, s1, (320 - w1) / 2, 195, COLOR_TEXT);
        }
        if let Ok(s2) = core::str::from_utf8(&hex_str[32..64]) {
            let w2 = measure_hint(s2);
            draw_lato_hint(&mut self.display, s2, (320 - w2) / 2, 210, COLOR_TEXT);
        }

        let bw = measure_hint("Tap to dismiss — KEEP SECRET");
        draw_lato_hint(&mut self.display, "Tap to dismiss — KEEP SECRET", (320 - bw) / 2, 232, warn_color);
    }

    /// Draw export choice screen — uses same paged list layout as draw_menu_screen
    pub fn draw_export_choice_screen(&mut self, menu: &crate::app::input::Menu) {
        self.draw_menu_screen("EXPORT WALLET", menu);
    }

    /// Draw xprv export screen — shows xprv as QR with warning
    pub fn draw_export_xprv_screen(&mut self, xprv_str: &[u8], xprv_len: usize) {
        self.display.clear(COLOR_BG).ok();

        let warn_color = Rgb565::new(31, 24, 0);
        let tw = measure_hint("! xprv — KEEP SECRET !");
        draw_lato_hint(&mut self.display, "! xprv — KEEP SECRET !", (320 - tw) / 2, 14, warn_color);

        if let Ok(qr) = crate::qr::encoder::encode(&xprv_str[..xprv_len]) {
            let qr_size = qr.size as i32;
            let scale = (190 / qr_size).max(1);
            let total = qr_size * scale;
            let offset_x = (DISPLAY_W as i32 - total) / 2;
            let offset_y = 20 + (200 - total) / 2;

            Rectangle::new(
                Point::new(offset_x - 4, offset_y - 4),
                Size::new((total + 8) as u32, (total + 8) as u32),
            )
            .into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
            .draw(&mut self.display).ok();

            for y in 0..qr_size {
                for x in 0..qr_size {
                    if qr.get(x as u8, y as u8) {
                        Rectangle::new(
                            Point::new(offset_x + x * scale, offset_y + y * scale),
                            Size::new(scale as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                        .draw(&mut self.display).ok();
                    }
                }
            }
        } else {
            let ew = measure_title("QR Error");
            draw_lato_title(&mut self.display, "QR Error", (320 - ew) / 2, 120, COLOR_DANGER);
        }

        let hw = measure_hint("Tap to dismiss");
        draw_lato_hint(&mut self.display, "Tap to dismiss", (320 - hw) / 2, 232, warn_color);
    }

    // draw_settings_menu_screen removed — now uses draw_menu_screen with persistent settings_menu

    /// Draw SD card settings screen
    pub fn draw_sdcard_settings(&mut self, card_present: bool, card_type_str: &str, _seed_loaded: bool) {
        self.display.clear(COLOR_BG).ok();

        self.draw_back_button();

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
            let sw = measure_body("Card detected");
            draw_lato_body(&mut self.display, "Card detected", (320 - sw) / 2, 85, KASPA_TEAL);

            // Buttons — rounded, centered
            let btn_corner = CornerRadii::new(Size::new(6, 6));
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

    /// Draw SD card formatting progress
    pub fn draw_sdcard_formatting(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let s1 = "Formatting...";
        let s1w = measure_title(s1);
        draw_lato_title(&mut self.display, s1, (320 - s1w) / 2, 100, KASPA_TEAL);
        let s2 = "Do not remove card";
        let s2w = measure_body(s2);
        draw_lato_body(&mut self.display, s2, (320 - s2w) / 2, 135, COLOR_TEXT_DIM);
    }

    /// Draw SD card format complete
    pub fn draw_sdcard_format_done(&mut self, success: bool) {
        use embedded_graphics::image::{Image, ImageRawLE};

        if success {
            static LOGO_DATA: &[u8] = include_bytes!("../../assets/logo_320x240.raw");
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

    /// Draw SD card R/W test in progress
    pub fn draw_sdcard_testing(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let s1 = "Testing R/W...";
        let s1w = measure_title(s1);
        draw_lato_title(&mut self.display, s1, (320 - s1w) / 2, 100, KASPA_TEAL);
        let s2 = "Do not remove card";
        let s2w = measure_body(s2);
        draw_lato_body(&mut self.display, s2, (320 - s2w) / 2, 135, COLOR_TEXT_DIM);
    }

    /// Draw SD card R/W test result (multi-line)
    pub fn draw_sdcard_test_result(&mut self, lines: &[&str], success: bool) {
        use embedded_graphics::image::{Image, ImageRawLE};

        if success {
            static LOGO_DATA: &[u8] = include_bytes!("../../assets/logo_320x240.raw");
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

    /// Draw SD backup password security warning screen
    /// Shows before entering the password, with [OK] to continue
    pub fn draw_sd_backup_warning(&mut self) {
        self.display.clear(COLOR_BG).ok();

        let warn_color = Rgb565::new(31, 24, 0); // amber/yellow
        let orange = Rgb565::new(31, 20, 0); // orange for emphasis
        let tw = measure_header("! WARNING !");
        draw_oswald_header(&mut self.display, "! WARNING !", (320 - tw) / 2, 25, warn_color);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(warn_color, 1))
            .draw(&mut self.display).ok();

        // Line 1: strong password requirement (orange)
        let l1 = "Choose a STRONG password:";
        let l1w = measure_body(l1);
        draw_lato_body(&mut self.display, l1, (320 - l1w) / 2, 60, orange);

        // Lines 2-4: requirements (white)
        let l2 = "8+ characters minimum";
        let l2w = measure_body(l2);
        draw_lato_body(&mut self.display, l2, (320 - l2w) / 2, 85, COLOR_TEXT);
        let l3 = "Mix letters + numbers";
        let l3w = measure_body(l3);
        draw_lato_body(&mut self.display, l3, (320 - l3w) / 2, 105, COLOR_TEXT);
        let l4 = "NOT your BIP39 passphrase";
        let l4w = measure_body(l4);
        draw_lato_body(&mut self.display, l4, (320 - l4w) / 2, 125, orange);

        // Lines 5-6: unrecoverable warning (orange)
        let l5 = "If you lose this password,";
        let l5w = measure_body(l5);
        draw_lato_body(&mut self.display, l5, (320 - l5w) / 2, 155, COLOR_TEXT);
        let l6 = "the backup is UNRECOVERABLE.";
        let l6w = measure_body(l6);
        draw_lato_body(&mut self.display, l6, (320 - l6w) / 2, 175, orange);

        // [I understand] button — bigger, centered
        let btn_corner = CornerRadii::new(Size::new(8, 8));
        let ok_rect = Rectangle::new(Point::new(85, 205), Size::new(150, 32));
        RoundedRectangle::new(ok_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(Rgb565::new(2, 8, 2)))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(ok_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display).ok();
        let uw = measure_body("I understand");
        draw_lato_body(&mut self.display, "I understand", 85 + (150 - uw) / 2, 226, KASPA_TEAL);

        self.draw_back_button();
    }

    /// Draw SD file list for restore — shows up to 8 backup files found on SD
    /// Draw SD file list. If `seed_fps` is provided (up to 4 fingerprints from loaded seeds),
    /// files whose name matches a fingerprint will show the slot label (e.g. "Seed #1").
    pub fn draw_sd_file_list_ex(
        &mut self, files: &[[u8; 11]], count: u8, scroll: u8,
        seed_fps: &[[u8; 4]; 4], seed_count: u8,
    ) {
        self.display.clear(COLOR_BG).ok();

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
                let dlen = crate::hw::sd_backup::format_83_display(&files[abs as usize], &mut disp);

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
                    crate::hw::icon_data::ICON_TRASH, crate::hw::icon_data::ICON_TRASH_W);
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

        self.draw_back_button();
    }

    pub fn draw_sd_file_list(&mut self, files: &[[u8; 11]], count: u8, scroll: u8) {
        let empty_fps = [[0u8; 4]; 4];
        self.draw_sd_file_list_ex(files, count, scroll, &empty_fps, 0);
    }

    /// Draw display settings screen (brightness control)
    pub fn draw_display_settings(&mut self, brightness: u8) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("DISPLAY");
        draw_oswald_header(&mut self.display, "DISPLAY", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let bw = measure_body("Brightness:");
        draw_lato_body(&mut self.display, "Brightness:", (320 - bw) / 2, 65, COLOR_TEXT);

        let btn_bg = COLOR_CARD;
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        // [-] button
        let btn_m = Rectangle::new(Point::new(20, 80), Size::new(40, 30));
        RoundedRectangle::new(btn_m, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(btn_bg))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_m, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "-", 33, 101, COLOR_TEXT);

        // [+] button
        let btn_p = Rectangle::new(Point::new(260, 80), Size::new(40, 30));
        RoundedRectangle::new(btn_p, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(btn_bg))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_p, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "+", 272, 101, COLOR_TEXT);

        // Draw bar + value (shared with partial update)
        self.update_brightness_bar(brightness);

        self.draw_back_button();
    }

    /// Partial redraw: only the brightness bar fill + percentage text.
    /// Much faster than full screen redraw during drag.
    pub fn update_brightness_bar(&mut self, brightness: u8) {
        // Clear bar area (bar + border)
        Rectangle::new(Point::new(70, 85), Size::new(180, 20))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // Bar outline
        Rectangle::new(Point::new(70, 85), Size::new(180, 20))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT, 1))
            .draw(&mut self.display).ok();

        // Bar fill
        let bar_w = (brightness as u32) * 180 / 255;
        if bar_w > 0 {
            Rectangle::new(Point::new(70, 85), Size::new(bar_w, 20))
                .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
                .draw(&mut self.display).ok();
        }

        // Clear percentage area
        Rectangle::new(Point::new(100, 115), Size::new(120, 30))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // Percentage text
        let pct = (brightness as u16 * 100 / 255) as u8;
        let mut pct_buf: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut pct_buf, format_args!("{pct}%")).ok();
        let pw = measure_title(pct_buf.as_str());
        draw_lato_title(&mut self.display, &pct_buf, (320 - pw) / 2, 135, COLOR_TEXT);
    }

    /// Draw audio settings screen (volume control) — M5Stack only
    #[cfg(feature = "m5stack")]
    pub fn draw_audio_settings(&mut self, volume: u8) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("AUDIO");
        draw_oswald_header(&mut self.display, "AUDIO", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let bw = measure_body("Volume:");
        draw_lato_body(&mut self.display, "Volume:", (320 - bw) / 2, 65, COLOR_TEXT);

        let btn_bg = COLOR_CARD;
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        // [-] button
        let btn_m = Rectangle::new(Point::new(20, 80), Size::new(40, 30));
        RoundedRectangle::new(btn_m, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(btn_bg))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_m, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "-", 33, 101, COLOR_TEXT);

        // [+] button
        let btn_p = Rectangle::new(Point::new(260, 80), Size::new(40, 30));
        RoundedRectangle::new(btn_p, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(btn_bg))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_p, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "+", 272, 101, COLOR_TEXT);

        // Bar outline
        Rectangle::new(Point::new(70, 85), Size::new(180, 20))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT, 1))
            .draw(&mut self.display).ok();

        // Bar fill
        let bar_w = (volume as u32) * 180 / 255;
        if bar_w > 0 {
            Rectangle::new(Point::new(70, 85), Size::new(bar_w, 20))
                .into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT))
                .draw(&mut self.display).ok();
        }

        // Percentage text
        let pct = (volume as u16 * 100 / 255) as u8;
        let mut pct_buf: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut pct_buf, format_args!("{}%", pct)).ok();
        let pw = measure_title(pct_buf.as_str());
        draw_lato_title(&mut self.display, &pct_buf, (320 - pw) / 2, 135, COLOR_TEXT);

        self.draw_back_button();
    }

    /// Draw camera / QR scanner screen
    /// Shows status info and a viewfinder-style frame
    pub fn draw_camera_screen(&mut self, _status: &str, _hint: &str) {
        self.display.clear(COLOR_BG).ok();
        #[cfg(feature = "waveshare")]
        self.draw_camera_screen_chrome();
        #[cfg(feature = "m5stack")]
        {
            self.draw_back_button();
            let tw = measure_header("SCAN QR");
            draw_oswald_header(&mut self.display, "SCAN QR", (320 - tw) / 2, 30, COLOR_TEXT);
            Line::new(Point::new(20, 40), Point::new(300, 40))
                .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                .draw(&mut self.display).ok();
        }
    }

    /// Draw only the ScanQR chrome (back icon, gear icon, header) without clearing screen.
    /// Used when returning from cam-tune overlay to avoid full redraw cycle.
    #[cfg(feature = "waveshare")]
    pub fn draw_camera_screen_chrome(&mut self) {
        // Back icon only (no home — gear replaces it on ScanQR)
        use embedded_graphics::image::{Image, ImageRawLE};
        let back: ImageRawLE<Rgb565> = ImageRawLE::new(
            crate::hw::icon_data::ICON_BACK, crate::hw::icon_data::ICON_BACK_W);
        Image::new(&back, Point::new(0, 0)).draw(&mut self.display).ok();
        self.draw_gear_icon();

        let tw = measure_header("SCAN QR");
        draw_oswald_header(&mut self.display, "SCAN QR", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
    }

    /// Blit a grayscale camera frame into the viewfinder area.
    /// Renders at (40, 30) with 240x180 pixels, leaving top 30px for back button.
    /// Redraws back button after blit so it's always visible during streaming.
    pub fn blit_camera_frame(&mut self, frame: &[u8], width: usize, height: usize,
                             qr_guide_info: u8) {
        use embedded_graphics::primitives::{Rectangle, PrimitiveStyle};
        use embedded_graphics::prelude::*;
        use embedded_graphics::pixelcolor::Rgb565;
        use embedded_graphics::draw_target::DrawTarget;
        
        // Display area: centered below header chrome
        // Waveshare: 240x180 at (40, 45) — cam-tune can expand to (0, 0)
        // M5Stack: 240x194 at (40, 42) — below 42px chrome zone (back+header+divider)
        #[cfg(feature = "waveshare")]
        let cam_tune_mode = (qr_guide_info & 0x40) != 0;
        #[cfg(feature = "waveshare")]
        let (vf_x, vf_y, vf_w, vf_h) = if cam_tune_mode {
            (0i32, 0i32, 198usize, 178usize)
        } else {
            (40i32, 45i32, 240usize, 180usize)
        };
        #[cfg(feature = "m5stack")]
        let (vf_x, vf_y, vf_w, vf_h) = (40i32, 44i32, 240usize, 180usize);

        if width == 0 || height == 0 { return; }

        let dw = vf_w;
        let dh = vf_h;

        // Decode guide info: bit 7 = finders active
        let finders_active = (qr_guide_info & 0x80) != 0;

        // Frame border: 2px thick around entire viewfinder
        // Red/orange when idle, flashing green when finders detected
        let border_w = 2i32;
        let border_color = if finders_active {
            // Flash between bright and dim green using frame data parity
            let flash = (frame[0] as u16 + frame[width/2] as u16) & 1;
            if flash == 0 {
                Rgb565::new(0, 63, 0)
            } else {
                Rgb565::new(0, 42, 0)
            }
        } else {
            Rgb565::new(20, 8, 0) // dim red/amber — "scanning"
        };

        for vy in 0..dh {
            let src_y = if height > vf_h {
                vy * height / vf_h
            } else {
                vy * height / dh
            };
            if src_y >= height { break; }
            
            let area = Rectangle::new(
                Point::new(vf_x, vf_y + vy as i32),
                Size::new(dw as u32, 1),
            );
            
            let abs_y = vf_y + vy as i32;
            let on_top_border = abs_y < vf_y + border_w;
            let on_bot_border = abs_y >= vf_y + vf_h as i32 - border_w;

            let row_start = src_y * width;
            let _ = self.display.fill_contiguous(
                &area,
                (0..dw).map(move |vx| {
                    let abs_x = vf_x + vx as i32;
                    let on_left = abs_x < vf_x + border_w;
                    let on_right = abs_x >= vf_x + vf_w as i32 - border_w;
                    if on_top_border || on_bot_border || on_left || on_right {
                        return border_color;
                    }

                    let sx = if width >= vf_w {
                        (vx * width / vf_w).min(width - 1)
                    } else {
                        (vx * width / dw).min(width - 1)
                    };
                    let gray = frame[row_start + sx];
                    Rgb565::new(gray >> 3, gray >> 2, gray >> 3)
                }),
            );
        }

        // Icons persist outside blit rectangle — no per-frame redraw needed.
    }

    // ═══════════════════════════════════════════════════════════════
    // Confirm Seed Deletion Screen
    // ═══════════════════════════════════════════════════════════════

    /// Draw warning screen before deleting a seed slot.
    /// Shows fingerprint, word count, warning text, and CANCEL / DELETE buttons.
    pub fn draw_confirm_delete_screen(&mut self, fp_str: &str, word_count: u8) {
        self.display.clear(COLOR_BG).ok();

        // Header
        let tw = measure_header("DELETE SEED?");
        draw_oswald_header(&mut self.display, "DELETE SEED?", (320 - tw) / 2, 30, COLOR_ORANGE);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_RED_BTN, 1))
            .draw(&mut self.display).ok();

        // Slot info: fingerprint + type
        let type_str = match word_count {
            1 => "KEY", 2 => "xprv", 12 => "12-word seed", 24 => "24-word seed", _ => "seed",
        };
        let mut info_buf: heapless::String<40> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut info_buf, format_args!("Slot: {fp_str} ({type_str})")).ok();
        let iw = measure_body(&info_buf);
        draw_lato_body(&mut self.display, &info_buf, (320 - iw) / 2, 65, COLOR_TEXT);

        // Warning lines — all centered
        let w1 = measure_body("This action is irreversible.");
        draw_lato_body(&mut self.display, "This action is irreversible.", (320 - w1) / 2, 95, COLOR_ORANGE);
        let w2 = measure_body("Without a backup, your funds");
        draw_lato_body(&mut self.display, "Without a backup, your funds", (320 - w2) / 2, 120, COLOR_TEXT);
        let w3 = measure_body("will be permanently lost.");
        draw_lato_body(&mut self.display, "will be permanently lost.", (320 - w3) / 2, 145, COLOR_TEXT);

        // === CANCEL button (left, teal outline) — y=185..225 ===
        let btn_corner = CornerRadii::new(Size::new(8, 8));
        let cancel_rect = Rectangle::new(Point::new(30, 185), Size::new(120, 40));
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display).ok();
        let cw = measure_title("CANCEL");
        draw_lato_title(&mut self.display, "CANCEL", 30 + (120 - cw) / 2, 212, KASPA_TEAL);

        // === DELETE button (right, red fill) — y=185..225 ===
        let del_rect = Rectangle::new(Point::new(170, 185), Size::new(120, 40));
        RoundedRectangle::new(del_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
            .draw(&mut self.display).ok();
        let dw = measure_title("DELETE");
        draw_lato_title(&mut self.display, "DELETE", 170 + (120 - dw) / 2, 212, COLOR_TEXT);

        self.draw_back_button();
    }

    // ═══════════════════════════════════════════════════════════════
    // BIP85 Child Mnemonic Screens
    // ═══════════════════════════════════════════════════════════════

    /// Draw BIP85 index input screen with +/- buttons
    pub fn draw_bip85_index_screen(&mut self, index: u8, word_count: u8) {
        self.display.clear(COLOR_BG).ok();

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

        self.draw_back_button();
    }

    /// Draw BIP85 deriving progress screen
    pub fn draw_bip85_deriving(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("DERIVING");
        draw_oswald_header(&mut self.display, "DERIVING", (320 - tw) / 2, 100, KASPA_TEAL);
        let sw = measure_body("Generating child seed...");
        draw_lato_body(&mut self.display, "Generating child seed...", (320 - sw) / 2, 130, COLOR_TEXT_DIM);
    }

    /// Draw BIP85 child word display (reuses word screen pattern but with BIP85 title)
    pub fn draw_bip85_word_screen(&mut self, word_num: u8, total_words: u8, word: &str) {
        self.display.clear(COLOR_BG).ok();

        let mut title_buf: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("BIP85 {}/{}", word_num + 1, total_words)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 40, COLOR_TEXT);

        Line::new(Point::new(60, 55), Point::new(260, 55))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let mut num_buf: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut num_buf,
            format_args!("#{}", word_num + 1)).ok();
        let nw = measure_title(num_buf.as_str());
        draw_lato_title(&mut self.display, &num_buf, (320 - nw) / 2, 100, KASPA_TEAL);

        let ww = measure_big(word);
        draw_rubik_big(&mut self.display, word, (320 - ww) / 2, 135, COLOR_TEXT);

        let hw = measure_hint("Write it down! Tap for next.");
        draw_lato_hint(&mut self.display, "Write it down! Tap for next.", (320 - hw) / 2, 210, COLOR_HINT);

        self.draw_back_button();
    }

    // ═══════════════════════════════════════════════════════════════
    // Multisig Wallet Creation Screens
    // ═══════════════════════════════════════════════════════════════

    /// Draw multisig M-of-N chooser screen
    /// Layout: header, M selector with +/-, N selector with +/-, GO button
    /// Touch zones:
    ///   M-: (40,72,50,36)  M+: (230,72,50,36)
    ///   N-: (40,122,50,36) N+: (230,122,50,36)
    ///   GO: (90,175,140,40)
    pub fn draw_multisig_choose_mn(&mut self, m: u8, n: u8) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("CREATE MULTISIG");
        draw_oswald_header(&mut self.display, "CREATE MULTISIG", (320 - tw) / 2, 28, KASPA_TEAL);
        Line::new(Point::new(20, 38), Point::new(300, 38))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let btn_corner = CornerRadii::new(Size::new(6, 6));

        // ── M row: "Required sigs (M)"  [-]  value  [+] ──
        let lm = measure_body("Required sigs (M):");
        draw_lato_body(&mut self.display, "Required sigs (M):", (320 - lm) / 2, 62, COLOR_TEXT_DIM);

        let row_m_y: i32 = 72;
        // [-] button
        let m_minus = Rectangle::new(Point::new(60, row_m_y), Size::new(50, 38));
        RoundedRectangle::new(m_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(m_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let mmw = measure_title("-");
        draw_lato_title(&mut self.display, "-", 60 + (50 - mmw) / 2, row_m_y + 27, COLOR_TEXT);

        // M value (big centered)
        let mut m_buf: heapless::String<4> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut m_buf, format_args!("{m}")).ok();
        let mvw = measure_big(m_buf.as_str());
        draw_rubik_big(&mut self.display, &m_buf, (320 - mvw) / 2, row_m_y + 30, KASPA_ACCENT);

        // [+] button
        let m_plus = Rectangle::new(Point::new(210, row_m_y), Size::new(50, 38));
        RoundedRectangle::new(m_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(m_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let mpw = measure_title("+");
        draw_lato_title(&mut self.display, "+", 210 + (50 - mpw) / 2, row_m_y + 27, COLOR_TEXT);

        // ── N row: "Total keys (N)"  [-]  value  [+] ──
        let ln = measure_body("Total keys (N):");
        draw_lato_body(&mut self.display, "Total keys (N):", (320 - ln) / 2, 130, COLOR_TEXT_DIM);

        let row_n_y: i32 = 140;
        let n_minus = Rectangle::new(Point::new(60, row_n_y), Size::new(50, 38));
        RoundedRectangle::new(n_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(n_minus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let nmw = measure_title("-");
        draw_lato_title(&mut self.display, "-", 60 + (50 - nmw) / 2, row_n_y + 27, COLOR_TEXT);

        let mut n_buf: heapless::String<4> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut n_buf, format_args!("{n}")).ok();
        let nvw = measure_big(n_buf.as_str());
        draw_rubik_big(&mut self.display, &n_buf, (320 - nvw) / 2, row_n_y + 30, KASPA_ACCENT);

        let n_plus = Rectangle::new(Point::new(210, row_n_y), Size::new(50, 38));
        RoundedRectangle::new(n_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(n_plus, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let npw = measure_title("+");
        draw_lato_title(&mut self.display, "+", 210 + (50 - npw) / 2, row_n_y + 27, COLOR_TEXT);

        // Validation hint
        let valid = m >= 1 && m <= n && n <= 5;
        if !valid {
            let hw = measure_hint("M must be 1..N, N max 5");
            draw_lato_hint(&mut self.display, "M must be 1..N, N max 5", (320 - hw) / 2, 192, COLOR_DANGER);
        }

        // NEXT button — teal when valid, dim when not
        let btn_w: u32 = 160;
        let btn_x: i32 = (320 - btn_w as i32) / 2;
        let btn_y: i32 = 190;
        let go_color = if valid { KASPA_TEAL } else { COLOR_CARD };
        let go_rect = Rectangle::new(Point::new(btn_x, btn_y), Size::new(btn_w, 40));
        RoundedRectangle::new(go_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(go_color))
            .draw(&mut self.display).ok();
        let text_color = if valid { COLOR_BG } else { COLOR_TEXT_DIM };
        let gw = measure_title("NEXT");
        draw_lato_title(&mut self.display, "NEXT", btn_x + (btn_w as i32 - gw) / 2, btn_y + 28, text_color);

        self.draw_back_button();
    }

    /// Draw multisig "add key" screen — prompts to scan kpub or use loaded seed
    /// key_idx: which key we're collecting (0-based), n: total keys needed
    /// has_loaded: whether there's at least one loaded seed to offer as option
    /// Touch zones:
    ///   "Scan QR":   (30, 90, 260, 45)
    ///   "Use Loaded": (30, 145, 260, 45)
    pub fn draw_multisig_add_key(&mut self, key_idx: u8, n: u8, has_loaded: bool) {
        self.display.clear(COLOR_BG).ok();

        let mut title_buf: heapless::String<20> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("KEY {}/{}", key_idx + 1, n)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 28, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        draw_lato_body(&mut self.display, "Add a public key (kpub or x-only):", 20, 65, COLOR_TEXT);
        let hw = measure_hint("Scan a kpub QR or use a loaded seed");
        draw_lato_hint(&mut self.display, "Scan a kpub QR or use a loaded seed", (320 - hw) / 2, 80, COLOR_TEXT_DIM);

        let btn_corner = CornerRadii::new(Size::new(8, 8));

        // "Scan QR" button
        let scan_rect = Rectangle::new(Point::new(30, 90), Size::new(260, 45));
        RoundedRectangle::new(scan_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(scan_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let sw = measure_title("Scan kpub QR");
        draw_lato_title(&mut self.display, "Scan kpub QR", 30 + (260 - sw) / 2, 120, COLOR_TEXT);

        // "Use Loaded Seed" button
        let use_color = if has_loaded { COLOR_CARD } else { COLOR_BG };
        let use_border = if has_loaded { KASPA_TEAL } else { COLOR_CARD_BORDER };
        let use_rect = Rectangle::new(Point::new(30, 145), Size::new(260, 45));
        RoundedRectangle::new(use_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(use_color))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(use_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(use_border, 1))
            .draw(&mut self.display).ok();
        let label = if has_loaded { "Use Loaded Seed" } else { "No seeds loaded" };
        let text_color = if has_loaded { COLOR_TEXT } else { COLOR_TEXT_DIM };
        let lw = measure_title(label);
        draw_lato_title(&mut self.display, label, 30 + (260 - lw) / 2, 175, text_color);

        // Show keys collected so far
        if key_idx > 0 {
            let mut prog: heapless::String<16> = heapless::String::new();
            core::fmt::Write::write_fmt(&mut prog, format_args!("{key_idx} key(s) added")).ok();
            let pw = measure_hint(prog.as_str());
            draw_lato_hint(&mut self.display, &prog, (320 - pw) / 2, 210, KASPA_ACCENT);
        }

        self.draw_back_button();
    }

    /// Draw multisig seed picker — matches SeedList style with fingerprints and arrows
    pub fn draw_multisig_pick_seed(&mut self, key_idx: u8, n: u8, seed_mgr: &crate::ui::seed_manager::SeedManager, scroll: u8) {
        self.display.clear(COLOR_BG).ok();

        let mut title_buf: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut title_buf,
            format_args!("SELECT SEED ({}/{})", key_idx + 1, n)).ok();
        let tw = measure_header(title_buf.as_str());
        draw_oswald_header(&mut self.display, &title_buf, (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Collect non-empty slots
        let mut loaded: [usize; 16] = [0; 16];
        let mut loaded_count: usize = 0;
        for i in 0..crate::ui::seed_manager::MAX_SLOTS {
            if !seed_mgr.slots[i].is_empty() {
                loaded[loaded_count] = i;
                loaded_count += 1;
            }
        }

        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let start_y: i32 = 46;
        let card_w: u32 = 232;
        let start_x: i32 = 44;
        let card_corner = CornerRadii::new(Size::new(6, 6));
        let max_visible: usize = 3;
        let teal_dark = Rgb565::new(0b00001, 0b000100, 0b00010);
        let scroll_off = scroll as usize;

        for vis in 0..max_visible {
            let row_y = start_y + (vis as i32) * (card_h + card_gap);
            let list_idx = scroll_off + vis;

            if list_idx < loaded_count {
                let i = loaded[list_idx];
                let slot = &seed_mgr.slots[i];
                let is_active = seed_mgr.active == i as u8;

                let card_fill = if is_active { Rgb565::new(0b00010, 0b000110, 0b00011) } else { COLOR_CARD };
                let card_border = if is_active { KASPA_ACCENT } else { COLOR_CARD_BORDER };

                let slot_rect = Rectangle::new(Point::new(start_x, row_y), Size::new(card_w, card_h as u32));
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(card_fill))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(card_border, if is_active { 2 } else { 1 }))
                    .draw(&mut self.display).ok();

                // Fingerprint icon
                let fp_icon = size24px::identity::Fingerprint::new(COLOR_TEXT);
                Image::new(&fp_icon, Point::new(start_x + 6, row_y + 9)).draw(&mut self.display).ok();

                // Fingerprint hex
                let mut fp_hex = [0u8; 8];
                slot.fingerprint_hex(&mut fp_hex);
                let fp_str = core::str::from_utf8(&fp_hex).unwrap_or("????????");
                draw_lato_title(&mut self.display, fp_str, start_x + 36, row_y + 28, COLOR_TEXT);

                // Word count
                let type_str = match slot.word_count {
                    1 => "KEY", 2 => "xprv", 12 => "12w", 24 => "24w", _ => "??",
                };
                draw_lato_body(&mut self.display, type_str, start_x + 130, row_y + 28, COLOR_TEXT_DIM);

                // Passphrase indicator
                if (slot.word_count == 12 || slot.word_count == 24) && slot.passphrase_len > 0 {
                    draw_lato_hint(&mut self.display, "PP", start_x + 170, row_y + 26, COLOR_ORANGE);
                }

                // Slot number — top-right, clear of delete button
                let mut slot_buf: heapless::String<8> = heapless::String::new();
                core::fmt::Write::write_fmt(&mut slot_buf, format_args!("Slot {}", i + 1)).ok();
                let sw = measure_hint(slot_buf.as_str());
                draw_lato_hint(&mut self.display, &slot_buf, start_x + card_w as i32 - 48 - sw, row_y + 14, COLOR_TEXT_DIM);

                // Delete button — trash icon (rightmost area of card)
                let del_rect = Rectangle::new(Point::new(start_x + card_w as i32 - 44, row_y + 3), Size::new(38, 36));
                let del_corner = CornerRadii::new(Size::new(4, 4));
                RoundedRectangle::new(del_rect, del_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
                    .draw(&mut self.display).ok();
                use embedded_graphics::image::ImageRawLE;
                let trash_raw: ImageRawLE<Rgb565> = ImageRawLE::new(
                    crate::hw::icon_data::ICON_TRASH, crate::hw::icon_data::ICON_TRASH_W);
                Image::new(&trash_raw, Point::new(start_x + card_w as i32 - 35, row_y + 9)).draw(&mut self.display).ok();
            } else {
                // Empty slot — tappable to go to Tools menu
                let slot_rect = Rectangle::new(Point::new(start_x, row_y), Size::new(card_w, card_h as u32));
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                    .draw(&mut self.display).ok();
                // "+" icon hint
                let pw = measure_title("+");
                draw_lato_title(&mut self.display, "+", start_x + (card_w as i32 - pw) / 2, row_y + 28, COLOR_TEXT_DIM);
            }
        }

        // Navigation arrows
        let arrow_cy = start_y + (max_visible as i32 * (card_h + card_gap) - card_gap) / 2;
        let can_up = scroll_off > 0;
        let can_down = loaded_count > scroll_off + max_visible;

        let arr_color = if can_up { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(5, arrow_cy), Point::new(30, arrow_cy - 17), Point::new(30, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(arr_color))
            .draw(&mut self.display).ok();

        let arr_color = if can_down { KASPA_TEAL } else { teal_dark };
        Triangle::new(
            Point::new(315, arrow_cy), Point::new(290, arrow_cy - 17), Point::new(290, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(arr_color))
            .draw(&mut self.display).ok();

        // Page dots
        if loaded_count > max_visible {
            let total_pages = ((loaded_count + max_visible - 1) / max_visible) as u8;
            let current_page = (scroll_off / max_visible) as u8;
            let dot_d: i32 = 7;
            let dot_gap: i32 = 8;
            let total_w = (total_pages as i32) * dot_d + ((total_pages as i32) - 1) * dot_gap;
            let dot_start_x = (320 - total_w) / 2;
            for p in 0..total_pages {
                let dx = dot_start_x + (p as i32) * (dot_d + dot_gap);
                let color = if p == current_page { KASPA_ACCENT } else { teal_dark };
                Circle::new(Point::new(dx, 232), dot_d as u32)
                    .into_styled(PrimitiveStyle::with_fill(color))
                    .draw(&mut self.display).ok();
            }
        }

        // Hint
        let hw = measure_hint("Tap a seed to use its key");
        draw_lato_hint(&mut self.display, "Tap a seed to use its key", (320 - hw) / 2, 195, COLOR_HINT);

        self.draw_back_button();
    }

    /// Draw multisig result screen — shows M-of-N label + P2SH address. Tap for QR.
    pub fn draw_multisig_result(&mut self, label: &str, address: &str, addr_index: u32, _script: &[u8]) {
        self.display.clear(COLOR_BG).ok();

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

        let btn_c = Rectangle::new(Point::new(110, 210), Size::new(100, 28));
        RoundedRectangle::new(btn_c, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_c, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let mut idx_label: heapless::String<12> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut idx_label, format_args!("#{addr_index}")).ok();
        let il = measure_title(idx_label.as_str());
        draw_lato_title(&mut self.display, &idx_label, 110 + (100 - il) / 2, 230, KASPA_TEAL);

        let btn_r = Rectangle::new(Point::new(260, 210), Size::new(50, 28));
        RoundedRectangle::new(btn_r, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(btn_r, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let rw = measure_title(">");
        draw_lato_title(&mut self.display, ">", 260 + (50 - rw) / 2, 230, KASPA_TEAL);

        self.draw_back_button();
    }

    /// Draw multisig wallet descriptor text screen.
    /// Shows the descriptor in format: multi(M, pubkey1_hex, ..., pubkeyN_hex)
    /// This allows companion wallets to reconstruct the same multisig address.
    pub fn draw_multisig_descriptor(&mut self, _m: u8, n: u8, pubkeys: &[[u8; 32]], label: &str) {
        self.display.clear(COLOR_BG).ok();

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

        self.draw_back_button();
    }
    /// Draw steganography JPEG file picker
    pub fn draw_stego_jpeg_pick(&mut self, disp_names: &[[u8; 32]; 8], disp_lens: &[u8; 8], count: u8, selected: u8) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("SELECT JPEG");
        draw_oswald_header(&mut self.display, "SELECT JPEG", (320 - tw) / 2, 30, COLOR_TEXT);
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

        // Page-based scroll from selected
        let scroll = (selected / max_visible) * max_visible;

        for vis in 0..max_visible {
            let idx = scroll + vis;
            let row_y = start_y + (vis as i32) * (card_h + card_gap);
            let slot_rect = Rectangle::new(Point::new(start_x, row_y), Size::new(card_w, card_h as u32));

            if idx < count {
                let is_sel = idx == selected;
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(if is_sel { COLOR_CARD_BORDER } else { COLOR_CARD }))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(if is_sel { KASPA_TEAL } else { COLOR_CARD_BORDER }, 1))
                    .draw(&mut self.display).ok();

                // File icon — MediaImage for JPEG files
                let icon = size24px::photos_and_videos::MediaImage::new(if is_sel { KASPA_TEAL } else { COLOR_TEXT });
                Image::new(&icon, Point::new(start_x + 6, row_y + 9)).draw(&mut self.display).ok();

                let name_len = disp_lens[idx as usize] as usize;
                let name = core::str::from_utf8(&disp_names[idx as usize][..name_len]).unwrap_or("?");
                // Truncate long names: max 14 chars + ".."
                let mut trunc_buf = [0u8; 18];
                let trunc_name = if name.len() > 16 {
                    let t = name.len().min(14);
                    trunc_buf[..t].copy_from_slice(&name.as_bytes()[..t]);
                    trunc_buf[t] = b'.';
                    trunc_buf[t+1] = b'.';
                    core::str::from_utf8(&trunc_buf[..t+2]).unwrap_or(name)
                } else {
                    name
                };
                draw_lato_title(&mut self.display, trunc_name, start_x + 36, row_y + 28, if is_sel { KASPA_TEAL } else { COLOR_TEXT });
            } else {
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                    .draw(&mut self.display).ok();
            }
        }

        // Arrows always visible
        let arrow_cy = start_y + (max_visible as i32 * (card_h + card_gap) - card_gap) / 2;
        let can_up = scroll > 0;
        let can_down = (scroll + max_visible) < count;
        Triangle::new(
            Point::new(5, arrow_cy), Point::new(30, arrow_cy - 17), Point::new(30, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(if can_up { KASPA_TEAL } else { teal_dark }))
            .draw(&mut self.display).ok();
        Triangle::new(
            Point::new(315, arrow_cy), Point::new(290, arrow_cy - 17), Point::new(290, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(if can_down { KASPA_TEAL } else { teal_dark }))
            .draw(&mut self.display).ok();

        // Page dots
        if count > max_visible {
            let total_pages = (count + max_visible - 1) / max_visible;
            let current_page = scroll / max_visible;
            let dot_d: i32 = 7;
            let dot_gap: i32 = 8;
            let total_w = (total_pages as i32) * dot_d + ((total_pages as i32) - 1) * dot_gap;
            let dot_start_x = (320 - total_w) / 2;
            for p in 0..total_pages {
                let dx = dot_start_x + (p as i32) * (dot_d + dot_gap);
                let color = if p == current_page { KASPA_ACCENT } else { teal_dark };
                Circle::new(Point::new(dx, 232), dot_d as u32)
                    .into_styled(PrimitiveStyle::with_fill(color))
                    .draw(&mut self.display).ok();
            }
        }

        self.draw_back_button();
    }

    /// Draw descriptor input choice: Type manually / Load from SD
    /// Uses standard template layout with rows and icons
    pub fn draw_stego_desc_choice(&mut self, is_import: bool) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("DESCRIPTOR");
        draw_oswald_header(&mut self.display, "DESCRIPTOR", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Subtitle — context-aware
        let subtitle = if is_import { "This text decrypts your seed" } else { "This text encrypts your seed" };
        let sw = measure_body(subtitle);
        draw_lato_body(&mut self.display, subtitle, (320 - sw) / 2, 60, COLOR_TEXT_DIM);

        // Two rows in standard layout
        let card_h: i32 = 42;
        let card_gap: i32 = 4;
        let start_y: i32 = 70;
        let start_x: i32 = 44;
        let card_w: u32 = 232;
        let card_corner = CornerRadii::new(Size::new(6, 6));

        // Row 0: Type manually
        let r0 = Rectangle::new(Point::new(start_x, start_y), Size::new(card_w, card_h as u32));
        RoundedRectangle::new(r0, card_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(r0, card_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let kb_icon = size24px::editor::EditPencil::new(KASPA_TEAL);
        Image::new(&kb_icon, Point::new(start_x + 6, start_y + 9)).draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "Type manually", start_x + 42, start_y + 28, COLOR_TEXT);

        // Row 1: Load .TXT from SD
        let r1_y = start_y + card_h + card_gap;
        let r1 = Rectangle::new(Point::new(start_x, r1_y), Size::new(card_w, card_h as u32));
        RoundedRectangle::new(r1, card_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(r1, card_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
        let sd_icon = size24px::docs::Page::new(KASPA_TEAL);
        Image::new(&sd_icon, Point::new(start_x + 6, r1_y + 9)).draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "Load .TXT from SD", start_x + 42, r1_y + 28, COLOR_TEXT);

        self.draw_back_button();
    }

    /// Draw .TXT file picker with LFN display names — standard template layout
    pub fn draw_stego_txt_pick(&mut self, disp_names: &[[u8; 32]; 8], disp_lens: &[u8; 8], count: u8) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("SELECT TXT");
        draw_oswald_header(&mut self.display, "SELECT TXT", (320 - tw) / 2, 30, COLOR_TEXT);
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

        for vis in 0..max_visible {
            let idx = vis;
            let row_y = start_y + (vis as i32) * (card_h + card_gap);
            let slot_rect = Rectangle::new(Point::new(start_x, row_y), Size::new(card_w, card_h as u32));

            if idx < count {
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
                    .draw(&mut self.display).ok();

                // Page icon for TXT files
                let icon = size24px::docs::Page::new(COLOR_TEXT);
                Image::new(&icon, Point::new(start_x + 6, row_y + 9)).draw(&mut self.display).ok();

                let name_len = disp_lens[idx as usize] as usize;
                let name = core::str::from_utf8(&disp_names[idx as usize][..name_len]).unwrap_or("?");
                // Truncate long names
                let mut trunc_buf = [0u8; 18];
                let trunc_name = if name.len() > 16 {
                    let t = name.len().min(14);
                    trunc_buf[..t].copy_from_slice(&name.as_bytes()[..t]);
                    trunc_buf[t] = b'.';
                    trunc_buf[t+1] = b'.';
                    core::str::from_utf8(&trunc_buf[..t+2]).unwrap_or(name)
                } else {
                    name
                };
                draw_lato_title(&mut self.display, trunc_name, start_x + 36, row_y + 28, COLOR_TEXT);
            } else {
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                RoundedRectangle::new(slot_rect, card_corner)
                    .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                    .draw(&mut self.display).ok();
            }
        }

        // Arrows always visible
        let arrow_cy = start_y + (max_visible as i32 * (card_h + card_gap) - card_gap) / 2;
        Triangle::new(
            Point::new(5, arrow_cy), Point::new(30, arrow_cy - 17), Point::new(30, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(teal_dark))
            .draw(&mut self.display).ok();
        Triangle::new(
            Point::new(315, arrow_cy), Point::new(290, arrow_cy - 17), Point::new(290, arrow_cy + 17),
        ).into_styled(PrimitiveStyle::with_fill(teal_dark))
            .draw(&mut self.display).ok();

        self.draw_back_button();
    }

    /// Draw descriptor preview with password strength indicator
    pub fn draw_stego_desc_preview(&mut self, desc: &str) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("DESCRIPTOR PREVIEW");
        draw_oswald_header(&mut self.display, "DESCRIPTOR PREVIEW", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        // Show descriptor text (wrap at ~32 chars per line, max 3 lines, centered)
        let len = desc.len();
        let line1_end = len.min(32);
        let l1w = measure_body(&desc[..line1_end]);
        draw_lato_body(&mut self.display, &desc[..line1_end], (320 - l1w) / 2, 55, KASPA_ACCENT);

        if len > 32 {
            let line2_end = len.min(64);
            let l2w = measure_body(&desc[32..line2_end]);
            draw_lato_body(&mut self.display, &desc[32..line2_end], (320 - l2w) / 2, 73, KASPA_ACCENT);
        }
        if len > 64 {
            let line3_end = len.min(96);
            // Truncate with ".." if there's more
            if len > 96 {
                let mut trunc = [0u8; 34];
                let copy = 30.min(line3_end - 64);
                trunc[..copy].copy_from_slice(&desc.as_bytes()[64..64 + copy]);
                trunc[copy] = b'.';
                trunc[copy + 1] = b'.';
                if let Ok(s) = core::str::from_utf8(&trunc[..copy + 2]) {
                    let l3w = measure_body(s);
                    draw_lato_body(&mut self.display, s, (320 - l3w) / 2, 91, KASPA_ACCENT);
                }
            } else {
                let l3w = measure_body(&desc[64..line3_end]);
                draw_lato_body(&mut self.display, &desc[64..line3_end], (320 - l3w) / 2, 91, KASPA_ACCENT);
            }
        }

        // Strength assessment
        let strength = password_strength(desc);
        let (bar_color, label) = match strength {
            0 => (Rgb565::new(31, 0, 0), "WEAK"),
            1 => (Rgb565::new(31, 31, 0), "FAIR"),
            _ => (Rgb565::new(0, 50, 0), "STRONG"),
        };

        // Strength bar
        let bar_y = 112;
        Rectangle::new(Point::new(15, bar_y), Size::new(230, 8))
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        let fill_w = match strength {
            0 => 60u32,
            1 => 140u32,
            _ => 230u32,
        };
        Rectangle::new(Point::new(15, bar_y), Size::new(fill_w, 8))
            .into_styled(PrimitiveStyle::with_fill(bar_color))
            .draw(&mut self.display).ok();
        draw_lato_body(&mut self.display, label, 252, bar_y + 8, bar_color);

        // Character count
        let mut len_buf: heapless::String<16> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut len_buf, format_args!("{len} characters")).ok();
        let lw = measure_hint(len_buf.as_str());
        draw_lato_hint(&mut self.display, len_buf.as_str(), (320 - lw) / 2, 135, COLOR_HINT);

        // Hint text
        let hw = measure_hint("Also visible as EXIF image description.");
        draw_lato_hint(&mut self.display, "Also visible as EXIF image description.", (320 - hw) / 2, 148, COLOR_TEXT_DIM);

        // EDIT / USE buttons
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let edit_rect = Rectangle::new(Point::new(20, 185), Size::new(130, 40));
        RoundedRectangle::new(edit_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(edit_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let ew = measure_body("EDIT");
        draw_lato_body(&mut self.display, "EDIT", 20 + (130 - ew) / 2, 211, COLOR_TEXT);

        let use_rect = Rectangle::new(Point::new(170, 185), Size::new(130, 40));
        RoundedRectangle::new(use_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let uw = measure_body("USE");
        draw_lato_body(&mut self.display, "USE", 170 + (130 - uw) / 2, 211, COLOR_BG);

        self.draw_back_button();
    }

    /// Draw steganography JPEG confirm overwrite screen
    pub fn draw_stego_jpeg_confirm(&mut self, filename: &str, description: &str, has_pp: bool) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("CONFIRM OVERWRITE");
        draw_oswald_header(&mut self.display, "CONFIRM OVERWRITE", (320 - tw) / 2, 30, COLOR_ORANGE);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_ORANGE, 1))
            .draw(&mut self.display).ok();

        let tw1 = measure_body("This will modify:");
        draw_lato_body(&mut self.display, "This will modify:", (320 - tw1) / 2, 65, COLOR_TEXT);
        let fw = measure_title(filename);
        draw_lato_title(&mut self.display, filename, (320 - fw) / 2, 88, KASPA_TEAL);

        let dw1 = measure_body("Descriptor:");
        draw_lato_body(&mut self.display, "Descriptor:", (320 - dw1) / 2, 115, COLOR_TEXT);
        let show_len = description.len().min(35);
        let desc_show = &description[..show_len];
        let dw2 = measure_body(desc_show);
        draw_lato_body(&mut self.display, desc_show, (320 - dw2) / 2, 135, KASPA_ACCENT);

        if has_pp {
            let pw = measure_body("Hint: HIDDEN");
            draw_lato_body(&mut self.display, "Hint: HIDDEN", (320 - pw) / 2, 158, Rgb565::new(0, 50, 0));
        } else {
            let pw = measure_hint("Hint: not included");
            draw_lato_hint(&mut self.display, "Hint: not included", (320 - pw) / 2, 158, COLOR_HINT);
        }

        // CANCEL / CONFIRM buttons
        let btn_corner = CornerRadii::new(Size::new(6, 6));
        let cancel_rect = Rectangle::new(Point::new(20, 185), Size::new(130, 36));
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let cw = measure_body("CANCEL");
        draw_lato_body(&mut self.display, "CANCEL", 20 + (130 - cw) / 2, 209, COLOR_TEXT);

        let confirm_rect = Rectangle::new(Point::new(170, 185), Size::new(130, 36));
        RoundedRectangle::new(confirm_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let ow = measure_body("OVERWRITE");
        draw_lato_body(&mut self.display, "OVERWRITE", 170 + (130 - ow) / 2, 209, COLOR_BG);

        self.draw_back_button();
    }

    /// Draw "Hide a hint?" ask screen with YES/NO buttons
    pub fn draw_stego_pp_ask(&mut self) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("HIDE A HINT?");
        draw_oswald_header(&mut self.display, "HIDE A HINT?", (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let w1 = measure_body("Hide a personal hint inside");
        draw_lato_body(&mut self.display, "Hide a personal hint inside", (320 - w1) / 2, 70, COLOR_TEXT);
        let w2 = measure_body("the image descriptor to help");
        draw_lato_body(&mut self.display, "the image descriptor to help", (320 - w2) / 2, 90, COLOR_TEXT);
        let w3 = measure_body("you remember your passphrase.");
        draw_lato_body(&mut self.display, "you remember your passphrase.", (320 - w3) / 2, 110, COLOR_TEXT);
        let w4 = measure_hint("Optional. Tap NO to skip.");
        draw_lato_hint(&mut self.display, "Optional. Tap NO to skip.", (320 - w4) / 2, 140, COLOR_HINT);

        let btn_corner = CornerRadii::new(Size::new(6, 6));
        // NO button
        let no_rect = Rectangle::new(Point::new(20, 175), Size::new(130, 40));
        RoundedRectangle::new(no_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(no_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let nw = measure_body("NO");
        draw_lato_body(&mut self.display, "NO", 20 + (130 - nw) / 2, 201, COLOR_TEXT);

        // YES button
        let yes_rect = Rectangle::new(Point::new(170, 175), Size::new(130, 40));
        RoundedRectangle::new(yes_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let yw = measure_body("YES");
        draw_lato_body(&mut self.display, "YES", 170 + (130 - yw) / 2, 201, COLOR_BG);

        self.draw_back_button();
    }

    /// Draw hint picker screen: 4 presets + Custom option
    pub fn draw_stego_hint_picker(&mut self, _selected: u8) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("RECOVERY HINT");
        draw_oswald_header(&mut self.display, "RECOVERY HINT", (320 - tw) / 2, 25, KASPA_TEAL);
        Line::new(Point::new(20, 35), Point::new(300, 35))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let sw = measure_18("The answer IS your passphrase.");
        draw_lato_18(&mut self.display, "The answer IS your passphrase.", (320 - sw) / 2, 58, COLOR_ORANGE);

        let btn_corner = CornerRadii::new(Size::new(4, 4));
        for i in 0..4u8 {
            let hint = if (i as usize) < crate::features::stego::HINT_PRESETS.len() {
                crate::features::stego::HINT_PRESETS[i as usize]
            } else {
                "Custom..."
            };
            let row_y = 68 + i as i32 * 36;

            let rect = Rectangle::new(Point::new(15, row_y), Size::new(290, 30));
            RoundedRectangle::new(rect, btn_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            RoundedRectangle::new(rect, btn_corner)
                .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
                .draw(&mut self.display).ok();

            draw_lato_body(&mut self.display, hint, 25, row_y + 21, COLOR_TEXT);
        }

        self.draw_back_button();
    }

    /// Draw hint reveal screen after stego import (seed recovered + hint found)
    pub fn draw_stego_hint_reveal(&mut self, hint: &str) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("SEED RECOVERED");
        draw_oswald_header(&mut self.display, "SEED RECOVERED", (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let rw = measure_body("A recovery hint was found:");
        draw_lato_body(&mut self.display, "A recovery hint was found:", (320 - rw) / 2, 68, COLOR_TEXT);

        // Draw hint on gray row background, white text, centered
        let row_corner = CornerRadii::new(Size::new(4, 4));
        if hint.len() <= 30 {
            let row_rect = Rectangle::new(Point::new(15, 85), Size::new(290, 28));
            RoundedRectangle::new(row_rect, row_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            let hw = measure_title(hint);
            draw_lato_title(&mut self.display, hint, (320 - hw) / 2, 106, COLOR_TEXT);
        } else {
            let split = hint[..30].rfind(' ').unwrap_or(30);
            let line1 = &hint[..split];
            let rest_start = if hint.as_bytes()[split] == b' ' { split + 1 } else { split };
            let rest_end = hint.len().min(rest_start + 30);

            let row1_rect = Rectangle::new(Point::new(15, 82), Size::new(290, 26));
            RoundedRectangle::new(row1_rect, row_corner)
                .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                .draw(&mut self.display).ok();
            let hw1 = measure_title(line1);
            draw_lato_title(&mut self.display, line1, (320 - hw1) / 2, 102, COLOR_TEXT);

            if rest_start < hint.len() {
                let line2 = &hint[rest_start..rest_end];
                let row2_rect = Rectangle::new(Point::new(15, 110), Size::new(290, 26));
                RoundedRectangle::new(row2_rect, row_corner)
                    .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
                    .draw(&mut self.display).ok();
                let hw2 = measure_title(line2);
                draw_lato_title(&mut self.display, line2, (320 - hw2) / 2, 130, COLOR_TEXT);
            }
        }

        // "The answer IS your passphrase" — header font for maximum emphasis
        let aw = measure_header("The answer IS your passphrase.");
        draw_oswald_header(&mut self.display, "The answer IS your passphrase.", (320 - aw) / 2, 162, COLOR_ORANGE);
        let ew = measure_body("Enter it as your BIP39 25th word.");
        draw_lato_body(&mut self.display, "Enter it as your BIP39 25th word.", (320 - ew) / 2, 188, COLOR_TEXT_DIM);

        let cw = measure_hint("Tap to continue");
        draw_lato_hint(&mut self.display, "Tap to continue", (320 - cw) / 2, 222, COLOR_HINT);
    }

    /// Draw a success screen with a message
    pub fn draw_success_screen(&mut self, message: &str) {
        sound::stop_ticking();
        use embedded_graphics::image::{Image, ImageRawLE};

        static LOGO_DATA: &[u8] = include_bytes!("../../assets/logo_320x240.raw");
        let raw_img: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
        Image::new(&raw_img, Point::zero())
            .draw(&mut self.display).ok();

        let mut msg_buf: heapless::String<64> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut msg_buf, format_args!("!! {message} !!")).ok();
        let tw = measure_title(msg_buf.as_str());
        draw_lato_title(&mut self.display, msg_buf.as_str(), (320 - tw) / 2, 170, KASPA_TEAL);

        let cw = measure_hint("Tap to continue");
        draw_lato_hint(&mut self.display, "Tap to continue", (320 - cw) / 2, 222, COLOR_HINT);
    }

    /// Draw firmware update verification result
    pub fn draw_fw_update_screen(&mut self, version: &str, verified: bool) {
        self.display.clear(COLOR_BG).ok();
        let tw = measure_header("FIRMWARE UPDATE");
        draw_oswald_header(&mut self.display, "FIRMWARE UPDATE", (320 - tw) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        if verified {
            draw_lato_title(&mut self.display, "SIGNATURE VALID", 30, 80, Rgb565::new(0, 31, 0));

            use core::fmt::Write;
            let mut ver_text = heapless::String::<32>::new();
            write!(&mut ver_text, "Version: {version}").ok();
            draw_lato_body(&mut self.display, ver_text.as_str(), 30, 115, COLOR_TEXT);

            draw_lato_body(&mut self.display, "Copy firmware.bin to SD card", 30, 150, COLOR_TEXT);
            draw_lato_body(&mut self.display, "then flash via USB.", 30, 170, COLOR_TEXT);
        } else {
            draw_lato_title(&mut self.display, "INVALID SIGNATURE", 30, 80, COLOR_ORANGE);
            draw_lato_body(&mut self.display, "Update rejected. Do not flash.", 30, 120, COLOR_TEXT);
        }

        let hw = measure_hint("Tap to continue");
        draw_lato_hint(&mut self.display, "Tap to continue", (320 - hw) / 2, 218, COLOR_HINT);
    }

    /// Draw SD backup delete confirmation screen.
    /// Mirrors the seed delete confirmation layout: CANCEL left, DELETE right.
    pub fn draw_sd_delete_confirm(&mut self, filename: &[u8; 11]) {
        self.display.clear(COLOR_BG).ok();

        // Header
        let tw = measure_header("DELETE BACKUP?");
        draw_oswald_header(&mut self.display, "DELETE BACKUP?", (320 - tw) / 2, 30, COLOR_ORANGE);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_RED_BTN, 1))
            .draw(&mut self.display).ok();

        // Filename
        let mut disp = [0u8; 13];
        let dlen = crate::hw::sd_backup::format_83_display(filename, &mut disp);
        if let Ok(name_str) = core::str::from_utf8(&disp[..dlen]) {
            let nw = measure_body(name_str);
            draw_lato_body(&mut self.display, name_str, (320 - nw) / 2, 65, COLOR_TEXT);
        }

        // Warning lines — centered
        let w1 = measure_body("This action is irreversible.");
        draw_lato_body(&mut self.display, "This action is irreversible.", (320 - w1) / 2, 95, COLOR_ORANGE);
        let w2 = measure_body("The backup file will be");
        draw_lato_body(&mut self.display, "The backup file will be", (320 - w2) / 2, 120, COLOR_TEXT);
        let w3 = measure_body("permanently deleted from SD.");
        draw_lato_body(&mut self.display, "permanently deleted from SD.", (320 - w3) / 2, 145, COLOR_TEXT);

        // CANCEL button (left, teal outline) — y=185..225
        let btn_corner = CornerRadii::new(Size::new(8, 8));
        let cancel_rect = Rectangle::new(Point::new(30, 185), Size::new(120, 40));
        RoundedRectangle::new(cancel_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
            .draw(&mut self.display).ok();
        let cw = measure_title("CANCEL");
        draw_lato_title(&mut self.display, "CANCEL", 30 + (120 - cw) / 2, 212, KASPA_TEAL);

        // DELETE button (right, red fill) — y=185..225
        let del_rect = Rectangle::new(Point::new(170, 185), Size::new(120, 40));
        RoundedRectangle::new(del_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
            .draw(&mut self.display).ok();
        let dw = measure_title("DELETE");
        draw_lato_title(&mut self.display, "DELETE", 170 + (120 - dw) / 2, 212, COLOR_TEXT);

        self.draw_back_button();
    }

    /// Draw the ShowQR popup: "Save to SD" / "Back to QR" with header back = main menu
    pub fn draw_showqr_popup(&mut self) {
        self.draw_two_button_popup(
            "SIGNED TX",
            &["Transaction signed successfully.", "Save to SD card or return", "to view the QR code."],
            "Save to SD", "Back to QR",
        );
    }

    /// Draw kpub export popup: Save to SD / Back to QR (after showing kpub QR)
    pub fn draw_kpub_export_popup(&mut self) {
        self.draw_two_button_popup(
            "KPUB EXPORTED",
            &["Watch-only key exported.", "Save to SD card or return", "to view the QR code."],
            "Save to SD", "Back to QR",
        );
    }

    /// Draw kpub scanned popup: Show QR / Save to SD
    pub fn draw_kpub_scanned_popup(&mut self) {
        self.draw_two_button_popup(
            "KPUB SCANNED",
            &["Watch-only key received.", "Display as QR or save to SD."],
            "Show QR", "Save to SD",
        );
    }

    /// Draw the KSPT encrypt ask screen: "Encrypt?" with Yes / No buttons
    pub fn draw_kspt_encrypt_ask(&mut self) {
        self.draw_two_button_popup(
            "ENCRYPT FILE?",
            &["Encrypt the file with a", "password before saving?"],
            "Yes", "No",
        );
    }

    /// Generic Yes/No ask screen with custom header and body lines
    pub fn draw_yes_no_ask(&mut self, header: &str, line1: &str, line2: &str) {
        self.draw_two_button_popup(header, &[line1, line2], "Yes", "No");
    }

    /// Draw QR mode choice screen: "Auto Cycle" / "Manual" for multi-frame QR display
    pub fn draw_qr_mode_choice(&mut self) {
        self.draw_two_button_popup(
            "QR DISPLAY MODE",
            &["Multiple QR frames required.", "Choose display mode:"],
            "Auto Cycle", "Manual",
        );
        // Extra hint lines below buttons
        let h1 = measure_hint("Auto: frames cycle automatically");
        draw_lato_hint(&mut self.display, "Auto: frames cycle automatically", (320 - h1) / 2, 200, COLOR_HINT);
        let h2 = measure_hint("Manual: tap to advance frames");
        draw_lato_hint(&mut self.display, "Manual: tap to advance frames", (320 - h2) / 2, 216, COLOR_HINT);
    }

    /// Shared two-button popup layout: header + body lines + left (teal) / right (card) buttons + back.
    /// Used by all Save/Back, Yes/No, and choice popups.
    fn draw_two_button_popup(&mut self, header: &str, body: &[&str], left_label: &str, right_label: &str) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header(header);
        draw_oswald_header(&mut self.display, header, (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let y_positions: [i32; 3] = [75, 95, 115];
        for (i, &line) in body.iter().enumerate() {
            if i >= 3 { break; }
            let w = measure_body(line);
            draw_lato_body(&mut self.display, line, (320 - w) / 2, y_positions[i], COLOR_TEXT);
        }

        let btn_corner = CornerRadii::new(Size::new(6, 6));

        // Left button (teal, primary)
        let left_rect = Rectangle::new(Point::new(30, 140), Size::new(125, 45));
        RoundedRectangle::new(left_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let lw = measure_title(left_label);
        draw_lato_title(&mut self.display, left_label, 30 + (125 - lw) / 2, 169, COLOR_BG);

        // Right button (card, secondary)
        let right_rect = Rectangle::new(Point::new(165, 140), Size::new(125, 45));
        RoundedRectangle::new(right_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display).ok();
        RoundedRectangle::new(right_rect, btn_corner)
            .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
            .draw(&mut self.display).ok();
        let rw = measure_title(right_label);
        draw_lato_title(&mut self.display, right_label, 165 + (125 - rw) / 2, 169, COLOR_TEXT);

        self.draw_back_button();
    }

    pub fn draw_kpub_frame_count_choice(&mut self) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("KPUB EXPORT QR");
        draw_oswald_header(&mut self.display, "KPUB EXPORT QR", (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let btn_corner = CornerRadii::new(Size::new(6, 6));

        let bw: i32 = 130;
        let bh: i32 = 55;
        let by: i32 = 100;
        let gap: i32 = 16;
        let x0: i32 = (320 - 2 * bw - gap) / 2;

        // "Single" — left
        let r0 = Rectangle::new(Point::new(x0, by), Size::new(bw as u32, bh as u32));
        RoundedRectangle::new(r0, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let tw0 = measure_title("Single");
        draw_lato_title(&mut self.display, "Single", x0 + (bw - tw0) / 2, by + 35, COLOR_BG);

        // "Multi-frame" — right
        let x1 = x0 + bw + gap;
        let r1 = Rectangle::new(Point::new(x1, by), Size::new(bw as u32, bh as u32));
        RoundedRectangle::new(r1, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let tw1 = measure_title("Multi");
        draw_lato_title(&mut self.display, "Multi", x1 + (bw - tw1) / 2, by + 35, COLOR_BG);

        // Hints below buttons
        let h0 = measure_hint("1 QR code");
        draw_lato_hint(&mut self.display, "1 QR code", x0 + (bw - h0) / 2, by + bh + 14, COLOR_HINT);
        let h1 = measure_hint("4 large QR codes");
        draw_lato_hint(&mut self.display, "4 large QR codes", x1 + (bw - h1) / 2, by + bh + 14, COLOR_HINT);

        let h2 = measure_hint("Multi-frame for device-to-device scan");
        draw_lato_hint(&mut self.display, "Multi-frame for device-to-device scan", (320 - h2) / 2, 216, COLOR_HINT);

        self.draw_back_button();
    }

    pub fn draw_kspt_frame_choice(&mut self) {
        self.display.clear(COLOR_BG).ok();

        let tw = measure_header("SIGNED TX QR");
        draw_oswald_header(&mut self.display, "SIGNED TX QR", (320 - tw) / 2, 30, KASPA_TEAL);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let btn_corner = CornerRadii::new(Size::new(6, 6));

        let bw: i32 = 130;
        let bh: i32 = 55;
        let by: i32 = 100;
        let gap: i32 = 16;
        let x0: i32 = (320 - 2 * bw - gap) / 2;

        // "Single" — left
        let r0 = Rectangle::new(Point::new(x0, by), Size::new(bw as u32, bh as u32));
        RoundedRectangle::new(r0, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let tw0 = measure_title("Single");
        draw_lato_title(&mut self.display, "Single", x0 + (bw - tw0) / 2, by + 35, COLOR_BG);

        // "Multi" — right
        let x1 = x0 + bw + gap;
        let r1 = Rectangle::new(Point::new(x1, by), Size::new(bw as u32, bh as u32));
        RoundedRectangle::new(r1, btn_corner)
            .into_styled(PrimitiveStyle::with_fill(KASPA_TEAL))
            .draw(&mut self.display).ok();
        let tw1 = measure_title("Multi");
        draw_lato_title(&mut self.display, "Multi", x1 + (bw - tw1) / 2, by + 35, COLOR_BG);

        // Hints
        let h0 = measure_hint("for phone/KasSee");
        draw_lato_hint(&mut self.display, "for phone/KasSee", x0 + (bw - h0) / 2, by + bh + 14, COLOR_HINT);
        let h1 = measure_hint("for device scan");
        draw_lato_hint(&mut self.display, "for device scan", x1 + (bw - h1) / 2, by + bh + 14, COLOR_HINT);

        let h2 = measure_hint("Multi-frame for device-to-device scan");
        draw_lato_hint(&mut self.display, "Multi-frame for device-to-device scan", (320 - h2) / 2, 216, COLOR_HINT);

        self.draw_back_button();
    }
}

/// Guide box at (gx, gy) with size (gw, gh), corner arm length gc, thickness gt.
#[inline(always)]
fn is_guide_pixel(
    vx: usize, vy: usize,
    gx: usize, gy: usize, gw: usize, gh: usize, gc: usize, gt: usize,
) -> bool {
    // Top-left corner
    if vx >= gx && vx < gx + gc && vy >= gy && vy < gy + gt { return true; }
    if vx >= gx && vx < gx + gt && vy >= gy && vy < gy + gc { return true; }
    // Top-right corner
    let rx = gx + gw;
    if vx > rx - gc && vx <= rx && vy >= gy && vy < gy + gt { return true; }
    if vx > rx - gt && vx <= rx && vy >= gy && vy < gy + gc { return true; }
    // Bottom-left corner
    let by = gy + gh;
    if vx >= gx && vx < gx + gc && vy > by - gt && vy <= by { return true; }
    if vx >= gx && vx < gx + gt && vy > by - gc && vy <= by { return true; }
    // Bottom-right corner
    if vx > rx - gc && vx <= rx && vy > by - gt && vy <= by { return true; }
    if vx > rx - gt && vx <= rx && vy > by - gc && vy <= by { return true; }
    false
}

// ═══════════════════════════════════════════════════════════════
// Camera Tune Screen (dev tool, feature-gated)
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "waveshare")]
const CAM_TUNE_LABELS: [&str; 6] = [
    "AEC-H", "AEC-L", "Contr", "Brite", "AGC", "Sharp"
];

#[cfg(feature = "waveshare")]
impl<'a> crate::hw::display::BootDisplay<'a> {
    /// Draw the full cam-tune overlay: right panel (6 param buttons + EXIT) + bottom slider.
    /// Called once when cam-tune activates. Partial updates via update_cam_tune_slider.
    pub fn draw_cam_tune_overlay(&mut self, param: u8, vals: &[u8; 6]) {
        use embedded_graphics::prelude::*;
        use embedded_graphics::primitives::{Rectangle, PrimitiveStyle, RoundedRectangle};
        use embedded_graphics::primitives::CornerRadii;
        use crate::hw::display::*;

        let corner = CornerRadii::new(Size::new(6, 6));

        // Right panel (x=198..320, y=0..180)
        Rectangle::new(Point::new(198, 0), Size::new(122, 180))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // EXIT button (116x32)
        RoundedRectangle::new(
            Rectangle::new(Point::new(202, 2), Size::new(116, 32)),
            corner
        ).into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
        .draw(&mut self.display).ok();
        draw_lato_title(&mut self.display, "EXIT", 236, 26, COLOR_TEXT);

        // 6 param buttons: 3 rows x 2 cols
        let btn_w = 56u32;
        let btn_h = 44u32;
        let gap = 3i32;
        let grid_y0 = 38i32;
        let col0_x = 202i32;
        let col1_x = 262i32;
        let row_step = (btn_h as i32) + gap;

        for i in 0..6u8 {
            let row = i / 2;
            let col = i % 2;
            let bx = if col == 0 { col0_x } else { col1_x };
            let by = grid_y0 + row as i32 * row_step;
            let is_sel = i == param;

            let btn_bg = if is_sel {
                PrimitiveStyle::with_fill(KASPA_TEAL)
            } else {
                PrimitiveStyle::with_fill(COLOR_CARD)
            };
            RoundedRectangle::new(
                Rectangle::new(Point::new(bx, by), Size::new(btn_w, btn_h)),
                corner
            ).into_styled(btn_bg).draw(&mut self.display).ok();

            let label = CAM_TUNE_LABELS[i as usize];
            let label_color = if is_sel { COLOR_BG } else { COLOR_TEXT };
            let lw = measure_body(label);
            let lx = bx + (btn_w as i32 - lw) / 2;
            draw_lato_body(&mut self.display, label, lx.max(bx + 2), by + 30, label_color);
        }

        // Bottom slider bar
        self.update_cam_tune_slider(param, vals);
    }

    /// Partial redraw: only the bottom slider bar (y=180..240).
    pub fn update_cam_tune_slider(&mut self, param: u8, vals: &[u8; 6]) {
        use embedded_graphics::prelude::*;
        use embedded_graphics::primitives::{Rectangle, PrimitiveStyle, RoundedRectangle};
        use embedded_graphics::primitives::CornerRadii;
        use crate::hw::display::*;

        let corner = CornerRadii::new(Size::new(6, 6));
        let slider_y = 180i32;
        let active_val = vals[param as usize];

        // Clear bottom bar
        Rectangle::new(Point::new(0, slider_y), Size::new(320, 60))
            .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
            .draw(&mut self.display).ok();

        // Label + hex + pct — centered vertically in top strip (y=180..200)
        // lato_body ~13px height, baseline at y=193 centers nicely
        let label = CAM_TUNE_LABELS[param as usize];
        let lw = measure_body(label);
        // Center label+hex+pct group: label(lw) + gap(6) + hex(~40) + gap(6) + pct(~36) = ~lw+88
        // Approximate: center the whole group in 320px
        let group_w = lw + 6 + 40 + 6 + 36;
        let gx = ((320 - group_w) / 2).max(4);
        draw_lato_body(&mut self.display, label, gx, slider_y + 13, KASPA_TEAL);

        let mut vbuf = [0u8; 4];
        vbuf[0] = b'0'; vbuf[1] = b'x';
        vbuf[2] = b"0123456789ABCDEF"[(active_val >> 4) as usize];
        vbuf[3] = b"0123456789ABCDEF"[(active_val & 0x0F) as usize];
        if let Ok(vs) = core::str::from_utf8(&vbuf) {
            draw_lato_title(&mut self.display, vs, gx + lw + 6, slider_y + 13, COLOR_TEXT);
        }
        let pct = (active_val as u16 * 100 / 255) as u8;
        let mut dbuf = [b' '; 4];
        dbuf[0] = b'0' + (pct / 100); dbuf[1] = b'0' + ((pct / 10) % 10);
        dbuf[2] = b'0' + (pct % 10); dbuf[3] = b'%';
        if let Ok(ds) = core::str::from_utf8(&dbuf) {
            draw_lato_body(&mut self.display, ds, gx + lw + 6 + 40 + 6, slider_y + 13, COLOR_TEXT_DIM);
        }

        // [-] button (50x34 at x=2, y=slider_y+20) — center "-" in button
        let btn_m = Rectangle::new(Point::new(2, slider_y + 20), Size::new(50, 34));
        RoundedRectangle::new(btn_m, corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(btn_m, corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(&mut self.display).ok();
        let mw = measure_title("-");
        draw_lato_title(&mut self.display, "-", 2 + (50 - mw) / 2, slider_y + 44, COLOR_TEXT);

        // Slider track — centered vertically between buttons (y=200..234 → center y=217)
        let track_x0 = 56i32;
        let track_x1 = 264i32;
        let track_w = (track_x1 - track_x0) as u32;
        let track_y = slider_y + 30;
        let track_h = 10u32;

        RoundedRectangle::new(
            Rectangle::new(Point::new(track_x0, track_y), Size::new(track_w, track_h)),
            CornerRadii::new(Size::new(5, 5))
        ).into_styled(PrimitiveStyle::with_stroke(COLOR_TEXT_DIM, 1)).draw(&mut self.display).ok();
        let fill_w = (active_val as u32 * track_w) / 255;
        if fill_w > 0 {
            RoundedRectangle::new(
                Rectangle::new(Point::new(track_x0, track_y), Size::new(fill_w.min(track_w), track_h)),
                CornerRadii::new(Size::new(5, 5))
            ).into_styled(PrimitiveStyle::with_fill(KASPA_ACCENT)).draw(&mut self.display).ok();
        }
        let thumb_x = track_x0 + (active_val as i32 * (track_x1 - track_x0 - 12)) / 255;
        RoundedRectangle::new(
            Rectangle::new(Point::new(thumb_x, track_y - 4), Size::new(12, track_h + 8)),
            CornerRadii::new(Size::new(6, 6))
        ).into_styled(PrimitiveStyle::with_fill(KASPA_TEAL)).draw(&mut self.display).ok();

        // [+] button (50x34 at x=268, y=slider_y+20) — center "+" in button
        let btn_p = Rectangle::new(Point::new(268, slider_y + 20), Size::new(50, 34));
        RoundedRectangle::new(btn_p, corner)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD)).draw(&mut self.display).ok();
        RoundedRectangle::new(btn_p, corner)
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1)).draw(&mut self.display).ok();
        let pw = measure_title("+");
        draw_lato_title(&mut self.display, "+", 268 + (50 - pw) / 2, slider_y + 44, COLOR_TEXT);
    }
}


/// Extract the 2-byte fingerprint prefix from an SD backup filename.
/// Filenames are "SDxxxx" or "XPxxxx" where xxxx = 4 hex chars.
/// Returns Some([hi, lo]) or None if format doesn't match.
fn extract_fingerprint_from_filename(name: &[u8; 11]) -> Option<[u8; 2]> {
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'F' => Some(c - b'A' + 10),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    // Must start with "SD" or "XP"
    if !((name[0] == b'S' && name[1] == b'D') || (name[0] == b'X' && name[1] == b'P')) {
        return None;
    }
    let h0 = hex_val(name[2])?;
    let l0 = hex_val(name[3])?;
    let h1 = hex_val(name[4])?;
    let l1 = hex_val(name[5])?;
    Some([(h0 << 4) | l0, (h1 << 4) | l1])
}
