//! Transaction-review destination rendering.
use super::{
    BootDisplay,
    COLOR_TEXT,
    KASPA_ACCENT,
    KASPA_TEAL,
    draw_lato_body,
    draw_lato_title,
    measure_body,
    measure_title,
};
use core::fmt::Write;

impl<'a> BootDisplay<'a> {
    pub(super) fn draw_tx_destination(
        &mut self,
        script: &offline_signer::transaction::model::ScriptPublicKey,
        network: offline_signer::address::KaspaNetwork,
    ) {
        let is_p2pk = script.script_len == 34
            && script.script[0] == 0x20
            && script.script[33] == 0xAC;
        let is_p2sh = script.script_len == 35
            && script.script[0] == 0xAA
            && script.script[1] == 0x20
            && script.script[34] == 0x87;

        if !(is_p2pk || is_p2sh) {
            self.draw_script_preview(script);
            return;
        }

        let mut key_or_hash = [0u8; 32];
        let (address_type, source_start) = if is_p2pk {
            (offline_signer::address::AddressType::P2pk, 1usize)
        } else {
            (offline_signer::address::AddressType::P2sh, 2usize)
        };
        key_or_hash.copy_from_slice(&script.script[source_start..source_start + 32]);

        if network == offline_signer::address::KaspaNetwork::Unknown {
            let label = "NETWORK UNKNOWN";
            let width = measure_title(label);
            draw_lato_title(&mut self.display, label, (320 - width) / 2, 125, KASPA_ACCENT);
            self.draw_script_preview(script);
            return;
        }
        let mut address_buffer = [0u8; offline_signer::address::MAX_ADDR_LEN];
        let address = offline_signer::address::encode_address_str_for_network(
            &key_or_hash,
            address_type,
            network,
            &mut address_buffer,
        );
        if is_p2sh {
            let tag = "To P2SH address:";
            let width = measure_body(tag);
            draw_lato_body(
                &mut self.display,
                tag,
                (320 - width) / 2,
                95,
                KASPA_ACCENT,
            );
        }
        self.draw_address_block(address, is_p2sh);
    }

    fn draw_address_block(&mut self, address: &str, is_p2sh: bool) {
        let bytes = address.as_bytes();
        let total_len = bytes.len();
        let colon = bytes
            .iter()
            .position(|&byte| byte == b':')
            .map(|position| position + 1)
            .unwrap_or(0);
        let highlight_a_start = colon;
        let highlight_a_end = core::cmp::min(colon + 8, total_len);
        let highlight_b_start = total_len.saturating_sub(8);
        let (available_top, available_bottom) = if is_p2sh {
            (90i32, 188i32)
        } else {
            (70i32, 188i32)
        };

        if total_len < 30 {
            let width = measure_title(address);
            let y = available_top + (available_bottom - available_top) / 2;
            self.draw_addr_line_emph(
                address,
                0,
                highlight_a_start,
                highlight_a_end,
                highlight_b_start,
                (320 - width) / 2,
                y,
            );
            return;
        }

        let third = (total_len + 2) / 3;
        let first_end = third;
        let second_end = core::cmp::min(2 * third, total_len);
        let line_height = 26i32;
        let block_height = 3 * line_height;
        let y = available_top
            + (available_bottom - available_top - block_height) / 2
            + line_height;
        self.draw_address_line(
            &bytes[..first_end],
            0,
            highlight_a_start,
            highlight_a_end,
            highlight_b_start,
            y,
        );
        self.draw_address_line(
            &bytes[first_end..second_end],
            first_end,
            highlight_a_start,
            highlight_a_end,
            highlight_b_start,
            y + line_height,
        );
        self.draw_address_line(
            &bytes[second_end..],
            second_end,
            highlight_a_start,
            highlight_a_end,
            highlight_b_start,
            y + 2 * line_height,
        );
    }

    fn draw_address_line(
        &mut self,
        bytes: &[u8],
        line_start: usize,
        highlight_a_start: usize,
        highlight_a_end: usize,
        highlight_b_start: usize,
        y: i32,
    ) {
        if let Ok(line) = core::str::from_utf8(bytes) {
            let width = measure_title(line);
            self.draw_addr_line_emph(
                line,
                line_start,
                highlight_a_start,
                highlight_a_end,
                highlight_b_start,
                (320 - width) / 2,
                y,
            );
        }
    }

    fn draw_script_preview(&mut self, script: &offline_signer::transaction::model::ScriptPublicKey) {
        let mut preview = heapless::String::<48>::new();
        write!(&mut preview, "Script: ").ok();
        for byte in script.script.iter().take(core::cmp::min(8, script.script_len)) {
            write!(&mut preview, "{byte:02x}").ok();
        }
        write!(&mut preview, "...").ok();
        draw_lato_body(&mut self.display, preview.as_str(), 30, 100, COLOR_TEXT);
    }

    /// Draw one line of an address while emphasizing the two verification zones.
    fn draw_addr_line_emph(
        &mut self,
        line: &str,
        line_start: usize,
        highlight_a_start: usize,
        highlight_a_end: usize,
        highlight_b_start: usize,
        x: i32,
        y: i32,
    ) {
        let bytes = line.as_bytes();
        if bytes.is_empty() {
            return;
        }
        let highlighted = |global: usize| {
            (global >= highlight_a_start && global < highlight_a_end)
                || global >= highlight_b_start
        };
        let mut cursor = x;
        let mut segment_start = 0usize;
        let mut current_highlight = highlighted(line_start);
        for index in 1..=bytes.len() {
            let next_highlight = if index < bytes.len() {
                highlighted(line_start + index)
            } else {
                !current_highlight
            };
            if next_highlight == current_highlight {
                continue;
            }
            if let Ok(segment) = core::str::from_utf8(&bytes[segment_start..index]) {
                let color = if current_highlight {
                    KASPA_TEAL
                } else {
                    COLOR_TEXT
                };
                cursor += draw_lato_title(&mut self.display, segment, cursor, y, color);
            }
            segment_start = index;
            current_highlight = next_highlight;
        }
    }
}
