//! Advanced inspection screens for the UTXOs actually consumed by a transaction.

use super::{
    BootDisplay, COLOR_BG, COLOR_ORANGE, COLOR_TEXT, COLOR_TEXT_DIM, DrawTarget, Drawable,
    KASPA_ACCENT, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, draw_lato_body,
    draw_lato_title, draw_oswald_header, measure_body, measure_header, measure_title,
};
use core::fmt::Write;

impl<'a> BootDisplay<'a> {
    pub fn draw_utxo_summary_screen(
        &mut self,
        tx: &offline_signer::transaction::model::Transaction,
        totals: crate::runtime::signing::ReviewTotals,
    ) {
        self.display.clear(COLOR_BG).ok();
        let title = "UTXO INSPECTION";
        let width = measure_header(title);
        draw_oswald_header(&mut self.display, title, (320 - width) / 2, 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let mut line = heapless::String::<48>::new();
        write!(&mut line, "Transaction UTXOs: {}", tx.num_inputs).ok();
        centered_body(self, line.as_str(), 70, COLOR_TEXT);
        line.clear();
        write!(&mut line, "Input total: {}.{:08} KAS", totals.input_total / 100_000_000, totals.input_total % 100_000_000).ok();
        centered_body(self, line.as_str(), 96, COLOR_ORANGE);
        line.clear();
        write!(&mut line, "Send total:  {}.{:08} KAS", totals.external_total / 100_000_000, totals.external_total % 100_000_000).ok();
        centered_body(self, line.as_str(), 122, COLOR_TEXT);
        line.clear();
        write!(&mut line, "Change:      {}.{:08} KAS", totals.change_total / 100_000_000, totals.change_total % 100_000_000).ok();
        centered_body(self, line.as_str(), 148, KASPA_TEAL);
        line.clear();
        write!(&mut line, "Fee:         {}.{:08} KAS", totals.fee / 100_000_000, totals.fee % 100_000_000).ok();
        centered_body(self, line.as_str(), 174, COLOR_TEXT);
        centered_title(self, "VIEW UTXOS >", 208, KASPA_ACCENT);
        centered_body(self, "Touch/press to inspect", 228, COLOR_TEXT_DIM);
    }

    pub fn draw_utxo_detail_screen(
        &mut self,
        tx: &offline_signer::transaction::model::Transaction,
        index: usize,
        address_page: bool,
    ) {
        self.display.clear(COLOR_BG).ok();
        if index >= tx.num_inputs { return; }
        let input = &tx.inputs[index];
        let mut title = heapless::String::<32>::new();
        write!(&mut title, "UTXO {} / {}", index + 1, tx.num_inputs).ok();
        centered_header(self, title.as_str(), 30, COLOR_TEXT);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        if address_page {
            centered_body(self, "SOURCE ADDRESS", 62, KASPA_ACCENT);
            self.draw_tx_destination(&input.utxo_entry.script_public_key, tx.network);
            centered_body(self, "Touch/press for next UTXO", 230, COLOR_TEXT_DIM);
            return;
        }

        let mut amount = heapless::String::<36>::new();
        write!(&mut amount, "{}.{:08} KAS", input.utxo_entry.amount / 100_000_000, input.utxo_entry.amount % 100_000_000).ok();
        centered_title(self, amount.as_str(), 68, COLOR_ORANGE);
        centered_body(self, "TXID", 92, COLOR_TEXT_DIM);

        let mut hex = [0u8; 64];
        encode_hex(&input.previous_outpoint.transaction_id, &mut hex);
        if let Ok(first) = core::str::from_utf8(&hex[..32]) { centered_body(self, first, 112, COLOR_TEXT); }
        if let Ok(second) = core::str::from_utf8(&hex[32..]) { centered_body(self, second, 132, COLOR_TEXT); }

        let mut meta = heapless::String::<48>::new();
        write!(&mut meta, "Output index: {}", input.previous_outpoint.index).ok();
        centered_body(self, meta.as_str(), 160, KASPA_TEAL);
        meta.clear();
        write!(&mut meta, "DAA: {}", input.utxo_entry.block_daa_score).ok();
        centered_body(self, meta.as_str(), 182, COLOR_TEXT);
        centered_title(self, "ADDRESS >", 214, KASPA_ACCENT);
        centered_body(self, "Touch/press to continue", 232, COLOR_TEXT_DIM);
    }
}

fn encode_hex(bytes: &[u8; 32], output: &mut [u8; 64]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.iter().enumerate() {
        output[index * 2] = HEX[(byte >> 4) as usize];
        output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
}

fn centered_body(display: &mut BootDisplay<'_>, text: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
    let width = measure_body(text);
    draw_lato_body(&mut display.display, text, (320 - width) / 2, y, color);
}

fn centered_title(display: &mut BootDisplay<'_>, text: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
    let width = measure_title(text);
    draw_lato_title(&mut display.display, text, (320 - width) / 2, y, color);
}

fn centered_header(display: &mut BootDisplay<'_>, text: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
    let width = measure_header(text);
    draw_oswald_header(&mut display.display, text, (320 - width) / 2, y, color);
}
