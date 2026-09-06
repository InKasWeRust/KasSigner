//! Transaction review summary.
use super::{
    BootDisplay, COLOR_HINT, COLOR_ORANGE, COLOR_TEXT, Drawable, KASPA_ACCENT, KASPA_TEAL,
    Line, Point, Primitive, PrimitiveStyle, draw_lato_body, draw_lato_title, draw_oswald_header,
    measure_body, measure_header, measure_title,
};
use core::fmt::Write;

impl<'a> BootDisplay<'a> {
    pub(super) fn draw_tx_summary(
        &mut self,
        tx: &offline_signer::transaction::model::Transaction,
        ownership: &[crate::runtime::data::OutputOwnership; offline_signer::transaction::model::MAX_OUTPUTS],
    ) {
        let tw = measure_header("TX REVIEW");
        draw_oswald_header(&mut self.display, "TX REVIEW", (320 - tw) / 2, 28, COLOR_TEXT);
        Line::new(Point::new(20, 43), Point::new(300, 43))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();

        let Ok(totals) = crate::runtime::signing::transaction_review_totals(tx, ownership) else {
            self.draw_tx_error_screen("Invalid transaction", "Invalid monetary totals");
            return;
        };

        centered_body(self, tx.network.label(), 64, KASPA_ACCENT);

        let mut line = heapless::String::<40>::new();
        write!(&mut line, "Send: {}.{:08} KAS", totals.external_total / 100_000_000, totals.external_total % 100_000_000).ok();
        centered_body(self, line.as_str(), 88, COLOR_TEXT);
        line.clear();
        write!(&mut line, "Fee: {}.{:08} KAS", totals.fee / 100_000_000, totals.fee % 100_000_000).ok();
        centered_body(self, line.as_str(), 111, COLOR_ORANGE);
        line.clear();
        write!(&mut line, "Change: {}.{:08} KAS", totals.change_total / 100_000_000, totals.change_total % 100_000_000).ok();
        centered_body(self, line.as_str(), 134, KASPA_TEAL);
        line.clear();
        write!(&mut line, "Inputs: {}   Outputs: {}", tx.num_inputs, tx.num_outputs).ok();
        centered_body(self, line.as_str(), 157, COLOR_TEXT);

        draw_transaction_class(self, tx, 179);
        draw_payload_check(self, tx);
    }
}

fn draw_transaction_class(
    display: &mut BootDisplay<'_>,
    tx: &offline_signer::transaction::model::Transaction,
    y: i32,
) {
    let krc20 = crate::services::krc20::detect_krc20(tx);
    if krc20.detected {
        let mut text = heapless::String::<48>::new();
        write!(&mut text, "KRC-20 {} {}", krc20.op_str(), krc20.ticker_str()).ok();
        centered_title(display, text.as_str(), y, COLOR_ORANGE);
        return;
    }

    use offline_signer::transaction::model::{detect_script_type, parse_multisig_script, ScriptType};
    let Some(first_input) = tx.inputs().first() else { return; };
    let script = &first_input.utxo_entry.script_public_key;
    let script_type = detect_script_type(&script.script, script.script_len);
    if script_type == ScriptType::Multisig {
        if let Some(ms) = parse_multisig_script(&script.script, script.script_len) {
            let mut text = heapless::String::<32>::new();
            write!(&mut text, "{}-of-{} MULTISIG", ms.m, ms.n).ok();
            centered_title(display, text.as_str(), y, KASPA_ACCENT);
        }
    } else if script_type == ScriptType::P2SH {
        let redeem = tx.redeem_bytes(0);
        if !redeem.is_empty() && redeem[0] == 0x63 {
            centered_title(display, "COVENANT P2SH", y, KASPA_ACCENT);
        }
    }
}

fn draw_payload_check(display: &mut BootDisplay<'_>, tx: &offline_signer::transaction::model::Transaction) {
    if tx.payload_len == 0 { return; }
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&tx.payload[..tx.payload_len]);
    let hex = b"0123456789abcdef";
    let mut text = heapless::String::<24>::new();
    let _ = core::fmt::Write::write_str(&mut text, "PL ");
    for byte in hash.iter().take(8) {
        let _ = text.push(hex[(byte >> 4) as usize] as char);
        let _ = text.push(hex[(byte & 0x0f) as usize] as char);
    }
    let width = measure_body(text.as_str());
    draw_lato_body(&mut display.display, text.as_str(), 320 - width - 8, 188, COLOR_HINT);
}

fn centered_body(display: &mut BootDisplay<'_>, text: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
    let width = measure_body(text);
    draw_lato_body(&mut display.display, text, (320 - width) / 2, y, color);
}

fn centered_title(display: &mut BootDisplay<'_>, text: &str, y: i32, color: embedded_graphics::pixelcolor::Rgb565) {
    let width = measure_title(text);
    draw_lato_title(&mut display.display, text, (320 - width) / 2, y, color);
}
