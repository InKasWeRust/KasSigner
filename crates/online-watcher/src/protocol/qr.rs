// KasSee Web — QR rendering and canonical protocol adapter
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// KasSee owns SVG rendering and the WASM-facing decoder lifetime only. Raw QR
// framing/session semantics are owned by `kassigner-protocol`.

//! Thin KasSee adapter over the canonical KasSigner QR protocol.

use serde::Serialize;
use std::cell::RefCell;
use std::fmt::Write;

use kassigner_protocol::qr::{encode_frames, QrDecoder};

#[derive(Debug, Serialize)]
pub struct QrFrame {
    pub frame_num: u8,
    pub total_frames: u8,
    pub svg: String,
}

pub fn generate_frames(kspt_hex: &str) -> Result<Vec<QrFrame>, String> {
    let data = hex::decode(kspt_hex).map_err(|error| format!("Invalid hex: {error}"))?;
    if data.is_empty() {
        return Err("Empty data".into());
    }

    let frames = encode_frames(&data).map_err(map_protocol_error)?;
    frames
        .into_iter()
        .map(|frame| {
            let svg = qr_to_svg(&frame.payload)?;
            Ok(QrFrame {
                frame_num: frame.index,
                total_frames: frame.total,
                svg,
            })
        })
        .collect()
}

fn qr_to_svg(data: &[u8]) -> Result<String, String> {
    use qrcode::QrCode;

    let code = QrCode::new(data).map_err(|error| format!("QR failed: {error:?}"))?;
    let modules = code.to_colors();
    let size = code.width();
    let border = 2;
    let total = size + 4;

    let svg_capacity = total.saturating_mul(total).saturating_mul(60);
    let mut svg = String::with_capacity(svg_capacity);
    let _ = write!(svg, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" shape-rendering=\"crispEdges\"><rect width=\"{total}\" height=\"{total}\" fill=\"white\"/>");

    for (index, color) in modules.iter().enumerate() {
        if *color == qrcode::types::Color::Dark {
            let x = (index % size) + border;
            let y = (index / size) + border;
            let _ = write!(
                svg,
                "<rect x=\"{x}\" y=\"{y}\" width=\"1\" height=\"1\" fill=\"black\"/>"
            );
        }
    }

    svg.push_str("</svg>");
    Ok(svg)
}

thread_local! {
    /// WASM's free-function API needs one browser-thread decoder instance.
    /// The state machine itself is the canonical protocol `QrDecoder`.
    static DECODER: RefCell<QrDecoder> = RefCell::new(QrDecoder::new());
}

pub fn decode_frame(frame_hex: &str) -> Result<Option<String>, String> {
    let payload = hex::decode(frame_hex).map_err(|error| format!("Invalid hex: {error}"))?;
    DECODER.with(|cell| {
        cell.borrow_mut()
            .accept(&payload)
            .map(|complete| complete.map(hex::encode))
            .map_err(map_protocol_error)
    })
}

pub fn reset_decoder() {
    DECODER.with(|cell| cell.borrow_mut().reset());
}

/// Returns "0/0" while idle; otherwise the legacy KasSee progress JSON shape.
pub fn decoder_progress() -> String {
    DECODER.with(|cell| {
        let progress = cell.borrow().progress();
        if progress.total == 0 {
            return "0/0".into();
        }
        let bits = progress
            .bits
            .iter()
            .map(|received| if *received { "1" } else { "0" })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"total\":{},\"count\":{},\"bits\":[{}]}}",
            progress.total, progress.received, bits
        )
    })
}

/// Generate a single QR code SVG from a plain UTF-8 string (no framing, no hex encoding).
/// Used for swap invites and other non-KSPT data exchange.
pub fn generate_svg_from_text(text: &str) -> Result<String, String> {
    qr_to_svg(text.as_bytes())
}

fn map_protocol_error(error: kassigner_protocol::ProtocolError) -> String {
    let message = error.message();
    if let Some(rest) = message.strip_prefix("QR payload too large") {
        return format!("Too large{rest}");
    }
    let mut bytes = message.as_bytes().to_vec();
    if let Some(first) = bytes.first_mut() {
        first.make_ascii_uppercase();
    }
    String::from_utf8(bytes).unwrap_or_else(|_| message.to_string())
}
