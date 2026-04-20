// KasSee Web — QR frame generation and decoder
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// qr.rs — Generate QR frames as SVG strings, decode multi-frame protocol.
// Matches KasSigner's multi-frame QR format:
//   [frame_num(1)] [total_frames(1)] [frag_len(1)] [data(frag_len)]

use serde::Serialize;
use std::cell::RefCell;
use std::fmt::Write;

const MAX_FRAME_DATA: usize = 106;

/// Maximum number of frames for a multi-frame QR payload. Sized to
/// cover a 3-input 2-of-3 PSKT on the tightest hardware envelope
/// (WS-OV5640 → M5 LCD, ~37 B/frame at V3 ≈ 50 frames), with margin.
const MAX_FRAMES: usize = 64;

// ─── Frame generation ───

#[derive(Serialize)]
pub struct QrFrame {
    pub frame_num: u8,
    pub total_frames: u8,
    pub svg: String,
}

pub fn generate_frames(kspt_hex: &str) -> Result<Vec<QrFrame>, String> {
    let data = hex::decode(kspt_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;

    if data.is_empty() {
        return Err("Empty data".into());
    }

    // Single frame if small enough
    if data.len() <= 134 {
        let svg = qr_to_svg(&data)?;
        return Ok(vec![QrFrame {
            frame_num: 0,
            total_frames: 1,
            svg,
        }]);
    }

    // Multi-frame
    let total_frames = data.len().div_ceil(MAX_FRAME_DATA);
    if total_frames > MAX_FRAMES {
        return Err(format!("Too large: {} bytes ({} frames, max {})", data.len(), total_frames, MAX_FRAMES));
    }

    let balanced_size = data.len().div_ceil(total_frames);
    let total = total_frames as u8;
    let mut frames = Vec::with_capacity(total_frames);

    for frame_num in 0..total_frames {
        let start = frame_num * balanced_size;
        let end = (start + balanced_size).min(data.len());
        let frag = &data[start..end];

        let mut payload = Vec::with_capacity(3 + frag.len().max(20));
        payload.push(frame_num as u8);
        payload.push(total);
        payload.push(frag.len() as u8);
        payload.extend_from_slice(frag);

        // Pad short frames for reliable scanning
        if frag.len() < 20 {
            payload.resize(3 + 20, 0);
        }

        let svg = qr_to_svg(&payload)?;
        frames.push(QrFrame {
            frame_num: frame_num as u8,
            total_frames: total,
            svg,
        });
    }

    Ok(frames)
}

fn qr_to_svg(data: &[u8]) -> Result<String, String> {
    use qrcode::QrCode;

    let code = QrCode::new(data)
        .map_err(|e| format!("QR failed: {:?}", e))?;

    let modules = code.to_colors();
    let size = code.width();
    let border = 2;
    let total = size + border * 2;

    let mut svg = String::with_capacity(total * total * 60);
    let _ = write!(svg, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" shape-rendering=\"crispEdges\"><rect width=\"{total}\" height=\"{total}\" fill=\"white\"/>");

    for (i, color) in modules.iter().enumerate() {
        if *color == qrcode::types::Color::Dark {
            let x = (i % size) + border;
            let y = (i / size) + border;
            let _ = write!(svg, "<rect x=\"{}\" y=\"{}\" width=\"1\" height=\"1\" fill=\"black\"/>", x, y);
        }
    }

    svg.push_str("</svg>");
    Ok(svg)
}

// ─── Multi-frame decoder ───

thread_local! {
    static DECODER: RefCell<DecoderState> = RefCell::new(DecoderState::new());
}

struct DecoderState {
    total_frames: u8,
    received: [bool; MAX_FRAMES],
    fragments: [Vec<u8>; MAX_FRAMES],
}

impl DecoderState {
    fn new() -> Self {
        Self {
            total_frames: 0,
            received: [false; MAX_FRAMES],
            fragments: core::array::from_fn(|_| Vec::new()),
        }
    }

    fn reset(&mut self) {
        self.total_frames = 0;
        self.received = [false; MAX_FRAMES];
        for f in &mut self.fragments {
            f.clear();
        }
    }
}

pub fn decode_frame(frame_hex: &str) -> Result<Option<String>, String> {
    let payload = hex::decode(frame_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;

    if payload.len() < 3 {
        return Err("Frame too short".into());
    }

    let frame_num = payload[0] as usize;
    let total = payload[1] as usize;
    let frag_len = payload[2] as usize;

    if total == 0 || total > MAX_FRAMES || frame_num >= total {
        return Err(format!("Invalid frame {}/{}", frame_num, total));
    }
    if payload.len() < 3 + frag_len {
        return Err("Payload too short".into());
    }

    let frag_data = &payload[3..3 + frag_len];

    DECODER.with(|cell| {
        let mut state = cell.borrow_mut();

        // Reset if total changed
        if state.total_frames != total as u8 {
            state.reset();
            state.total_frames = total as u8;
        }

        state.received[frame_num] = true;
        state.fragments[frame_num] = frag_data.to_vec();

        // Check complete
        let all = (0..total).all(|i| state.received[i]);
        if all {
            let mut complete = Vec::new();
            for i in 0..total {
                complete.extend_from_slice(&state.fragments[i]);
            }
            state.reset();
            Ok(Some(hex::encode(&complete)))
        } else {
            Ok(None)
        }
    })
}

pub fn reset_decoder() {
    DECODER.with(|cell| {
        cell.borrow_mut().reset();
    });
}

/// Returns "received/total" string, e.g. "3/6" or "0/0" if no frames yet
pub fn decoder_progress() -> String {
    DECODER.with(|cell| {
        let state = cell.borrow();
        let total = state.total_frames as usize;
        if total == 0 { return "0/0".into(); }
        let received = (0..total).filter(|&i| state.received[i]).count();
        // Return JSON: {"received": [true,false,true,...], "total": 6, "count": 3}
        let bits: Vec<String> = (0..total).map(|i| if state.received[i] { "1".into() } else { "0".into() }).collect();
        format!("{{\"total\":{},\"count\":{},\"bits\":[{}]}}", total, received, bits.join(","))
    })
}
