use crate::protocol::qr;
use wasm_bindgen::prelude::*;

/// Generate QR frames (SVG strings) for a KSPT hex → return JSON array
#[wasm_bindgen]
pub fn generate_qr_frames(kspt_hex: &str) -> Result<String, JsValue> {
    let frames = qr::generate_frames(kspt_hex).map_err(|error| wasm_error!(&error))?;
    serde_json::to_string(&frames).map_err(|error| wasm_error!(&error.to_string()))
}

/// Generate a single QR code SVG from a plain UTF-8 string.
/// No framing, no hex encoding. Used for swap invites and data exchange.
#[wasm_bindgen]
pub fn generate_qr_svg_text(text: &str) -> Result<String, JsValue> {
    qr::generate_svg_from_text(text).map_err(|error| wasm_error!(&error))
}

/// Feed a scanned QR frame (hex). Returns complete KSPT hex when done, or empty string.
#[wasm_bindgen]
pub fn decode_qr_frame(frame_hex: &str) -> Result<String, JsValue> {
    qr::decode_frame(frame_hex)
        .map(|value| value.unwrap_or_default())
        .map_err(|error| wasm_error!(&error))
}

/// Reset multi-frame decoder state
#[wasm_bindgen]
pub fn reset_qr_decoder() {
    qr::reset_decoder();
}

/// Get decoder scan progress as JSON
#[wasm_bindgen]
pub fn decoder_progress() -> String {
    qr::decoder_progress()
}

/// Version string
#[wasm_bindgen]
pub fn version() -> String {
    "KasSee Web".into()
}
