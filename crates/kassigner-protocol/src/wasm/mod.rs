//! `wasm-bindgen` boundary for the low-level Rust protocol crate.

use js_sys::{Object, Reflect};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use super::{
    accept_privacy_pairing_response_text, attach_input_derivation, attach_output_derivation,
    create_privacy_pairing_request_hex, decode_account, encode_pskt_hex, finalize_json,
    merge_signed_kspt_hex, AddressBranch, Network, ProtocolError, ProtocolErrorKind, QrDecoder,
    PROTOCOL_VERSION,
};

fn to_json<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|error| {
        js_error(ProtocolError::new(
            ProtocolErrorKind::Internal,
            error.to_string(),
        ))
    })
}

fn parse_network(value: &str) -> Result<Network, JsValue> {
    Network::parse(value).map_err(js_error)
}

fn js_error(error: ProtocolError) -> JsValue {
    let object = Object::new();
    let _ = Reflect::set(
        &object,
        &JsValue::from_str("kind"),
        &JsValue::from_str(error.kind().as_str()),
    );
    let _ = Reflect::set(
        &object,
        &JsValue::from_str("message"),
        &JsValue::from_str(error.message()),
    );
    object.into()
}

fn malformed(message: impl Into<String>) -> JsValue {
    js_error(ProtocolError::new(
        ProtocolErrorKind::MalformedRequest,
        message,
    ))
}

#[wasm_bindgen]
pub fn kassigner_protocol_version() -> String {
    PROTOCOL_VERSION.to_string()
}

#[wasm_bindgen]
pub fn kassigner_protocol_decode_account(
    account_payload: &str,
    network: &str,
) -> Result<String, JsValue> {
    let network = parse_network(network)?;
    decode_account(account_payload, network)
        .map_err(js_error)
        .and_then(|value| to_json(&value))
}

#[wasm_bindgen]
pub fn kassigner_protocol_create_privacy_pairing_request(
    nonce_hex: &str,
    receive_start: u32,
    receive_count: u8,
    change_start: u32,
    change_count: u8,
) -> Result<String, JsValue> {
    create_privacy_pairing_request_hex(
        nonce_hex,
        receive_start,
        receive_count,
        change_start,
        change_count,
    )
    .map_err(js_error)
    .and_then(|value| to_json(&value))
}

#[wasm_bindgen]
pub fn kassigner_protocol_accept_privacy_pairing_response(
    request_json: &str,
    response_hex: &str,
    network: &str,
    expected_account_fingerprint: Option<String>,
) -> Result<String, JsValue> {
    accept_privacy_pairing_response_text(
        request_json,
        response_hex,
        network,
        expected_account_fingerprint.as_deref(),
    )
    .map_err(js_error)
    .and_then(|value| to_json(&value))
}

#[wasm_bindgen]
pub fn kassigner_protocol_pskt_to_kspt(pskt_hex: &str, network: &str) -> Result<String, JsValue> {
    encode_pskt_hex(pskt_hex, parse_network(network)?).map_err(js_error)
}

#[wasm_bindgen]
pub fn kassigner_protocol_kspt_to_pskt(
    original_pskt_hex: &str,
    signed_kspt_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    merge_signed_kspt_hex(original_pskt_hex, signed_kspt_hex, parse_network(network)?)
        .map_err(js_error)
}

#[wasm_bindgen]
pub fn kassigner_protocol_attach_input_derivation(
    pskt_hex: &str,
    input_index: usize,
    branch: u8,
    index: u32,
) -> Result<String, JsValue> {
    let branch = AddressBranch::from_code(branch).map_err(js_error)?;
    attach_input_derivation(pskt_hex, input_index, branch, index).map_err(js_error)
}

#[wasm_bindgen]
pub fn kassigner_protocol_attach_output_derivation(
    pskt_hex: &str,
    output_index: usize,
    branch: u8,
    index: u32,
) -> Result<String, JsValue> {
    let branch = AddressBranch::from_code(branch).map_err(js_error)?;
    attach_output_derivation(pskt_hex, output_index, branch, index).map_err(js_error)
}

#[wasm_bindgen]
pub fn kassigner_protocol_finalize_pskt(pskt_hex: &str) -> Result<String, JsValue> {
    finalize_json(pskt_hex).map_err(js_error)
}

#[wasm_bindgen]
pub struct ProtocolQrDecoder {
    decoder: QrDecoder,
}

#[wasm_bindgen]
impl ProtocolQrDecoder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            decoder: QrDecoder::new(),
        }
    }

    pub fn reset(&mut self) {
        self.decoder.reset();
    }

    pub fn progress(&self) -> Result<String, JsValue> {
        to_json(&self.decoder.progress())
    }

    pub fn accept(&mut self, frame_hex: &str) -> Result<Option<String>, JsValue> {
        let frame = hex::decode(frame_hex)
            .map_err(|error| malformed(format!("invalid QR frame hex: {error}")))?;
        self.decoder
            .accept(&frame)
            .map(|value| value.map(hex::encode))
            .map_err(js_error)
    }
}
