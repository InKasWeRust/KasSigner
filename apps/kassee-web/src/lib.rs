//! Thin WASM application shell. All online wallet behavior lives in `online-watcher`.

use wasm_bindgen::prelude::*;

pub use online_watcher::*;

#[wasm_bindgen(start)]
pub fn initialize_application() {
    console_error_panic_hook::set_once();
}

fn sdk_json<T: serde::Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn protocol_error(error: kassigner_sdk::ProtocolError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

fn sdk_error(error: kassigner_sdk::SdkError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[wasm_bindgen]
pub fn kassigner_sdk_limits() -> Result<String, JsValue> {
    sdk_json(&kassigner_sdk::limits())
}

// KasSee is the reference consumer of the same friendly Rust SDK used by
// third-party wallets. Transaction construction/coin selection remains a
// KasSee wallet-policy concern in online-watcher; only KasSigner protocol
// preparation and response validation/merge cross this facade.
#[wasm_bindgen]
pub fn kassigner_sdk_prepare(pskt_hex: &str, network: &str) -> Result<String, JsValue> {
    let network = kassigner_sdk::Network::parse(network).map_err(protocol_error)?;
    kassigner_sdk::prepare(pskt_hex, network)
        .map_err(sdk_error)
        .and_then(|value| sdk_json(&value))
}

#[wasm_bindgen]
pub fn kassigner_sdk_complete(
    original_pskt_hex: &str,
    response_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    parse_sdk_network(network)
        .and_then(|network| prepare_sdk_request(original_pskt_hex, network))
        .and_then(|request| complete_sdk_request(&request, response_hex))
        .and_then(|value| sdk_json(&value))
}

fn parse_sdk_network(network: &str) -> Result<kassigner_sdk::Network, JsValue> {
    kassigner_sdk::Network::parse(network).map_err(protocol_error)
}

fn prepare_sdk_request(
    pskt_hex: &str,
    network: kassigner_sdk::Network,
) -> Result<kassigner_sdk::SigningRequest, JsValue> {
    kassigner_sdk::prepare(pskt_hex, network).map_err(sdk_error)
}

fn complete_sdk_request(
    request: &kassigner_sdk::SigningRequest,
    response_hex: &str,
) -> Result<kassigner_sdk::SignedPskt, JsValue> {
    kassigner_sdk::complete(request, response_hex).map_err(sdk_error)
}
