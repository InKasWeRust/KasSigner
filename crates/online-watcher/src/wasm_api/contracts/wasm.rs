use crate::transaction_builder::covenant::{
    build, CovenantBuildRequest, CovenantEncoding, CovenantFeeShape,
};
use crate::wasm_api::utilities::common::{parse_request, parse_u64_field, parse_wallet};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
struct CovenantPskbApiRequest {
    wallet_json: String,
    covenant_address: String,
    #[serde(default)]
    covenant_type: String,
    send_amount: String,
    fee: String,
    change_address: String,
    #[serde(default)]
    payload_hex: String,
    #[serde(default)]
    utxo_indices_csv: String,
    ws_url: String,
    #[serde(default)]
    tag_genesis: bool,
}

impl CovenantPskbApiRequest {
    fn send_amount(&self) -> Result<u64, JsValue> {
        parse_u64_field(&self.send_amount, "send_amount")
    }

    fn fee(&self) -> Result<u64, JsValue> {
        parse_u64_field(&self.fee, "fee")
    }
}

/// Build a PSKB for a covenant genesis transaction with an attached payload.
#[wasm_bindgen]
pub async fn create_covenant_pskb_with_payload(request_json: &str) -> Result<String, JsValue> {
    let request: CovenantPskbApiRequest = parse_request(request_json, "covenant payload request")?;
    let wallet = parse_wallet(&request.wallet_json, "Bad wallet JSON")?;

    build(CovenantBuildRequest {
        wallet: &wallet,
        covenant_address: &request.covenant_address,
        covenant_type: &request.covenant_type,
        send_amount: request.send_amount()?,
        fee: request.fee()?,
        change_address: &request.change_address,
        utxo_indices_csv: &request.utxo_indices_csv,
        websocket_url: &request.ws_url,
        encoding: CovenantEncoding::Payload {
            payload_hex: &request.payload_hex,
            tag_genesis: request.tag_genesis,
        },
    })
    .await
    .map_err(|error| wasm_error!(&error))
}

/// Build a PSKB for a covenant genesis transaction.
#[wasm_bindgen]
pub async fn create_covenant_pskb(request_json: &str) -> Result<String, JsValue> {
    let request: CovenantPskbApiRequest = parse_request(request_json, "covenant request")?;
    let wallet = parse_wallet(&request.wallet_json, "Bad wallet JSON")?;

    build(CovenantBuildRequest {
        wallet: &wallet,
        covenant_address: &request.covenant_address,
        covenant_type: &request.covenant_type,
        send_amount: request.send_amount()?,
        fee: request.fee()?,
        change_address: &request.change_address,
        utxo_indices_csv: &request.utxo_indices_csv,
        websocket_url: &request.ws_url,
        encoding: CovenantEncoding::BoundGenesis,
    })
    .await
    .map_err(|error| wasm_error!(&error))
}

/// Estimate covenant transaction compute-mass fee in the typed Rust domain layer.
/// The browser supplies only shape metadata; monetary arithmetic stays out of JS.
#[wasm_bindgen]
pub fn estimate_covenant_fee(
    p2pk_inputs: u32,
    redeem_bytes: u32,
    payload_bytes: u32,
    binding_bytes: u32,
) -> Result<String, JsValue> {
    CovenantFeeShape {
        p2pk_inputs: u64::from(p2pk_inputs),
        redeem_bytes: u64::from(redeem_bytes),
        payload_bytes: u64::from(payload_bytes),
        binding_bytes: u64::from(binding_bytes),
    }
    .calculate()
    .map(|fee| fee.to_string())
    .map_err(|error| wasm_error!(&error))
}

#[cfg(test)]
mod unit_tests;
