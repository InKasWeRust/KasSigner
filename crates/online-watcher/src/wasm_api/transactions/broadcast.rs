use crate::{wasm_api::utilities::common::js_error, WatchWallet};
use wasm_bindgen::prelude::*;

/// Broadcast a signed KSPT hex to the network → return TX ID
#[wasm_bindgen]
pub async fn broadcast_signed(signed_hex: &str, ws_url: &str) -> Result<String, JsValue> {
    WatchWallet::new()
        .broadcast(signed_hex, ws_url)
        .await
        .map_err(js_error)
}

#[cfg(test)]
mod unit_tests;
