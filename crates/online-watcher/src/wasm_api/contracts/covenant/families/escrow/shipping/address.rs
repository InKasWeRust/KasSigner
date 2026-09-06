//! Thin WASM adapter for shipping-escrow construction.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn covenant_ship_escrow(request_json: &str) -> Result<String, JsValue> {
    crate::contracts::shipping_escrow::construction::build_random_json(request_json)
        .map_err(|error| wasm_error!(&error))
}

#[cfg(test)]
pub(crate) fn build_shipping_escrow_json(
    request_json: &str,
    salt: [u8; 8],
) -> Result<String, String> {
    crate::contracts::shipping_escrow::construction::build_json(request_json, salt)
}
