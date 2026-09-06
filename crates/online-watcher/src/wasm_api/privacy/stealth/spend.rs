//! Thin WASM adapter for stealth spend planning.

use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[cfg(test)]
pub(super) use crate::transaction_builder::stealth::prepare_material as prepare_stealth_spend_material;

#[wasm_bindgen]
pub async fn create_stealth_spend(
    one_time_pubkey_hex: &str,
    tweak_hex: &str,
    dest_address: &str,
    fee: u64,
    ws_url: &str,
    network: &str,
) -> Result<String, JsValue> {
    crate::transaction_builder::stealth::build(
        one_time_pubkey_hex,
        tweak_hex,
        dest_address,
        fee,
        ws_url,
        network,
    )
    .await
    .map_err(|error| wasm_error!(&error))
}
