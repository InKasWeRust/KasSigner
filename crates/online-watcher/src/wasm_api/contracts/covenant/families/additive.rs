use super::{wasm_bindgen, JsValue};

/// Build a Piggy Bank P2SH covenant address.
#[wasm_bindgen]
pub fn covenant_additive_address(
    owner_pubkey_hex: &str,
    threshold_sompi: u64,
    deadline_daa: u64,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::covenant::construction::additive::build_json(
        owner_pubkey_hex,
        threshold_sompi,
        deadline_daa,
        network,
    )
    .map_err(|error| wasm_error!(&error))
}
