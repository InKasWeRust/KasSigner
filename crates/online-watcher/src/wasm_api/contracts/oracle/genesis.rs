use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

/// Oracle Model-B genesis covenant.
#[wasm_bindgen]
pub fn covenant_oracle_mb(request_json: &str) -> Result<String, JsValue> {
    build_oracle_genesis_json(request_json).map_err(|error| wasm_error!(&error))
}

pub(crate) fn build_oracle_genesis_json(request_json: &str) -> Result<String, String> {
    crate::contracts::oracle::genesis::build_json(request_json)
}

/// Oracle Model-B heartbeat genesis covenant.
#[wasm_bindgen]
pub fn covenant_oracle_mb_heartbeat(network: &str) -> Result<String, JsValue> {
    crate::contracts::oracle::genesis::build_heartbeat_json(network)
        .map_err(|error| wasm_error!(&error))
}
