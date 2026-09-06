use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
// ─── Commit-Reveal Covenant (MEV Resistance) ───

/// Compute BLAKE2B hash of a preimage (for creating the commitment).
/// Returns hex string of the 32-byte hash.
#[wasm_bindgen]
pub fn commit_hash(preimage_hex: &str) -> Result<String, JsValue> {
    let preimage =
        hex::decode(preimage_hex).map_err(|e| wasm_error!(&format!("Bad preimage hex: {}", e)))?;
    let hash = crate::protocol::script::p2sh::blake2b_hash(&preimage);
    Ok(hex::encode(hash))
}
