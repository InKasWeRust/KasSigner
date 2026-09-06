use wasm_bindgen::prelude::*;

/// Compute unkeyed Blake2b-256 hash of the input bytes (hex in, hex out).
/// Generic byte-hash helper for script/address and commitment calculations.
#[wasm_bindgen]
pub fn blake2b_hash(input_hex: &str) -> Result<String, JsValue> {
    let input =
        hex::decode(input_hex).map_err(|error| wasm_error!(&format!("bad hex: {error}")))?;
    let hash = blake2b_simd::Params::new().hash_length(32).hash(&input);
    Ok(hex::encode(hash.as_bytes()))
}

/// Compute SHA-256 hash of the input bytes (hex in, hex out).
/// Generic SHA-256 helper for protocol fingerprints and exact byte commitments.
#[wasm_bindgen]
pub fn sha256_hash(input_hex: &str) -> Result<String, JsValue> {
    let input =
        hex::decode(input_hex).map_err(|error| wasm_error!(&format!("bad hex: {error}")))?;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&input);
    Ok(hex::encode(hash))
}
