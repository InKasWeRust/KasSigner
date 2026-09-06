#[must_use]
pub fn blake2b_hash(data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

pub fn script_to_address(redeem_script: &[u8], prefix: &str) -> Result<String, String> {
    Ok(crate::account::address::encode_p2sh_address(
        &blake2b_hash(redeem_script),
        prefix,
    ))
}
