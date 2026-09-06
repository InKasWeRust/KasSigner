//! Browser verification helper for the universal covenant anti-klepto transcript.

use wasm_bindgen::prelude::*;

use crate::{
    protocol::{anti_klepto::verify_nonce_relation, schnorr::bip340_verify},
    wasm_api::utilities::common::js_error,
};

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|_| format!("invalid {label} hex"))?;
    if bytes.len() != N {
        return Err(format!("{label} must be {N} bytes"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(super) fn verify_covenant_anti_klepto_string(
    pubkey_x_hex: &str,
    commitment_hex: &str,
    nonce_point_hex: &str,
    signature_hex: &str,
    session_id_hex: &str,
    host_secret_hex: &str,
) -> Result<bool, String> {
    let pubkey_x = decode_fixed::<32>(pubkey_x_hex, "covenant public key")?;
    let commitment = decode_fixed::<32>(commitment_hex, "covenant commitment")?;
    let nonce_point = decode_fixed::<33>(nonce_point_hex, "provisional nonce")?;
    let signature_bytes = decode_fixed::<64>(signature_hex, "covenant signature")?;
    let session_id = decode_fixed::<{ shared_signer::covenant_sign::SESSION_ID_LEN }>(
        session_id_hex,
        "covenant session",
    )?;
    let mut host_secret = decode_fixed::<32>(host_secret_hex, "host secret")?;
    let mut public_key = [0u8; 33];
    public_key[0] = 0x02;
    public_key[1..].copy_from_slice(&pubkey_x);
    let result = bip340_verify(&pubkey_x, &commitment, &signature_bytes).unwrap_or(false)
        && verify_nonce_relation(
            &nonce_point,
            &signature_bytes,
            &session_id,
            &host_secret,
            0,
            0,
            &public_key,
        )
        .is_ok();
    shared_signer::bytes::zeroize_bytes(&mut host_secret);
    Ok(result)
}

#[wasm_bindgen]
pub fn verify_covenant_anti_klepto(
    pubkey_x_hex: &str,
    commitment_hex: &str,
    nonce_point_hex: &str,
    signature_hex: &str,
    session_id_hex: &str,
    host_secret_hex: &str,
) -> Result<bool, JsValue> {
    verify_covenant_anti_klepto_string(
        pubkey_x_hex,
        commitment_hex,
        nonce_point_hex,
        signature_hex,
        session_id_hex,
        host_secret_hex,
    )
    .map_err(js_error)
}

#[cfg(test)]
mod unit_tests;
