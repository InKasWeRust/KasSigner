use wasm_bindgen::prelude::*;

use crate::wasm_api::utilities::common::js_error;

#[wasm_bindgen]
pub fn covenant_private_swap(
    owner_pubkey_hex: &str,
    claimer_pubkey_hex: &str,
    destination_address: &str,
    refund_locktime_daa: u64,
    salt_hex: &str,
    network: &str,
) -> Result<String, JsValue> {
    crate::contracts::covenant::construction::private_swap::build_json(
        owner_pubkey_hex,
        claimer_pubkey_hex,
        destination_address,
        refund_locktime_daa,
        salt_hex,
        network,
    )
    .map_err(js_error)
}

#[wasm_bindgen]
pub fn private_swap_key_request() -> Result<String, JsValue> {
    private_swap_key_request_string().map_err(js_error)
}

fn private_swap_key_request_string() -> Result<String, String> {
    let request = shared_signer::covenant_sign::private_swap::PrivateSwapRequest {
        kind: shared_signer::covenant_sign::private_swap::RequestKind::KeyInfo,
        session_id: [0; 16],
        host_commitment: [0; 32],
        key_id: [0; 32],
        binding_token: [0; 32],
        adaptor_point: [0; 32],
        presignature: [0; 64],
        presignature_negated: false,
        payload: &[],
    };
    encode_request_hex(&request)
}

#[wasm_bindgen]
pub fn private_swap_bind_request(
    key_id_hex: &str,
    adaptor_point_hex: &str,
    redeem_script_hex: &str,
) -> Result<String, JsValue> {
    private_swap_bind_request_string(key_id_hex, adaptor_point_hex, redeem_script_hex)
        .map_err(js_error)
}

fn private_swap_bind_request_string(
    key_id_hex: &str,
    adaptor_point_hex: &str,
    redeem_script_hex: &str,
) -> Result<String, String> {
    let key = decode32(key_id_hex, "key id")?;
    let point = decode32(adaptor_point_hex, "adaptor point")?;
    let script =
        hex::decode(redeem_script_hex).map_err(|error| format!("Bad redeem script: {error}"))?;
    let request = shared_signer::covenant_sign::private_swap::PrivateSwapRequest {
        kind: shared_signer::covenant_sign::private_swap::RequestKind::Bind,
        session_id: [0; 16],
        host_commitment: [0; 32],
        key_id: key,
        binding_token: [0; 32],
        adaptor_point: point,
        presignature: [0; 64],
        presignature_negated: false,
        payload: &script,
    };
    encode_request_hex(&request)
}

#[wasm_bindgen]
pub fn private_swap_presign_request(
    key_id_hex: &str,
    binding_token_hex: &str,
    adaptor_point_hex: &str,
    kspt_hex: &str,
    host_secret_hex: &str,
) -> Result<String, JsValue> {
    private_swap_presign_request_string(
        key_id_hex,
        binding_token_hex,
        adaptor_point_hex,
        kspt_hex,
        host_secret_hex,
    )
    .map_err(js_error)
}

fn private_swap_presign_request_string(
    key_id_hex: &str,
    binding_token_hex: &str,
    adaptor_point_hex: &str,
    kspt_hex: &str,
    host_secret_hex: &str,
) -> Result<String, String> {
    let key = decode32(key_id_hex, "key id")?;
    let token = decode32(binding_token_hex, "binding token")?;
    let point = decode32(adaptor_point_hex, "adaptor point")?;
    let secret = decode32(host_secret_hex, "host secret")?;
    let kspt = hex::decode(kspt_hex).map_err(|error| format!("Bad KSPT: {error}"))?;
    let host = shared_signer::anti_klepto::host_commitment(&secret);
    let session =
        shared_signer::covenant_sign::private_swap::session_id(&host, &kspt, &key, &point);
    let request = shared_signer::covenant_sign::private_swap::PrivateSwapRequest {
        kind: shared_signer::covenant_sign::private_swap::RequestKind::PreSign,
        session_id: session,
        host_commitment: host,
        key_id: key,
        binding_token: token,
        adaptor_point: point,
        presignature: [0; 64],
        presignature_negated: false,
        payload: &kspt,
    };
    let request_hex = encode_request_hex(&request)?;
    crate::protocol::private_swap::encode_presign_metadata_json(&request_hex, &session, &host)
}

#[wasm_bindgen]
pub fn private_swap_reveal_request(
    session_hex: &str,
    key_id_hex: &str,
    sighash_hex: &str,
    host_secret_hex: &str,
) -> Result<String, JsValue> {
    private_swap_reveal_request_string(session_hex, key_id_hex, sighash_hex, host_secret_hex)
        .map_err(js_error)
}

fn private_swap_reveal_request_string(
    session_hex: &str,
    key_id_hex: &str,
    sighash_hex: &str,
    host_secret_hex: &str,
) -> Result<String, String> {
    let session_bytes =
        hex::decode(session_hex).map_err(|error| format!("Bad session: {error}"))?;
    if session_bytes.len() != 16 {
        return Err("session must be 16 bytes".to_string());
    }
    let mut session = [0u8; 16];
    session.copy_from_slice(&session_bytes);
    let reveal = shared_signer::covenant_sign::private_swap::PrivateSwapReveal {
        session_id: session,
        key_id: decode32(key_id_hex, "key id")?,
        sighash: decode32(sighash_hex, "sighash")?,
        host_secret: decode32(host_secret_hex, "host secret")?,
    };
    let mut out = [0u8; shared_signer::covenant_sign::private_swap::REVEAL_LEN];
    let len = shared_signer::covenant_sign::private_swap::encode_reveal(&reveal, &mut out)
        .map_err(|_| "Private Swap reveal encode failed".to_string())?;
    Ok(hex::encode(&out[..len]))
}

#[wasm_bindgen]
pub fn private_swap_complete_request(
    key_id_hex: &str,
    binding_token_hex: &str,
    adaptor_point_hex: &str,
    kspt_hex: &str,
    presig_hex: &str,
    negated: bool,
) -> Result<String, JsValue> {
    private_swap_complete_request_string(
        key_id_hex,
        binding_token_hex,
        adaptor_point_hex,
        kspt_hex,
        presig_hex,
        negated,
    )
    .map_err(js_error)
}

fn private_swap_complete_request_string(
    key_id_hex: &str,
    binding_token_hex: &str,
    adaptor_point_hex: &str,
    kspt_hex: &str,
    presig_hex: &str,
    negated: bool,
) -> Result<String, String> {
    let presig = parse_presig(presig_hex, negated)?;
    let kspt = hex::decode(kspt_hex).map_err(|error| format!("Bad KSPT: {error}"))?;
    let request = shared_signer::covenant_sign::private_swap::PrivateSwapRequest {
        kind: shared_signer::covenant_sign::private_swap::RequestKind::Complete,
        session_id: [0; 16],
        host_commitment: [0; 32],
        key_id: decode32(key_id_hex, "key id")?,
        binding_token: decode32(binding_token_hex, "binding token")?,
        adaptor_point: decode32(adaptor_point_hex, "adaptor point")?,
        presignature: presig.bytes,
        presignature_negated: presig.negated,
        payload: &kspt,
    };
    encode_request_hex(&request)
}

#[wasm_bindgen]
pub fn private_swap_parse_response(response_hex: &str) -> Result<String, JsValue> {
    private_swap_parse_response_string(response_hex).map_err(js_error)
}

fn private_swap_parse_response_string(response_hex: &str) -> Result<String, String> {
    let bytes =
        hex::decode(response_hex).map_err(|error| format!("Bad Private Swap response: {error}"))?;
    let response = shared_signer::covenant_sign::private_swap::parse_response(&bytes)
        .map_err(|_| "Invalid Private Swap response".to_string())?;
    crate::protocol::private_swap::encode_response_json(&response)
}

#[wasm_bindgen]
pub fn private_swap_claim_sighash(kspt_hex: &str) -> Result<String, JsValue> {
    let kspt = hex::decode(kspt_hex).map_err(|error| js_error(format!("Bad KSPT: {error}")))?;
    crate::protocol::pskt::compact_kspt_sighash_wire(&kspt)
        .map(hex::encode)
        .map_err(js_error)
}

#[wasm_bindgen]
pub fn private_swap_verify_presignature(
    public_key_hex: &str,
    sighash_hex: &str,
    presig_hex: &str,
    negated: bool,
    adaptor_point_hex: &str,
) -> bool {
    parse_presig(presig_hex, negated)
        .and_then(|presig| {
            Ok(crate::protocol::private_swap::adaptor::verify_presignature(
                &decode32(public_key_hex, "pubkey")?,
                &decode32(sighash_hex, "sighash")?,
                &presig,
                &decode32(adaptor_point_hex, "adaptor point")?,
            )
            .is_ok())
        })
        .unwrap_or(false)
}

// Positional arguments are part of the stable wasm-bindgen API.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn private_swap_verify_host_relation(
    public_key_hex: &str,
    sighash_hex: &str,
    adaptor_point_hex: &str,
    session_hex: &str,
    host_secret_hex: &str,
    nonce_point_hex: &str,
    presig_hex: &str,
    negated: bool,
) -> bool {
    let Ok(session) = decode16(session_hex, "session") else {
        return false;
    };
    let Ok(nonce) = decode33(nonce_point_hex, "nonce point") else {
        return false;
    };
    parse_presig(presig_hex, negated)
        .and_then(|presig| {
            Ok(
                crate::protocol::private_swap::adaptor::verify_host_nonce_relation(
                    &decode32(public_key_hex, "pubkey")?,
                    &decode32(sighash_hex, "sighash")?,
                    &decode32(adaptor_point_hex, "adaptor point")?,
                    &session,
                    &decode32(host_secret_hex, "host secret")?,
                    &nonce,
                    &presig,
                )
                .is_ok(),
            )
        })
        .unwrap_or(false)
}

#[wasm_bindgen]
pub fn private_swap_verify_completed(
    public_key_hex: &str,
    sighash_hex: &str,
    signature_hex: &str,
) -> bool {
    let Ok(signature) = decode64(signature_hex, "signature") else {
        return false;
    };
    let Ok(public_key) = decode32(public_key_hex, "pubkey") else {
        return false;
    };
    let Ok(message) = decode32(sighash_hex, "sighash") else {
        return false;
    };
    crate::protocol::private_swap::adaptor::verify_bip340(&public_key, &message, &signature).is_ok()
}

#[wasm_bindgen]
pub fn private_swap_complete_public(
    presig_hex: &str,
    negated: bool,
    secret_hex: &str,
) -> Result<String, JsValue> {
    private_swap_complete_public_string(presig_hex, negated, secret_hex).map_err(js_error)
}

fn private_swap_complete_public_string(
    presig_hex: &str,
    negated: bool,
    secret_hex: &str,
) -> Result<String, String> {
    let presig = parse_presig(presig_hex, negated)?;
    let secret = decode32(secret_hex, "adaptor secret")?;
    crate::protocol::private_swap::adaptor::complete_presignature(&presig, &secret).map(hex::encode)
}

#[wasm_bindgen]
pub fn private_swap_extract_secret(
    presig_hex: &str,
    negated: bool,
    completed_sig_hex: &str,
) -> Result<String, JsValue> {
    private_swap_extract_secret_string(presig_hex, negated, completed_sig_hex).map_err(js_error)
}

fn private_swap_extract_secret_string(
    presig_hex: &str,
    negated: bool,
    completed_sig_hex: &str,
) -> Result<String, String> {
    let p = parse_presig(presig_hex, negated)?;
    let final_sig = decode64(completed_sig_hex, "completed signature")?;
    crate::protocol::private_swap::adaptor::extract_secret(&final_sig, &p).map(hex::encode)
}

#[wasm_bindgen]
pub async fn create_private_swap_claim(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    selected_utxo_json: &str,
    fee: u64,
) -> Result<String, JsValue> {
    crate::transaction_builder::covenant::private_swap::build_claim(
        covenant_address,
        destination_address,
        redeem_script_hex,
        selected_utxo_json,
        fee,
    )
    .map_err(js_error)
}

#[cfg(test)]
use crate::transaction_builder::covenant::private_swap::{
    insert_completed_signature_hex as insert_completed_signature,
    prepare_claim as prepare_private_swap_claim,
};

#[wasm_bindgen]
pub fn private_swap_insert_completed_signature(
    pskb_hex: &str,
    claim_pubkey_x_hex: &str,
    signature_hex: &str,
) -> Result<String, JsValue> {
    private_swap_insert_completed_signature_string(pskb_hex, claim_pubkey_x_hex, signature_hex)
        .map_err(js_error)
}

fn private_swap_insert_completed_signature_string(
    pskb_hex: &str,
    claim_pubkey_x_hex: &str,
    signature_hex: &str,
) -> Result<String, String> {
    let signature = decode64(signature_hex, "Private Swap completed signature")?;
    let public_key = decode32(claim_pubkey_x_hex, "claim pubkey")?;
    crate::transaction_builder::covenant::private_swap::insert_completed_signature_hex(
        pskb_hex,
        &public_key,
        &signature,
    )
}

fn encode_request_hex(
    request: &shared_signer::covenant_sign::private_swap::PrivateSwapRequest<'_>,
) -> Result<String, String> {
    let mut out = vec![
        0u8;
        shared_signer::covenant_sign::private_swap::REQUEST_HEADER_LEN
            + request.payload.len()
    ];
    let len = shared_signer::covenant_sign::private_swap::encode_request(request, &mut out)
        .map_err(|_| "Private Swap request encode failed".to_string())?;
    Ok(hex::encode(&out[..len]))
}

fn decode16(value: &str, label: &str) -> Result<[u8; 16], String> {
    decode_fixed(value, label)
}
fn decode32(value: &str, label: &str) -> Result<[u8; 32], String> {
    decode_fixed(value, label)
}
fn decode33(value: &str, label: &str) -> Result<[u8; 33], String> {
    decode_fixed(value, label)
}
fn decode64(value: &str, label: &str) -> Result<[u8; 64], String> {
    decode_fixed(value, label)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|error| format!("Bad {label}: {error}"))?;
    if bytes.len() != N {
        return Err(format!("{label} must be {N} bytes"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_presig(
    value: &str,
    negated: bool,
) -> Result<crate::protocol::private_swap::adaptor::AdaptorPreSignature, String> {
    Ok(
        crate::protocol::private_swap::adaptor::AdaptorPreSignature {
            bytes: decode64(value, "pre-signature")?,
            negated,
        },
    )
}

#[cfg(test)]
mod unit_tests;
