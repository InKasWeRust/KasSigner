//! Browser-side anti-klepto transcript facade.

use shared_signer::anti_klepto;
use wasm_bindgen::prelude::*;

use crate::{
    protocol::pskt::{
        validate_anti_klepto_transaction_wire, validate_host_commitment_wire,
        verify_host_transcript_wire,
    },
    wasm_api::utilities::common::js_error,
};

type SignedWireSet = (Vec<u8>, Vec<u8>, Vec<u8>);

fn decode_hex32_string(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("invalid {label} hex"))?;
    if bytes.len() != 32 {
        return Err(format!("{label} must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_wire_string(value: &str, label: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|_| format!("invalid {label} hex"))
}

fn decode_signed_wires_string(
    request_hex: &str,
    commitment_hex: &str,
    signed_hex: &str,
) -> Result<SignedWireSet, String> {
    Ok((
        decode_wire_string(request_hex, "request")?,
        decode_wire_string(commitment_hex, "commitment")?,
        decode_wire_string(signed_hex, "signed response")?,
    ))
}

fn request_commitment_matches(
    request: &anti_klepto::Request<'_>,
    commitment: &anti_klepto::Commitment<'_>,
    host_secret: &[u8; 32],
) -> bool {
    (request.session_id, request.transaction_digest)
        == (commitment.session_id, commitment.transaction_digest)
        && anti_klepto::verify_host_secret(&request.host_commitment, host_secret)
}

fn signed_transcript_matches(
    request: &anti_klepto::Request<'_>,
    commitment: &anti_klepto::Commitment<'_>,
    signed: &anti_klepto::Signed<'_>,
    host_secret: &[u8; 32],
) -> bool {
    (request.session_id, request.transaction_digest)
        == (commitment.session_id, commitment.transaction_digest)
        && (request.session_id, request.transaction_digest)
            == (signed.session_id, signed.transaction_digest)
        && anti_klepto::verify_host_secret(&request.host_commitment, host_secret)
}

pub(super) fn anti_klepto_begin_with_secret_string(
    kspt_hex: &str,
    host_secret: &[u8; 32],
) -> Result<String, String> {
    let transaction = decode_wire_string(kspt_hex, "KSPT")?;
    validate_anti_klepto_transaction_wire(&transaction)
        .map_err(|error| format!("invalid compact KSPT: {error}"))?;
    let mut request = vec![0u8; transaction.len() + 128];
    let request_len = anti_klepto::encode_request(host_secret, &transaction, &mut request)
        .map_err(|error| format!("anti-klepto request failed: {error:?}"))?;
    let response = serde_json::json!({
        "requestHex": hex::encode(&request[..request_len]),
        "hostSecretHex": hex::encode(host_secret),
    });
    serde_json::to_string(&response).map_err(|error| error.to_string())
}

fn anti_klepto_begin_string(kspt_hex: &str) -> Result<String, String> {
    let mut host_secret = [0u8; 32];
    let result = getrandom::getrandom(&mut host_secret)
        .map_err(|_| "browser cryptographic randomness unavailable".to_string())
        .and_then(|_| anti_klepto_begin_with_secret_string(kspt_hex, &host_secret));
    shared_signer::bytes::zeroize_bytes(&mut host_secret);
    result
}

#[wasm_bindgen]
pub fn anti_klepto_begin(kspt_hex: &str) -> Result<String, JsValue> {
    anti_klepto_begin_string(kspt_hex).map_err(js_error)
}

fn parse_commitment_pair_string<'a>(
    request_wire: &'a [u8],
    commitment_wire: &'a [u8],
) -> Result<(anti_klepto::Request<'a>, anti_klepto::Commitment<'a>), String> {
    let request = anti_klepto::parse_request(request_wire)
        .map_err(|error| format!("invalid anti-klepto request: {error:?}"))?;
    let commitment = anti_klepto::parse_commitment(commitment_wire)
        .map_err(|error| format!("invalid signer commitment: {error:?}"))?;
    Ok((request, commitment))
}

fn accept_commitment_inner_string(
    request_wire: &[u8],
    commitment_wire: &[u8],
    host_secret: &[u8; 32],
) -> Result<String, String> {
    let (request, commitment) = parse_commitment_pair_string(request_wire, commitment_wire)?;
    if !request_commitment_matches(&request, &commitment, host_secret) {
        return Err("anti-klepto transcript mismatch".to_string());
    }
    validate_host_commitment_wire(request.transaction, &commitment)
        .map_err(|error| format!("unsafe signer commitment: {error}"))?;
    let mut reveal = [0u8; 96];
    let reveal_len = anti_klepto::encode_reveal(&request.session_id, host_secret, &mut reveal)
        .map_err(|error| format!("anti-klepto reveal failed: {error:?}"))?;
    Ok(hex::encode(&reveal[..reveal_len]))
}

pub(super) fn anti_klepto_accept_commitment_string(
    request_hex: &str,
    commitment_hex: &str,
    host_secret_hex: &str,
) -> Result<String, String> {
    let request_wire = decode_wire_string(request_hex, "request")?;
    let commitment_wire = decode_wire_string(commitment_hex, "commitment")?;
    let mut host_secret = decode_hex32_string(host_secret_hex, "host secret")?;
    let result = accept_commitment_inner_string(&request_wire, &commitment_wire, &host_secret);
    shared_signer::bytes::zeroize_bytes(&mut host_secret);
    result
}

#[wasm_bindgen]
pub fn anti_klepto_accept_commitment(
    request_hex: &str,
    commitment_hex: &str,
    host_secret_hex: &str,
) -> Result<String, JsValue> {
    anti_klepto_accept_commitment_string(request_hex, commitment_hex, host_secret_hex)
        .map_err(js_error)
}

fn verify_signed_inner_string(
    request_wire: &[u8],
    commitment_wire: &[u8],
    signed_wire: &[u8],
    host_secret: &[u8; 32],
) -> Result<String, String> {
    let (request, commitment) = parse_commitment_pair_string(request_wire, commitment_wire)?;
    let signed = anti_klepto::parse_signed(signed_wire)
        .map_err(|error| format!("invalid signed response: {error:?}"))?;
    if !signed_transcript_matches(&request, &commitment, &signed, host_secret) {
        return Err("anti-klepto transcript mismatch".to_string());
    }
    verify_host_transcript_wire(
        request.transaction,
        signed.transaction,
        &commitment,
        &signed,
        host_secret,
    )
    .map_err(|error| format!("anti-klepto verification failed: {error}"))?;
    Ok(hex::encode(signed.transaction))
}

pub(super) fn anti_klepto_verify_signed_string(
    request_hex: &str,
    commitment_hex: &str,
    signed_hex: &str,
    host_secret_hex: &str,
) -> Result<String, String> {
    let (request_wire, commitment_wire, signed_wire) =
        decode_signed_wires_string(request_hex, commitment_hex, signed_hex)?;
    let mut host_secret = decode_hex32_string(host_secret_hex, "host secret")?;
    let result =
        verify_signed_inner_string(&request_wire, &commitment_wire, &signed_wire, &host_secret);
    shared_signer::bytes::zeroize_bytes(&mut host_secret);
    result
}

#[wasm_bindgen]
pub fn anti_klepto_verify_signed(
    request_hex: &str,
    commitment_hex: &str,
    signed_hex: &str,
    host_secret_hex: &str,
) -> Result<String, JsValue> {
    anti_klepto_verify_signed_string(request_hex, commitment_hex, signed_hex, host_secret_hex)
        .map_err(js_error)
}
