pub(crate) mod adaptor;

pub(crate) fn encode_presign_metadata_json(
    request_hex: &str,
    session_id: &[u8; 16],
    host_commitment: &[u8; 32],
) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "request_hex": request_hex,
        "session_id": hex::encode(session_id),
        "host_commitment": hex::encode(host_commitment),
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn encode_response_json(
    response: &shared_signer::covenant_sign::private_swap::PrivateSwapResponse,
) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "kind": response.kind as u8,
        "session_id": hex::encode(response.session_id),
        "key_id": hex::encode(response.key_id),
        "claim_pubkey": hex::encode(response.claim_pubkey),
        "binding_token": hex::encode(response.binding_token),
        "adaptor_point": hex::encode(response.adaptor_point),
        "commitment": hex::encode(response.commitment),
        "nonce_point": hex::encode(response.nonce_point),
        "signature": hex::encode(response.signature),
        "negated": response.negated,
    }))
    .map_err(|error| error.to_string())
}
