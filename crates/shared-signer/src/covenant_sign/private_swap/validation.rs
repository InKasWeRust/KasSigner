//! Private-swap request and response validation.

use super::{
    session_id, PrivateSwapRequest, PrivateSwapResponse, ProtocolError, RequestKind, ResponseKind,
    MAX_PAYLOAD_LEN, REQUEST_HEADER_LEN, REQUEST_MAGIC, SESSION_ID_LEN, VERSION,
};

pub(super) fn validate_request_prefix(input: &[u8]) -> Result<(), ProtocolError> {
    if input.len() < REQUEST_HEADER_LEN || !input.starts_with(&REQUEST_MAGIC) {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if input[219] != 0 || input[220] != 0 {
        return Err(ProtocolError::InvalidFields);
    }
    Ok(())
}

pub(super) fn validate_request_payload_length(input: &[u8]) -> Result<(), ProtocolError> {
    let payload_len = u32::from_be_bytes([input[215], input[216], input[217], input[218]]) as usize;
    if payload_len > MAX_PAYLOAD_LEN
        || REQUEST_HEADER_LEN.checked_add(payload_len) != Some(input.len())
    {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(())
}

pub(super) fn parse_bool(value: u8) -> Result<bool, ProtocolError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProtocolError::InvalidFields),
    }
}

pub(super) fn validate_request(request: &PrivateSwapRequest<'_>) -> Result<(), ProtocolError> {
    if request.payload.len() > MAX_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    match request.kind {
        RequestKind::KeyInfo => validate_key_info_request(request),
        RequestKind::Bind => validate_bind_request(request),
        RequestKind::PreSign => validate_presign_request(request),
        RequestKind::Complete => validate_complete_request(request),
    }
}

fn validate_key_info_request(request: &PrivateSwapRequest<'_>) -> Result<(), ProtocolError> {
    let valid = request.session_id == [0; SESSION_ID_LEN]
        && request.host_commitment == [0; 32]
        && request.key_id == [0; 32]
        && request.binding_token == [0; 32]
        && request.adaptor_point == [0; 32]
        && request.presignature == [0; 64]
        && !request.presignature_negated
        && request.payload.is_empty();
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_bind_request(request: &PrivateSwapRequest<'_>) -> Result<(), ProtocolError> {
    let valid = request.session_id == [0; SESSION_ID_LEN]
        && request.host_commitment == [0; 32]
        && request.key_id != [0; 32]
        && request.binding_token == [0; 32]
        && request.adaptor_point != [0; 32]
        && request.presignature == [0; 64]
        && !request.presignature_negated
        && !request.payload.is_empty();
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_presign_request(request: &PrivateSwapRequest<'_>) -> Result<(), ProtocolError> {
    let fields_valid = request.host_commitment != [0; 32]
        && request.key_id != [0; 32]
        && request.binding_token != [0; 32]
        && request.adaptor_point != [0; 32]
        && request.presignature == [0; 64]
        && !request.presignature_negated
        && !request.payload.is_empty();
    if !fields_valid {
        return Err(ProtocolError::InvalidFields);
    }
    let expected = session_id(
        &request.host_commitment,
        request.payload,
        &request.key_id,
        &request.adaptor_point,
    );
    (request.session_id == expected)
        .then_some(())
        .ok_or(ProtocolError::InvalidFields)
}

fn validate_complete_request(request: &PrivateSwapRequest<'_>) -> Result<(), ProtocolError> {
    let valid = request.session_id == [0; SESSION_ID_LEN]
        && request.host_commitment == [0; 32]
        && request.key_id != [0; 32]
        && request.binding_token != [0; 32]
        && request.adaptor_point != [0; 32]
        && request.presignature != [0; 64]
        && !request.payload.is_empty();
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

pub(super) fn validate_response(response: &PrivateSwapResponse) -> Result<(), ProtocolError> {
    validate_response_identity(response)?;
    match response.kind {
        ResponseKind::KeyInfo => validate_key_info_response(response),
        ResponseKind::Binding => validate_binding_response(response),
        ResponseKind::Nonce => validate_nonce_response(response),
        ResponseKind::PreSignature => validate_presignature_response(response),
        ResponseKind::Completed => validate_completed_response(response),
    }
}

fn validate_response_identity(response: &PrivateSwapResponse) -> Result<(), ProtocolError> {
    let valid = response.key_id != [0; 32]
        && response.claim_pubkey != [0; 32]
        && response.adaptor_point != [0; 32];
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_key_info_response(response: &PrivateSwapResponse) -> Result<(), ProtocolError> {
    let valid = response.session_id == [0; SESSION_ID_LEN]
        && response.binding_token == [0; 32]
        && response.commitment == [0; 32]
        && response.nonce_point == [0; 33]
        && response.signature == [0; 64]
        && !response.negated;
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_binding_response(response: &PrivateSwapResponse) -> Result<(), ProtocolError> {
    let valid = response.session_id == [0; SESSION_ID_LEN]
        && response.binding_token != [0; 32]
        && response.commitment != [0; 32]
        && response.nonce_point == [0; 33]
        && response.signature == [0; 64]
        && !response.negated;
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_nonce_response(response: &PrivateSwapResponse) -> Result<(), ProtocolError> {
    let valid = response.session_id != [0; SESSION_ID_LEN]
        && response.binding_token != [0; 32]
        && response.commitment != [0; 32]
        && response.nonce_point != [0; 33]
        && response.signature == [0; 64]
        && !response.negated;
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_presignature_response(response: &PrivateSwapResponse) -> Result<(), ProtocolError> {
    let valid = response.session_id != [0; SESSION_ID_LEN]
        && response.binding_token != [0; 32]
        && response.commitment != [0; 32]
        && response.nonce_point != [0; 33]
        && response.signature != [0; 64];
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_completed_response(response: &PrivateSwapResponse) -> Result<(), ProtocolError> {
    let valid = response.session_id == [0; SESSION_ID_LEN]
        && response.binding_token != [0; 32]
        && response.commitment != [0; 32]
        && response.nonce_point == [0; 33]
        && response.signature != [0; 64]
        && !response.negated;
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}
