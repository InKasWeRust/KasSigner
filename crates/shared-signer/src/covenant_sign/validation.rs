use super::{
    expected_known_binding, BindingHint, CovenantSignRequest, CovenantSignResponse, KnownScheme,
    ProtocolError, RequestKind, ResponseKind, MAX_CONTEXT_LEN, MAX_SCRIPT_LEN, REQUEST_HEADER_LEN,
    REQUEST_MAGIC, SESSION_ID_LEN, VERSION,
};

pub(super) fn validate_request_prefix(input: &[u8]) -> Result<(), ProtocolError> {
    if input.len() < REQUEST_HEADER_LEN || !input.starts_with(&REQUEST_MAGIC) {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok(())
}

pub(super) fn validate_lengths(script_len: usize, context_len: usize) -> Result<(), ProtocolError> {
    if script_len > MAX_SCRIPT_LEN || context_len > MAX_CONTEXT_LEN {
        Err(ProtocolError::InvalidLength)
    } else {
        Ok(())
    }
}

pub(super) fn request_total_len(
    script_len: usize,
    context_len: usize,
) -> Result<usize, ProtocolError> {
    REQUEST_HEADER_LEN
        .checked_add(script_len)
        .and_then(|value| value.checked_add(context_len))
        .ok_or(ProtocolError::InvalidLength)
}

pub(super) fn validate_fields(request: &CovenantSignRequest<'_>) -> Result<(), ProtocolError> {
    match request.kind {
        RequestKind::KeyInfo => validate_key_info_fields(request),
        RequestKind::Bind => validate_bind_fields(request),
        RequestKind::Known => validate_known_fields(request),
        RequestKind::Opaque => validate_opaque_fields(request),
    }
}

fn validate_key_info_fields(request: &CovenantSignRequest<'_>) -> Result<(), ProtocolError> {
    let valid = request.scheme == KnownScheme::None
        && request.binding == BindingHint::None
        && request.session_id == [0u8; SESSION_ID_LEN]
        && request.host_commitment == [0u8; 32]
        && request.key_id == [0u8; 32]
        && request.binding_token == [0u8; 32]
        && request.commitment == [0u8; 32]
        && request.script.is_empty()
        && request.context.is_empty();
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_bind_fields(request: &CovenantSignRequest<'_>) -> Result<(), ProtocolError> {
    let base = request.session_id == [0u8; SESSION_ID_LEN]
        && request.host_commitment == [0u8; 32]
        && request.key_id != [0u8; 32]
        && request.binding_token == [0u8; 32]
        && !request.script.is_empty();
    let shape = if request.scheme == KnownScheme::None {
        matches!(request.binding, BindingHint::None | BindingHint::KeyPresent)
            && request.commitment == [0u8; 32]
            && request.context.is_empty()
    } else {
        request.binding == expected_known_binding(request.scheme) && !request.context.is_empty()
    };
    (base && shape)
        .then_some(())
        .ok_or(ProtocolError::InvalidFields)
}

fn validate_known_fields(request: &CovenantSignRequest<'_>) -> Result<(), ProtocolError> {
    let valid = request.scheme != KnownScheme::None
        && request.binding == expected_known_binding(request.scheme)
        && request.session_id != [0u8; SESSION_ID_LEN]
        && request.host_commitment != [0u8; 32]
        && request.key_id != [0u8; 32]
        && request.binding_token != [0u8; 32]
        && !request.script.is_empty()
        && !request.context.is_empty();
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

fn validate_opaque_fields(request: &CovenantSignRequest<'_>) -> Result<(), ProtocolError> {
    let valid = request.scheme == KnownScheme::None
        && matches!(request.binding, BindingHint::None | BindingHint::KeyPresent)
        && request.session_id != [0u8; SESSION_ID_LEN]
        && request.host_commitment != [0u8; 32]
        && request.key_id != [0u8; 32]
        && request.binding_token != [0u8; 32]
        && !request.script.is_empty()
        && request.context.is_empty();
    valid.then_some(()).ok_or(ProtocolError::InvalidFields)
}

pub(super) fn validate_response(response: &CovenantSignResponse) -> Result<(), ProtocolError> {
    if response.key_id == [0u8; 32] || response.pubkey_x == [0u8; 32] {
        return Err(ProtocolError::InvalidFields);
    }
    response_shape_valid(response)
        .then_some(())
        .ok_or(ProtocolError::InvalidFields)
}

pub(super) fn response_shape_valid(response: &CovenantSignResponse) -> bool {
    match response.kind {
        ResponseKind::KeyInfo => key_info_response_valid(response),
        ResponseKind::Binding => binding_response_valid(response),
        ResponseKind::NonceCommitment => nonce_response_valid(response),
        ResponseKind::Signature => signature_response_valid(response),
    }
}

pub(super) fn key_info_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id == [0u8; SESSION_ID_LEN]
        && response.binding_token == [0u8; 32]
        && response.commitment == [0u8; 32]
        && response.nonce_point == [0u8; 33]
        && response.signature == [0u8; 64]
}

pub(super) fn binding_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id == [0u8; SESSION_ID_LEN]
        && response.binding_token != [0u8; 32]
        && response.commitment != [0u8; 32]
        && response.nonce_point == [0u8; 33]
        && response.signature == [0u8; 64]
}

pub(super) fn nonce_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id != [0u8; SESSION_ID_LEN]
        && response.binding_token != [0u8; 32]
        && response.nonce_point[0] == 0x02
        && response.signature == [0u8; 64]
}

pub(super) fn signature_response_valid(response: &CovenantSignResponse) -> bool {
    response.session_id != [0u8; SESSION_ID_LEN]
        && response.binding_token != [0u8; 32]
        && response.nonce_point[0] == 0x02
        && response.signature != [0u8; 64]
}

pub(super) fn valid_review_context<'a>(
    context: &'a [u8],
    max_len: usize,
    prefix: Option<&[u8]>,
) -> Option<&'a [u8]> {
    if context.is_empty() || context.len() > max_len {
        return None;
    }
    core::str::from_utf8(context).ok()?;
    if !context.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return None;
    }
    if prefix.is_some_and(|expected| !context.starts_with(expected)) {
        return None;
    }
    Some(context)
}
