//! Universal covenant-signing transport and safety envelope.
//!
//! The envelope is KasSigner-specific. The 32-byte covenant commitment inside
//! it is not rehashed or reformatted before BIP340 signing. Wallet-spending
//! keys never consume this protocol. Signing requests use a host-committed
//! two-round anti-klepto exchange so the signer never has unilateral nonce
//! control on this new raw-commitment signing surface.

use sha2::{Digest, Sha256};

pub mod private_swap;
mod script_int;
mod validation;

use script_int::canonical_u64_push;
use validation::{
    request_total_len, valid_review_context, validate_fields, validate_lengths,
    validate_request_prefix, validate_response,
};

#[cfg(test)]
use validation::{
    binding_response_valid, key_info_response_valid, nonce_response_valid, response_shape_valid,
    signature_response_valid,
};

pub const REQUEST_MAGIC: [u8; 4] = *b"CVSG";
pub const REVEAL_MAGIC: [u8; 4] = *b"CVRV";
pub const RESPONSE_MAGIC: [u8; 4] = *b"CVSR";
pub const VERSION: u8 = 2;
pub const SESSION_ID_LEN: usize = 16;
pub const REQUEST_HEADER_LEN: usize = 156;
pub const REVEAL_LEN: usize = 117;
pub const RESPONSE_LEN: usize = 247;
pub const MAX_SCRIPT_LEN: usize = 3_072;
pub const MAX_CONTEXT_LEN: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RequestKind {
    KeyInfo = 0,
    Known = 1,
    Opaque = 2,
    Bind = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KnownScheme {
    None = 0,
    /// Exact commitment = SHA256(context bytes).
    Sha256Preimage = 1,
    /// Oracle-v1 exact commitment = SHA256(exact UTF-8 release statement).
    OracleV1 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BindingHint {
    None = 0,
    /// Optional opaque-mode sanity check for scripts embedding the raw x-only
    /// key. It is not required for universal third-party covenant signing.
    KeyPresent = 1,
    /// Known-mode script contains PUSH32(commitment), PUSH32(pubkey),
    /// OP_CHECKSIGFROMSTACK exactly in that order.
    FixedCheckSigFromStack = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidKind,
    InvalidScheme,
    InvalidBinding,
    InvalidLength,
    InvalidFields,
    OutputTooSmall,
}

pub struct CovenantSignRequest<'a> {
    pub kind: RequestKind,
    pub scheme: KnownScheme,
    pub binding: BindingHint,
    pub session_id: [u8; SESSION_ID_LEN],
    pub host_commitment: [u8; 32],
    pub key_id: [u8; 32],
    pub binding_token: [u8; 32],
    pub commitment: [u8; 32],
    pub script: &'a [u8],
    pub context: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CovenantSignReveal {
    pub session_id: [u8; SESSION_ID_LEN],
    pub key_id: [u8; 32],
    pub commitment: [u8; 32],
    pub host_secret: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResponseKind {
    KeyInfo = 0,
    NonceCommitment = 1,
    Signature = 2,
    Binding = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CovenantSignResponse {
    pub kind: ResponseKind,
    pub session_id: [u8; SESSION_ID_LEN],
    pub key_id: [u8; 32],
    pub pubkey_x: [u8; 32],
    pub binding_token: [u8; 32],
    pub commitment: [u8; 32],
    pub nonce_point: [u8; 33],
    pub signature: [u8; 64],
}

#[must_use]
pub fn is_message(input: &[u8]) -> bool {
    input.len() >= 5
        && input[4] == VERSION
        && (input.starts_with(&REQUEST_MAGIC) || input.starts_with(&REVEAL_MAGIC))
}

pub fn parse_request(input: &[u8]) -> Result<CovenantSignRequest<'_>, ProtocolError> {
    validate_request_prefix(input)?;
    let kind = parse_kind(input[5])?;
    let scheme = parse_scheme(input[6])?;
    let binding = parse_binding(input[7])?;
    let session_id = array16(&input[8..24]);
    let host_commitment = array32(&input[24..56]);
    let key_id = array32(&input[56..88]);
    let binding_token = array32(&input[88..120]);
    let commitment = array32(&input[120..152]);
    let script_len = usize::from(u16::from_be_bytes([input[152], input[153]]));
    let context_len = usize::from(u16::from_be_bytes([input[154], input[155]]));
    validate_lengths(script_len, context_len)?;
    let total = request_total_len(script_len, context_len)?;
    if total != input.len() {
        return Err(ProtocolError::InvalidLength);
    }
    let script_end = REQUEST_HEADER_LEN + script_len;
    let request = CovenantSignRequest {
        kind,
        scheme,
        binding,
        session_id,
        host_commitment,
        key_id,
        binding_token,
        commitment,
        script: &input[REQUEST_HEADER_LEN..script_end],
        context: &input[script_end..],
    };
    validate_fields(&request)?;
    Ok(request)
}

pub fn encode_request(
    request: &CovenantSignRequest<'_>,
    out: &mut [u8],
) -> Result<usize, ProtocolError> {
    validate_lengths(request.script.len(), request.context.len())?;
    validate_fields(request)?;
    let total = request_total_len(request.script.len(), request.context.len())?;
    if out.len() < total {
        return Err(ProtocolError::OutputTooSmall);
    }
    out[..4].copy_from_slice(&REQUEST_MAGIC);
    out[4] = VERSION;
    out[5] = request.kind as u8;
    out[6] = request.scheme as u8;
    out[7] = request.binding as u8;
    out[8..24].copy_from_slice(&request.session_id);
    out[24..56].copy_from_slice(&request.host_commitment);
    out[56..88].copy_from_slice(&request.key_id);
    out[88..120].copy_from_slice(&request.binding_token);
    out[120..152].copy_from_slice(&request.commitment);
    out[152..154].copy_from_slice(&(request.script.len() as u16).to_be_bytes());
    out[154..156].copy_from_slice(&(request.context.len() as u16).to_be_bytes());
    let mut pos = REQUEST_HEADER_LEN;
    out[pos..pos + request.script.len()].copy_from_slice(request.script);
    pos += request.script.len();
    out[pos..pos + request.context.len()].copy_from_slice(request.context);
    Ok(total)
}

pub fn encode_reveal(reveal: &CovenantSignReveal, out: &mut [u8]) -> Result<usize, ProtocolError> {
    if out.len() < REVEAL_LEN {
        return Err(ProtocolError::OutputTooSmall);
    }
    if reveal.session_id == [0u8; SESSION_ID_LEN] || reveal.key_id == [0u8; 32] {
        return Err(ProtocolError::InvalidFields);
    }
    out[..4].copy_from_slice(&REVEAL_MAGIC);
    out[4] = VERSION;
    out[5..21].copy_from_slice(&reveal.session_id);
    out[21..53].copy_from_slice(&reveal.key_id);
    out[53..85].copy_from_slice(&reveal.commitment);
    out[85..117].copy_from_slice(&reveal.host_secret);
    Ok(REVEAL_LEN)
}

pub fn parse_reveal(input: &[u8]) -> Result<CovenantSignReveal, ProtocolError> {
    if input.len() != REVEAL_LEN || !input.starts_with(&REVEAL_MAGIC) {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let reveal = CovenantSignReveal {
        session_id: array16(&input[5..21]),
        key_id: array32(&input[21..53]),
        commitment: array32(&input[53..85]),
        host_secret: array32(&input[85..117]),
    };
    if reveal.session_id == [0u8; SESSION_ID_LEN] || reveal.key_id == [0u8; 32] {
        return Err(ProtocolError::InvalidFields);
    }
    Ok(reveal)
}

pub fn encode_response(
    response: &CovenantSignResponse,
    out: &mut [u8],
) -> Result<usize, ProtocolError> {
    validate_response(response)?;
    if out.len() < RESPONSE_LEN {
        return Err(ProtocolError::OutputTooSmall);
    }
    out[..4].copy_from_slice(&RESPONSE_MAGIC);
    out[4] = VERSION;
    out[5] = response.kind as u8;
    out[6..22].copy_from_slice(&response.session_id);
    out[22..54].copy_from_slice(&response.key_id);
    out[54..86].copy_from_slice(&response.pubkey_x);
    out[86..118].copy_from_slice(&response.binding_token);
    out[118..150].copy_from_slice(&response.commitment);
    out[150..183].copy_from_slice(&response.nonce_point);
    out[183..247].copy_from_slice(&response.signature);
    Ok(RESPONSE_LEN)
}

pub fn parse_response(input: &[u8]) -> Result<CovenantSignResponse, ProtocolError> {
    if input.len() != RESPONSE_LEN || !input.starts_with(&RESPONSE_MAGIC) {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let kind = match input[5] {
        0 => ResponseKind::KeyInfo,
        1 => ResponseKind::NonceCommitment,
        2 => ResponseKind::Signature,
        3 => ResponseKind::Binding,
        _ => return Err(ProtocolError::InvalidKind),
    };
    let mut nonce_point = [0u8; 33];
    nonce_point.copy_from_slice(&input[150..183]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&input[183..247]);
    let response = CovenantSignResponse {
        kind,
        session_id: array16(&input[6..22]),
        key_id: array32(&input[22..54]),
        pubkey_x: array32(&input[54..86]),
        binding_token: array32(&input[86..118]),
        commitment: array32(&input[118..150]),
        nonce_point,
        signature,
    };
    validate_response(&response)?;
    Ok(response)
}

#[must_use]
pub fn recompute_known_commitment(scheme: KnownScheme, context: &[u8]) -> Option<[u8; 32]> {
    match scheme {
        KnownScheme::Sha256Preimage => valid_review_context(context, MAX_CONTEXT_LEN, None)
            .map(|bytes| Sha256::digest(bytes).into()),
        KnownScheme::OracleV1 => valid_review_context(context, 256, Some(b"KasSigner Oracle v1 "))
            .map(|bytes| Sha256::digest(bytes).into()),
        KnownScheme::None => None,
    }
}

#[must_use]
pub fn script_contains_xonly_key(script: &[u8], pubkey_x: &[u8; 32]) -> bool {
    script.windows(32).any(|window| window == pubkey_x)
}

#[must_use]
pub fn script_binds_fixed_commitment(
    script: &[u8],
    commitment: &[u8; 32],
    pubkey_x: &[u8; 32],
) -> bool {
    let pattern = fixed_checksigfromstack_pattern(commitment, pubkey_x);
    script
        .windows(pattern.len())
        .any(|window| window == pattern)
}

/// Validate the complete registered script grammar for a known covenant.
/// Finding a convenient byte pattern inside an otherwise unknown script is
/// intentionally insufficient for the device to call a request verified.
#[must_use]
pub fn known_script_binds(
    scheme: KnownScheme,
    script: &[u8],
    commitment: &[u8; 32],
    pubkey_x: &[u8; 32],
) -> bool {
    match scheme {
        KnownScheme::Sha256Preimage => {
            let pattern = fixed_checksigfromstack_pattern(commitment, pubkey_x);
            script == pattern.as_slice()
        }
        KnownScheme::OracleV1 => oracle_v1_script_binds(script, commitment, pubkey_x),
        KnownScheme::None => false,
    }
}

fn fixed_checksigfromstack_pattern(commitment: &[u8; 32], pubkey_x: &[u8; 32]) -> [u8; 67] {
    let mut pattern = [0u8; 67];
    pattern[0] = 0x20;
    pattern[1..33].copy_from_slice(commitment);
    pattern[33] = 0x20;
    pattern[34..66].copy_from_slice(pubkey_x);
    pattern[66] = 0xd7;
    pattern
}

fn oracle_v1_script_binds(script: &[u8], commitment: &[u8; 32], oracle: &[u8; 32]) -> bool {
    let Some(tail) = script.len().checked_sub(107) else {
        return false;
    };
    if tail < 54 || !oracle_v1_fixed_layout(script, tail) || !canonical_u64_push(&script[53..tail])
    {
        return false;
    }
    script.get(tail + 38..tail + 70) == Some(commitment.as_slice())
        && script.get(tail + 71..tail + 103) == Some(oracle.as_slice())
}

fn oracle_v1_fixed_layout(script: &[u8], tail: usize) -> bool {
    let fixed = [
        (0usize, 0x10),
        (17, 0x75),
        (18, 0x63),
        (19, 0x20),
        (52, 0xad),
        (tail, 0xb0),
        (tail + 1, 0x51),
        (tail + 2, 0x67),
        (tail + 3, 0x20),
        (tail + 36, 0xad),
        (tail + 37, 0x20),
        (tail + 70, 0x20),
        (tail + 103, 0xd7),
        (tail + 104, 0x69),
        (tail + 105, 0x51),
        (tail + 106, 0x68),
    ];
    fixed
        .iter()
        .all(|(index, expected)| script.get(*index) == Some(expected))
}

#[must_use]
pub const fn expected_known_binding(scheme: KnownScheme) -> BindingHint {
    match scheme {
        KnownScheme::Sha256Preimage | KnownScheme::OracleV1 => BindingHint::FixedCheckSigFromStack,
        KnownScheme::None => BindingHint::None,
    }
}

fn parse_kind(value: u8) -> Result<RequestKind, ProtocolError> {
    match value {
        0 => Ok(RequestKind::KeyInfo),
        1 => Ok(RequestKind::Known),
        2 => Ok(RequestKind::Opaque),
        3 => Ok(RequestKind::Bind),
        _ => Err(ProtocolError::InvalidKind),
    }
}

fn parse_scheme(value: u8) -> Result<KnownScheme, ProtocolError> {
    match value {
        0 => Ok(KnownScheme::None),
        1 => Ok(KnownScheme::Sha256Preimage),
        2 => Ok(KnownScheme::OracleV1),
        _ => Err(ProtocolError::InvalidScheme),
    }
}
fn parse_binding(value: u8) -> Result<BindingHint, ProtocolError> {
    match value {
        0 => Ok(BindingHint::None),
        1 => Ok(BindingHint::KeyPresent),
        2 => Ok(BindingHint::FixedCheckSigFromStack),
        _ => Err(ProtocolError::InvalidBinding),
    }
}
fn array16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    out
}
fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod unit_tests;
