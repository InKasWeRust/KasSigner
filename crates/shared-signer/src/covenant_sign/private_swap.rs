//! Private Swap v2 transport.
//!
//! This protocol is deliberately separate from generic COVENANT SIGN because
//! an adaptor pre-signature is not an ordinary BIP340 signature.  It reuses
//! the same device-allocated covenant instance IDs and portable script-binding
//! tokens while binding every pre-signature to an exact compact-KSPT claim
//! transaction.  Ordinary wallet-spending keys never consume this protocol.

use sha2::{Digest, Sha256};

mod validation;

use validation::{
    parse_bool, validate_request, validate_request_payload_length, validate_request_prefix,
    validate_response,
};

pub const REQUEST_MAGIC: [u8; 4] = *b"PSWG";
pub const REVEAL_MAGIC: [u8; 4] = *b"PSWR";
pub const RESPONSE_MAGIC: [u8; 4] = *b"PSWS";
pub const VERSION: u8 = 1;
pub const SESSION_ID_LEN: usize = 16;
pub const REQUEST_HEADER_LEN: usize = 221;
pub const REVEAL_LEN: usize = 117;
pub const RESPONSE_LEN: usize = 280;
pub const MAX_PAYLOAD_LEN: usize = 2_600;

const SESSION_DOMAIN: &[u8] = b"KasSigner Private Swap Session v2\0";
const TX_DOMAIN: &[u8] = b"KasSigner Private Swap KSPT v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RequestKind {
    KeyInfo = 0,
    Bind = 1,
    PreSign = 2,
    Complete = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResponseKind {
    KeyInfo = 0,
    Binding = 1,
    Nonce = 2,
    PreSignature = 3,
    Completed = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidKind,
    InvalidLength,
    InvalidFields,
    OutputTooSmall,
}

pub struct PrivateSwapRequest<'a> {
    pub kind: RequestKind,
    pub session_id: [u8; SESSION_ID_LEN],
    pub host_commitment: [u8; 32],
    pub key_id: [u8; 32],
    pub binding_token: [u8; 32],
    pub adaptor_point: [u8; 32],
    pub presignature: [u8; 64],
    pub presignature_negated: bool,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateSwapReveal {
    pub session_id: [u8; SESSION_ID_LEN],
    pub key_id: [u8; 32],
    pub sighash: [u8; 32],
    pub host_secret: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateSwapResponse {
    pub kind: ResponseKind,
    pub session_id: [u8; SESSION_ID_LEN],
    pub key_id: [u8; 32],
    pub claim_pubkey: [u8; 32],
    pub binding_token: [u8; 32],
    pub adaptor_point: [u8; 32],
    /// Binding responses carry SHA256(redeem script) here.  Signing responses
    /// carry the exact Kaspa transaction sighash.
    pub commitment: [u8; 32],
    pub nonce_point: [u8; 33],
    pub signature: [u8; 64],
    pub negated: bool,
}

#[must_use]
pub fn is_message(input: &[u8]) -> bool {
    input.len() >= 5
        && input[4] == VERSION
        && (input.starts_with(&REQUEST_MAGIC) || input.starts_with(&REVEAL_MAGIC))
}

#[must_use]
pub fn transaction_digest(transaction: &[u8]) -> [u8; 32] {
    domain_hash(TX_DOMAIN, &[transaction])
}

#[must_use]
pub fn session_id(
    host_commitment: &[u8; 32],
    transaction: &[u8],
    key_id: &[u8; 32],
    adaptor_point: &[u8; 32],
) -> [u8; SESSION_ID_LEN] {
    let tx_digest = transaction_digest(transaction);
    let digest = domain_hash(
        SESSION_DOMAIN,
        &[host_commitment, &tx_digest, key_id, adaptor_point],
    );
    let mut out = [0u8; SESSION_ID_LEN];
    out.copy_from_slice(&digest[..SESSION_ID_LEN]);
    out
}

pub fn encode_request(
    request: &PrivateSwapRequest<'_>,
    out: &mut [u8],
) -> Result<usize, ProtocolError> {
    validate_request(request)?;
    let total = REQUEST_HEADER_LEN
        .checked_add(request.payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if out.len() < total {
        return Err(ProtocolError::OutputTooSmall);
    }
    out[..4].copy_from_slice(&REQUEST_MAGIC);
    out[4] = VERSION;
    out[5] = request.kind as u8;
    out[6..22].copy_from_slice(&request.session_id);
    out[22..54].copy_from_slice(&request.host_commitment);
    out[54..86].copy_from_slice(&request.key_id);
    out[86..118].copy_from_slice(&request.binding_token);
    out[118..150].copy_from_slice(&request.adaptor_point);
    out[150..214].copy_from_slice(&request.presignature);
    out[214] = u8::from(request.presignature_negated);
    out[215..219].copy_from_slice(&(request.payload.len() as u32).to_be_bytes());
    // Reserved bytes are authenticated by transport shape and must remain zero.
    out[219..221].fill(0);
    out[REQUEST_HEADER_LEN..total].copy_from_slice(request.payload);
    Ok(total)
}

pub fn parse_request(input: &[u8]) -> Result<PrivateSwapRequest<'_>, ProtocolError> {
    validate_request_prefix(input)?;
    let kind = parse_request_kind(input[5])?;
    validate_request_payload_length(input)?;
    let mut presignature = [0u8; 64];
    presignature.copy_from_slice(&input[150..214]);
    let request = PrivateSwapRequest {
        kind,
        session_id: array16(&input[6..22]),
        host_commitment: array32(&input[22..54]),
        key_id: array32(&input[54..86]),
        binding_token: array32(&input[86..118]),
        adaptor_point: array32(&input[118..150]),
        presignature,
        presignature_negated: parse_bool(input[214])?,
        payload: &input[REQUEST_HEADER_LEN..],
    };
    validate_request(&request)?;
    Ok(request)
}

pub fn encode_reveal(reveal: &PrivateSwapReveal, out: &mut [u8]) -> Result<usize, ProtocolError> {
    if out.len() < REVEAL_LEN {
        return Err(ProtocolError::OutputTooSmall);
    }
    if reveal.session_id == [0; SESSION_ID_LEN]
        || reveal.key_id == [0; 32]
        || reveal.sighash == [0; 32]
        || reveal.host_secret == [0; 32]
    {
        return Err(ProtocolError::InvalidFields);
    }
    out[..4].copy_from_slice(&REVEAL_MAGIC);
    out[4] = VERSION;
    out[5..21].copy_from_slice(&reveal.session_id);
    out[21..53].copy_from_slice(&reveal.key_id);
    out[53..85].copy_from_slice(&reveal.sighash);
    out[85..117].copy_from_slice(&reveal.host_secret);
    Ok(REVEAL_LEN)
}

pub fn parse_reveal(input: &[u8]) -> Result<PrivateSwapReveal, ProtocolError> {
    if input.len() != REVEAL_LEN || !input.starts_with(&REVEAL_MAGIC) {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let reveal = PrivateSwapReveal {
        session_id: array16(&input[5..21]),
        key_id: array32(&input[21..53]),
        sighash: array32(&input[53..85]),
        host_secret: array32(&input[85..117]),
    };
    if reveal.session_id == [0; SESSION_ID_LEN]
        || reveal.key_id == [0; 32]
        || reveal.sighash == [0; 32]
        || reveal.host_secret == [0; 32]
    {
        return Err(ProtocolError::InvalidFields);
    }
    Ok(reveal)
}

pub fn encode_response(
    response: &PrivateSwapResponse,
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
    out[54..86].copy_from_slice(&response.claim_pubkey);
    out[86..118].copy_from_slice(&response.binding_token);
    out[118..150].copy_from_slice(&response.adaptor_point);
    out[150..182].copy_from_slice(&response.commitment);
    out[182..215].copy_from_slice(&response.nonce_point);
    out[215..279].copy_from_slice(&response.signature);
    out[279] = u8::from(response.negated);
    Ok(RESPONSE_LEN)
}

pub fn parse_response(input: &[u8]) -> Result<PrivateSwapResponse, ProtocolError> {
    if input.len() != RESPONSE_LEN || !input.starts_with(&RESPONSE_MAGIC) {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let kind = parse_response_kind(input[5])?;
    let mut nonce_point = [0u8; 33];
    nonce_point.copy_from_slice(&input[182..215]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&input[215..279]);
    let response = PrivateSwapResponse {
        kind,
        session_id: array16(&input[6..22]),
        key_id: array32(&input[22..54]),
        claim_pubkey: array32(&input[54..86]),
        binding_token: array32(&input[86..118]),
        adaptor_point: array32(&input[118..150]),
        commitment: array32(&input[150..182]),
        nonce_point,
        signature,
        negated: match input[279] {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::InvalidFields),
        },
    };
    validate_response(&response)?;
    Ok(response)
}

fn parse_request_kind(value: u8) -> Result<RequestKind, ProtocolError> {
    match value {
        0 => Ok(RequestKind::KeyInfo),
        1 => Ok(RequestKind::Bind),
        2 => Ok(RequestKind::PreSign),
        3 => Ok(RequestKind::Complete),
        _ => Err(ProtocolError::InvalidKind),
    }
}
fn parse_response_kind(value: u8) -> Result<ResponseKind, ProtocolError> {
    match value {
        0 => Ok(ResponseKind::KeyInfo),
        1 => Ok(ResponseKind::Binding),
        2 => Ok(ResponseKind::Nonce),
        3 => Ok(ResponseKind::PreSignature),
        4 => Ok(ResponseKind::Completed),
        _ => Err(ProtocolError::InvalidKind),
    }
}
fn array16(input: &[u8]) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(input);
    out
}
fn array32(input: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(input);
    out
}
fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[cfg(test)]
mod unit_tests;
