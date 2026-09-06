//! KasSigner/KasSee anti-klepto transaction-signing wire protocol.
//!
//! Version 2 uses 32-bit transaction lengths, proof counts, and input indices.
//! Version 1 wire messages are intentionally unsupported.

mod wire;

use wire::domain_hash;
pub use wire::{
    encode_commitment, encode_request, encode_reveal, encode_signed, parse_commitment,
    parse_request, parse_reveal, parse_signed,
};

#[cfg(test)]
use wire::{
    parse_header, read_signed_proof_count, read_u32, request_layout, signed_layout, write_header,
};

pub const MAGIC: [u8; 4] = *b"KAKP";
pub const VERSION: u8 = 2;
pub const SESSION_ID_LEN: usize = 16;
pub const HASH_LEN: usize = 32;

const HEADER_LEN: usize = 4 + 1 + 1 + SESSION_ID_LEN;
const REVEAL_LEN: usize = HEADER_LEN + HASH_LEN;
const HOST_COMMIT_DOMAIN: &[u8] = b"KasSigner/anti-klepto/host-commit/v1";
const TX_DIGEST_DOMAIN: &[u8] = b"KasSigner/anti-klepto/tx/v1";
const SESSION_DOMAIN: &[u8] = b"KasSigner/anti-klepto/session/v1";
const HOST_SCALAR_DOMAIN: &[u8] = b"KasSigner/anti-klepto/host-scalar/v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    Request = 1,
    Commitment = 2,
    Reveal = 3,
    Signed = 4,
}

impl MessageKind {
    fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Commitment),
            3 => Ok(Self::Reveal),
            4 => Ok(Self::Signed),
            _ => Err(WireError::WrongKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    WrongKind,
    InvalidLength,
    TooManyProofs,
    OutputTooSmall,
    SessionMismatch,
    TransactionMismatch,
    HostCommitmentMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub version: u8,
    pub kind: MessageKind,
    pub session_id: [u8; SESSION_ID_LEN],
}

#[derive(Debug)]
pub struct Request<'a> {
    pub session_id: [u8; SESSION_ID_LEN],
    pub host_commitment: [u8; HASH_LEN],
    pub transaction_digest: [u8; HASH_LEN],
    pub transaction: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceCommitment {
    pub input_index: u32,
    pub signature_slot: u8,
    pub public_key: [u8; 33],
    pub nonce_point: [u8; 33],
}

#[derive(Debug)]
pub struct Commitment<'a> {
    pub session_id: [u8; SESSION_ID_LEN],
    pub transaction_digest: [u8; HASH_LEN],
    record_bytes: &'a [u8],
    count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProof {
    pub input_index: u32,
    pub signature_slot: u8,
}

#[derive(Debug)]
pub struct Signed<'a> {
    pub session_id: [u8; SESSION_ID_LEN],
    pub transaction_digest: [u8; HASH_LEN],
    proof_bytes: &'a [u8],
    proof_count: usize,
    pub transaction: &'a [u8],
}

pub fn is_message(input: &[u8]) -> bool {
    input.len() >= HEADER_LEN && input[..4] == MAGIC && input[4] == VERSION
}

pub fn host_commitment(host_secret: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    domain_hash(HOST_COMMIT_DOMAIN, &[host_secret])
}
pub fn transaction_digest(transaction: &[u8]) -> [u8; HASH_LEN] {
    domain_hash(TX_DIGEST_DOMAIN, &[transaction])
}

pub fn session_id(commitment: &[u8; HASH_LEN], tx_digest: &[u8; HASH_LEN]) -> [u8; SESSION_ID_LEN] {
    let digest = domain_hash(SESSION_DOMAIN, &[commitment, tx_digest]);
    let mut session = [0u8; SESSION_ID_LEN];
    session.copy_from_slice(&digest[..SESSION_ID_LEN]);
    session
}

pub fn host_scalar_material(
    session: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; HASH_LEN],
    input_index: u32,
    signature_slot: u8,
    public_key: &[u8; 33],
    nonce_point: &[u8; 33],
) -> [u8; HASH_LEN] {
    let input = input_index.to_le_bytes();
    let slot = [signature_slot];
    domain_hash(
        HOST_SCALAR_DOMAIN,
        &[session, host_secret, &input, &slot, public_key, nonce_point],
    )
}

pub fn verify_host_secret(
    expected_commitment: &[u8; HASH_LEN],
    host_secret: &[u8; HASH_LEN],
) -> bool {
    crate::bytes::constant_time_eq_32(expected_commitment, &host_commitment(host_secret))
}

#[cfg(test)]
#[path = "unit_tests/anti_klepto_tests.rs"]
mod anti_klepto_tests;
