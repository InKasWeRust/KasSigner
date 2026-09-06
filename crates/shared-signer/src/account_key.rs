//! Canonical watch-only account-key encoding shared by signer and watcher.

use crate::bytes::{decode_lower_hex, encode_lower_hex};

pub const ACCOUNT_KEY_VERSION: [u8; 4] = [0x03, 0x8f, 0x33, 0x2e];
pub const ACCOUNT_KEY_PAYLOAD_LEN: usize = 78;
pub const ACCOUNT_KEY_TEXT_PREFIX: &[u8; 6] = b"kpub1:";
pub const ACCOUNT_KEY_TEXT_LEN: usize = ACCOUNT_KEY_TEXT_PREFIX.len() + ACCOUNT_KEY_PAYLOAD_LEN * 2;
pub const ACCOUNT_KEY_DEPTH: u8 = 3;
pub const ACCOUNT_KEY_CHILD_INDEX: u32 = 0x8000_0000;

#[must_use]
pub fn validate_account_key_payload(payload: &[u8]) -> bool {
    payload.len() == ACCOUNT_KEY_PAYLOAD_LEN
        && payload[..4] == ACCOUNT_KEY_VERSION
        && payload[4] == ACCOUNT_KEY_DEPTH
        && payload[9..13] == ACCOUNT_KEY_CHILD_INDEX.to_be_bytes()
        && matches!(payload[45], 0x02 | 0x03)
}

pub fn encode_account_key_text(
    payload: &[u8; ACCOUNT_KEY_PAYLOAD_LEN],
    output: &mut [u8; ACCOUNT_KEY_TEXT_LEN],
) -> Option<usize> {
    if !validate_account_key_payload(payload) {
        return None;
    }
    output[..ACCOUNT_KEY_TEXT_PREFIX.len()].copy_from_slice(ACCOUNT_KEY_TEXT_PREFIX);
    let encoded = encode_lower_hex(payload, &mut output[ACCOUNT_KEY_TEXT_PREFIX.len()..])?;
    Some(ACCOUNT_KEY_TEXT_PREFIX.len() + encoded)
}

pub fn decode_account_key_text(
    text: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Option<usize> {
    if text.len() != ACCOUNT_KEY_TEXT_LEN || !text.starts_with(ACCOUNT_KEY_TEXT_PREFIX) {
        return None;
    }
    // Exact canonical text length fixes the hex body at 156 bytes, and the
    // destination is exactly 78 bytes. A successful decoder therefore always
    // writes ACCOUNT_KEY_PAYLOAD_LEN bytes; there is no separate length branch.
    decode_lower_hex(&text[ACCOUNT_KEY_TEXT_PREFIX.len()..], output)?;
    validate_account_key_payload(output).then_some(ACCOUNT_KEY_PAYLOAD_LEN)
}
