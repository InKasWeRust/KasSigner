//! Decode-only compatibility for historical KasSigner account keys and
//! account-level BIP32 xpubs exported by the Kaspa CLI.
//!
//! New code emits the canonical `kpub1:` encoding. This module exists only so
//! original users can import old Base58Check watch-only exports, while CLI users
//! can import account-level xpubs, and immediately normalize either form to the
//! current account-key model.

use sha2::{Digest, Sha256};

use crate::account_key::{
    validate_account_key_payload, ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH,
    ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_VERSION,
};

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_BASE58_BYTES: usize = 128;
const BIP32_XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyAccountKeyError {
    Empty,
    InvalidCharacter,
    Overflow,
    InvalidChecksum,
    InvalidPayload,
}

fn alphabet_value(byte: u8) -> Option<u8> {
    BASE58_ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

fn decode_base58(
    input: &[u8],
    output: &mut [u8; MAX_BASE58_BYTES],
) -> Result<usize, LegacyAccountKeyError> {
    if input.is_empty() {
        return Err(LegacyAccountKeyError::Empty);
    }

    let leading_zeroes = input.iter().take_while(|byte| **byte == b'1').count();
    let mut number = [0u8; MAX_BASE58_BYTES];
    let mut number_len = 0usize;

    for byte in input {
        let digit = alphabet_value(*byte).ok_or(LegacyAccountKeyError::InvalidCharacter)?;
        let mut carry = u32::from(digit);
        for index in (0..number_len).rev() {
            carry += u32::from(number[index]) * 58;
            number[index] = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry != 0 {
            if number_len == MAX_BASE58_BYTES {
                return Err(LegacyAccountKeyError::Overflow);
            }
            number.copy_within(0..number_len, 1);
            number[0] = (carry & 0xff) as u8;
            carry >>= 8;
            number_len += 1;
        }
    }

    let total = leading_zeroes
        .checked_add(number_len)
        .ok_or(LegacyAccountKeyError::Overflow)?;
    let target = output
        .get_mut(..total)
        .ok_or(LegacyAccountKeyError::Overflow)?;
    target[..leading_zeroes].fill(0);
    target[leading_zeroes..].copy_from_slice(&number[..number_len]);
    Ok(total)
}

fn decode_base58check_account_payload(
    encoded: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<(), LegacyAccountKeyError> {
    let mut decoded = [0u8; MAX_BASE58_BYTES];
    let decoded_len = decode_base58(encoded, &mut decoded)?;
    let expected_len = ACCOUNT_KEY_PAYLOAD_LEN + 4;
    if decoded_len != expected_len {
        return Err(LegacyAccountKeyError::InvalidPayload);
    }

    let checksum = sha256d(&decoded[..ACCOUNT_KEY_PAYLOAD_LEN]);
    if decoded[ACCOUNT_KEY_PAYLOAD_LEN..expected_len] != checksum[..4] {
        return Err(LegacyAccountKeyError::InvalidChecksum);
    }

    output.copy_from_slice(&decoded[..ACCOUNT_KEY_PAYLOAD_LEN]);
    Ok(())
}

/// Decode a historical Base58Check `kpub...` string into the canonical
/// 78-byte account-key payload.
///
/// This function never emits the legacy representation.
pub fn decode_legacy_kpub(
    encoded: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<usize, LegacyAccountKeyError> {
    decode_base58check_account_payload(encoded, output)?;
    if !validate_account_key_payload(output) {
        output.fill(0);
        return Err(LegacyAccountKeyError::InvalidPayload);
    }
    Ok(ACCOUNT_KEY_PAYLOAD_LEN)
}

/// Decode an account-level BIP32 `xpub...` produced by the Kaspa CLI.
///
/// The BIP32 serialization metadata is checked before its standard xpub
/// version is replaced with KasSigner's canonical account-key version. The
/// chain code, parent fingerprint, child index, and compressed public key are
/// preserved byte-for-byte.
pub fn decode_bip32_xpub(
    encoded: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<usize, LegacyAccountKeyError> {
    decode_base58check_account_payload(encoded, output)?;
    if output[..4] != BIP32_XPUB_VERSION
        || output[4] != ACCOUNT_KEY_DEPTH
        || output[9..13] != ACCOUNT_KEY_CHILD_INDEX.to_be_bytes()
        || !matches!(output[45], 0x02 | 0x03)
    {
        output.fill(0);
        return Err(LegacyAccountKeyError::InvalidPayload);
    }

    output[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    Ok(ACCOUNT_KEY_PAYLOAD_LEN)
}
