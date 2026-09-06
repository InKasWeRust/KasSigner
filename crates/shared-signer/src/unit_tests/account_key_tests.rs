use sha2::{Digest, Sha256};
use std::{vec, vec::Vec};

use crate::{
    account_key::{
        decode_account_key_text, encode_account_key_text, validate_account_key_payload,
        ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_TEXT_LEN,
        ACCOUNT_KEY_VERSION,
    },
    legacy_account_key::{decode_bip32_xpub, decode_legacy_kpub, LegacyAccountKeyError},
};

const KASPA_CLI_ACCOUNT_XPUB: &[u8] = b"xpub6BtkpE81MZgN8a3jn6A8ZnivpLvZfei6iJm43BeRrqscqPZNJoTzS5LAHvkDPmn2NCiqhs342s78kGiwibgGnpjabYPkCHqLtzd82ATmiF6";
const BIP32_XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn canonical_payload() -> [u8; ACCOUNT_KEY_PAYLOAD_LEN] {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[4] = ACCOUNT_KEY_DEPTH;
    payload[5..9].copy_from_slice(&[0x20, 0xcf, 0x6e, 0xe4]);
    payload[9..13].copy_from_slice(&ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
    payload[13..45].copy_from_slice(&[
        0xd4, 0x98, 0xb3, 0x15, 0x86, 0xc7, 0x6a, 0x0a, 0xd7, 0xf1, 0xf3, 0xb0, 0x56, 0xfb, 0xef,
        0x7a, 0xcc, 0x01, 0x98, 0xb4, 0x03, 0x24, 0x27, 0xf8, 0x61, 0x41, 0xaf, 0x02, 0xce, 0x18,
        0xfd, 0x82,
    ]);
    payload[45..78].copy_from_slice(&[
        0x02, 0x1f, 0xb4, 0xb5, 0xb8, 0xac, 0x58, 0x0d, 0x6d, 0xae, 0x63, 0x35, 0x7f, 0x22, 0xea,
        0x93, 0x36, 0xb9, 0x04, 0xaf, 0x4a, 0xbc, 0x98, 0xc9, 0x8c, 0x4a, 0xea, 0x3b, 0x5a, 0xce,
        0x07, 0xd3, 0x9c,
    ]);
    payload
}

fn base58check_encode(payload: &[u8]) -> Vec<u8> {
    let first = Sha256::digest(payload);
    let checksum = Sha256::digest(first);
    let mut number = Vec::from(payload);
    number.extend_from_slice(&checksum[..4]);

    let leading_zeroes = number.iter().take_while(|byte| **byte == 0).count();
    let mut digits = Vec::new();
    let mut start = leading_zeroes;
    while start < number.len() {
        let mut remainder = 0u32;
        for value in &mut number[start..] {
            let accumulator = (remainder << 8) | u32::from(*value);
            *value = (accumulator / 58) as u8;
            remainder = accumulator % 58;
        }
        digits.push(BASE58_ALPHABET[remainder as usize]);
        while start < number.len() && number[start] == 0 {
            start += 1;
        }
    }

    let mut encoded = vec![b'1'; leading_zeroes];
    encoded.extend(digits.into_iter().rev());
    encoded
}

#[test]
fn kaspa_cli_account_xpub_normalizes_without_changing_key_material() {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_bip32_xpub(KASPA_CLI_ACCOUNT_XPUB, &mut payload),
        Ok(ACCOUNT_KEY_PAYLOAD_LEN)
    );
    assert_eq!(payload, canonical_payload());

    let mut canonical = [0u8; ACCOUNT_KEY_TEXT_LEN];
    assert_eq!(
        encode_account_key_text(&payload, &mut canonical),
        Some(ACCOUNT_KEY_TEXT_LEN)
    );
    assert!(canonical.starts_with(b"kpub1:"));

    let mut decoded = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_account_key_text(&canonical, &mut decoded),
        Some(ACCOUNT_KEY_PAYLOAD_LEN)
    );
    assert_eq!(decoded, payload);
}

#[test]
fn canonical_account_key_rejects_every_noncanonical_metadata_boundary() {
    let payload = canonical_payload();
    assert!(validate_account_key_payload(&payload));
    assert!(!validate_account_key_payload(
        &payload[..ACCOUNT_KEY_PAYLOAD_LEN - 1]
    ));

    for (index, replacement) in [
        (0usize, ACCOUNT_KEY_VERSION[0] ^ 1),
        (4, ACCOUNT_KEY_DEPTH - 1),
        (9, 0),
        (45, 0x04),
    ] {
        let mut invalid = payload;
        invalid[index] = replacement;
        assert!(!validate_account_key_payload(&invalid), "index {index}");
        let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
        assert_eq!(encode_account_key_text(&invalid, &mut text), None);
    }

    let mut alternate_key_prefix = payload;
    alternate_key_prefix[45] = 0x03;
    assert!(validate_account_key_payload(&alternate_key_prefix));
}

#[test]
fn canonical_text_decoder_rejects_length_prefix_case_and_payload_errors() {
    let payload = canonical_payload();
    let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
    assert_eq!(
        encode_account_key_text(&payload, &mut text),
        Some(ACCOUNT_KEY_TEXT_LEN)
    );

    let mut output = [0x55u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_account_key_text(&text[..text.len() - 1], &mut output),
        None
    );

    let mut bad_prefix = text;
    bad_prefix[0] = b'K';
    assert_eq!(decode_account_key_text(&bad_prefix, &mut output), None);

    let mut uppercase = text;
    let hex_index = uppercase
        .iter()
        .position(|byte| matches!(*byte, b'a'..=b'f'))
        .expect("fixture contains a hexadecimal letter");
    uppercase[hex_index] = uppercase[hex_index].to_ascii_uppercase();
    assert_eq!(decode_account_key_text(&uppercase, &mut output), None);

    let mut invalid_payload = text;
    invalid_payload[6..14].copy_from_slice(b"00000000");
    assert_eq!(decode_account_key_text(&invalid_payload, &mut output), None);
}

#[test]
fn legacy_kpub_accepts_only_canonical_payloads_and_zeroes_invalid_metadata() {
    let payload = canonical_payload();
    let encoded = base58check_encode(&payload);
    let mut output = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_legacy_kpub(&encoded, &mut output),
        Ok(ACCOUNT_KEY_PAYLOAD_LEN)
    );
    assert_eq!(output, payload);

    for (index, replacement) in [
        (0usize, ACCOUNT_KEY_VERSION[0] ^ 1),
        (4, ACCOUNT_KEY_DEPTH - 1),
        (9, 0),
        (45, 0x04),
    ] {
        let mut invalid = payload;
        invalid[index] = replacement;
        let invalid_encoded = base58check_encode(&invalid);
        output.fill(0x55);
        assert_eq!(
            decode_legacy_kpub(&invalid_encoded, &mut output),
            Err(LegacyAccountKeyError::InvalidPayload),
            "index {index}"
        );
        assert_eq!(output, [0u8; ACCOUNT_KEY_PAYLOAD_LEN]);
    }
}

#[test]
fn bip32_xpub_rejects_metadata_variants_and_zeroes_the_output() {
    let canonical = canonical_payload();
    let mut xpub_payload = canonical;
    xpub_payload[..4].copy_from_slice(&BIP32_XPUB_VERSION);

    for (index, replacement) in [
        (0usize, BIP32_XPUB_VERSION[0] ^ 1),
        (4, ACCOUNT_KEY_DEPTH - 1),
        (9, 0),
        (45, 0x04),
    ] {
        let mut invalid = xpub_payload;
        invalid[index] = replacement;
        let encoded = base58check_encode(&invalid);
        let mut output = [0x55u8; ACCOUNT_KEY_PAYLOAD_LEN];
        assert_eq!(
            decode_bip32_xpub(&encoded, &mut output),
            Err(LegacyAccountKeyError::InvalidPayload),
            "index {index}"
        );
        assert_eq!(output, [0u8; ACCOUNT_KEY_PAYLOAD_LEN]);
    }
}

#[test]
fn legacy_decoders_classify_empty_character_length_and_checksum_failures() {
    let mut output = [0x55u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_bip32_xpub(b"", &mut output),
        Err(LegacyAccountKeyError::Empty)
    );
    assert_eq!(
        decode_bip32_xpub(b"0", &mut output),
        Err(LegacyAccountKeyError::InvalidCharacter)
    );
    assert_eq!(
        decode_bip32_xpub(b"1", &mut output),
        Err(LegacyAccountKeyError::InvalidPayload)
    );

    let mut corrupted = KASPA_CLI_ACCOUNT_XPUB.to_vec();
    let last = corrupted.last_mut().expect("xpub is not empty");
    *last = if *last == b'1' { b'2' } else { b'1' };
    assert_eq!(
        decode_bip32_xpub(&corrupted, &mut output),
        Err(LegacyAccountKeyError::InvalidChecksum)
    );
}

#[test]
fn legacy_base58_decoder_rejects_numeric_and_leading_zero_overflow() {
    let mut output = [0x55u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_legacy_kpub(&[b'z'; 300], &mut output),
        Err(LegacyAccountKeyError::Overflow)
    );
    assert_eq!(
        decode_legacy_kpub(&[b'1'; 129], &mut output),
        Err(LegacyAccountKeyError::Overflow)
    );
}
