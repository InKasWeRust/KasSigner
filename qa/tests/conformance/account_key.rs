use shared_signer::account_key::{
    decode_account_key_text, encode_account_key_text, validate_account_key_payload,
    ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN,
    ACCOUNT_KEY_TEXT_LEN, ACCOUNT_KEY_TEXT_PREFIX, ACCOUNT_KEY_VERSION,
};
use shared_signer::legacy_account_key::decode_bip32_xpub;

const EVEN_COMPRESSED_KEY_PREFIX: u8 = 0x02;
const ODD_COMPRESSED_KEY_PREFIX: u8 = 0x03;
const UNCOMPRESSED_KEY_PREFIX: u8 = 0x04;

fn valid_payload_with_key_prefix(key_prefix: u8) -> [u8; ACCOUNT_KEY_PAYLOAD_LEN] {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[4] = ACCOUNT_KEY_DEPTH;
    payload[9..13].copy_from_slice(&ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
    payload[45] = key_prefix;
    payload
}

fn valid_payload() -> [u8; ACCOUNT_KEY_PAYLOAD_LEN] {
    valid_payload_with_key_prefix(EVEN_COMPRESSED_KEY_PREFIX)
}

#[test]
fn canonical_account_key_round_trips() {
    let payload = valid_payload();
    let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
    let written = encode_account_key_text(&payload, &mut text).expect("valid payload");
    assert_eq!(written, ACCOUNT_KEY_TEXT_LEN);
    assert!(text.starts_with(ACCOUNT_KEY_TEXT_PREFIX));

    let mut decoded = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(decode_account_key_text(&text, &mut decoded), Some(ACCOUNT_KEY_PAYLOAD_LEN));
    assert_eq!(decoded, payload);
}

#[test]
fn account_key_accepts_both_compressed_key_parities() {
    for key_prefix in [EVEN_COMPRESSED_KEY_PREFIX, ODD_COMPRESSED_KEY_PREFIX] {
        assert!(validate_account_key_payload(&valid_payload_with_key_prefix(key_prefix)));
    }
}

#[test]
fn account_key_rejects_noncanonical_metadata_and_text() {
    let payload = valid_payload();

    for index in [0usize, 4, 9] {
        let mut changed = payload;
        changed[index] ^= 0x01;
        assert!(!validate_account_key_payload(&changed));
    }

    let mut invalid_key_prefix = payload;
    invalid_key_prefix[45] = UNCOMPRESSED_KEY_PREFIX;
    assert!(!validate_account_key_payload(&invalid_key_prefix));

    let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
    encode_account_key_text(&payload, &mut text).expect("valid payload");
    text[ACCOUNT_KEY_TEXT_PREFIX.len()] = b'A';
    let mut decoded = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(decode_account_key_text(&text, &mut decoded), None);
}

#[test]
fn kaspa_cli_account_xpub_normalizes_to_the_canonical_payload() {
    const KASPA_CLI_ACCOUNT_XPUB: &[u8] = b"xpub6BtkpE81MZgN8a3jn6A8ZnivpLvZfei6iJm43BeRrqscqPZNJoTzS5LAHvkDPmn2NCiqhs342s78kGiwibgGnpjabYPkCHqLtzd82ATmiF6";
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_bip32_xpub(KASPA_CLI_ACCOUNT_XPUB, &mut payload),
        Ok(ACCOUNT_KEY_PAYLOAD_LEN)
    );
    assert_eq!(&payload[..4], &ACCOUNT_KEY_VERSION);
    assert_eq!(payload[4], ACCOUNT_KEY_DEPTH);
    assert_eq!(&payload[9..13], &ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
    assert_eq!(
        &payload[13..45],
        &[
            0xd4, 0x98, 0xb3, 0x15, 0x86, 0xc7, 0x6a, 0x0a, 0xd7, 0xf1, 0xf3,
            0xb0, 0x56, 0xfb, 0xef, 0x7a, 0xcc, 0x01, 0x98, 0xb4, 0x03, 0x24,
            0x27, 0xf8, 0x61, 0x41, 0xaf, 0x02, 0xce, 0x18, 0xfd, 0x82,
        ]
    );
    assert_eq!(
        &payload[45..78],
        &[
            0x02, 0x1f, 0xb4, 0xb5, 0xb8, 0xac, 0x58, 0x0d, 0x6d, 0xae, 0x63,
            0x35, 0x7f, 0x22, 0xea, 0x93, 0x36, 0xb9, 0x04, 0xaf, 0x4a, 0xbc,
            0x98, 0xc9, 0x8c, 0x4a, 0xea, 0x3b, 0x5a, 0xce, 0x07, 0xd3, 0x9c,
        ]
    );
}
