#![no_main]

use libfuzzer_sys::fuzz_target;
use shared_signer::account_key::{
    decode_account_key_text, encode_account_key_text, validate_account_key_payload,
    ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_TEXT_LEN,
    ACCOUNT_KEY_VERSION,
};

fuzz_target!(|data: &[u8]| {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    let take = data.len().min(payload.len());
    payload[..take].copy_from_slice(&data[..take]);
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[4] = ACCOUNT_KEY_DEPTH;
    payload[9..13].copy_from_slice(&ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
    payload[45] = if data.first().copied().unwrap_or(0) & 1 == 0 { 0x02 } else { 0x03 };
    assert!(validate_account_key_payload(&payload));

    let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
    assert_eq!(encode_account_key_text(&payload, &mut text), Some(ACCOUNT_KEY_TEXT_LEN));
    let mut decoded = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(decode_account_key_text(&text, &mut decoded), Some(ACCOUNT_KEY_PAYLOAD_LEN));
    assert_eq!(decoded, payload);

    if data.len() == ACCOUNT_KEY_TEXT_LEN {
        let mut arbitrary = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
        if decode_account_key_text(data, &mut arbitrary).is_some() {
            let mut canonical = [0u8; ACCOUNT_KEY_TEXT_LEN];
            assert_eq!(encode_account_key_text(&arbitrary, &mut canonical), Some(ACCOUNT_KEY_TEXT_LEN));
            assert_eq!(canonical.as_slice(), data);
        }
    }
});
