#![no_main]

use libfuzzer_sys::fuzz_target;
use shared_signer::bytes::encode_lower_hex;
use signer_firmware_core::qr::classification::{
    classify_qr_payload, decode_hex, is_covenant_hex, QrPayloadKind,
};

fuzz_target!(|data: &[u8]| {
    let declared = data.first().copied().map(usize::from).unwrap_or(0);
    let _ = classify_qr_payload(data, declared);

    let raw_len = data.len().min(256);
    let mut encoded = [0u8; 512];
    let encoded_len = encode_lower_hex(&data[..raw_len], &mut encoded).expect("hex buffer fits");
    let mut decoded = [0u8; 256];
    assert_eq!(decode_hex(&encoded[..encoded_len], &mut decoded), Ok(raw_len));
    assert_eq!(&decoded[..raw_len], &data[..raw_len]);

    if is_covenant_hex(&encoded[..encoded_len]) {
        assert!(matches!(
            classify_qr_payload(&encoded[..encoded_len], encoded_len),
            QrPayloadKind::CovenantHex
        ));
    }
});
