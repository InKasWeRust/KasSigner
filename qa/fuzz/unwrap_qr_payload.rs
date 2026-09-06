#![no_main]

use libfuzzer_sys::fuzz_target;
use kassigner_protocol::wire::qr_payload::{unwrap_v1_raw, PAYLOAD_V1_RAW};

fuzz_target!(|data: &[u8]| {
    match unwrap_v1_raw(data) {
        Some(body) => {
            assert_eq!(data.first().copied(), Some(PAYLOAD_V1_RAW));
            assert!(!body.is_empty());
            assert_eq!(body, &data[1..]);
        }
        None => {
            assert!(data.len() < 2 || data[0] != PAYLOAD_V1_RAW);
        }
    }
});
