#![no_main]

use libfuzzer_sys::fuzz_target;
use shared_signer::qr_frame::{encode_frame, parse_frame, session_id, verify_session, MIN_ENCODED_FRAME_LEN};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let fragment_len = data.len().min(u8::MAX as usize);
    let fragment = &data[..fragment_len];
    let identifier = session_id(fragment);
    let mut encoded = [0u8; 512];
    let written = encode_frame(&identifier, 0, 2, fragment, &mut encoded)
        .expect("bounded frame must encode");
    assert!(written >= MIN_ENCODED_FRAME_LEN);
    let parsed = parse_frame(&encoded[..written]).expect("encoded frame must parse");
    assert_eq!(parsed.session_id, identifier);
    assert_eq!(parsed.frame_index, 0);
    assert_eq!(parsed.total_frames, 2);
    assert_eq!(parsed.fragment, fragment);
    assert!(verify_session(fragment, &parsed.session_id));
});
