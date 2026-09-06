use std::vec::Vec;

use crate::qr_frame::{
    encode_frame, is_session_frame, parse_frame, session_id, verify_session, FrameError,
};

#[test]
fn session_bound_frames_round_trip() {
    let payload = b"KSPT-session-bound-payload";
    let identifier = session_id(payload);
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];
    let first_len = encode_frame(&identifier, 0, 2, &payload[..10], &mut first).unwrap();
    let second_len = encode_frame(&identifier, 1, 2, &payload[10..], &mut second).unwrap();
    let first = parse_frame(&first[..first_len]).unwrap();
    let second = parse_frame(&second[..second_len]).unwrap();
    let mut assembled = Vec::new();
    assembled.extend_from_slice(first.fragment);
    assembled.extend_from_slice(second.fragment);
    assert_eq!(assembled, payload);
    assert!(verify_session(&assembled, &identifier));
}

#[test]
fn mixed_sessions_and_noncanonical_padding_are_rejected() {
    let first_id = session_id(b"first");
    let second_id = session_id(b"second");
    assert_ne!(first_id, second_id);

    let mut encoded = [0u8; 64];
    let length = encode_frame(&first_id, 0, 2, b"x", &mut encoded).unwrap();
    encoded[length - 1] = 1;
    assert!(matches!(
        parse_frame(&encoded[..length]),
        Err(FrameError::NonCanonicalPadding)
    ));
}

#[test]
fn session_frame_detection_covers_short_bad_and_valid_headers() {
    assert!(!is_session_frame(b""));
    assert!(!is_session_frame(b"KQ"));

    let identifier = session_id(b"frame");
    let mut encoded = [0u8; 64];
    let length = encode_frame(&identifier, 0, 2, b"x", &mut encoded).unwrap();
    assert!(is_session_frame(&encoded[..length]));

    encoded[2] = 0xff;
    assert!(!is_session_frame(&encoded[..length]));
}

#[test]
fn frame_encoder_rejects_invalid_counts_indices_fragments_and_buffers() {
    let identifier = session_id(b"boundaries");
    let mut output = [0u8; 300];

    assert_eq!(
        encode_frame(&identifier, 0, 1, b"x", &mut output),
        Err(FrameError::InvalidIndex)
    );
    assert_eq!(
        encode_frame(&identifier, 0, 65, b"x", &mut output),
        Err(FrameError::InvalidIndex)
    );
    assert_eq!(
        encode_frame(&identifier, 2, 2, b"x", &mut output),
        Err(FrameError::InvalidIndex)
    );
    assert_eq!(
        encode_frame(&identifier, 0, 2, b"", &mut output),
        Err(FrameError::InvalidIndex)
    );
    assert_eq!(
        encode_frame(&identifier, 0, 2, &[0x55; 256], &mut output),
        Err(FrameError::InvalidIndex)
    );

    let mut short = [0u8; 19];
    assert_eq!(
        encode_frame(&identifier, 0, 2, b"x", &mut short),
        Err(FrameError::BufferTooSmall)
    );

    let mut exact = [0u8; 20];
    assert_eq!(encode_frame(&identifier, 0, 2, b"x", &mut exact), Ok(20));
    assert_eq!(&exact[19..], &[0]);
}

#[test]
fn frame_parser_classifies_header_index_length_and_padding_failures() {
    let identifier = session_id(b"parser-boundaries");
    let mut encoded = [0u8; 64];
    let length = encode_frame(&identifier, 0, 2, b"abc", &mut encoded).unwrap();

    assert_eq!(
        parse_frame(&encoded[..17]).map(|_| ()),
        Err(FrameError::InvalidHeader)
    );

    let mut bad_magic = encoded;
    bad_magic[0] ^= 1;
    assert_eq!(
        parse_frame(&bad_magic[..length]).map(|_| ()),
        Err(FrameError::InvalidHeader)
    );

    let mut bad_version = encoded;
    bad_version[2] = 2;
    assert_eq!(
        parse_frame(&bad_version[..length]).map(|_| ()),
        Err(FrameError::InvalidHeader)
    );

    for (offset, value) in [(16usize, 1u8), (16, 65), (15, 2), (17, 0)] {
        let mut invalid = encoded;
        invalid[offset] = value;
        assert_eq!(
            parse_frame(&invalid[..length]).map(|_| ()),
            Err(FrameError::InvalidIndex),
            "offset {offset}"
        );
    }

    let mut truncated = encoded;
    truncated[17] = 4;
    assert_eq!(
        parse_frame(&truncated[..length]).map(|_| ()),
        Err(FrameError::InvalidLength)
    );

    let mut padded = [0u8; 64];
    let padded_len = encode_frame(&identifier, 0, 2, b"x", &mut padded).unwrap();
    assert_eq!(padded_len, 20);
    padded[padded_len - 1] = 1;
    assert_eq!(
        parse_frame(&padded[..padded_len]).map(|_| ()),
        Err(FrameError::NonCanonicalPadding)
    );
}

#[test]
fn session_verification_rejects_payload_and_identifier_changes() {
    let identifier = session_id(b"expected");
    assert!(verify_session(b"expected", &identifier));
    assert!(!verify_session(b"changed", &identifier));

    let mut changed_identifier = identifier;
    changed_identifier[0] ^= 1;
    assert!(!verify_session(b"expected", &changed_identifier));
}
