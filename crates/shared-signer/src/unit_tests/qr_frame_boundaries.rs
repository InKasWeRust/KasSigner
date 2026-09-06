use crate::qr_frame::{
    encode_frame, parse_frame, session_id, FrameError, FRAME_HEADER_LEN, FRAME_MAGIC,
    FRAME_VERSION, MAX_FRAMES, SESSION_ID_LEN,
};

#[test]
fn qr_frame_accepts_exact_protocol_maxima() {
    let identifier = session_id(b"max-frame-boundaries");
    let fragment = [0xa5u8; u8::MAX as usize];
    let mut encoded = [0u8; FRAME_HEADER_LEN + u8::MAX as usize];
    let written = encode_frame(
        &identifier,
        (MAX_FRAMES - 1) as u8,
        MAX_FRAMES as u8,
        &fragment,
        &mut encoded,
    )
    .expect("exact protocol maxima must encode");

    assert_eq!(written, encoded.len());
    let parsed = parse_frame(&encoded).expect("exact protocol maxima must parse");
    assert_eq!(parsed.frame_index, (MAX_FRAMES - 1) as u8);
    assert_eq!(parsed.total_frames, MAX_FRAMES as u8);
    assert_eq!(parsed.fragment, fragment.as_slice());
}

#[test]
fn qr_frame_header_exact_length_reaches_index_validation() {
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[..2].copy_from_slice(&FRAME_MAGIC);
    header[2] = FRAME_VERSION;
    header[3..3 + SESSION_ID_LEN].copy_from_slice(&session_id(b"header-only"));
    header[3 + SESSION_ID_LEN] = 0;
    header[4 + SESSION_ID_LEN] = 2;
    header[5 + SESSION_ID_LEN] = 0;

    assert_eq!(
        parse_frame(&header).map(|_| ()),
        Err(FrameError::InvalidIndex)
    );
}
