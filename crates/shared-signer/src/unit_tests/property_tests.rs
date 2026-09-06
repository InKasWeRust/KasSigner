use crate::{
    account_key::{
        decode_account_key_text, encode_account_key_text, ACCOUNT_KEY_CHILD_INDEX,
        ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_TEXT_LEN, ACCOUNT_KEY_VERSION,
    },
    bytes::{decode_lower_hex, encode_lower_hex},
    qr_frame::{encode_frame, parse_frame, session_id, verify_session},
};

fn deterministic_bytes(seed: u32, output: &mut [u8]) {
    let mut state = seed.wrapping_add(0x9e37_79b9);
    for byte in output {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = state as u8;
    }
}

#[test]
fn canonical_account_keys_round_trip_for_generated_payloads() {
    for case in 0..256u32 {
        let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
        deterministic_bytes(case, &mut payload);
        payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
        payload[4] = ACCOUNT_KEY_DEPTH;
        payload[9..13].copy_from_slice(&ACCOUNT_KEY_CHILD_INDEX.to_be_bytes());
        payload[45] = if case & 1 == 0 { 0x02 } else { 0x03 };

        let mut text = [0u8; ACCOUNT_KEY_TEXT_LEN];
        assert_eq!(
            encode_account_key_text(&payload, &mut text),
            Some(ACCOUNT_KEY_TEXT_LEN),
            "case {case} must encode"
        );
        let mut recovered = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
        assert_eq!(
            decode_account_key_text(&text, &mut recovered),
            Some(ACCOUNT_KEY_PAYLOAD_LEN),
            "case {case} must decode"
        );
        assert_eq!(recovered, payload, "case {case} changed key material");
    }
}

#[test]
fn qr_frames_round_trip_across_boundaries_and_reject_corruption() {
    for length in 2..=96usize {
        let mut payload = [0u8; 96];
        deterministic_bytes(length as u32, &mut payload[..length]);
        let identifier = session_id(&payload[..length]);
        let split = length / 2;

        let mut first_encoded = [0u8; 256];
        let first_written = encode_frame(&identifier, 0, 2, &payload[..split], &mut first_encoded)
            .expect("first generated frame must encode");
        let mut second_encoded = [0u8; 256];
        let second_written = encode_frame(
            &identifier,
            1,
            2,
            &payload[split..length],
            &mut second_encoded,
        )
        .expect("second generated frame must encode");

        let first = parse_frame(&first_encoded[..first_written]).expect("first frame must parse");
        let second =
            parse_frame(&second_encoded[..second_written]).expect("second frame must parse");
        assert_eq!(first.frame_index, 0);
        assert_eq!(second.frame_index, 1);
        assert_eq!(first.total_frames, 2);
        assert_eq!(second.total_frames, 2);
        assert_eq!(first.session_id, second.session_id);

        let mut assembled = [0u8; 96];
        assembled[..first.fragment.len()].copy_from_slice(first.fragment);
        assembled[first.fragment.len()..length].copy_from_slice(second.fragment);
        assert_eq!(&assembled[..length], &payload[..length]);
        assert!(verify_session(&assembled[..length], &first.session_id));

        first_encoded[2] ^= 1;
        assert!(parse_frame(&first_encoded[..first_written]).is_err());
    }
}

#[test]
fn lowercase_hex_round_trip_holds_for_generated_lengths() {
    for length in 0..=128usize {
        let mut raw = [0u8; 128];
        deterministic_bytes(length as u32 ^ 0xa5a5_5a5a, &mut raw[..length]);
        let mut text = [0u8; 256];
        let written = encode_lower_hex(&raw[..length], &mut text).expect("hex output fits");
        let mut recovered = [0u8; 128];
        assert_eq!(
            decode_lower_hex(&text[..written], &mut recovered),
            Some(length)
        );
        assert_eq!(&recovered[..length], &raw[..length]);
        if written > 0 {
            text[0] = b'G';
            assert_eq!(decode_lower_hex(&text[..written], &mut recovered), None);
        }
    }
}
