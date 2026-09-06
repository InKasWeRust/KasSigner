use crate::bytes::{
    constant_time_eq, constant_time_eq_32, decode_hex_nibble, decode_lower_hex, encode_lower_hex,
    strict_forward_progress, zeroize_u16,
};

#[test]
fn hexadecimal_nibble_decoder_accepts_every_canonical_digit_and_rejects_neighbors() {
    for (input, expected) in b"0123456789abcdef".iter().copied().zip(0u8..16) {
        assert_eq!(decode_hex_nibble(input), Some(expected));
    }
    for (input, expected) in b"ABCDEF".iter().copied().zip(10u8..16) {
        assert_eq!(decode_hex_nibble(input), Some(expected));
    }
    for input in [b'/', b':', b'@', b'G', b'`', b'g', 0xff] {
        assert_eq!(decode_hex_nibble(input), None);
    }
}

#[test]
fn lowercase_hex_round_trips_and_enforces_canonical_input() {
    let source = [0x00, 0x01, 0x7f, 0x80, 0xab, 0xff];
    let mut encoded = [0u8; 12];
    assert_eq!(encode_lower_hex(&source, &mut encoded), Some(encoded.len()));
    assert_eq!(&encoded, b"00017f80abff");

    let mut decoded = [0u8; 6];
    assert_eq!(
        decode_lower_hex(&encoded, &mut decoded),
        Some(decoded.len())
    );
    assert_eq!(decoded, source);

    assert_eq!(decode_lower_hex(b"0", &mut decoded), None);
    assert_eq!(decode_lower_hex(b"0A", &mut decoded), None);
    assert_eq!(decode_lower_hex(b"0g", &mut decoded), None);
    assert_eq!(decode_lower_hex(b"0001", &mut decoded[..1]), None);
    assert_eq!(encode_lower_hex(&source, &mut encoded[..11]), None);
}

#[test]
fn strict_forward_progress_requires_remaining_bytes_to_decrease() {
    assert!(strict_forward_progress(2, 1));
    assert!(strict_forward_progress(usize::MAX, usize::MAX - 1));
    assert!(!strict_forward_progress(1, 1));
    assert!(!strict_forward_progress(0, 0));
    assert!(!strict_forward_progress(1, 2));
}

#[test]
fn constant_time_equality_and_u16_zeroization_are_observable() {
    let baseline = [0x5au8; 32];
    assert!(constant_time_eq_32(&baseline, &baseline));

    let mut one_difference = baseline;
    one_difference[7] ^= 0x04;
    assert!(!constant_time_eq_32(&baseline, &one_difference));

    // Two differences in the same bit position must not cancel. This catches
    // an accidental XOR accumulator replacing the required OR accumulator.
    let mut two_differences = baseline;
    two_differences[7] ^= 0x04;
    two_differences[19] ^= 0x04;
    assert!(!constant_time_eq_32(&baseline, &two_differences));

    assert!(constant_time_eq(b"KasSigner", b"KasSigner"));
    assert!(!constant_time_eq(b"KasSigner", b"KasSigneR"));
    assert!(!constant_time_eq(b"KasSigner", b"KasSigner!"));

    let mut words = [0x1234u16, 0xabcd, 1, u16::MAX];
    zeroize_u16(&mut words);
    assert_eq!(words, [0u16; 4]);
}
