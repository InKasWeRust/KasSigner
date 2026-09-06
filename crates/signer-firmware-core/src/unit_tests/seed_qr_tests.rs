use crate::backup::seed_qr::{
    decode_compact_seedqr, decode_seedqr, encode_compact_seedqr, encode_seedqr,
};

fn indices_12() -> [u16; 12] {
    [0, 1, 2, 3, 10, 99, 100, 999, 1024, 1536, 2000, 2047]
}

fn indices_24() -> [u16; 24] {
    let mut out = [0u16; 24];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = ((index * 83) % 2048) as u16;
    }
    out
}

#[test]
fn standard_seedqr_round_trips_12_and_24_words_and_rejects_malformed_digits() {
    let twelve = indices_12();
    let mut text = [0u8; 96];
    assert_eq!(encode_seedqr(&twelve, 12, &mut text), 48);
    let mut decoded = [0u16; 24];
    assert_eq!(decode_seedqr(&text[..48], &mut decoded), 12);
    assert_eq!(&decoded[..12], &twelve);

    let twenty_four = indices_24();
    assert_eq!(encode_seedqr(&twenty_four, 24, &mut text), 96);
    assert_eq!(decode_seedqr(&text, &mut decoded), 24);
    assert_eq!(decoded, twenty_four);

    assert_eq!(decode_seedqr(b"", &mut decoded), 0);
    let mut nondigit = text;
    nondigit[10] = b'x';
    assert_eq!(decode_seedqr(&nondigit, &mut decoded), 0);
    let mut out_of_range = text;
    out_of_range[..4].copy_from_slice(b"2048");
    assert_eq!(decode_seedqr(&out_of_range, &mut decoded), 0);
}

#[test]
fn seedqr_encoders_reject_invalid_word_counts_short_inputs_and_indices() {
    let twelve = indices_12();
    let mut text = [0u8; 96];
    let mut compact = [0u8; 32];
    assert_eq!(encode_seedqr(&twelve, 13, &mut text), 0);
    assert_eq!(encode_compact_seedqr(&twelve, 13, &mut compact), 0);
    assert_eq!(encode_seedqr(&twelve[..11], 12, &mut text), 0);
    assert_eq!(encode_compact_seedqr(&twelve[..11], 12, &mut compact), 0);
    let mut invalid = twelve;
    invalid[11] = 2048;
    assert_eq!(encode_seedqr(&invalid, 12, &mut text), 0);
    assert_eq!(encode_compact_seedqr(&invalid, 12, &mut compact), 0);
}

#[test]
fn compact_seedqr_encodes_expected_lengths_and_decode_is_deterministic() {
    let twelve = indices_12();
    let mut compact = [0u8; 32];
    assert_eq!(encode_compact_seedqr(&twelve, 12, &mut compact), 16);
    let mut decoded_a = [0u16; 24];
    let mut decoded_b = [0u16; 24];
    assert_eq!(decode_compact_seedqr(&compact[..16], &mut decoded_a), 12);
    assert_eq!(decode_compact_seedqr(&compact[..16], &mut decoded_b), 12);
    assert_eq!(decoded_a, decoded_b);

    let twenty_four = indices_24();
    assert_eq!(encode_compact_seedqr(&twenty_four, 24, &mut compact), 32);
    assert_eq!(decode_compact_seedqr(&compact, &mut decoded_a), 24);
    assert_eq!(decode_compact_seedqr(&compact[..15], &mut decoded_a), 0);
    assert_eq!(decode_compact_seedqr(&compact[..31], &mut decoded_a), 0);
}
