use super::{
    byte_at, capacity_bits, decode_payload_bits, embed, embed_payload_bits, framed_byte,
    payload_bits_from_window, PictureError,
};
use super::{codec, frame, huffman, permutation::PositionPermutation};

const NOISE_JPEG: &[u8] = include_bytes!(
    "../../../../../../apps/signer-firmware/src/runtime/workflow_tests/fixtures/stego_noise.jpg"
);
const FLAT_JPEG: &[u8] = include_bytes!(
    "../../../../../../apps/signer-firmware/src/runtime/workflow_tests/fixtures/stego_flat.jpg"
);
const KEY: &[u8] = b"KasSigner host stego coverage";

#[test]
fn picture_error_messages_cover_every_public_error() {
    let cases = [
        (PictureError::Malformed, "Malformed JPEG"),
        (PictureError::NotBaseline, "Progressive JPEG unsupported"),
        (PictureError::NoCapacity, "Photo has insufficient capacity"),
        (PictureError::BufferTooSmall, "JPEG output buffer too small"),
        (
            PictureError::Unencodable,
            "JPEG table cannot encode payload",
        ),
        (
            PictureError::AllocationFailed,
            "Not enough memory for JPEG operation",
        ),
        (
            PictureError::WorkLimitExceeded,
            "JPEG dimensions exceed work budget",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.message(), message);
    }
}

#[test]
fn picture_fixture_round_trip_exercises_real_frame_huffman_and_codec_paths() {
    let payload = [0x5au8; 179];
    let required = ((payload.len() + 2) * 8) as u32;
    assert!(capacity_bits(NOISE_JPEG, KEY).expect("noise capacity") >= required);
    assert!(capacity_bits(FLAT_JPEG, KEY).expect("flat capacity") < required);

    let mut encoded = std::vec![0u8; NOISE_JPEG.len() * 2 + 4_096];
    let encoded_len = embed(NOISE_JPEG, &payload, KEY, &mut encoded).expect("embed");
    encoded.truncate(encoded_len);
    assert!(encoded.starts_with(&[0xff, 0xd8]));
    assert!(encoded.ends_with(&[0xff, 0xd9]));

    let mut decoded = [0u8; 179];
    let decoded_len = super::extract(&encoded, KEY, &mut decoded).expect("extract");
    assert_eq!(decoded_len, payload.len());
    assert_eq!(decoded, payload);

    let mut short = [0u8; 8];
    assert_eq!(
        super::extract(&encoded, KEY, &mut short),
        Err(PictureError::BufferTooSmall)
    );

    let mut wrong = [0u8; 179];
    if let Ok(length) = super::extract(&encoded, b"wrong key", &mut wrong) {
        assert!(length != payload.len() || wrong != payload);
    }
}

#[test]
fn picture_embedding_rejects_empty_oversized_low_capacity_and_short_output() {
    let mut output = std::vec![0u8; NOISE_JPEG.len() * 2 + 4_096];
    assert_eq!(
        embed(NOISE_JPEG, &[], KEY, &mut output),
        Err(PictureError::NoCapacity)
    );
    let oversized = std::vec![0u8; usize::from(u16::MAX) + 1];
    assert_eq!(
        embed(NOISE_JPEG, &oversized, KEY, &mut output),
        Err(PictureError::NoCapacity)
    );

    let payload = [0x33u8; 179];
    assert_eq!(
        embed(FLAT_JPEG, &payload, KEY, &mut output),
        Err(PictureError::NoCapacity)
    );
    let mut tiny = [0u8; 16];
    assert_eq!(
        embed(NOISE_JPEG, &payload, KEY, &mut tiny),
        Err(PictureError::BufferTooSmall)
    );
}

#[test]
fn payload_bit_helpers_cover_change_no_change_absent_zero_and_decode_boundaries() {
    let payload = [0xa5u8, 0x5a, 0xff];
    let rank_window = 64u32;
    let present = [0xffu8; 8];
    let mut coefficients = [2i16; 64];
    let changed = embed_payload_bits(&payload, rank_window, &present, &mut coefficients)
        .expect("controlled embedding");
    assert!(changed.iter().any(|byte| *byte != 0));
    let bits =
        payload_bits_from_window(&coefficients, &present, rank_window).expect("payload bits");
    let mut decoded = [0u8; 3];
    assert_eq!(decode_payload_bits(&bits, &mut decoded), Ok(3));
    assert_eq!(decoded, payload);

    assert_eq!(
        decode_payload_bits(&[], &mut decoded),
        Err(PictureError::Malformed)
    );
    let zero_length = [0u8; 16];
    assert_eq!(
        decode_payload_bits(&zero_length, &mut decoded),
        Err(PictureError::Malformed)
    );
    let mut too_small = [0u8; 1];
    assert_eq!(
        decode_payload_bits(&bits, &mut too_small),
        Err(PictureError::BufferTooSmall)
    );

    assert_eq!(framed_byte(&payload, 0), Ok(0));
    assert_eq!(framed_byte(&payload, 1), Ok(3));
    assert_eq!(framed_byte(&payload, 2), Ok(0xa5));
    assert_eq!(framed_byte(&payload, 5), Err(PictureError::Malformed));
    assert_eq!(byte_at(&[1, 0, 1], 0), Err(PictureError::Malformed));

    let mut coefficients = [2i16; 4];
    let mut changed = [0u8; 1];
    assert!(!super::consume_embedding_rank(
        &payload,
        &[0],
        &mut coefficients,
        &mut changed,
        0,
        0
    ));
    coefficients[0] = 0;
    assert!(!super::consume_embedding_rank(
        &payload,
        &[1],
        &mut coefficients,
        &mut changed,
        0,
        0
    ));
    assert!(!super::consume_embedding_rank(
        &payload,
        &[1],
        &mut [],
        &mut changed,
        0,
        0
    ));
}

#[test]
fn jpeg_marker_mutations_cover_baseline_and_table_validation_fail_closed_paths() {
    assert!(frame::parse(NOISE_JPEG).is_ok());

    let mut progressive = NOISE_JPEG.to_vec();
    progressive[159] = 0xc2;
    assert!(matches!(
        frame::parse(&progressive),
        Err(PictureError::NotBaseline)
    ));

    let mut bad_component_count = NOISE_JPEG.to_vec();
    bad_component_count[167] = 0;
    assert_eq!(
        frame::parse(&bad_component_count).err(),
        Some(PictureError::Malformed)
    );

    let mut bad_sampling = NOISE_JPEG.to_vec();
    bad_sampling[169] = 0;
    assert_eq!(
        frame::parse(&bad_sampling).err(),
        Some(PictureError::Malformed)
    );

    let mut bad_huffman_class = NOISE_JPEG.to_vec();
    bad_huffman_class[181] = 0x20;
    assert_eq!(
        frame::parse(&bad_huffman_class).err(),
        Some(PictureError::Malformed)
    );

    let mut bad_scan_count = NOISE_JPEG.to_vec();
    bad_scan_count[613] = 0;
    assert_eq!(
        frame::parse(&bad_scan_count).err(),
        Some(PictureError::NotBaseline)
    );

    let mut bad_spectral_end = NOISE_JPEG.to_vec();
    bad_spectral_end[621] = 62;
    assert_eq!(
        frame::parse(&bad_spectral_end).err(),
        Some(PictureError::NotBaseline)
    );

    let mut unknown_component = NOISE_JPEG.to_vec();
    unknown_component[614] = 0xfe;
    assert_eq!(
        frame::parse(&unknown_component).err(),
        Some(PictureError::Malformed)
    );

    let mut invalid_table_index = NOISE_JPEG.to_vec();
    invalid_table_index[615] = 0x44;
    assert_eq!(
        frame::parse(&invalid_table_index).err(),
        Some(PictureError::Malformed)
    );

    let mut missing_table = NOISE_JPEG.to_vec();
    missing_table[615] = 0x33;
    assert_eq!(
        frame::parse(&missing_table).err(),
        Some(PictureError::Malformed)
    );
}

#[test]
fn huffman_bit_io_and_permutation_cover_canonical_boundaries() {
    let mut table = huffman::HuffmanTable::empty();
    let mut counts = [0u8; 16];
    counts[0] = 2;
    table.rebuild(&counts, &[0x11, 0x22]).expect("simple table");
    assert_eq!(table.encoded(0x11), Ok((0, 1)));
    assert_eq!(table.encoded(0x22), Ok((1, 1)));
    assert_eq!(table.encoded(0x33), Err(PictureError::Unencodable));

    let mut mismatch = huffman::HuffmanTable::empty();
    let mut one = [0u8; 16];
    one[0] = 2;
    assert_eq!(mismatch.rebuild(&one, &[1]), Err(PictureError::Malformed));
    assert_eq!(
        mismatch.rebuild(&[0; 16], &std::vec![0u8; 257]),
        Err(PictureError::Malformed)
    );

    let mut zero_reader = huffman::BitReader::new(&[0x00]);
    assert_eq!(zero_reader.decode(&table), Ok(0x11));
    let mut one_reader = huffman::BitReader::new(&[0x80]);
    assert_eq!(one_reader.decode(&table), Ok(0x22));
    let empty = huffman::HuffmanTable::empty();
    assert_eq!(
        huffman::BitReader::new(&[]).decode(&empty),
        Err(PictureError::Malformed)
    );

    let mut stuffed = huffman::BitReader::new(&[0xff, 0x00, 0x80]);
    assert_eq!(stuffed.bits(8), 0xff);
    assert_eq!(stuffed.bits(1), 1);
    let mut restart = huffman::BitReader::new(&[0x12, 0xff, 0xd3, 0x80]);
    restart.resync();
    assert_eq!(restart.bits(1), 1);
    let mut no_restart = huffman::BitReader::new(&[1, 2, 3]);
    no_restart.resync();
    assert_eq!(no_restart.bits(1), 0);

    let mut buffer = [0u8; 4];
    let overflowed = {
        let mut writer = huffman::BitWriter::new(&mut buffer);
        writer.bits(0xff, 8);
        writer.code(&table, 0x11).expect("encodable symbol");
        writer.flush();
        writer.overflowed
    };
    assert_eq!(&buffer[..2], &[0xff, 0x00]);
    assert!(!overflowed);
    let mut empty_output = [];
    let mut overflow = huffman::BitWriter::new(&mut empty_output);
    overflow.put(1);
    assert!(overflow.overflowed);

    assert_eq!(huffman::magnitude_category(0), 0);
    assert_eq!(huffman::magnitude_category(-7), 3);
    assert_eq!(huffman::extend(0, 0), 0);
    assert_eq!(huffman::extend(0, 3), -7);
    assert_eq!(huffman::extend(7, 3), 7);
    assert_eq!(huffman::magnitude_bits(5, 3), 5);
    assert_eq!(huffman::magnitude_bits(-5, 3), 2);

    assert!(PositionPermutation::new(0, KEY).is_none());
    assert!(PositionPermutation::new(1, KEY).is_none());
    let permutation = PositionPermutation::new(17, KEY).expect("permutation");
    let mut seen = [false; 17];
    for position in 0..17u32 {
        let rank = permutation.rank(position);
        assert!(rank < 17);
        assert!(!seen[rank as usize]);
        seen[rank as usize] = true;
    }
}

#[test]
fn codec_block_helpers_cover_dc_ac_zero_run_and_encoding_boundaries() {
    fn table(symbols: &[u8], length: usize) -> huffman::HuffmanTable {
        let mut counts = [0u8; 16];
        counts[length - 1] = symbols.len() as u8;
        let mut table = huffman::HuffmanTable::empty();
        table.rebuild(&counts, symbols).expect("test huffman table");
        table
    }

    let dc_zero = table(&[0], 1);
    let ac_eob = table(&[0x00], 1);
    let mut coefficients = [99i16; 64];
    let mut reader = huffman::BitReader::new(&[0]);
    codec::decode_block(&mut reader, &dc_zero, &ac_eob, &mut coefficients).expect("zero block");
    assert_eq!(coefficients, [0; 64]);

    let dc_too_wide = table(&[16], 1);
    let mut reader = huffman::BitReader::new(&[0]);
    assert_eq!(
        codec::decode_block(&mut reader, &dc_too_wide, &ac_eob, &mut coefficients),
        Err(PictureError::Malformed),
    );

    let ac_zrl = table(&[0xF0], 1);
    let mut reader = huffman::BitReader::new(&[0]);
    assert_eq!(
        codec::decode_block(&mut reader, &dc_zero, &ac_zrl, &mut coefficients),
        Err(PictureError::Malformed),
    );

    let ac_run_value = table(&[0xF1], 1);
    let mut reader = huffman::BitReader::new(&[0]);
    assert_eq!(
        codec::decode_block(&mut reader, &dc_zero, &ac_run_value, &mut coefficients),
        Err(PictureError::Malformed),
    );

    let dc_encode = table(&[0, 1], 2);
    let ac_encode = table(&[0x00, 0xF0, 0x11], 2);
    let mut block = [0i16; 64];
    block[0] = 1;
    block[34] = 1;
    let mut bytes = [0u8; 32];
    let mut writer = huffman::BitWriter::new(&mut bytes);
    codec::encode_block(&mut writer, &dc_encode, &ac_encode, &block).expect("encoded block");
    writer.flush();
    assert!(!writer.overflowed);
    assert!(writer.position > 0);

    let mut zero_bytes = [0u8; 8];
    let mut zero_writer = huffman::BitWriter::new(&mut zero_bytes);
    codec::encode_block(&mut zero_writer, &dc_encode, &ac_encode, &[0; 64])
        .expect("zero block encoding");
    zero_writer.flush();
    assert!(zero_writer.position > 0);
}

#[test]
fn frame_parser_covers_marker_skips_restart_interval_and_scan_shape_boundaries() {
    let mut with_padding = NOISE_JPEG.to_vec();
    with_padding.insert(2, 0x42);
    assert!(frame::parse(&with_padding).is_ok());

    let mut with_restart_marker = NOISE_JPEG.to_vec();
    with_restart_marker.splice(2..2, [0xFF, 0xD0]);
    assert!(frame::parse(&with_restart_marker).is_ok());

    assert_eq!(
        frame::parse(&[0xFF, 0xD8, 0xFF, 0xD9]).err(),
        Some(PictureError::Malformed)
    );

    let sos = NOISE_JPEG
        .windows(2)
        .position(|window| window == [0xFF, 0xDA])
        .expect("SOS marker");
    let mut with_dri = NOISE_JPEG.to_vec();
    with_dri.splice(sos..sos, [0xFF, 0xDD, 0x00, 0x04, 0x00, 0x01]);
    let parsed = frame::parse(&with_dri).expect("DRI frame");
    assert_eq!(parsed.restart_interval, 1);

    let mut empty_scan = NOISE_JPEG.to_vec();
    empty_scan[sos + 2..sos + 4].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        frame::parse(&empty_scan).err(),
        Some(PictureError::Malformed)
    );

    let mut too_many_components = NOISE_JPEG.to_vec();
    too_many_components[sos + 4] = 5;
    assert_eq!(
        frame::parse(&too_many_components).err(),
        Some(PictureError::NotBaseline)
    );

    let mut mismatched_components = NOISE_JPEG.to_vec();
    mismatched_components[sos + 4] = 2;
    assert_eq!(
        frame::parse(&mismatched_components).err(),
        Some(PictureError::NotBaseline)
    );

    let mut spectral_start = NOISE_JPEG.to_vec();
    spectral_start[sos + 4 + 1 + 3 * 2] = 1;
    assert_eq!(
        frame::parse(&spectral_start).err(),
        Some(PictureError::NotBaseline)
    );

    let mut approximation = NOISE_JPEG.to_vec();
    approximation[sos + 4 + 1 + 3 * 2 + 2] = 1;
    assert_eq!(
        frame::parse(&approximation).err(),
        Some(PictureError::NotBaseline)
    );
}

#[test]
fn huffman_segment_parser_and_rebuild_cover_multi_table_and_trailing_boundaries() {
    fn tables() -> (
        std::vec::Vec<huffman::HuffmanTable>,
        std::vec::Vec<huffman::HuffmanTable>,
    ) {
        (
            (0..4).map(|_| huffman::HuffmanTable::empty()).collect(),
            (0..4).map(|_| huffman::HuffmanTable::empty()).collect(),
        )
    }

    let mut one = std::vec![0u8; 18];
    one[0] = 0x00;
    one[1] = 1;
    one[17] = 0x2A;
    let (mut dc, mut ac) = tables();
    frame::parse_huffman_tables(&one, &mut dc, &mut ac).expect("one DHT");
    assert!(dc[0].present);
    assert_eq!(dc[0].encoded(0x2A), Ok((0, 1)));

    let mut two = one.clone();
    let mut second = one.clone();
    second[0] = 0x10;
    second[17] = 0x33;
    two.extend_from_slice(&second);
    let (mut dc, mut ac) = tables();
    frame::parse_huffman_tables(&two, &mut dc, &mut ac).expect("two DHTs");
    assert!(dc[0].present && ac[0].present);

    let mut trailing = one.clone();
    trailing.push(0);
    let (mut dc, mut ac) = tables();
    assert_eq!(
        frame::parse_huffman_tables(&trailing, &mut dc, &mut ac),
        Err(PictureError::Malformed),
    );

    let mut truncated_values = one.clone();
    truncated_values[1] = 2;
    let (mut dc, mut ac) = tables();
    assert_eq!(
        frame::parse_huffman_tables(&truncated_values, &mut dc, &mut ac),
        Err(PictureError::Malformed),
    );

    let mut bad_class = one.clone();
    bad_class[0] = 0x20;
    let (mut dc, mut ac) = tables();
    assert_eq!(
        frame::parse_huffman_tables(&bad_class, &mut dc, &mut ac),
        Err(PictureError::Malformed),
    );

    let mut bad_index = one.clone();
    bad_index[0] = 0x04;
    let (mut dc, mut ac) = tables();
    assert_eq!(
        frame::parse_huffman_tables(&bad_index, &mut dc, &mut ac),
        Err(PictureError::Malformed),
    );

    let mut empty = huffman::HuffmanTable::empty();
    empty.rebuild(&[0; 16], &[]).expect("empty canonical table");
    assert!(empty.present);
    let mut leftover = huffman::HuffmanTable::empty();
    assert_eq!(
        leftover.rebuild(&[0; 16], &[1]),
        Err(PictureError::Malformed)
    );

    let mut multi_length = huffman::HuffmanTable::empty();
    let mut counts = [0u8; 16];
    counts[0] = 1;
    counts[1] = 2;
    multi_length
        .rebuild(&counts, &[1, 2, 3])
        .expect("multi-length table");
    assert_eq!(multi_length.encoded(1), Ok((0, 1)));
    assert_eq!(multi_length.encoded(2), Ok((2, 2)));
    assert_eq!(multi_length.encoded(3), Ok((3, 2)));
}
