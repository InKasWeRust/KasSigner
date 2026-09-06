use crate::update::attestation::{
    advance_segment, appended_hash_offset, attestation_words, parse_image_header,
    parse_signature_digest, secure_boot_signature_offset, segment_data_len, signed_image_end,
    ImageLayoutError, ESP_IMAGE_HEADER_SIZE, ESP_SEGMENT_HEADER_SIZE,
};

#[test]
fn image_layout_tracks_checksum_hash_and_secure_boot_boundaries() {
    let mut image = [0u8; ESP_IMAGE_HEADER_SIZE];
    image[0] = 0xE9;
    image[1] = 3;
    image[23] = 1;
    let parsed = parse_image_header(&image).unwrap();
    assert_eq!(parsed.segment_count, 3);
    assert!(parsed.hash_appended);

    let mut segment = [0u8; ESP_SEGMENT_HEADER_SIZE];
    segment[4..8].copy_from_slice(&1234u32.to_le_bytes());
    assert_eq!(segment_data_len(&segment), Ok(1234));
    let segment_end = advance_segment(24, 1234).unwrap();
    let hash_offset = appended_hash_offset(segment_end).unwrap();
    assert_eq!(hash_offset % 16, 0);
    let image_end = signed_image_end(hash_offset).unwrap();
    let signature_offset = secure_boot_signature_offset(image_end).unwrap();
    assert_eq!(signature_offset % (64 * 1024), 0);
    assert!(signature_offset >= image_end);
}

#[test]
fn image_layout_rejects_unhashed_or_malformed_images() {
    let mut image = [0u8; ESP_IMAGE_HEADER_SIZE];
    image[0] = 0xE9;
    image[1] = 1;
    assert_eq!(
        parse_image_header(&image),
        Err(ImageLayoutError::MissingImageHash)
    );
    image[23] = 1;
    image[0] = 0;
    assert_eq!(
        parse_image_header(&image),
        Err(ImageLayoutError::InvalidHeader)
    );

    let mut segment = [0u8; ESP_SEGMENT_HEADER_SIZE];
    segment[4..8].copy_from_slice(&(9 * 1024 * 1024u32).to_le_bytes());
    assert_eq!(
        segment_data_len(&segment),
        Err(ImageLayoutError::InvalidSegment)
    );
}

#[test]
fn signature_prefix_extracts_the_secure_boot_image_digest() {
    let mut prefix = [0u8; 36];
    prefix[0] = 0xE7;
    prefix[1] = 0x02;
    for (index, byte) in prefix[4..36].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let digest = parse_signature_digest(&prefix).unwrap();
    assert_eq!(digest[0], 0);
    assert_eq!(digest[31], 31);
    prefix[1] = 0x01;
    assert_eq!(
        parse_signature_digest(&prefix),
        Err(ImageLayoutError::InvalidSignatureBlock)
    );
}

#[test]
fn attestation_phrase_is_deterministic_and_uses_twenty_four_hash_bits() {
    let mut hash = [0u8; 32];
    hash[..3].copy_from_slice(&[0b0000_0011, 0b1111_0000, 0b1010_1000]);
    let words = attestation_words(&hash);
    assert_eq!(words, ["amber", "zinc", "apple", "opal"]);
    assert_eq!(attestation_words(&hash), words);
}

#[test]
fn image_header_rejects_each_segment_count_boundary_with_valid_magic() {
    for segment_count in [0u8, 17u8] {
        let mut image = [0u8; ESP_IMAGE_HEADER_SIZE];
        image[0] = 0xE9;
        image[1] = segment_count;
        image[23] = 1;
        assert_eq!(
            parse_image_header(&image),
            Err(ImageLayoutError::InvalidHeader)
        );
    }
}

#[test]
fn image_layout_overflow_guards_fail_closed_independently() {
    assert_eq!(
        advance_segment(u32::MAX, 0),
        Err(ImageLayoutError::Overflow)
    );
    assert_eq!(
        advance_segment(u32::MAX - 8, 1),
        Err(ImageLayoutError::Overflow)
    );
    assert_eq!(
        appended_hash_offset(u32::MAX),
        Err(ImageLayoutError::Overflow)
    );
    assert_eq!(signed_image_end(u32::MAX), Err(ImageLayoutError::Overflow));
    assert_eq!(
        secure_boot_signature_offset(u32::MAX),
        Err(ImageLayoutError::Overflow)
    );
}

#[test]
fn signature_prefix_rejects_each_header_field_independently() {
    let valid = || {
        let mut prefix = [0u8; 36];
        prefix[0] = 0xE7;
        prefix[1] = 0x02;
        prefix
    };
    for (index, value) in [(0usize, 0u8), (1, 1), (2, 1), (3, 1)] {
        let mut prefix = valid();
        prefix[index] = value;
        assert_eq!(
            parse_signature_digest(&prefix),
            Err(ImageLayoutError::InvalidSignatureBlock)
        );
    }
}
