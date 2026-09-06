use super::*;

fn blank(kind: MultisigDescriptorKind) -> ParsedMultisigDescriptor {
    ParsedMultisigDescriptor {
        threshold: 1,
        participant_count: 0,
        kind,
        v45: matches!(kind, MultisigDescriptorKind::Hd45),
        static_public_keys: [[0; 32]; MAX_DESCRIPTOR_PARTICIPANTS],
        public_keys: [[0; 33]; MAX_DESCRIPTOR_PARTICIPANTS],
        chain_codes: [[0; 32]; MAX_DESCRIPTOR_PARTICIPANTS],
        depths: [0; MAX_DESCRIPTOR_PARTICIPANTS],
        parent_fingerprints: [[0; 4]; MAX_DESCRIPTOR_PARTICIPANTS],
        child_numbers: [[0; 4]; MAX_DESCRIPTOR_PARTICIPANTS],
    }
}

#[test]
fn kind_predicates_distinguish_all_three_descriptor_kinds() {
    let static_descriptor = blank(MultisigDescriptorKind::Static);
    let hd44 = blank(MultisigDescriptorKind::Hd44);
    let hd45 = blank(MultisigDescriptorKind::Hd45);
    assert!(!static_descriptor.is_hd());
    assert!(!static_descriptor.is_hd45());
    assert!(hd44.is_hd());
    assert!(!hd44.is_hd45());
    assert!(hd45.is_hd());
    assert!(hd45.is_hd45());
}

#[test]
fn threshold_grammar_checks_each_boundary_independently() {
    assert_eq!(
        split_threshold(b",aa"),
        Err(MultisigDescriptorError::InvalidThreshold)
    );
    assert_eq!(
        split_threshold(b"1234,aa"),
        Err(MultisigDescriptorError::InvalidThreshold)
    );
    assert_eq!(
        split_threshold(b"x,aa"),
        Err(MultisigDescriptorError::InvalidThreshold)
    );
    let (threshold, tail) = split_threshold(b"123,aa").expect("three-digit threshold");
    assert_eq!(threshold, 123);
    assert_eq!(tail, b"aa");
}

#[test]
fn trimming_and_hex_decoding_make_progress_and_preserve_exact_bytes() {
    assert_eq!(trim_trailing_ascii_whitespace(b"abc \t\r\n"), b"abc");
    let mut decoded = [0u8; 3];
    decode_hex_bytes(b"0fab10", &mut decoded).expect("hex");
    assert_eq!(decoded, [0x0f, 0xab, 0x10]);
}

#[test]
fn hd45_sort_moves_parallel_metadata_and_handles_equal_neighbors() {
    let mut parsed = blank(MultisigDescriptorKind::Hd45);
    parsed.participant_count = 3;
    parsed.public_keys[0][1] = 30;
    parsed.public_keys[1][1] = 20;
    parsed.public_keys[2][1] = 10;
    parsed.chain_codes[0][0] = 3;
    parsed.chain_codes[1][0] = 2;
    parsed.chain_codes[2][0] = 1;
    parsed.depths[0] = 30;
    parsed.depths[1] = 20;
    parsed.depths[2] = 10;
    parsed.parent_fingerprints[0][0] = 3;
    parsed.parent_fingerprints[1][0] = 2;
    parsed.parent_fingerprints[2][0] = 1;
    parsed.child_numbers[0][0] = 3;
    parsed.child_numbers[1][0] = 2;
    parsed.child_numbers[2][0] = 1;
    let mut encoded = [[0u8; HD45_KPUB_LEN]; MAX_DESCRIPTOR_PARTICIPANTS];
    encoded[0][0] = 3;
    encoded[1][0] = 2;
    encoded[2][0] = 1;
    sort_hd45_by_encoded(&mut parsed, &mut encoded);
    assert_eq!([encoded[0][0], encoded[1][0], encoded[2][0]], [1, 2, 3]);
    assert_eq!(
        [
            parsed.public_keys[0][1],
            parsed.public_keys[1][1],
            parsed.public_keys[2][1]
        ],
        [10, 20, 30]
    );
    assert_eq!(
        [
            parsed.chain_codes[0][0],
            parsed.chain_codes[1][0],
            parsed.chain_codes[2][0]
        ],
        [1, 2, 3]
    );
    assert_eq!(
        [parsed.depths[0], parsed.depths[1], parsed.depths[2]],
        [10, 20, 30]
    );
    assert_eq!(
        [
            parsed.parent_fingerprints[0][0],
            parsed.parent_fingerprints[1][0],
            parsed.parent_fingerprints[2][0],
        ],
        [1, 2, 3],
    );
    assert_eq!(
        [
            parsed.child_numbers[0][0],
            parsed.child_numbers[1][0],
            parsed.child_numbers[2][0],
        ],
        [1, 2, 3],
    );

    encoded[0] = [7; HD45_KPUB_LEN];
    encoded[1] = [7; HD45_KPUB_LEN];
    parsed.participant_count = 2;
    parsed.public_keys[0][1] = 10;
    parsed.public_keys[1][1] = 20;
    sort_hd45_by_encoded(&mut parsed, &mut encoded);
    assert_eq!(encoded[0], encoded[1]);
    assert_eq!(
        [parsed.public_keys[0][1], parsed.public_keys[1][1]],
        [10, 20],
        "equal encoded participants must keep canonical stable order",
    );
}

#[test]
fn duplicate_hd_requires_both_pubkey_and_chain_code_to_match() {
    let mut parsed = blank(MultisigDescriptorKind::Hd44);
    parsed.participant_count = 2;
    parsed.public_keys[0][0] = 2;
    parsed.public_keys[1][0] = 2;
    parsed.chain_codes[0][0] = 1;
    parsed.chain_codes[1][0] = 2;
    assert_eq!(reject_duplicate_hd(&parsed), Ok(()));

    parsed.public_keys[1][0] = 3;
    parsed.chain_codes[1][0] = 1;
    assert_eq!(reject_duplicate_hd(&parsed), Ok(()));

    parsed.public_keys[1] = parsed.public_keys[0];
    parsed.chain_codes[1] = parsed.chain_codes[0];
    assert_eq!(
        reject_duplicate_hd(&parsed),
        Err(MultisigDescriptorError::DuplicateParticipant)
    );
}
