use crate::wire::multisig_descriptor::{
    parse_multisig_descriptor, MultisigDescriptorError, MultisigDescriptorKind,
    MAX_DESCRIPTOR_PARTICIPANTS,
};

fn hd44_participant(prefix: u8, fill: u8) -> String {
    let mut raw = [fill; 65];
    raw[0] = prefix;
    hex::encode(raw)
}

#[test]
fn canonical_multisig_parser_covers_static_and_hd44_without_heap_owned_grammar() {
    let static_a = "11".repeat(32);
    let static_b = "22".repeat(32);
    let parsed = parse_multisig_descriptor(format!("multi(1,{static_a},{static_b})").as_bytes())
        .expect("static descriptor");
    assert_eq!(parsed.kind, MultisigDescriptorKind::Static);
    assert_eq!(parsed.participant_count, 2);

    let first = hd44_participant(0x02, 0x31);
    let second = hd44_participant(0x03, 0x52);
    let parsed = parse_multisig_descriptor(
        format!("# exported descriptor\n  multi_hd(2,{first},{second})\r\n").as_bytes(),
    )
    .expect("HD44 descriptor");
    assert_eq!(parsed.kind, MultisigDescriptorKind::Hd44);
    assert_eq!(parsed.threshold, 2);
    assert_eq!(parsed.public_keys[0][0], 0x02);
    assert_eq!(parsed.public_keys[1][0], 0x03);
}

#[test]
fn canonical_multisig_parser_enforces_bounds_thresholds_and_duplicates() {
    let first = hd44_participant(0x02, 0x31);
    let second = hd44_participant(0x03, 0x52);
    assert_eq!(
        parse_multisig_descriptor(format!("multi_hd(0,{first},{second})").as_bytes()),
        Err(MultisigDescriptorError::InvalidThreshold),
    );
    assert_eq!(
        parse_multisig_descriptor(format!("multi_hd(1,{first},{first})").as_bytes()),
        Err(MultisigDescriptorError::DuplicateParticipant),
    );

    let entries = (0..=MAX_DESCRIPTOR_PARTICIPANTS)
        .map(|index| {
            hd44_participant(
                if index.is_multiple_of(2) { 0x02 } else { 0x03 },
                index as u8 + 1,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        parse_multisig_descriptor(format!("multi_hd(1,{entries})").as_bytes()),
        Err(MultisigDescriptorError::TooManyParticipants),
    );
}

#[test]
fn canonical_hd45_order_is_identical_for_unsorted_and_sorted_kpub_text() {
    const FIRST: &str = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    const SECOND: &str = "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz";
    let unsorted = format!("multi_hd45(1,{SECOND},{FIRST})");
    let sorted = format!("multi_hd45(1,{FIRST},{SECOND})");
    let left = parse_multisig_descriptor(unsorted.as_bytes()).expect("unsorted HD45");
    let right = parse_multisig_descriptor(sorted.as_bytes()).expect("sorted HD45");
    assert_eq!(left.kind, MultisigDescriptorKind::Hd45);
    assert_eq!(left, right);
}

#[test]
fn multisig_descriptor_error_messages_cover_every_stable_variant_without_branching() {
    let errors = [
        MultisigDescriptorError::UnsupportedFormat,
        MultisigDescriptorError::InvalidThreshold,
        MultisigDescriptorError::TooFewParticipants,
        MultisigDescriptorError::TooManyParticipants,
        MultisigDescriptorError::InvalidParticipantLength,
        MultisigDescriptorError::InvalidHex,
        MultisigDescriptorError::InvalidCompressedPublicKey,
        MultisigDescriptorError::InvalidLegacyKpub,
        MultisigDescriptorError::InvalidLegacyDepth,
        MultisigDescriptorError::DuplicateParticipant,
    ];
    for error in errors {
        assert!(!error.message().is_empty());
    }
    assert_eq!(errors.len(), 10);
}

#[test]
fn canonical_multisig_parser_covers_static_format_length_hex_and_threshold_failures() {
    let key = "11".repeat(32);
    assert_eq!(
        parse_multisig_descriptor(b"not-a-descriptor"),
        Err(MultisigDescriptorError::UnsupportedFormat),
    );
    assert_eq!(
        parse_multisig_descriptor(format!("multi(1,{})", "11".repeat(31)).as_bytes()),
        Err(MultisigDescriptorError::InvalidParticipantLength),
    );
    let invalid_hex_key = format!("{}2z", "22".repeat(31));
    assert_eq!(
        parse_multisig_descriptor(format!("multi(1,{key},{invalid_hex_key})").as_bytes()),
        Err(MultisigDescriptorError::InvalidHex),
    );
    assert_eq!(
        parse_multisig_descriptor(format!("multi(3,{key},{})", "22".repeat(32)).as_bytes()),
        Err(MultisigDescriptorError::InvalidThreshold),
    );
}
