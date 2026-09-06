use alloc::{vec, vec::Vec};

use shared_signer::{PsktParsed, PsktUnknownScope, TxInputFormat, MAX_PSKT_UNKNOWN_REGIONS};

use crate::transaction::model::Transaction;

use super::super::{serialize_pskt, PskError, PSKT_MAGIC};
use super::common::{
    contains_subslice, count_subslice, parse_json, serialize_json, transaction_json,
};

#[test]
fn captured_unknown_ranges_enforce_every_json_boundary() {
    use super::super::preservation::capture_unknown;

    let scope = PsktUnknownScope::global();
    let mut parsed = PsktParsed::empty();
    parsed.json_start = 10;
    parsed.json_len = 20;

    capture_unknown(&mut parsed, scope, 10, 30).expect("inclusive JSON boundaries");
    assert_eq!(parsed.unknowns_count, 1);
    assert_eq!(parsed.unknowns[0], (10, 30));
    assert_eq!(parsed.unknown_scopes[0], scope);

    for (start, end) in [(9usize, 10usize), (20, 19), (10, 31), (65_536, 65_536)] {
        let mut invalid = PsktParsed::empty();
        invalid.json_start = 10;
        invalid.json_len = if end > u16::MAX as usize {
            u16::MAX
        } else {
            20
        };
        assert_eq!(
            capture_unknown(&mut invalid, scope, start, end),
            Err(PskError::JsonTooLarge),
            "range {start}..{end}",
        );
    }

    let mut full = PsktParsed::empty();
    full.json_len = 1;
    full.unknowns_count = MAX_PSKT_UNKNOWN_REGIONS as u8;
    assert_eq!(
        capture_unknown(&mut full, scope, 0, 1),
        Err(PskError::TooManyUnknownRegions),
    );
}

#[test]
fn preservation_is_scoped_and_tolerates_whitespace_around_colons() {
    let json = transaction_json(
        ",\"proprietaries\" : {\"g\":1}",
        ",\"proprietaries\" : {\"i\":2}",
        ",\"proprietaries\" : {\"o\":3}",
    );
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse");
    let emitted =
        serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktPskb).expect("serialize");
    assert_eq!(count_subslice(&emitted, b"{\"g\":1}"), 1);
    assert_eq!(count_subslice(&emitted, b"{\"i\":2}"), 1);
    assert_eq!(count_subslice(&emitted, b"{\"o\":3}"), 1);
}

#[test]
fn metadata_and_output_redeem_script_are_preserved() {
    let mut json = transaction_json("", "", ",\"redeemScript\":\"aa\"");
    let needle = b"\"scriptPublicKey\":\"0000\"";
    let position = json
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("input script public key");
    let insert_at = position + needle.len();
    json.splice(
        insert_at..insert_at,
        b",\"blockDaaScore\":42,\"isCoinbase\":true".iter().copied(),
    );

    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse");
    let emitted =
        serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktPskb).expect("serialize");
    assert!(contains_subslice(&emitted, b"\"blockDaaScore\":\"42\""));
    assert!(contains_subslice(&emitted, b"\"isCoinbase\":true"));
    assert!(contains_subslice(&emitted, b"\"redeemScript\":\"aa\""));
}

#[test]
fn invalid_external_preservation_metadata_is_not_silently_dropped() {
    let mut parsed = PsktParsed::empty();
    parsed.unknowns_count = 1;
    parsed.unknowns[0] = (0, 10);
    parsed.unknown_scopes[0] = PsktUnknownScope::global();
    parsed.json_len = 2;

    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 1;
    let mut output = vec![0u8; 4096];
    assert_eq!(
        serialize_pskt(&tx, &parsed, b"{}", TxInputFormat::PsktSingle, &mut output,),
        Err(PskError::UnexpectedToken)
    );
}

#[test]
fn preservation_metadata_rejects_a_field_start_before_the_declared_json_window() {
    use super::super::preservation::validate_preservation_metadata;

    let scratch = b"X\"x\":1Z";
    let mut parsed = PsktParsed::empty();
    parsed.json_start = 2;
    parsed.json_len = 4;
    parsed.unknowns_count = 1;
    parsed.unknowns[0] = (1, 6);
    parsed.unknown_scopes[0] = PsktUnknownScope::global();

    assert_eq!(
        validate_preservation_metadata(&parsed, scratch, 1, 1),
        Err(PskError::UnexpectedToken),
    );
}

#[test]
fn preservation_metadata_count_and_scope_are_validated_before_writing() {
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 1;
    let mut output = vec![0u8; 4096];

    let mut excessive = PsktParsed::empty();
    excessive.unknowns_count = (MAX_PSKT_UNKNOWN_REGIONS + 1) as u8;
    assert_eq!(
        serialize_pskt(&tx, &excessive, b"", TxInputFormat::PsktSingle, &mut output,),
        Err(PskError::TooManyUnknownRegions)
    );

    let mut invalid_scope = PsktParsed::empty();
    invalid_scope.unknowns_count = 1;
    invalid_scope.unknowns[0] = (0, 5);
    invalid_scope.unknown_scopes[0] = PsktUnknownScope::input(0);
    invalid_scope.json_len = 5;
    assert_eq!(
        serialize_pskt(
            &tx,
            &invalid_scope,
            b"\"x\":1",
            TxInputFormat::PsktSingle,
            &mut output,
        ),
        Err(PskError::UnexpectedToken)
    );
}

#[test]
fn preservation_scope_rejects_output_index_equal_to_output_count() {
    use super::super::preservation::validate_preservation_metadata;

    let scratch = b"\"x\":1";
    let mut parsed = PsktParsed::empty();
    parsed.json_len = scratch.len() as u16;
    parsed.unknowns_count = 1;
    parsed.unknowns[0] = (0, scratch.len() as u16);
    parsed.unknown_scopes[0] = PsktUnknownScope::output(1);

    assert_eq!(
        validate_preservation_metadata(&parsed, scratch, 1, 1),
        Err(PskError::UnexpectedToken),
    );
}

#[test]
fn duplicate_preserved_names_in_one_scope_are_rejected() {
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 1;
    let scratch = b"\"x\":1,\"x\":2";
    let mut parsed = PsktParsed::empty();
    parsed.unknowns_count = 2;
    parsed.unknowns[0] = (0, 5);
    parsed.unknowns[1] = (6, 11);
    parsed.unknown_scopes[0] = PsktUnknownScope::global();
    parsed.unknown_scopes[1] = PsktUnknownScope::global();
    parsed.json_len = scratch.len() as u16;

    let mut output = vec![0u8; 4096];
    assert_eq!(
        serialize_pskt(
            &tx,
            &parsed,
            scratch,
            TxInputFormat::PsktSingle,
            &mut output,
        ),
        Err(PskError::DuplicateField)
    );
}

#[test]
fn preservation_range_accepts_u16_end_boundary_and_rejects_empty_regions() {
    use super::super::preservation::capture_unknown;

    let mut parsed = PsktParsed::empty();
    parsed.json_len = u16::MAX;
    capture_unknown(
        &mut parsed,
        PsktUnknownScope::global(),
        0,
        u16::MAX as usize,
    )
    .expect("u16::MAX end offset is representable");
    assert_eq!(parsed.unknowns_count, 1);
    assert_eq!(parsed.unknowns[0], (0, u16::MAX));

    let mut empty = PsktParsed::empty();
    empty.json_len = 16;
    assert_eq!(
        capture_unknown(&mut empty, PsktUnknownScope::global(), 7, 7),
        Err(PskError::JsonTooLarge),
    );
    assert_eq!(empty.unknowns_count, 0);
}

#[test]
fn preservation_accepts_exact_region_capacity_and_rejects_exact_scope_boundary() {
    use super::super::preservation::{capture_unknown, validate_preservation_metadata};

    let mut scratch = Vec::new();
    let mut ranges = Vec::new();
    for index in 0..MAX_PSKT_UNKNOWN_REGIONS {
        let start = scratch.len();
        scratch.extend_from_slice(b"\"");
        scratch.push(b'a' + index as u8);
        scratch.extend_from_slice(b"\":1");
        let end = scratch.len();
        ranges.push((start, end));
        if index + 1 != MAX_PSKT_UNKNOWN_REGIONS {
            scratch.push(b',');
        }
    }

    let mut parsed = PsktParsed::empty();
    parsed.json_len = scratch.len() as u16;
    for (start, end) in ranges {
        capture_unknown(&mut parsed, PsktUnknownScope::global(), start, end)
            .expect("exact preservation capacity");
    }
    assert_eq!(parsed.unknowns_count as usize, MAX_PSKT_UNKNOWN_REGIONS);
    assert_eq!(
        validate_preservation_metadata(&parsed, &scratch, 1, 1),
        Ok(())
    );

    let mut invalid_scope = PsktParsed::empty();
    invalid_scope.json_len = 5;
    invalid_scope.unknowns_count = 1;
    invalid_scope.unknowns[0] = (0, 5);
    invalid_scope.unknown_scopes[0] = PsktUnknownScope::input(1);
    assert_eq!(
        validate_preservation_metadata(&invalid_scope, b"\"x\":1", 1, 1),
        Err(PskError::UnexpectedToken),
    );
}

#[test]
fn captured_field_rejects_each_independent_range_violation() {
    use super::super::preservation::captured_field_at;

    fn parsed(start: u16, end: u16, json_start: u16, json_len: u16) -> PsktParsed {
        let mut parsed = PsktParsed::empty();
        parsed.unknowns_count = 1;
        parsed.unknowns[0] = (start, end);
        parsed.unknown_scopes[0] = PsktUnknownScope::global();
        parsed.json_start = json_start;
        parsed.json_len = json_len;
        parsed
    }

    let scratch = b"..\"x\":1..";
    assert!(matches!(
        captured_field_at(&parsed(1, 7, 2, 5), scratch, 0),
        Err(PskError::UnexpectedToken)
    ));
    assert!(matches!(
        captured_field_at(&parsed(2, 2, 2, 5), scratch, 0),
        Err(PskError::UnexpectedToken)
    ));
    assert!(matches!(
        captured_field_at(&parsed(2, 8, 2, 5), scratch, 0),
        Err(PskError::UnexpectedToken)
    ));
    assert!(matches!(
        captured_field_at(&parsed(2, 7, 2, 20), scratch, 0),
        Err(PskError::UnexpectedToken)
    ));
}
