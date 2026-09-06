use super::{extract_cltv_locktime, extract_csv_sequence, push_data, push_int};

#[test]
fn locktime_extractors_share_the_same_integer_parser() {
    let mut cltv = Vec::new();
    push_int(&mut cltv, 500);
    cltv.push(0xb0);
    assert_eq!(extract_cltv_locktime(&cltv).expect("parse"), Some(500));

    let mut csv = Vec::new();
    push_int(&mut csv, 42);
    csv.push(0xb1);
    assert_eq!(extract_csv_sequence(&csv).expect("parse"), Some(42));
}

#[test]
fn push_data_uses_checked_length_prefixes() {
    let mut script = Vec::new();
    push_data(&mut script, &[7; 76]);
    assert_eq!(&script[..2], &[0x4c, 76]);
}

#[test]
fn push_data_covers_exact_prefix_boundaries() {
    let mut direct = Vec::new();
    push_data(&mut direct, &[0x11; 75]);
    assert_eq!(direct[0], 75);
    assert_eq!(direct.len(), 76);

    let mut pushdata1 = Vec::new();
    push_data(&mut pushdata1, &[0x22; 255]);
    assert_eq!(&pushdata1[..2], &[0x4c, 0xff]);

    let mut pushdata2 = Vec::new();
    push_data(&mut pushdata2, &[0x33; 256]);
    assert_eq!(&pushdata2[..3], &[0x4d, 0x00, 0x01]);

    let pushdata4_payload = vec![0x44; 65_536];
    let mut pushdata4 = Vec::new();
    push_data(&mut pushdata4, &pushdata4_payload);
    assert_eq!(&pushdata4[..5], &[0x4e, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(&pushdata4[5..], pushdata4_payload.as_slice());
}

#[test]
fn locktime_parser_rejects_oversized_script_integers() {
    let mut script = vec![9u8];
    script.extend_from_slice(&[1u8; 9]);
    script.push(0xb0);
    assert!(extract_cltv_locktime(&script).is_err());
}

#[test]
fn locktime_parser_supports_pushdata4_lengths() {
    let mut script = vec![0x4e];
    script.extend_from_slice(&1u32.to_le_bytes());
    script.push(7);
    script.push(0xb0);
    assert_eq!(extract_cltv_locktime(&script).expect("parse"), Some(7));
}

#[test]
fn locktime_extractors_skip_non_integer_data_pushes() {
    let mut script = Vec::new();
    push_data(&mut script, &[0x11; 32]);
    script.push(0xac);
    push_int(&mut script, 42);
    script.push(0xb1);
    assert_eq!(extract_csv_sequence(&script).expect("parse"), Some(42));

    let mut salted = Vec::new();
    push_data(&mut salted, &[0x22; 8]);
    salted.push(0x75);
    push_data(&mut salted, &[0x33; 32]);
    salted.push(0xad);
    push_int(&mut salted, 500);
    salted.push(0xb0);
    assert_eq!(extract_cltv_locktime(&salted).expect("parse"), Some(500));
}

#[test]
fn locktime_extractors_require_the_integer_to_immediately_precede_the_opcode() {
    let mut script = Vec::new();
    push_int(&mut script, 99);
    script.push(0x75);
    script.push(0xb1);
    assert_eq!(extract_csv_sequence(&script).expect("parse"), None);
}

#[test]
fn locktime_extractors_handle_real_covenant_scripts() {
    let dms =
        crate::contracts::covenant::script::build_dms_csv_script(&[0x41; 32], &[0x42; 32], 15);
    assert_eq!(extract_csv_sequence(&dms).expect("DMS CSV"), Some(15));

    let allowance = crate::contracts::covenant::script::build_allowance_script(
        &[0x43; 32],
        &[0x44; 32],
        50_000_000,
        12,
        123,
    );
    assert_eq!(
        extract_csv_sequence(&allowance).expect("allowance CSV"),
        Some(12),
    );
    assert_eq!(
        extract_cltv_locktime(&allowance).expect("allowance CLTV"),
        Some(123),
    );

    let global_allowance = crate::contracts::covenant::script::build_global_allowance_script(
        &[0x45; 32],
        &[0x46; 32],
        50_000_000,
        4,
        321,
        &[0x47; 8],
    );
    assert_eq!(
        extract_csv_sequence(&global_allowance).expect("global allowance CSV"),
        Some(4),
    );
    assert_eq!(
        extract_cltv_locktime(&global_allowance).expect("global allowance CLTV"),
        Some(321),
    );

    let spending = crate::contracts::covenant::script::build_global_spending_limit_script(
        &[0x48; 32],
        50_000_000,
        5,
        &[0x49; 8],
    );
    assert_eq!(
        extract_csv_sequence(&spending).expect("global spending-limit CSV"),
        Some(5),
    );
}

#[test]
fn allowance_builders_cover_absent_optional_locktimes() {
    let local = crate::contracts::covenant::script::build_allowance_script(
        &[0x51; 32],
        &[0x52; 32],
        50_000_000,
        0,
        0,
    );
    assert_eq!(
        extract_csv_sequence(&local).expect("local allowance CSV"),
        None
    );
    assert_eq!(
        extract_cltv_locktime(&local).expect("local allowance CLTV"),
        None
    );

    let global = crate::contracts::covenant::script::build_global_allowance_script(
        &[0x53; 32],
        &[0x54; 32],
        50_000_000,
        0,
        0,
        &[0x55; 8],
    );
    assert_eq!(
        extract_csv_sequence(&global).expect("global allowance CSV"),
        None
    );
    assert_eq!(
        extract_cltv_locktime(&global).expect("global allowance CLTV"),
        None
    );
}

#[test]
fn locktime_parser_covers_pushdata1_and_pushdata2_items() {
    let mut pushdata1 = vec![0x4c, 1, 7, 0xb0];
    assert_eq!(extract_cltv_locktime(&pushdata1).unwrap(), Some(7));
    pushdata1[1] = 3;
    assert_eq!(
        extract_cltv_locktime(&pushdata1).unwrap_err(),
        "Truncated OP_PUSHDATA1 data"
    );

    let mut pushdata2 = vec![0x4d, 1, 0, 9, 0xb1];
    assert_eq!(extract_csv_sequence(&pushdata2).unwrap(), Some(9));
    pushdata2[1] = 3;
    assert_eq!(
        extract_csv_sequence(&pushdata2).unwrap_err(),
        "Truncated OP_PUSHDATA2 data"
    );
}

#[test]
fn pushdata_length_readers_are_directly_host_testable() {
    use super::number::{read_pushdata1, read_pushdata2, ScriptItem};

    assert_eq!(
        read_pushdata1(&[0x4c, 2, 7, 8], 0).unwrap(),
        (4, ScriptItem::Integer(0x0807)),
    );
    assert_eq!(
        read_pushdata2(&[0x4d, 2, 0, 9, 10], 0).unwrap(),
        (5, ScriptItem::Integer(0x0a09)),
    );
    assert!(read_pushdata1(&[0x4c], 0).is_err());
    assert!(read_pushdata2(&[0x4d, 1], 0).is_err());
}

#[test]
fn script_walker_covers_all_push_widths_and_truncation() {
    use super::walk::{contains_opcode_pair, item_end};

    assert_eq!(item_end(&[0x51], 0), Some(1));
    assert_eq!(item_end(&[0x02, 7, 8], 0), Some(3));
    assert_eq!(item_end(&[0x4c, 2, 7, 8], 0), Some(4));
    assert_eq!(item_end(&[0x4d, 2, 0, 7, 8], 0), Some(5));
    assert_eq!(item_end(&[0x4e, 2, 0, 0, 0, 7, 8], 0), Some(7));
    assert_eq!(item_end(&[0x4c], 0), None);
    assert_eq!(item_end(&[0x4d, 1], 0), None);
    assert_eq!(item_end(&[0x4e, 1, 0, 0], 0), None);
    assert_eq!(item_end(&[0x02, 7], 0), None);

    assert!(contains_opcode_pair(&[0x51, 0x67, 0x63], 0x67, 0x63));
    assert!(!contains_opcode_pair(&[0x02, 0x67, 0x63, 0x51], 0x67, 0x63));
    assert!(!contains_opcode_pair(&[0x67, 0x64], 0x67, 0x63));
    assert!(!contains_opcode_pair(&[0x62, 0x63], 0x67, 0x63));
    assert!(!contains_opcode_pair(&[0x4c], 0x67, 0x63));
}

#[test]
fn next_script_item_covers_integer_pushdata_and_opcode_classes() {
    use super::number::{next_script_item, ScriptItem};

    assert_eq!(
        next_script_item(&[0x00], 0, 0x00).unwrap(),
        (1, ScriptItem::Integer(0)),
    );
    assert_eq!(
        next_script_item(&[0x60], 0, 0x60).unwrap(),
        (1, ScriptItem::Integer(16)),
    );
    assert_eq!(
        next_script_item(&[0x02, 7, 8], 0, 0x02).unwrap(),
        (3, ScriptItem::Integer(0x0807)),
    );
    assert_eq!(
        next_script_item(&[0x4c, 1, 9], 0, 0x4c).unwrap(),
        (3, ScriptItem::Integer(9)),
    );
    assert_eq!(
        next_script_item(&[0x4d, 1, 0, 10], 0, 0x4d).unwrap(),
        (4, ScriptItem::Integer(10)),
    );
    assert_eq!(
        next_script_item(&[0x4e, 1, 0, 0, 0, 11], 0, 0x4e).unwrap(),
        (6, ScriptItem::Integer(11)),
    );
    assert_eq!(
        next_script_item(&[0xac], 0, 0xac).unwrap(),
        (1, ScriptItem::Opcode),
    );
    assert_eq!(
        next_script_item(&[0x51, 0x52], 1, 0x52).unwrap(),
        (2, ScriptItem::Integer(2)),
    );
    assert_eq!(
        next_script_item(&[0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9], 0, 0x09)
            .unwrap()
            .1,
        ScriptItem::OversizedInteger,
    );
    assert_eq!(
        next_script_item(&[0x02, 7], 0, 0x02).unwrap_err(),
        "Truncated direct script push",
    );
    assert_eq!(
        next_script_item(&[], 0, 0x00).unwrap_err(),
        "Truncated script item",
    );
    assert_eq!(
        next_script_item(&[], 0, 0xac).unwrap_err(),
        "Truncated script item",
    );
}

#[test]
fn script_integer_encoding_and_eight_byte_boundary_are_exact() {
    use super::number::{next_script_item, ScriptItem};

    for (value, expected) in [
        (0u64, vec![0x00]),
        (1, vec![0x51]),
        (16, vec![0x60]),
        (17, vec![0x01, 0x11]),
        (127, vec![0x01, 0x7f]),
        (128, vec![0x02, 0x80, 0x00]),
        (255, vec![0x02, 0xff, 0x00]),
        (256, vec![0x02, 0x00, 0x01]),
        (0x80ff, vec![0x03, 0xff, 0x80, 0x00]),
    ] {
        let mut script = Vec::new();
        push_int(&mut script, value);
        assert_eq!(script, expected, "value {value}");
    }

    let eight = [0x08, 1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        next_script_item(&eight, 0, 0x08).unwrap(),
        (9, ScriptItem::Integer(0x0807_0605_0403_0201)),
    );
    let nine = [0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    assert_eq!(
        next_script_item(&nine, 0, 0x09).unwrap().1,
        ScriptItem::OversizedInteger
    );

    assert_eq!(
        next_script_item(&[0x4c, 0], 0, 0x4c).unwrap(),
        (2, ScriptItem::Integer(0)),
    );
}
