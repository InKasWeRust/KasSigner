use super::*;

#[test]
fn derivation_path_extraction_covers_valid_missing_and_malformed_json_regions() {
    let valid = br#"{"derivationPath":"m/45'/111111'/0'/2/1/17"}"#;
    assert_eq!(
        find_derivation_path(valid),
        Some(b"m/45'/111111'/0'/2/1/17".as_slice()),
    );
    assert_eq!(
        extract_ms45_hint(valid, 0, valid.len()),
        Some(Ms45Hint {
            present: true,
            cosigner: 2,
            chain: 1,
            index: 17,
        })
    );
    assert_eq!(find_derivation_path(br#"{"other":"value"}"#), None);
    assert_eq!(
        find_derivation_path(br#"{"derivationPath", "value"}"#),
        None
    );
    assert_eq!(
        find_derivation_path(br#"{"derivationPath":"unterminated}"#),
        None
    );
    assert_eq!(
        extract_ms45_hint(valid, valid.len() + 1, valid.len() + 2),
        None
    );
}

#[test]
fn ms45_path_parser_rejects_short_hardened_invalid_chain_and_large_components() {
    assert_eq!(
        parse_ms45_path(b"m/45'/111111'/0'/3/0/9"),
        Some(Ms45Hint {
            present: true,
            cosigner: 3,
            chain: 0,
            index: 9,
        })
    );
    for invalid in [
        b"m/45'/111111'/0'/3/9".as_slice(),
        b"m/45'/111111'/0'/3/2/9".as_slice(),
        b"m/45'/111111'/0'/x/0/9".as_slice(),
        b"m/45'/111111'/0'/3/0/9'".as_slice(),
        b"m/45'/111111'/0'/2147483648/0/9".as_slice(),
        b"m/44'/111111'/0'/3/0/9".as_slice(),
        b"m/45'/111111'/0'/3/0/9/10".as_slice(),
    ] {
        assert_eq!(parse_ms45_path(invalid), None);
    }
    assert_eq!(parse_soft_decimal(b"0"), Some(0));
    assert_eq!(parse_soft_decimal(b"2147483647"), Some(0x7fff_ffff));
    assert_eq!(parse_soft_decimal(b"2147483648"), None);
    assert_eq!(parse_soft_decimal(b"42949672960"), None);
    assert_eq!(parse_soft_decimal(&[0xff]), None);
    assert_eq!(parse_soft_decimal(b""), None);
}

#[test]
fn derivation_path_delimiter_search_is_limited_to_the_pre_value_region() {
    let source = br#"{"derivationPath":"m/45'/111111'/0'/2/1/17","later":1}"#;
    let hint = extract_ms45_hint(source, 0, source.len()).expect("hint");
    assert_eq!(hint.cosigner, 2);
    assert_eq!(hint.chain, 1);
    assert_eq!(hint.index, 17);
}
