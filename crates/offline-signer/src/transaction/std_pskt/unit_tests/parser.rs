use alloc::{format, string::ToString, vec, vec::Vec};

use shared_signer::PsktParsed;

use crate::transaction::model::Transaction;

use super::super::{
    hex_decode_strict, parse_pskt, parse_u64_num, PskError, PSKB_MAGIC, PSKT_MAGIC,
};
use super::common::{encode_wire, parse_json, transaction_json, COVENANT_ID, TXID_ZERO};

#[test]
fn strict_hex_decoder_covers_each_fail_closed_boundary() {
    let mut out = [0u8; 2];
    assert_eq!(
        hex_decode_strict(b"abc", &mut out),
        Err(PskError::OddHexLength)
    );
    assert_eq!(
        hex_decode_strict(b"aabb", &mut out[..1]),
        Err(PskError::ScratchBufferTooSmall)
    );
    assert_eq!(
        hex_decode_strict(b"gb", &mut out),
        Err(PskError::BadHexChar)
    );
    assert_eq!(
        hex_decode_strict(b"ag", &mut out),
        Err(PskError::BadHexChar)
    );
    assert_eq!(hex_decode_strict(b"a0ff", &mut out), Ok(2));
    assert_eq!(out, [0xa0, 0xff]);
}

#[test]
fn declared_counts_are_validated_after_field_order_is_resolved() {
    let json = format!(
        "{{\"inputs\":[{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}}],\"outputs\":[],\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":0,\"outputCount\":0}}}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, json.as_bytes()).unwrap_err(),
        PskError::CountMismatch
    );
}

#[test]
fn zero_count_transaction_uses_the_explicit_empty_array_grammar() {
    let json = br#"{"global":{"version":0,"txVersion":1,"inputCount":0,"outputCount":0},"inputs":[],"outputs":[]}"#;
    let (tx, _, _) = parse_json(PSKT_MAGIC, json).expect("zero-count PSKT grammar");
    assert_eq!(tx.num_inputs, 0);
    assert_eq!(tx.num_outputs, 0);
}

#[test]
fn pskt_parser_rejects_aggregate_monetary_overflow_and_accepts_exact_u64_max() {
    let max = u64::MAX;
    let input_overflow = format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":2,\"outputCount\":1}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":{max},\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}},{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":1}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":{max},\"scriptPublicKey\":\"0000\"}}]}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, input_overflow.as_bytes()).unwrap_err(),
        PskError::InputAmountOverflow
    );

    let output_overflow = format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":2}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":{max},\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":{max},\"scriptPublicKey\":\"0000\"}},{{\"amount\":1,\"scriptPublicKey\":\"0000\"}}]}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, output_overflow.as_bytes()).unwrap_err(),
        PskError::OutputAmountOverflow
    );

    let outputs_exceed_inputs = format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":41,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":42,\"scriptPublicKey\":\"0000\"}}]}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, outputs_exceed_inputs.as_bytes()).unwrap_err(),
        PskError::OutputsExceedInputs
    );

    let exact_max = format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":2,\"outputCount\":1}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":{},\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}},{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":1}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":{max},\"scriptPublicKey\":\"0000\"}}]}}",
        max - 1
    );
    let (parsed, _, _) = parse_json(PSKT_MAGIC, exact_max.as_bytes()).expect("exact max parses");
    assert_eq!(
        parsed
            .checked_amounts()
            .expect("exact max amounts")
            .input_total,
        max
    );
    assert_eq!(parsed.checked_amounts().expect("exact max amounts").fee, 0);
}

#[test]
fn mismatched_nested_delimiters_are_rejected() {
    let json = format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1}},\"future\":{{\"a\":[1}}],\"inputs\":[{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\"}}]}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, json.as_bytes()).unwrap_err(),
        PskError::UnexpectedToken
    );
}

#[test]
fn opaque_json_requires_full_container_grammar() {
    for extra in [",\"future\":{\"a\":1,}", ",\"future\":{\"a\" 1}"] {
        let json = transaction_json(extra, "", "");
        assert_eq!(
            parse_json(PSKT_MAGIC, &json).unwrap_err(),
            PskError::UnexpectedToken
        );
    }
}

#[test]
fn empty_required_objects_and_opaque_nested_objects_have_distinct_grammar_results() {
    let empty_global = format!(
        "{{\"global\":{{}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\"}}]}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, empty_global.as_bytes()).unwrap_err(),
        PskError::MissingField
    );

    for extra in [
        r#","future":{}"#,
        r#","future":[{"nested":true}]"#,
        r#","future":{"nested":{}}"#,
    ] {
        parse_json(PSKT_MAGIC, &transaction_json(extra, "", ""))
            .expect("opaque nested JSON remains valid");
    }
}

#[test]
fn opaque_json_nesting_is_bounded() {
    let mut nested = Vec::new();
    nested.extend_from_slice(
        b"{\"global\":{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1},\"future\":",
    );
    nested.extend(core::iter::repeat_n(b'[', 33));
    nested.push(b'0');
    nested.extend(core::iter::repeat_n(b']', 33));
    nested.extend_from_slice(
        b",\"inputs\":[{\"utxoEntry\":{\"amount\":1,\"scriptPublicKey\":\"0000\"},\"previousOutpoint\":{\"transactionId\":\"",
    );
    nested.extend_from_slice(TXID_ZERO.as_bytes());
    nested.extend_from_slice(
        b"\",\"index\":0},\"sighashType\":1}],\"outputs\":[{\"amount\":1,\"scriptPublicKey\":\"0000\"}]}",
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, &nested).unwrap_err(),
        PskError::JsonNestingTooDeep
    );
}

#[test]
fn duplicate_known_fields_are_rejected_consistently() {
    let input_duplicates = [
        ",\"sequence\":1,\"sequence\":2",
        ",\"redeemScript\":null,\"redeemScript\":null",
        ",\"sigOpCount\":1,\"sigOpCount\":1",
        ",\"partialSigs\":{},\"partialSigs\":{}",
        ",\"bip32Derivations\":{},\"bip32Derivations\":{}",
        ",\"minTime\":null,\"minTime\":null",
        ",\"finalScriptSig\":null,\"finalScriptSig\":null",
        ",\"proprietaries\":{},\"proprietaries\":{}",
    ];
    for extra in input_duplicates {
        assert_eq!(
            parse_json(PSKT_MAGIC, &transaction_json("", extra, "")).unwrap_err(),
            PskError::DuplicateField
        );
    }

    let output_duplicates = [
        ",\"redeemScript\":null,\"redeemScript\":null",
        ",\"bip32Derivations\":{},\"bip32Derivations\":{}",
        ",\"proprietaries\":{},\"proprietaries\":{}",
    ];
    for extra in output_duplicates {
        assert_eq!(
            parse_json(PSKT_MAGIC, &transaction_json("", "", extra)).unwrap_err(),
            PskError::DuplicateField
        );
    }
}

#[test]
fn known_fields_require_their_declared_types() {
    let invalid_input_fields = [
        ",\"sequence\":null",
        ",\"redeemScript\":1",
        ",\"sigOpCount\":null",
        ",\"partialSigs\":[]",
        ",\"bip32Derivations\":[]",
        ",\"minTime\":false",
        ",\"finalScriptSig\":{}",
        ",\"proprietaries\":[]",
    ];
    for extra in invalid_input_fields {
        assert_eq!(
            parse_json(PSKT_MAGIC, &transaction_json("", extra, "")).unwrap_err(),
            PskError::UnexpectedToken
        );
    }

    let invalid_global_fields = [
        ",\"fallbackLockTime\":false",
        ",\"inputsModifiable\":0",
        ",\"outputsModifiable\":null",
        ",\"xpubs\":[]",
        ",\"id\":{}",
        ",\"proprietaries\":[]",
    ];
    for extra in invalid_global_fields {
        assert_eq!(
            parse_json(PSKT_MAGIC, &transaction_json(extra, "", "")).unwrap_err(),
            PskError::UnexpectedToken
        );
    }
}

#[test]
fn duplicate_global_and_top_level_fields_are_rejected() {
    let global_duplicates = [
        ",\"version\":0",
        ",\"txVersion\":1",
        ",\"fallbackLockTime\":null,\"fallbackLockTime\":null",
        ",\"inputsModifiable\":true,\"inputsModifiable\":true",
        ",\"outputsModifiable\":true,\"outputsModifiable\":true",
        ",\"inputCount\":1",
        ",\"outputCount\":1",
        ",\"xpubs\":{},\"xpubs\":{}",
        ",\"id\":null,\"id\":null",
        ",\"proprietaries\":{},\"proprietaries\":{}",
    ];
    for extra in global_duplicates {
        assert_eq!(
            parse_json(PSKT_MAGIC, &transaction_json(extra, "", "")).unwrap_err(),
            PskError::DuplicateField
        );
    }

    let duplicate_top_level = format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1}},\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\"}}]}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, duplicate_top_level.as_bytes()).unwrap_err(),
        PskError::DuplicateField
    );
}

#[test]
fn output_fields_require_their_declared_types() {
    let invalid_output_fields = [
        ",\"redeemScript\":1",
        ",\"bip32Derivations\":[]",
        ",\"proprietaries\":[]",
        ",\"covenantBinding\":\"not-an-object\"",
    ];
    for extra in invalid_output_fields {
        assert_eq!(
            parse_json(PSKT_MAGIC, &transaction_json("", "", extra)).unwrap_err(),
            PskError::UnexpectedToken
        );
    }
}

#[test]
fn numeric_parser_rejects_each_noncanonical_condition_and_accepts_u64_max() {
    assert_eq!(parse_u64_num(b"0"), Ok(0));
    assert_eq!(parse_u64_num(b"18446744073709551615"), Ok(u64::MAX));
    for invalid in [&b""[..], &b"00"[..], &b"01"[..], &b"1x"[..], &b"+1"[..]] {
        assert_eq!(parse_u64_num(invalid), Err(PskError::UnexpectedToken));
    }
    assert_eq!(
        parse_u64_num(b"18446744073709551616"),
        Err(PskError::UnexpectedToken)
    );
}

#[test]
fn pskb_bundle_rejects_a_second_element_at_the_comma_boundary() {
    let object = transaction_json("", "", "");
    let mut bundle = Vec::with_capacity(object.len() * 2 + 3);
    bundle.push(b'[');
    bundle.extend_from_slice(&object);
    bundle.push(b',');
    bundle.extend_from_slice(&object);
    bundle.push(b']');
    assert_eq!(
        parse_json(PSKB_MAGIC, &bundle).unwrap_err(),
        PskError::BundleMultiElement
    );
}

#[test]
fn decoded_json_accepts_exact_u16_offset_capacity() {
    let mut json = transaction_json("", "", "");
    assert!(json.len() < u16::MAX as usize);
    json.resize(u16::MAX as usize, b' ');
    let (tx, parsed, _) = parse_json(PSKT_MAGIC, &json).expect("exact u16 JSON length");
    assert_eq!(parsed.json_len, u16::MAX);
    assert_eq!(tx.num_inputs, 1);
    assert_eq!(tx.num_outputs, 1);
}

#[test]
fn decoded_json_larger_than_u16_offsets_is_rejected() {
    let json = vec![b'a'; u16::MAX as usize + 1];
    let wire = encode_wire(PSKT_MAGIC, &json);
    let mut scratch = vec![0u8; json.len()];
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    let mut parsed = PsktParsed::empty();
    assert_eq!(
        parse_pskt(&wire, &mut scratch, &mut tx, &mut parsed),
        Err(PskError::JsonTooLarge)
    );
}

#[test]
fn partial_signatures_cover_empty_valid_and_invalid_entries() {
    let pubkey = format!("02{}", "11".repeat(32));
    let signature = "22".repeat(64);
    let valid = format!(",\"partialSigs\":{{\"{pubkey}\":{{\"schnorr\":\"{signature}\"}}}}");
    let (tx, _, _) = parse_json(PSKT_MAGIC, &transaction_json("", &valid, "")).unwrap();
    assert_eq!(tx.inputs[0].incoming_partial_sigs_count, 1);

    let empty = parse_json(PSKT_MAGIC, &transaction_json("", ",\"partialSigs\":{}", "")).unwrap();
    assert_eq!(empty.0.inputs[0].incoming_partial_sigs_count, 0);

    let duplicate = format!(
        ",\"partialSigs\":{{\"{pubkey}\":{{\"schnorr\":\"{signature}\"}},\"{pubkey}\":{{\"schnorr\":\"{signature}\"}}}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", &duplicate, "")).unwrap_err(),
        PskError::DuplicateField
    );

    for invalid in [
        format!(",\"partialSigs\":{{\"00\":{{\"schnorr\":\"{signature}\"}}}}"),
        format!(",\"partialSigs\":{{\"{pubkey}\":{{\"ecdsa\":\"{signature}\"}}}}"),
        format!(",\"partialSigs\":{{\"{pubkey}\":{{\"schnorr\":\"22\"}}}}"),
    ] {
        assert!(parse_json(PSKT_MAGIC, &transaction_json("", &invalid, "")).is_err());
    }
}

#[test]
fn signature_kind_and_preserved_hex_fail_with_specific_errors() {
    let pubkey = format!("02{}", "11".repeat(32));
    let signature = "22".repeat(64);
    let ecdsa = format!(",\"partialSigs\":{{\"{pubkey}\":{{\"ecdsa\":\"{signature}\"}}}}");
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", &ecdsa, "")).unwrap_err(),
        PskError::InvalidSignatureType
    );

    assert_eq!(
        parse_json(
            PSKT_MAGIC,
            &transaction_json("", ",\"finalScriptSig\":\"zz\"", ""),
        )
        .unwrap_err(),
        PskError::BadHexChar
    );
}

#[test]
fn bip32_derivations_cover_null_objects_duplicates_and_limits() {
    let first = format!("02{}", "11".repeat(32));
    let second = format!("03{}", "22".repeat(32));
    let value = format!(
        ",\"bip32Derivations\":{{\"{first}\":null,\"{second}\":{{\"masterFingerprint\":\"00000000\",\"path\":[]}}}}"
    );
    let (_, parsed, _) = parse_json(PSKT_MAGIC, &transaction_json("", &value, "")).unwrap();
    assert!(parsed.unknowns_count > 0);

    let duplicate = format!(",\"bip32Derivations\":{{\"{first}\":null,\"{first}\":null}}");
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", &duplicate, "")).unwrap_err(),
        PskError::DuplicateField
    );

    for invalid in [
        ",\"bip32Derivations\":{\"00\":null}".to_string(),
        format!(",\"bip32Derivations\":{{\"{first}\":[]}}"),
    ] {
        assert!(parse_json(PSKT_MAGIC, &transaction_json("", &invalid, "")).is_err());
    }
}

#[test]
fn outpoint_parser_covers_unknown_duplicate_missing_and_bounds() {
    let unknown = format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"future\":{{\"nested\":true}},\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1}}],\"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\"}}]}}"
    );
    let (_, parsed, _) = parse_json(PSKT_MAGIC, unknown.as_bytes()).unwrap();
    assert!(parsed.unknowns_count > 0);

    for outpoint in [
        format!("{{\"transactionId\":\"{TXID_ZERO}\"}}"),
        "{\"index\":0}".to_string(),
        format!(
            "{{\"transactionId\":\"{TXID_ZERO}\",\"transactionId\":\"{TXID_ZERO}\",\"index\":0}}"
        ),
        format!("{{\"transactionId\":\"{TXID_ZERO}\",\"index\":4294967296}}"),
        "{\"transactionId\":\"00\",\"index\":0}".to_string(),
    ] {
        let json = format!(
            "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{outpoint},\"sighashType\":1}}],\"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\"}}]}}"
        );
        assert!(parse_json(PSKT_MAGIC, json.as_bytes()).is_err());
    }
}

#[test]
fn parser_capture_redeem_and_unknown_paths_are_covered_end_to_end() {
    use shared_signer::TxInputFormat;

    use super::super::hex_encode_lower;
    use super::common::{contains_subslice, serialize_json};

    let mut json = transaction_json(
        ",\"futureGlobal\":{\"nested\":[1,true,null]}",
        ",\"redeemScript\":\"51ac\",\"futureInput\":{\"x\":1}",
        ",\"futureOutput\":[1,2,3]",
    );
    let needle = b"\"scriptPublicKey\":\"0000\"";
    let position = json
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("input UTXO script key");
    let insert_at = position + needle.len();
    json.splice(
        insert_at..insert_at,
        b",\"futureUtxo\":{\"nested\":false}".iter().copied(),
    );

    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse with preserved fields");
    // Four fields are unknown and preserved by scope. `redeemScript` is a
    // recognized input field decoded into the transaction model, so it must
    // not inflate the unknown-region count.
    assert_eq!(parsed.unknowns_count, 4);
    assert_eq!(tx.inputs[0].redeem_script_len, 2);
    assert_eq!(&tx.inputs[0].redeem_script[..2], &[0x51, 0xac]);

    let emitted = serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktPskb)
        .expect("serialize preserved fields");
    for field in [
        b"\"futureGlobal\"".as_slice(),
        b"\"futureInput\"".as_slice(),
        b"\"futureUtxo\"".as_slice(),
        b"\"futureOutput\"".as_slice(),
        b"\"redeemScript\":\"51ac\"".as_slice(),
    ] {
        assert!(contains_subslice(&emitted, field));
    }

    let mut encoded = [0u8; 4];
    assert_eq!(hex_encode_lower(&[0xde, 0xad], &mut encoded).unwrap(), 4);
    assert_eq!(&encoded, b"dead");
    assert!(hex_encode_lower(&[0xde, 0xad], &mut encoded[..3]).is_err());
}

#[test]
fn tokenizer_number_string_and_keyword_boundaries_are_exact() {
    use super::super::{Tok, Tokenizer};

    for (source, expected, position) in [
        (b"0,".as_slice(), b"0".as_slice(), 1usize),
        (b"1,".as_slice(), b"1".as_slice(), 1usize),
        (b"12345}".as_slice(), b"12345".as_slice(), 5usize),
        (b"9".as_slice(), b"9".as_slice(), 1usize),
    ] {
        let mut tokenizer = Tokenizer::new(source);
        assert_eq!(tokenizer.next_token().expect("number"), Tok::Num(expected));
        assert_eq!(tokenizer.position(), position);
    }

    for invalid in [
        b"00".as_slice(),
        b"01".as_slice(),
        b"1.0".as_slice(),
        b"1e2".as_slice(),
        b"1E2".as_slice(),
    ] {
        let mut tokenizer = Tokenizer::new(invalid);
        assert_eq!(tokenizer.next_token(), Err(PskError::UnexpectedToken));
    }

    let mut quoted = Tokenizer::new(br#""plain""#);
    assert_eq!(
        quoted.next_token().expect("plain string"),
        Tok::Str(b"plain")
    );
    let mut escaped = Tokenizer::new(br#""bad\\escape""#);
    assert_eq!(escaped.next_token(), Err(PskError::UnexpectedToken));
    let mut controlled = Tokenizer::new(b"\"bad\x1fchar\"");
    assert_eq!(controlled.next_token(), Err(PskError::UnexpectedToken));

    for (source, expected) in [
        (b"true".as_slice(), Tok::True),
        (b"false".as_slice(), Tok::False),
        (b"null".as_slice(), Tok::Null),
    ] {
        let mut tokenizer = Tokenizer::new(source);
        assert_eq!(tokenizer.next_token().expect("keyword"), expected);
        assert_eq!(tokenizer.next_token().expect("eof"), Tok::Eof);
    }
    for truncated in [b"tru".as_slice(), b"fals".as_slice(), b"nul".as_slice()] {
        let mut tokenizer = Tokenizer::new(truncated);
        assert_eq!(tokenizer.next_token(), Err(PskError::TruncatedEnvelope));
    }
}

#[test]
fn required_pskt_schema_fields_are_independently_enforced() {
    let valid_global = r#"{"version":0,"txVersion":1,"inputCount":1,"outputCount":1}"#;
    let valid_utxo = r#"{"amount":1,"scriptPublicKey":"0000"}"#;
    let valid_outpoint = format!(r#"{{"transactionId":"{TXID_ZERO}","index":0}}"#);
    let valid_input = format!(
        r#"{{"utxoEntry":{valid_utxo},"previousOutpoint":{valid_outpoint},"sighashType":1}}"#
    );
    let valid_output = r#"{"amount":1,"scriptPublicKey":"0000"}"#;
    let document = |global: &str, input: &str, output: &str| {
        format!(r#"{{"global":{global},"inputs":[{input}],"outputs":[{output}]}}"#)
    };

    for global in [
        r#"{"txVersion":1,"inputCount":1,"outputCount":1}"#,
        r#"{"version":0,"inputCount":1,"outputCount":1}"#,
        r#"{"version":0,"txVersion":1,"outputCount":1}"#,
        r#"{"version":0,"txVersion":1,"inputCount":1}"#,
    ] {
        assert_eq!(
            parse_json(
                PSKT_MAGIC,
                document(global, &valid_input, valid_output).as_bytes()
            )
            .unwrap_err(),
            PskError::MissingField,
        );
    }

    for input in [
        format!(r#"{{"previousOutpoint":{valid_outpoint},"sighashType":1}}"#),
        format!(r#"{{"utxoEntry":{valid_utxo},"sighashType":1}}"#),
        format!(r#"{{"utxoEntry":{valid_utxo},"previousOutpoint":{valid_outpoint}}}"#),
    ] {
        assert_eq!(
            parse_json(
                PSKT_MAGIC,
                document(valid_global, &input, valid_output).as_bytes()
            )
            .unwrap_err(),
            PskError::MissingField,
        );
    }

    for utxo in [r#"{"scriptPublicKey":"0000"}"#, r#"{"amount":1}"#] {
        let input = format!(
            r#"{{"utxoEntry":{utxo},"previousOutpoint":{valid_outpoint},"sighashType":1}}"#
        );
        assert_eq!(
            parse_json(
                PSKT_MAGIC,
                document(valid_global, &input, valid_output).as_bytes()
            )
            .unwrap_err(),
            PskError::MissingField,
        );
    }

    for outpoint in [
        r#"{"index":0}"#.to_string(),
        format!(r#"{{"transactionId":"{TXID_ZERO}"}}"#),
    ] {
        let input = format!(
            r#"{{"utxoEntry":{valid_utxo},"previousOutpoint":{outpoint},"sighashType":1}}"#
        );
        assert_eq!(
            parse_json(
                PSKT_MAGIC,
                document(valid_global, &input, valid_output).as_bytes()
            )
            .unwrap_err(),
            PskError::MissingField,
        );
    }

    for output in [r#"{"scriptPublicKey":"0000"}"#, r#"{"amount":1}"#] {
        assert_eq!(
            parse_json(
                PSKT_MAGIC,
                document(valid_global, &valid_input, output).as_bytes()
            )
            .unwrap_err(),
            PskError::MissingField,
        );
    }
}

#[test]
fn pskt_parser_accepts_dynamic_inputs_and_fixed_output_boundaries() {
    let input = format!(
        r#"{{"utxoEntry":{{"amount":1,"scriptPublicKey":"0000"}},"previousOutpoint":{{"transactionId":"{TXID_ZERO}","index":0}},"sighashType":1}}"#
    );
    let output = r#"{"amount":1,"scriptPublicKey":"0000"}"#;
    let inputs_thirty_two = vec![input.as_str(); 32].join(",");
    let outputs_eight = [
        output, output, output, output, output, output, output, output,
    ]
    .join(",");

    let dynamic_inputs = format!(
        r#"{{"global":{{"version":0,"txVersion":1,"inputCount":32,"outputCount":1}},"inputs":[{inputs_thirty_two}],"outputs":[{output}]}}"#
    );
    let parsed_inputs = parse_json(PSKT_MAGIC, dynamic_inputs.as_bytes()).expect("dynamic inputs");
    assert_eq!(parsed_inputs.0.num_inputs, 32);

    // Keep the output-capacity fixture monetarily valid: eight outputs of one sompi
    // require at least eight sompi of input value. This test is about the fixed
    // output-count boundary, not the OutputsExceedInputs rejection path.
    let input_for_eight_outputs = format!(
        r#"{{"utxoEntry":{{"amount":8,"scriptPublicKey":"0000"}},"previousOutpoint":{{"transactionId":"{TXID_ZERO}","index":0}},"sighashType":1}}"#
    );
    let max_outputs = format!(
        r#"{{"global":{{"version":0,"txVersion":1,"inputCount":1,"outputCount":8}},"inputs":[{input_for_eight_outputs}],"outputs":[{outputs_eight}]}}"#
    );
    let parsed_outputs = parse_json(PSKT_MAGIC, max_outputs.as_bytes()).expect("eight outputs");
    assert_eq!(parsed_outputs.0.num_outputs, 8);
    assert_eq!(
        parsed_outputs.0.total_input_value().expect("input total"),
        8
    );
    assert_eq!(
        parsed_outputs.0.total_output_value().expect("output total"),
        8
    );

    let tx_version_zero = format!(
        r#"{{"global":{{"version":0,"txVersion":0,"inputCount":1,"outputCount":1}},"inputs":[{input}],"outputs":[{output}]}}"#
    );
    assert!(parse_json(PSKT_MAGIC, tx_version_zero.as_bytes()).is_ok());

    let max_index_input = format!(
        r#"{{"utxoEntry":{{"amount":1,"scriptPublicKey":"0000"}},"previousOutpoint":{{"transactionId":"{TXID_ZERO}","index":4294967295}},"sighashType":1,"sigOpCount":5}}"#
    );
    let max_index_document = format!(
        r#"{{"global":{{"version":0,"txVersion":1,"inputCount":1,"outputCount":1}},"inputs":[{max_index_input}],"outputs":[{output}]}}"#
    );
    let parsed = parse_json(PSKT_MAGIC, max_index_document.as_bytes()).expect("u32 max index");
    assert_eq!(parsed.0.inputs[0].previous_outpoint.index, u32::MAX);
    assert_eq!(parsed.0.inputs[0].sig_op_count, 5);

    let too_many_sigops = max_index_document.replace(r#""sigOpCount":5"#, r#""sigOpCount":6"#);
    assert_eq!(
        parse_json(PSKT_MAGIC, too_many_sigops.as_bytes()).unwrap_err(),
        PskError::TooManyPartialSigs,
    );

    let too_large_index = max_index_document.replace("4294967295", "4294967296");
    assert_eq!(
        parse_json(PSKT_MAGIC, too_large_index.as_bytes()).unwrap_err(),
        PskError::UnexpectedToken,
    );

    let script_at_limit = "aa".repeat(512);
    let redeem_at_limit = format!(r#","redeemScript":"{script_at_limit}""#);
    assert!(parse_json(PSKT_MAGIC, &transaction_json("", &redeem_at_limit, ""),).is_ok());
    let redeem_too_large = format!(r#","redeemScript":"{}""#, "aa".repeat(513));
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", &redeem_too_large, "")).unwrap_err(),
        PskError::InvalidScriptLen,
    );

    let spk_at_limit = format!("0000{}", "aa".repeat(512));
    let large_output = format!(r#"{{"amount":1,"scriptPublicKey":"{spk_at_limit}"}}"#);
    let large_output_document = format!(
        r#"{{"global":{{"version":0,"txVersion":1,"inputCount":1,"outputCount":1}},"inputs":[{input}],"outputs":[{large_output}]}}"#
    );
    let parsed = parse_json(PSKT_MAGIC, large_output_document.as_bytes()).expect("512-byte SPK");
    assert_eq!(parsed.0.outputs[0].script_public_key.script_len, 512);

    let spk_too_large = format!("0000{}", "aa".repeat(513));
    let too_large_output = large_output_document.replace(&spk_at_limit, &spk_too_large);
    assert_eq!(
        parse_json(PSKT_MAGIC, too_large_output.as_bytes()).unwrap_err(),
        PskError::InvalidScriptLen,
    );
}

#[test]
fn optional_numeric_string_and_default_utxo_metadata_paths_remain_distinct() {
    let (tx, parsed, _) = parse_json(
        PSKT_MAGIC,
        &transaction_json(
            r#","fallbackLockTime":7,"id":"session-1""#,
            r#","minTime":9,"finalScriptSig":"aa""#,
            "",
        ),
    )
    .expect("optional numeric/string fields");
    assert_eq!(tx.num_inputs, 1);
    assert!(parsed.unknowns_count >= 4);

    let default_metadata = format!(
        r#"{{"global":{{"version":0,"txVersion":1,"inputCount":1,"outputCount":1}},"inputs":[{{"utxoEntry":{{"amount":1,"scriptPublicKey":"0000","blockDaaScore":0,"isCoinbase":false}},"previousOutpoint":{{"transactionId":"{TXID_ZERO}","index":0}},"sighashType":1}}],"outputs":[{{"amount":1,"scriptPublicKey":"0000"}}]}}"#
    );
    let (_, parsed, _) =
        parse_json(PSKT_MAGIC, default_metadata.as_bytes()).expect("default metadata");
    assert_eq!(parsed.unknowns_count, 0);

    let nondefault_metadata = default_metadata
        .replace(r#""blockDaaScore":0"#, r#""blockDaaScore":17"#)
        .replace(r#""isCoinbase":false"#, r#""isCoinbase":true"#);
    let (tx, parsed, scratch) =
        parse_json(PSKT_MAGIC, nondefault_metadata.as_bytes()).expect("nondefault metadata");
    assert_eq!(tx.inputs[0].utxo_entry.block_daa_score, 17);
    // `blockDaaScore` is now a typed exact-u64 field; only the unmodeled
    // non-default `isCoinbase` flag belongs in preservation metadata.
    assert_eq!(parsed.unknowns_count, 1);

    use super::common::{contains_subslice, serialize_json};
    use shared_signer::TxInputFormat;

    let emitted = serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktSingle)
        .expect("serialize exact UTXO metadata");
    assert!(contains_subslice(&emitted, b"\"blockDaaScore\":\"17\""));
    assert!(contains_subslice(&emitted, b"\"isCoinbase\":true"));
}

#[test]
fn covenant_binding_accepts_dynamic_authorizer_and_requires_both_members() {
    const MANY_INPUTS: usize = 16;
    let input = format!(
        r#"{{"utxoEntry":{{"amount":1,"scriptPublicKey":"0000"}},"previousOutpoint":{{"transactionId":"{TXID_ZERO}","index":0}},"sighashType":1}}"#
    );
    let inputs = vec![input.as_str(); MANY_INPUTS].join(",");
    let max_authorizer = MANY_INPUTS - 1;
    let output = format!(
        r#"{{"amount":1,"scriptPublicKey":"0000","covenantBinding":{{"authorizingInput":{max_authorizer},"covenantId":"{COVENANT_ID}"}}}}"#
    );
    let document = format!(
        r#"{{"global":{{"version":0,"txVersion":1,"inputCount":{MANY_INPUTS},"outputCount":1}},"inputs":[{inputs}],"outputs":[{output}]}}"#
    );

    let (tx, _, _) = parse_json(PSKT_MAGIC, document.as_bytes())
        .expect("maximum real covenant authorizing input");
    assert!(tx.outputs[0].has_covenant);
    assert_eq!(tx.outputs[0].covenant_auth_input as usize, max_authorizer);
    assert_eq!(tx.outputs[0].covenant_id, [0x11; 32]);

    let nonexistent = document.replace(
        &format!(r#""authorizingInput":{max_authorizer}"#),
        &format!(r#""authorizingInput":{MANY_INPUTS}"#),
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, nonexistent.as_bytes()).unwrap_err(),
        PskError::InvalidCovenantBinding,
    );

    let too_large = document.replace(
        &format!(r#""authorizingInput":{max_authorizer}"#),
        r#""authorizingInput":65536"#,
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, too_large.as_bytes()).unwrap_err(),
        PskError::InvalidCovenantBinding,
    );

    let missing_authorizer = format!(r#","covenantBinding":{{"covenantId":"{COVENANT_ID}"}}"#);
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", "", &missing_authorizer)).unwrap_err(),
        PskError::MissingField,
    );
}

#[test]
fn global_parser_covers_version_count_and_modifiable_branch_boundaries() {
    fn replace_once(mut json: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
        let text = core::str::from_utf8(&json).expect("fixture JSON");
        let start = text.find(from).expect("fixture field");
        json.splice(start..start + from.len(), to.bytes());
        json
    }

    for (from, to, expected) in [
        (
            "\"version\":0",
            "\"version\":1",
            PskError::VersionNotSupported,
        ),
        (
            "\"txVersion\":1",
            "\"txVersion\":2",
            PskError::VersionNotSupported,
        ),
        (
            "\"outputCount\":1",
            "\"outputCount\":9",
            PskError::TooManyOutputs,
        ),
    ] {
        let json = replace_once(transaction_json("", "", ""), from, to);
        assert_eq!(parse_json(PSKT_MAGIC, &json).unwrap_err(), expected);
    }

    let dynamic_count_without_matching_inputs = replace_once(
        transaction_json("", "", ""),
        "\"inputCount\":1",
        "\"inputCount\":9",
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, &dynamic_count_without_matching_inputs).unwrap_err(),
        PskError::CountMismatch,
    );

    // `true` is accepted directly, while `false` is preserved as an explicit
    // non-default global value. Exercise both sides of parse_modifiable().
    let (_, true_parsed, _) = parse_json(
        PSKT_MAGIC,
        &transaction_json(",\"inputsModifiable\":true", "", ""),
    )
    .expect("true modifiable flag");
    let (_, false_parsed, _) = parse_json(
        PSKT_MAGIC,
        &transaction_json(",\"inputsModifiable\":false", "", ""),
    )
    .expect("false modifiable flag");
    assert_eq!(true_parsed.unknowns_count, 0);
    assert_eq!(false_parsed.unknowns_count, 1);
}

#[test]
fn bip32_derivation_path_populates_untrusted_ms45_hint_end_to_end() {
    let pubkey = format!("02{}", "11".repeat(32));
    let derivation = format!(
        ",\"bip32Derivations\":{{\"{pubkey}\":{{\"masterFingerprint\":\"00000000\",\"derivationPath\":\"m/45'/111111'/0'/2/1/17\"}}}}"
    );
    let (tx, _, _) = parse_json(PSKT_MAGIC, &transaction_json("", &derivation, ""))
        .expect("PSKT with 45' derivation hint");
    assert_eq!(
        tx.inputs[0].ms45_hint,
        crate::transaction::model::Ms45Hint {
            present: true,
            cosigner: 2,
            chain: 1,
            index: 17
        },
    );

    let invalid = format!(
        ",\"bip32Derivations\":{{\"{pubkey}\":{{\"derivationPath\":\"m/45'/111111'/0'/2/2/17\"}}}}"
    );
    let (tx, _, _) = parse_json(PSKT_MAGIC, &transaction_json("", &invalid, ""))
        .expect("PSKT keeps invalid hint non-authoritative");
    assert_eq!(
        tx.inputs[0].ms45_hint,
        crate::transaction::model::Ms45Hint::none()
    );
}

#[test]
fn output_bip32_derivation_extracts_ms45_hint_when_no_hint_is_present_yet() {
    let pubkey = format!("02{}", "33".repeat(32));
    let extra = format!(
        ",\"bip32Derivations\":{{\"{pubkey}\":{{\"masterFingerprint\":\"00000000\",\"derivationPath\":\"m/45'/111111'/0'/2/1/17\"}}}}"
    );
    let (tx, _, _) =
        parse_json(PSKT_MAGIC, &transaction_json("", "", &extra)).expect("output derivation");
    assert!(tx.outputs[0].ms45_hint.present);
    assert_eq!(tx.outputs[0].ms45_hint.cosigner, 2);
    assert_eq!(tx.outputs[0].ms45_hint.chain, 1);
    assert_eq!(tx.outputs[0].ms45_hint.index, 17);
}
