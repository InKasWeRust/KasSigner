use alloc::{format, vec};

use shared_signer::TxInputFormat;

use super::super::{serialize_pskt, PskError, PSKT_MAGIC};
use super::common::{contains_subslice, parse_json, serialize_json, transaction_json, COVENANT_ID};

#[test]
fn covenant_binding_is_strict_and_is_emitted() {
    let binding =
        format!(",\"covenantBinding\":{{\"authorizingInput\":0,\"covenantId\":\"{COVENANT_ID}\"}}");
    let json = transaction_json("", "", &binding);
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse");
    assert!(tx.outputs[0].has_covenant);

    let emitted =
        serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktPskb).expect("serialize");
    let expected =
        format!("\"covenantBinding\":{{\"authorizingInput\":0,\"covenantId\":\"{COVENANT_ID}\"}}");
    assert!(contains_subslice(&emitted, expected.as_bytes()));
}

#[test]
fn malformed_covenant_id_and_authorizing_index_are_rejected() {
    let bad_id = format!(
        ",\"covenantBinding\":{{\"authorizingInput\":0,\"covenantId\":\"{}g\"}}",
        &COVENANT_ID[..63],
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", "", &bad_id)).unwrap_err(),
        PskError::InvalidCovenantBinding
    );

    let bad_index = format!(
        ",\"covenantBinding\":{{\"authorizingInput\":65536,\"covenantId\":\"{COVENANT_ID}\"}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", "", &bad_index)).unwrap_err(),
        PskError::InvalidCovenantBinding
    );
}

#[test]
fn covenant_binding_requires_unique_complete_fields_and_a_real_input() {
    let duplicate = format!(
        ",\"covenantBinding\":{{\"authorizingInput\":0,\"authorizingInput\":0,\"covenantId\":\"{COVENANT_ID}\"}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", "", &duplicate)).unwrap_err(),
        PskError::DuplicateField
    );

    assert_eq!(
        parse_json(
            PSKT_MAGIC,
            &transaction_json("", "", ",\"covenantBinding\":{\"authorizingInput\":0}",),
        )
        .unwrap_err(),
        PskError::MissingField
    );

    let unknown_field = format!(
        ",\"covenantBinding\":{{\"authorizingInput\":0,\"covenantId\":\"{COVENANT_ID}\",\"future\":null}}"
    );
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", "", &unknown_field)).unwrap_err(),
        PskError::UnexpectedToken
    );

    let nonexistent =
        format!(",\"covenantBinding\":{{\"authorizingInput\":1,\"covenantId\":\"{COVENANT_ID}\"}}");
    assert_eq!(
        parse_json(PSKT_MAGIC, &transaction_json("", "", &nonexistent)).unwrap_err(),
        PskError::InvalidCovenantBinding
    );
}

#[test]
fn explicit_null_covenant_binding_is_preserved() {
    let json = transaction_json("", "", ",\"covenantBinding\":null");
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse");
    let emitted =
        serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktSingle).expect("serialize");
    assert!(contains_subslice(&emitted, b"\"covenantBinding\":null"));
}

#[test]
fn serializer_rejects_a_programmatic_covenant_with_no_authorizing_input() {
    let json = transaction_json("", "", "");
    let (mut tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse");
    tx.outputs[0].has_covenant = true;
    tx.outputs[0].covenant_auth_input = 1;

    let mut wire = vec![0u8; 8192];
    assert_eq!(
        serialize_pskt(&tx, &parsed, &scratch, TxInputFormat::PsktSingle, &mut wire,),
        Err(PskError::InvalidCovenantBinding)
    );
}
