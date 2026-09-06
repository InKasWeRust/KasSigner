use alloc::{format, vec, vec::Vec};

use shared_signer::{PsktParsed, TxInputFormat};

use crate::transaction::model::Transaction;

use super::super::{
    parse_pskt, serialize_pskt, serialize_pskt_vec, PskError, PSKB_MAGIC, PSKT_MAGIC,
};
use super::common::{
    contains_subslice, count_subslice, decode_json, encode_wire, parse_json, serialize_json,
    transaction_json,
};

#[test]
fn heap_pskt_serializer_is_covered_by_round_trip_fixture() {
    let json = transaction_json("", "", "");
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse heap fixture");
    let wire = serialize_pskt_vec(&tx, &parsed, &scratch, TxInputFormat::PsktSingle)
        .expect("heap PSKT serialization");
    assert_eq!(&wire[..4], PSKT_MAGIC);
    let mut reparsed_scratch = vec![0u8; (wire.len() - 4) / 2];
    let mut reparsed_tx = Transaction::try_new().expect("transaction test allocation");
    let mut reparsed = PsktParsed::empty();
    parse_pskt(
        &wire,
        &mut reparsed_scratch,
        &mut reparsed_tx,
        &mut reparsed,
    )
    .expect("reparse heap PSKT");
    assert_eq!(reparsed_tx.num_inputs, 1);
}

#[test]
fn serializer_rejects_invalid_aggregate_monetary_shapes_before_emitting_wire() {
    let parsed = PsktParsed::empty();
    let mut out = vec![0u8; 4096];

    let mut input_overflow = Transaction::try_new().expect("transaction test allocation");
    input_overflow.num_inputs = 2;
    input_overflow.num_outputs = 1;
    input_overflow.inputs[0].utxo_entry.amount = u64::MAX;
    input_overflow.inputs[1].utxo_entry.amount = 1;
    input_overflow.outputs[0].value = u64::MAX;
    assert_eq!(
        serialize_pskt(
            &input_overflow,
            &parsed,
            b"",
            TxInputFormat::PsktSingle,
            &mut out,
        ),
        Err(PskError::InputAmountOverflow)
    );

    let mut output_overflow = Transaction::try_new().expect("transaction test allocation");
    output_overflow.num_inputs = 1;
    output_overflow.num_outputs = 2;
    output_overflow.inputs[0].utxo_entry.amount = u64::MAX;
    output_overflow.outputs[0].value = u64::MAX;
    output_overflow.outputs[1].value = 1;
    assert_eq!(
        serialize_pskt(
            &output_overflow,
            &parsed,
            b"",
            TxInputFormat::PsktSingle,
            &mut out,
        ),
        Err(PskError::OutputAmountOverflow)
    );

    let mut outputs_exceed_inputs = Transaction::try_new().expect("transaction test allocation");
    outputs_exceed_inputs.num_inputs = 1;
    outputs_exceed_inputs.num_outputs = 1;
    outputs_exceed_inputs.inputs[0].utxo_entry.amount = 9;
    outputs_exceed_inputs.outputs[0].value = 10;
    assert_eq!(
        serialize_pskt(
            &outputs_exceed_inputs,
            &parsed,
            b"",
            TxInputFormat::PsktSingle,
            &mut out,
        ),
        Err(PskError::OutputsExceedInputs)
    );
}

#[test]
fn serializer_emits_commas_between_two_valid_outputs() {
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.num_inputs = 1;
    tx.num_outputs = 2;
    tx.inputs[0].utxo_entry.amount = 30;
    tx.inputs[0].sighash_type = 1;
    tx.outputs[0].value = 10;
    tx.outputs[1].value = 20;
    let parsed = PsktParsed::empty();
    let emitted = serialize_json(&tx, &parsed, b"", TxInputFormat::PsktSingle)
        .expect("serialize two outputs");
    let (reparsed, _, _) = parse_json(PSKT_MAGIC, &emitted).expect("two-output JSON reparses");
    assert_eq!(reparsed.num_outputs, 2);
    assert_eq!(reparsed.outputs[0].value, 10);
    assert_eq!(reparsed.outputs[1].value, 20);
}

#[test]
fn generated_bip32_derivations_follow_incoming_signature_pubkeys() {
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    tx.inputs[0].utxo_entry.amount = 1;
    tx.outputs[0].value = 1;
    tx.inputs[0].sighash_type = 1;
    tx.inputs[0].incoming_partial_sigs_count = 1;
    tx.inputs[0].incoming_partial_sigs[0].present = true;
    for (index, byte) in tx.inputs[0].incoming_partial_sigs[0]
        .pubkey
        .iter_mut()
        .enumerate()
    {
        *byte = index as u8;
    }
    tx.inputs[0].incoming_partial_sigs[0].signature = [0x24; 64];

    let emitted = serialize_json(&tx, &PsktParsed::empty(), b"", TxInputFormat::PsktSingle)
        .expect("serialize generated derivation");
    let pubkey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let signature = "24".repeat(64);
    assert_eq!(count_subslice(&emitted, pubkey.as_bytes()), 2);
    assert!(contains_subslice(
        &emitted,
        format!("\"partialSigs\":{{\"{pubkey}\":{{\"schnorr\":\"{signature}\"}}}}").as_bytes(),
    ));
    assert!(contains_subslice(
        &emitted,
        format!("\"bip32Derivations\":{{\"{pubkey}\":null}}").as_bytes(),
    ));
}

#[test]
fn pskt_single_round_trips_through_the_single_object_parser() {
    let json = transaction_json("", "", "");
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse single");
    let mut wire = vec![0u8; 8192];
    let len = serialize_pskt(&tx, &parsed, &scratch, TxInputFormat::PsktSingle, &mut wire)
        .expect("serialize single");
    wire.truncate(len);
    assert_eq!(&wire[..4], PSKT_MAGIC);

    let mut reparsed_scratch = vec![0u8; (wire.len() - 4) / 2];
    let mut reparsed_tx = Transaction::try_new().expect("transaction test allocation");
    let mut reparsed = PsktParsed::empty();
    parse_pskt(
        &wire,
        &mut reparsed_scratch,
        &mut reparsed_tx,
        &mut reparsed,
    )
    .expect("reparse single");
    assert_eq!(reparsed_tx.num_inputs, 1);
    assert_eq!(reparsed_tx.num_outputs, 1);
}

#[test]
fn pskb_bundle_uses_the_array_parser() {
    let object = transaction_json("", "", "");
    let mut bundle = Vec::with_capacity(object.len() + 2);
    bundle.push(b'[');
    bundle.extend_from_slice(&object);
    bundle.push(b']');

    let (tx, parsed, scratch) = parse_json(PSKB_MAGIC, &bundle).expect("parse bundle");
    let mut wire = vec![0u8; 8192];
    let len = serialize_pskt(&tx, &parsed, &scratch, TxInputFormat::PsktPskb, &mut wire)
        .expect("serialize bundle");
    let emitted = decode_json(&wire[..len]);
    assert_eq!(emitted.first(), Some(&b'['));
    assert_eq!(emitted.last(), Some(&b']'));

    let unwrapped = encode_wire(PSKB_MAGIC, &object);
    let mut bad_scratch = vec![0u8; object.len()];
    let mut bad_tx = Transaction::try_new().expect("transaction test allocation");
    let mut bad_parsed = PsktParsed::empty();
    assert!(parse_pskt(&unwrapped, &mut bad_scratch, &mut bad_tx, &mut bad_parsed,).is_err());
}

#[test]
fn partial_signatures_and_derivations_serialize_canonically() {
    let first = format!("02{}", "11".repeat(32));
    let second = format!("03{}", "22".repeat(32));
    let first_sig = "aa".repeat(64);
    let second_sig = "bb".repeat(64);
    let input_extra = format!(
        ",\"partialSigs\":{{\"{first}\":{{\"schnorr\":\"{first_sig}\"}},\"{second}\":{{\"schnorr\":\"{second_sig}\"}}}},\"bip32Derivations\":{{\"{first}\":null,\"{second}\":null}}"
    );
    let json = transaction_json("", &input_extra, "");
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse signatures");
    let emitted = serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktSingle)
        .expect("serialize signatures");
    assert!(contains_subslice(&emitted, b"\"partialSigs\":{"));
    assert_eq!(count_subslice(&emitted, first.as_bytes()), 2);
    assert_eq!(count_subslice(&emitted, second.as_bytes()), 2);
    assert!(contains_subslice(&emitted, first_sig.as_bytes()));
    assert!(contains_subslice(&emitted, second_sig.as_bytes()));
    assert!(contains_subslice(&emitted, b"\"bip32Derivations\":{"));
}

#[test]
fn global_serializer_preserves_locktime_modifiability_and_absent_covenant_exactly() {
    let json = transaction_json(
        ",\"fallbackLockTime\":7,\"inputsModifiable\":false,\"outputsModifiable\":false",
        "",
        "",
    );
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse global fields");
    let emitted = serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktSingle)
        .expect("serialize global fields");

    assert!(contains_subslice(&emitted, b"\"fallbackLockTime\":\"7\""));
    assert!(contains_subslice(&emitted, b"\"inputsModifiable\":false"));
    assert!(contains_subslice(&emitted, b"\"outputsModifiable\":false"));
    assert!(!contains_subslice(&emitted, b"\"covenantBinding\":"));
}

#[test]
fn script_public_key_serialization_preserves_every_version_and_script_nibble() {
    let mut json = transaction_json("", "", "");
    let needle = b"\"scriptPublicKey\":\"0000\"";
    let first = json
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("input script public key");
    let second_relative = json[first + needle.len()..]
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("output script public key");
    let second = first + needle.len() + second_relative;
    let replacement = b"\"scriptPublicKey\":\"abcd0123ff\"";
    json.splice(second..second + needle.len(), replacement.iter().copied());

    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse custom script");
    assert_eq!(tx.outputs[0].script_public_key.version, 0xabcd);
    assert_eq!(tx.outputs[0].script_public_key.script_len, 3);
    assert_eq!(
        &tx.outputs[0].script_public_key.script[..3],
        &[0x01, 0x23, 0xff]
    );

    let emitted = serialize_json(&tx, &parsed, &scratch, TxInputFormat::PsktSingle)
        .expect("serialize custom script");
    assert!(contains_subslice(
        &emitted,
        b"\"scriptPublicKey\":\"abcd0123ff\"",
    ));
}

#[test]
fn serializer_accepts_an_exact_output_buffer_and_rejects_one_byte_short() {
    let json = transaction_json(
        ",\"futureGlobal\":{\"nested\":[1,2,3]}",
        ",\"futureInput\":\"tail\"",
        ",\"futureOutput\":true",
    );
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse exact-buffer fixture");

    let mut oversized = vec![0u8; 16_384];
    let required = serialize_pskt(
        &tx,
        &parsed,
        &scratch,
        TxInputFormat::PsktSingle,
        &mut oversized,
    )
    .expect("measure serialized size");

    let mut exact = vec![0u8; required];
    let exact_len = serialize_pskt(
        &tx,
        &parsed,
        &scratch,
        TxInputFormat::PsktSingle,
        &mut exact,
    )
    .expect("exact-sized output must fit");
    assert_eq!(exact_len, required);
    assert_eq!(exact, oversized[..required]);

    let mut short = vec![0u8; required - 1];
    assert_eq!(
        serialize_pskt(
            &tx,
            &parsed,
            &scratch,
            TxInputFormat::PsktSingle,
            &mut short,
        ),
        Err(PskError::OutputBufferTooSmall),
    );
}

#[test]
fn serializer_separates_multiple_inputs_signatures_and_derivations_exactly() {
    use crate::transaction::model::IncomingPartialSig;

    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 1;
    tx.num_inputs = 2;
    tx.num_outputs = 1;
    for input_index in 0..2 {
        let input = &mut tx.inputs[input_index];
        input.previous_outpoint.transaction_id = [0x30 + input_index as u8; 32];
        input.previous_outpoint.index = input_index as u32;
        input.sighash_type = 1;
        input.incoming_partial_sigs_count = 2;
        input.incoming_partial_sigs[0] = IncomingPartialSig {
            pubkey: [0x40 + input_index as u8; 33],
            signature: [0x50 + input_index as u8; 64],
            present: true,
        };
        input.incoming_partial_sigs[1] = IncomingPartialSig {
            pubkey: [0x60 + input_index as u8; 33],
            signature: [0x70 + input_index as u8; 64],
            present: true,
        };
    }

    let parsed = PsktParsed::empty();
    let emitted = serialize_json(&tx, &parsed, b"", TxInputFormat::PsktSingle)
        .expect("serialize two inputs and signatures");
    let (reparsed, _, _) = parse_json(PSKT_MAGIC, &emitted).expect("serialized JSON reparses");
    assert_eq!(reparsed.num_inputs, 2);
    assert_eq!(reparsed.inputs[0].sighash_type, 1);
    assert_eq!(reparsed.inputs[1].sighash_type, 1);
    assert_eq!(reparsed.inputs[0].incoming_partial_sigs_count, 2);
    assert_eq!(reparsed.inputs[1].incoming_partial_sigs_count, 2);
    assert_eq!(
        reparsed.inputs[0].incoming_partial_sigs[0].pubkey,
        [0x40; 33]
    );
    assert_eq!(
        reparsed.inputs[0].incoming_partial_sigs[1].pubkey,
        [0x60; 33]
    );
    assert_eq!(
        reparsed.inputs[1].incoming_partial_sigs[0].pubkey,
        [0x41; 33]
    );
    assert_eq!(
        reparsed.inputs[1].incoming_partial_sigs[1].pubkey,
        [0x61; 33]
    );
    assert_eq!(
        reparsed.inputs[0].incoming_partial_sigs[0].signature,
        [0x50; 64]
    );
    assert_eq!(
        reparsed.inputs[1].incoming_partial_sigs[1].signature,
        [0x71; 64]
    );

    // `partialSigs` is input-only, while `bip32Derivations` is part of both
    // input and output PSKT schemas. This fixture has two inputs and one output.
    assert_eq!(count_subslice(&emitted, b"\"partialSigs\":{"), 2);
    assert_eq!(count_subslice(&emitted, b"\"bip32Derivations\":{"), 3);
}

#[test]
fn envelope_detection_and_magic_boundaries_are_exact() {
    use super::super::{detect_tx_format, strip_pskt_magic, DetectedFormat, KSPT_MAGIC};
    use shared_signer::TxInputFormat;

    assert_eq!(detect_tx_format(b"KSPT\x04"), DetectedFormat::KsptCompact);
    assert_eq!(
        detect_tx_format(b"KSPT\x04tail"),
        DetectedFormat::KsptCompact
    );
    assert_eq!(detect_tx_format(b"KSPT\x03"), DetectedFormat::Unknown);
    assert_eq!(detect_tx_format(b"KSPT"), DetectedFormat::Unknown);
    assert_eq!(detect_tx_format(b"KSPT\x02"), DetectedFormat::Unknown);
    assert_eq!(detect_tx_format(b"PSKB"), DetectedFormat::PsktPskb);
    assert_eq!(detect_tx_format(b"PSKT"), DetectedFormat::PsktSingle);
    assert_eq!(detect_tx_format(b"PSKX\x03"), DetectedFormat::Unknown);

    assert_eq!(
        DetectedFormat::KsptCompact.to_tx_input_format(),
        Some(TxInputFormat::KsptCompact),
    );
    assert_eq!(
        DetectedFormat::PsktPskb.to_tx_input_format(),
        Some(TxInputFormat::PsktPskb),
    );
    assert_eq!(
        DetectedFormat::PsktSingle.to_tx_input_format(),
        Some(TxInputFormat::PsktSingle),
    );
    assert_eq!(DetectedFormat::Unknown.to_tx_input_format(), None);

    for short in [b"".as_slice(), b"P", b"PS", b"PSK"] {
        assert_eq!(strip_pskt_magic(short), Err(PskError::TooShort));
    }
    assert_eq!(strip_pskt_magic(KSPT_MAGIC), Err(PskError::BadMagic));
    assert_eq!(
        strip_pskt_magic(PSKT_MAGIC),
        Err(PskError::TruncatedEnvelope)
    );
    assert_eq!(
        strip_pskt_magic(PSKB_MAGIC),
        Err(PskError::TruncatedEnvelope)
    );
    assert_eq!(strip_pskt_magic(b"PSKTx"), Ok(b"x".as_slice()));
    assert_eq!(strip_pskt_magic(b"PSKBxy"), Ok(b"xy".as_slice()));
}

#[test]
fn serializer_exact_capacity_boundaries_preserve_canonical_bytes_and_tail() {
    let json = transaction_json(
        ",\"futureGlobal\":{\"nested\":[1,2,3]}",
        ",\"futureInput\":\"tail\"",
        ",\"futureOutput\":true",
    );
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse capacity fixture");

    let mut measure = vec![0u8; 16_384];
    let required = serialize_pskt(
        &tx,
        &parsed,
        &scratch,
        TxInputFormat::PsktSingle,
        &mut measure,
    )
    .expect("measure canonical PSKT");
    measure.truncate(required);

    let mut one_short = vec![0u8; required - 1];
    assert_eq!(
        serialize_pskt(
            &tx,
            &parsed,
            &scratch,
            TxInputFormat::PsktSingle,
            &mut one_short,
        ),
        Err(PskError::OutputBufferTooSmall),
    );

    let mut exact = vec![0u8; required];
    assert_eq!(
        serialize_pskt(
            &tx,
            &parsed,
            &scratch,
            TxInputFormat::PsktSingle,
            &mut exact,
        ),
        Ok(required),
    );
    assert_eq!(exact, measure);

    let mut one_long = vec![0xa5u8; required + 1];
    assert_eq!(
        serialize_pskt(
            &tx,
            &parsed,
            &scratch,
            TxInputFormat::PsktSingle,
            &mut one_long,
        ),
        Ok(required),
    );
    assert_eq!(&one_long[..required], measure.as_slice());
    assert_eq!(one_long[required], 0xa5);
}

#[test]
fn serializer_accepts_maximum_output_and_script_capacity_and_rejects_next_value() {
    use crate::transaction::model::MAX_OUTPUTS;

    let json = transaction_json("", "", "");
    let (mut tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse maximum fixture");
    let template = tx.outputs[0].clone();
    for index in 0..MAX_OUTPUTS {
        tx.outputs[index] = template.clone();
        tx.outputs[index].value = index as u64 + 1;
    }
    tx.num_outputs = MAX_OUTPUTS;
    tx.inputs[0].utxo_entry.amount = (1..=MAX_OUTPUTS as u64).sum();

    let script_capacity = tx.outputs[0].script_public_key.script.len();
    tx.outputs[0].script_public_key.version = 0xabcd;
    tx.outputs[0].script_public_key.script_len = script_capacity;
    for (index, byte) in tx.outputs[0]
        .script_public_key
        .script
        .iter_mut()
        .enumerate()
    {
        *byte = index as u8;
    }

    let mut wire = vec![0u8; 32_768];
    let len = serialize_pskt(&tx, &parsed, &scratch, TxInputFormat::PsktSingle, &mut wire)
        .expect("maximum legal output/script shape must serialize");
    assert!(len > 4);

    tx.outputs[0].script_public_key.script_len = script_capacity + 1;
    assert_eq!(
        serialize_pskt(&tx, &parsed, &scratch, TxInputFormat::PsktSingle, &mut wire,),
        Err(PskError::InvalidScriptLen),
    );

    tx.outputs[0].script_public_key.script_len = 0;
    tx.num_outputs = MAX_OUTPUTS + 1;
    assert_eq!(
        serialize_pskt(&tx, &parsed, &scratch, TxInputFormat::PsktSingle, &mut wire,),
        Err(PskError::TooManyOutputs),
    );
}

#[test]
fn heap_serializer_does_not_retry_non_capacity_errors() {
    let json = transaction_json("", "", "");
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse retry fixture");
    assert_eq!(
        serialize_pskt_vec(&tx, &parsed, &scratch, TxInputFormat::KsptCompact),
        Err(PskError::UnexpectedToken),
    );
}

#[test]
fn canonical_pskt_wire_is_byte_idempotent_and_every_truncated_prefix_is_rejected() {
    let json = transaction_json(
        ",\"futureGlobal\":{\"a\":1}",
        ",\"futureInput\":{\"b\":[true,false]}",
        ",\"futureOutput\":\"tail\"",
    );
    let (tx, parsed, scratch) = parse_json(PSKT_MAGIC, &json).expect("parse canonical fixture");
    let canonical = serialize_pskt_vec(&tx, &parsed, &scratch, TxInputFormat::PsktSingle)
        .expect("canonical serialization");

    for end in 0..canonical.len() {
        let prefix = &canonical[..end];
        let decoded_capacity = prefix.len().saturating_sub(4).div_ceil(2).max(1);
        let mut prefix_scratch = vec![0u8; decoded_capacity];
        let mut prefix_tx = Transaction::try_new().expect("transaction test allocation");
        let mut prefix_parsed = PsktParsed::empty();
        assert!(
            parse_pskt(
                prefix,
                &mut prefix_scratch,
                &mut prefix_tx,
                &mut prefix_parsed
            )
            .is_err(),
            "truncated PSKT prefix of {end} bytes unexpectedly parsed",
        );
    }

    let mut reparsed_scratch = vec![0u8; (canonical.len() - 4) / 2];
    let mut reparsed_tx = Transaction::try_new().expect("transaction test allocation");
    let mut reparsed = PsktParsed::empty();
    parse_pskt(
        &canonical,
        &mut reparsed_scratch,
        &mut reparsed_tx,
        &mut reparsed,
    )
    .expect("canonical PSKT reparses");
    let second = serialize_pskt_vec(
        &reparsed_tx,
        &reparsed,
        &reparsed_scratch,
        TxInputFormat::PsktSingle,
    )
    .expect("canonical PSKT reserializes");
    assert_eq!(second, canonical);
}
