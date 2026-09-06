// KasSee Web — compact KSPT parser characterization tests
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use super::super::kspt_bridge::{
    parse_compact_kspt_signatures, parse_compact_kspt_transaction,
    require_compact_trailer_progress, xonly_at_position,
};

const SIGNATURE: [u8; 64] = [0x5a; 64];
const KEY_A: [u8; 32] = [0x11; 32];
const KEY_B: [u8; 32] = [0x22; 32];

#[test]
fn compact_parser_extracts_signatures_and_accepts_supported_trailers() {
    let mut trailers = stealth_trailer();
    trailers.extend(covenant_trailer(0, 0));
    let blob = compact_blob(&[SIGNATURE], &[0x51], &[0x01, 0x02], 1, &trailers);

    let parsed = parse_compact_kspt_signatures(&blob).unwrap();

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].len(), 1);
    assert_eq!(parsed[0][0].pubkey_pos, 0);
    assert_eq!(parsed[0][0].sighash_type, 0x01);
    assert_eq!(parsed[0][0].sig, SIGNATURE);
}

#[test]
fn compact_parser_accepts_empty_transaction_shape() {
    let blob = compact_blob(&[], &[], &[], 0, &[]);

    assert!(parse_compact_kspt_signatures(&blob).unwrap().is_empty());
}

#[test]
fn compact_parser_accepts_covenant_before_stealth_trailer() {
    let mut trailers = covenant_trailer(0, 0);
    trailers.extend(stealth_trailer());
    let blob = compact_blob(&[], &[0x51], &[], 1, &trailers);

    assert!(parse_compact_kspt_signatures(&blob).is_ok());
}

#[test]
fn compact_parser_rejects_magic_and_generation_mismatches() {
    let mut bad_magic = compact_blob(&[], &[], &[], 0, &[]);
    bad_magic[..4].copy_from_slice(b"NOPE");
    assert_eq!(parse_error(&bad_magic), "invalid KSPT magic");

    let mut bad_generation = compact_blob(&[], &[], &[], 0, &[]);
    for retired in [0x01, 0x02, 0x03] {
        bad_generation[4] = retired;
        assert_eq!(parse_error(&bad_generation), "unsupported KSPT generation");
    }
}

#[test]
fn compact_parser_rejects_every_truncated_required_prefix() {
    let required = compact_blob(&[SIGNATURE], &[0x51], &[0xaa], 1, &[]);
    for end in 0..required.len() {
        assert!(
            parse_compact_kspt_signatures(&required[..end]).is_err(),
            "required prefix of length {end} unexpectedly parsed"
        );
    }

    let with_stealth = compact_blob(&[SIGNATURE], &[0x51], &[0xaa], 1, &stealth_trailer());
    for end in required.len() + 1..with_stealth.len() {
        assert!(
            parse_compact_kspt_signatures(&with_stealth[..end]).is_err(),
            "partial stealth trailer of length {end} unexpectedly parsed"
        );
    }
}

#[test]
fn compact_parser_rejects_invalid_stealth_trailers() {
    let mut duplicate = stealth_trailer();
    duplicate.extend(stealth_trailer());
    let error = parse_error(&compact_blob(&[], &[], &[], 0, &duplicate));
    assert_eq!(error, "KSPT contains an invalid or duplicate trailer");

    let error = parse_error(&compact_blob(&[], &[], &[], 0, b"S"));
    assert!(error.starts_with("KSPT is truncated"));
}

#[test]
fn compact_parser_rejects_invalid_covenant_trailer_indexes() {
    let output_error = parse_error(&compact_blob(&[], &[0x51], &[], 1, &covenant_trailer(1, 0)));
    assert_eq!(
        output_error,
        "KSPT contains an invalid or duplicate trailer"
    );

    let input_error = parse_error(&compact_blob(&[], &[0x51], &[], 1, &covenant_trailer(0, 1)));
    assert_eq!(input_error, "KSPT contains an invalid or duplicate trailer");
}

#[test]
fn compact_parser_rejects_duplicate_covenant_output_and_unknown_trailer() {
    let mut duplicate = covenant_trailer(0, 0);
    duplicate.extend(covenant_trailer(0, 0));
    let duplicate_error = parse_error(&compact_blob(&[], &[0x51], &[], 1, &duplicate));
    assert_eq!(
        duplicate_error,
        "KSPT contains an invalid or duplicate trailer"
    );

    let unknown_error = parse_error(&compact_blob(&[], &[], &[], 0, b"X"));
    assert_eq!(unknown_error, "KSPT contains unrecognized trailing data");
}

#[test]
fn xonly_position_reads_p2pk_key() {
    let mut script = Vec::with_capacity(34);
    script.push(0x20);
    script.extend_from_slice(&KEY_A);
    script.push(0xac);

    assert_eq!(xonly_at_position(&script, 0), Some(KEY_A));
    assert_eq!(xonly_at_position(&script, 1), None);
}

#[test]
fn xonly_position_reads_standard_multisig_keys() {
    let script = standard_multisig_script();

    assert_eq!(xonly_at_position(&script, 0), Some(KEY_A));
    assert_eq!(xonly_at_position(&script, 1), Some(KEY_B));
    assert_eq!(xonly_at_position(&script, 2), None);
}

#[test]
fn xonly_position_scans_covenant_checksig_patterns() {
    let mut script = pushed_bytes(&[0x20, 0xac, 0x00]);
    append_checksig_key(&mut script, &KEY_A, None);
    append_checksig_key(&mut script, &KEY_B, Some(0x75));

    assert_eq!(xonly_at_position(&script, 0), Some(KEY_A));
    assert_eq!(xonly_at_position(&script, 1), Some(KEY_B));
    assert_eq!(xonly_at_position(&script, 2), None);
}

#[test]
fn xonly_position_honors_all_pushdata_lengths() {
    for prefix in [
        pushed_bytes(&[0x20, 0xac]),
        pushdata1(&[0x20, 0xac]),
        pushdata2(&[0x20, 0xac]),
        pushdata4(&[0x20, 0xac]),
    ] {
        let mut script = prefix;
        append_checksig_key(&mut script, &KEY_A, None);
        assert_eq!(xonly_at_position(&script, 0), Some(KEY_A));
    }
}

#[test]
fn xonly_position_handles_short_and_truncated_pushdata() {
    assert_eq!(xonly_at_position(&[], 0), None);
    assert_eq!(xonly_at_position(&[0x00, 0x00, 0x00, 0x4c], 0), None);
    assert_eq!(xonly_at_position(&[0x00, 0x00, 0x4d, 0x01], 0), None);
    assert_eq!(xonly_at_position(&[0x4e, 0x01, 0x00, 0x00], 0), None);
}

#[test]
fn xonly_position_rejects_malformed_multisig_shapes_and_missing_checksig() {
    assert_eq!(xonly_at_position(&[0x50, 0x20, 0x11, 0x51, 0xae], 0), None);
    assert_eq!(xonly_at_position(&[0x51, 0x20, 0x11, 0x50, 0xae], 0), None);

    let mut missing_checksig = vec![0x20];
    missing_checksig.extend_from_slice(&KEY_A);
    missing_checksig.push(0x75);
    assert_eq!(xonly_at_position(&missing_checksig, 0), None);
}

#[test]
fn compact_v4_parser_rejects_impossible_input_count_before_allocation() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"KSPT");
    blob.push(0x04);
    blob.push(0x00);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&u32::MAX.to_le_bytes());
    blob.push(1);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0u8; 20]);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());

    assert_eq!(parse_error(&blob), "KSPT count exceeds wire capacity",);
}

#[test]
fn compact_v4_parser_covers_network_and_derivation_trailer_contract() {
    for network in 1u8..=4 {
        let mut trailers = network_trailer(network);
        trailers.extend(derivation_trailer(0, 0, 7));
        trailers.extend(derivation_trailer(1, 1, 0x7fff_ffff));
        let wire = compact_v4_blob(2, &trailers);
        let parsed =
            parse_compact_kspt_signatures(&wire).expect("valid v4 network and derivation trailers");
        assert!(parsed.is_empty());

        let transaction =
            parse_compact_kspt_transaction(&wire).expect("v4 trailer metadata is retained");
        assert_eq!(transaction.network, network);
        assert_eq!(transaction.outputs[0].derivation, Some((0, 7)));
        assert_eq!(transaction.outputs[1].derivation, Some((1, 0x7fff_ffff)));
    }

    let missing_network = compact_v4_blob(1, &derivation_trailer(0, 1, 9));
    assert_eq!(
        parse_error(&missing_network),
        "KSPT v4 is missing its network trailer",
    );

    for invalid_network in [0u8, 5u8, u8::MAX] {
        assert_eq!(
            parse_error(&compact_v4_blob(0, &network_trailer(invalid_network))),
            "KSPT contains an invalid network code",
        );
    }

    let mut duplicate_network = network_trailer(1);
    duplicate_network.extend(network_trailer(2));
    assert_eq!(
        parse_error(&compact_v4_blob(0, &duplicate_network)),
        "KSPT contains an invalid network code",
    );

    let mut bad_branch = network_trailer(1);
    bad_branch.extend(derivation_trailer(0, 2, 3));
    assert_eq!(
        parse_error(&compact_v4_blob(1, &bad_branch)),
        "KSPT contains an invalid or duplicate trailer",
    );

    let mut bad_output = network_trailer(1);
    bad_output.extend(derivation_trailer(1, 0, 3));
    assert_eq!(
        parse_error(&compact_v4_blob(1, &bad_output)),
        "KSPT contains an invalid or duplicate trailer",
    );

    let mut duplicate_derivation = network_trailer(1);
    duplicate_derivation.extend(derivation_trailer(0, 0, 3));
    duplicate_derivation.extend(derivation_trailer(0, 1, 4));
    assert_eq!(
        parse_error(&compact_v4_blob(1, &duplicate_derivation)),
        "KSPT contains an invalid or duplicate trailer",
    );

    let mut truncated_network = network_trailer(1);
    truncated_network.pop();
    assert!(parse_error(&compact_v4_blob(0, &truncated_network)).starts_with("KSPT is truncated"));

    let mut truncated_derivation = network_trailer(1);
    truncated_derivation.extend_from_slice(b"D\x00\x01");
    assert!(
        parse_error(&compact_v4_blob(1, &truncated_derivation)).starts_with("KSPT is truncated")
    );
}

fn parse_error(blob: &[u8]) -> String {
    match parse_compact_kspt_signatures(blob) {
        Ok(_) => panic!("compact KSPT unexpectedly parsed"),
        Err(error) => error,
    }
}

fn compact_blob(
    signatures: &[[u8; 64]],
    redeem_script: &[u8],
    payload: &[u8],
    output_count: u8,
    trailers: &[u8],
) -> Vec<u8> {
    let input_count = u8::from(!signatures.is_empty() || !redeem_script.is_empty());
    let mut blob = Vec::new();
    blob.extend_from_slice(b"KSPT");
    blob.push(0x04);
    blob.push(0x00);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&u32::from(input_count).to_le_bytes());
    blob.push(output_count);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0u8; 20]);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    blob.extend_from_slice(payload);

    if input_count == 1 {
        blob.extend_from_slice(&[0x33; 32]);
        blob.extend_from_slice(&7u32.to_le_bytes());
        blob.extend_from_slice(&100u64.to_le_bytes());
        blob.extend_from_slice(&9u64.to_le_bytes());
        blob.push(1);
        blob.extend_from_slice(&0u16.to_le_bytes());
        append_compact_script(&mut blob, &[0x20, 0x44]);
        blob.push(signatures.len() as u8);
        for (position, signature) in signatures.iter().enumerate() {
            blob.push(position as u8);
            blob.push(1);
            blob.extend_from_slice(signature);
        }
        blob.extend_from_slice(&(redeem_script.len() as u16).to_le_bytes());
        blob.extend_from_slice(redeem_script);
    }

    for index in 0..output_count {
        blob.extend_from_slice(&(90 + index as u64).to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        let script = vec![index; 256];
        append_compact_script(&mut blob, &script);
    }
    blob.extend_from_slice(&network_trailer(1));
    blob.extend_from_slice(trailers);
    blob
}

fn compact_v4_blob(output_count: u8, trailers: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"KSPT");
    blob.push(0x04);
    blob.push(0x00);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.push(output_count);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0u8; 20]);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    for index in 0..output_count {
        blob.extend_from_slice(&(90 + u64::from(index)).to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        append_compact_script(&mut blob, &[index]);
    }
    blob.extend_from_slice(trailers);
    blob
}

fn network_trailer(network: u8) -> Vec<u8> {
    vec![b'N', network]
}

fn derivation_trailer(output_index: u8, branch: u8, index: u32) -> Vec<u8> {
    let mut trailer = vec![b'D', output_index, branch];
    trailer.extend_from_slice(&index.to_le_bytes());
    trailer
}

fn append_compact_script(blob: &mut Vec<u8>, script: &[u8]) {
    if script.len() < 0xff {
        blob.push(script.len() as u8);
    } else {
        blob.push(0xff);
        blob.extend_from_slice(&(script.len() as u16).to_le_bytes());
    }
    blob.extend_from_slice(script);
}

fn stealth_trailer() -> Vec<u8> {
    let mut trailer = vec![b'S'];
    trailer.extend_from_slice(&[0x77; 32]);
    trailer
}

fn covenant_trailer(output_index: u8, authorizing_input: u16) -> Vec<u8> {
    let mut trailer = vec![b'C', output_index];
    trailer.extend_from_slice(&authorizing_input.to_le_bytes());
    trailer.extend_from_slice(&[0x88; 32]);
    trailer
}

fn standard_multisig_script() -> Vec<u8> {
    let mut script = vec![0x52, 0x20];
    script.extend_from_slice(&KEY_A);
    script.push(0x20);
    script.extend_from_slice(&KEY_B);
    script.extend_from_slice(&[0x52, 0xae]);
    script
}

fn append_checksig_key(script: &mut Vec<u8>, key: &[u8; 32], gap: Option<u8>) {
    script.push(0x20);
    script.extend_from_slice(key);
    if let Some(opcode) = gap {
        script.push(opcode);
    }
    script.push(0xac);
}

fn pushed_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut script = vec![bytes.len() as u8];
    script.extend_from_slice(bytes);
    script
}

fn pushdata1(bytes: &[u8]) -> Vec<u8> {
    let mut script = vec![0x4c, bytes.len() as u8];
    script.extend_from_slice(bytes);
    script
}

fn pushdata2(bytes: &[u8]) -> Vec<u8> {
    let mut script = vec![0x4d];
    script.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    script.extend_from_slice(bytes);
    script
}

fn pushdata4(bytes: &[u8]) -> Vec<u8> {
    let mut script = vec![0x4e];
    script.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    script.extend_from_slice(bytes);
    script
}

#[test]
fn compact_transaction_trailer_progress_is_strict() {
    assert_eq!(require_compact_trailer_progress(2, 1), Ok(()));
    assert_eq!(
        require_compact_trailer_progress(1, 1).unwrap_err(),
        "compact KSPT trailer made no forward progress",
    );
    assert!(require_compact_trailer_progress(1, 2).is_err());
}

#[test]
fn compact_parser_accepts_exact_minimum_input_capacity_and_rejects_one_missing_input() {
    let exact = compact_v4_minimal_inputs(1, 1);
    let parsed = parse_compact_kspt_signatures(&exact).expect("one exact-minimum input must parse");
    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].is_empty());

    let insufficient = compact_v4_minimal_inputs(2, 1);
    assert_eq!(
        parse_error(&insufficient),
        "KSPT count exceeds wire capacity",
    );
}

#[test]
fn compact_parser_signature_capacity_is_exact_and_duplicate_positions_fail_closed() {
    let five = [SIGNATURE; 5];
    let accepted = compact_blob(&five, &[], &[], 0, &[]);
    let parsed = parse_compact_kspt_signatures(&accepted).expect("five signatures are supported");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].len(), 5);
    for (position, signature) in parsed[0].iter().enumerate() {
        assert_eq!(usize::from(signature.pubkey_pos), position);
        assert_eq!(signature.sighash_type, 0x01);
        assert_eq!(signature.sig, SIGNATURE);
    }

    let six = [SIGNATURE; 6];
    assert_eq!(
        parse_error(&compact_blob(&six, &[], &[], 0, &[])),
        "compact KSPT has too many signatures for one input",
    );

    let mut duplicate = accepted;
    let signature_count_offset = compact_v4_signature_count_offset(&duplicate);
    let first_record = signature_count_offset + 1;
    let second_record = first_record + 66;
    duplicate[second_record] = duplicate[first_record];
    assert_eq!(
        parse_error(&duplicate),
        "KSPT repeats a signature public-key position",
    );
}

#[test]
fn compact_parser_rejects_retired_generation_three() {
    let mut retired = compact_blob(&[], &[], &[], 0, &[]);
    retired[4] = 0x03;
    assert_eq!(parse_error(&retired), "unsupported KSPT generation",);
}

fn compact_v4_minimal_inputs(declared_inputs: u8, actual_inputs: usize) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"KSPT");
    blob.push(0x04);
    blob.push(0x00);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&u32::from(declared_inputs).to_le_bytes());
    blob.push(0); // outputs
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0u8; 20]);
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes()); // payload

    for index in 0..actual_inputs {
        blob.extend_from_slice(&[index as u8; 32]);
        blob.extend_from_slice(&(index as u32).to_le_bytes());
        blob.extend_from_slice(&1u64.to_le_bytes());
        blob.extend_from_slice(&u64::MAX.to_le_bytes());
        blob.push(0); // sig-op count
        blob.extend_from_slice(&0u16.to_le_bytes()); // script version
        blob.push(0); // compact script length
        blob.push(0); // signature count
        blob.extend_from_slice(&0u16.to_le_bytes()); // redeem script length
    }
    blob.extend_from_slice(&network_trailer(1));
    blob
}

fn compact_v4_signature_count_offset(blob: &[u8]) -> usize {
    let mut offset = 4 + 1 + 1 + 2 + 4 + 1 + 8 + 20 + 8;
    let payload_len = u16::from_le_bytes([blob[offset], blob[offset + 1]]) as usize;
    offset += 2 + payload_len;
    offset += 32 + 4 + 8 + 8 + 1 + 2;
    let first_script_length = usize::from(blob[offset]);
    offset += 1 + first_script_length;
    offset
}

#[test]
fn canonical_kassee_sink_callbacks_cover_success_and_fail_closed_targets() {
    use super::super::kspt_bridge::KasSeeSink;
    use kassigner_protocol::wire::kspt::{
        DecodeSink, Derivation, Global, Input, Ms45Derivation, Output, Signature,
    };

    let global = Global {
        flags: 0,
        version: 0,
        input_count: 1,
        output_count: 1,
        locktime: 7,
        subnetwork_id: [0x11; 20],
        gas: 9,
        payload: &[0xaa, 0xbb],
    };
    let input = Input {
        previous_tx_id: [0x22; 32],
        previous_index: 3,
        amount: 100,
        sequence: 4,
        sig_op_count: 1,
        script_version: 0,
        script: &[0x20, 0x33, 0xac],
    };
    let output = Output {
        amount: 90,
        script_version: 0,
        script: &[0x51],
    };
    let signature = Signature {
        position: 0,
        sighash: 1,
        bytes: [0x44; 64],
    };
    let derivation = Derivation {
        branch: 1,
        index: 17,
    };
    let ms45 = Ms45Derivation {
        cosigner: 2,
        chain: 1,
        index: 19,
    };

    assert_eq!(
        KasSeeSink::default().finish(0).unwrap_err(),
        "compact KSPT global record is missing"
    );

    let mut missing_network = KasSeeSink::default();
    missing_network.global(global).expect("global");
    assert_eq!(
        missing_network.finish(0).unwrap_err(),
        "compact KSPT network is missing"
    );

    let mut sink = KasSeeSink::default();
    sink.global(global).expect("global");
    assert_eq!(
        sink.input(1, input, 0).unwrap_err(),
        "compact KSPT input order is invalid"
    );
    assert_eq!(
        sink.input(u32::MAX, input, 0).unwrap_err(),
        "compact KSPT input order is invalid"
    );
    assert_eq!(
        sink.input(0, input, 6).unwrap_err(),
        "compact KSPT has too many signatures for one input"
    );
    sink.input(0, input, 1).expect("input");
    assert_eq!(
        sink.signature(1, 0, signature).unwrap_err(),
        "compact KSPT signature input is invalid"
    );
    assert_eq!(
        sink.signature(u32::MAX, 0, signature).unwrap_err(),
        "compact KSPT signature input is invalid"
    );
    sink.signature(0, 0, signature).expect("signature");
    assert_eq!(
        sink.redeem(1, &[0x51]).unwrap_err(),
        "compact KSPT redeem input is invalid"
    );
    assert_eq!(
        sink.redeem(u32::MAX, &[0x51]).unwrap_err(),
        "compact KSPT redeem input is invalid"
    );
    sink.redeem(0, &[0x51, 0xae]).expect("redeem");
    assert_eq!(
        sink.output(1, output).unwrap_err(),
        "compact KSPT output order is invalid"
    );
    sink.output(0, output).expect("output");

    assert_eq!(
        sink.input_derivation(1, derivation).unwrap_err(),
        "compact KSPT input derivation target is invalid"
    );
    assert_eq!(
        sink.output_derivation(1, derivation).unwrap_err(),
        "compact KSPT output derivation target is invalid"
    );
    assert_eq!(
        sink.input_ms45(1, ms45).unwrap_err(),
        "compact KSPT multisig input target is invalid"
    );
    assert_eq!(
        sink.output_ms45(1, ms45).unwrap_err(),
        "compact KSPT multisig output target is invalid"
    );
    assert_eq!(
        sink.covenant(1, 0, [0x55; 32]).unwrap_err(),
        "compact KSPT covenant output target is invalid"
    );

    sink.input_derivation(0, derivation)
        .expect("input derivation");
    sink.output_derivation(0, derivation)
        .expect("output derivation");
    sink.input_ms45(0, ms45).expect("input ms45");
    sink.output_ms45(0, ms45).expect("output ms45");
    sink.covenant(0, 0, [0x55; 32]).expect("covenant");
    sink.network(1).expect("network");
    sink.stealth([0x66; 32]).expect("stealth");

    let transaction = sink.finish(1).expect("complete sink");
    assert_eq!(transaction.flags, 1);
    assert_eq!(transaction.version, 0);
    assert_eq!(transaction.locktime, 7);
    assert_eq!(transaction.gas, 9);
    assert_eq!(transaction.payload, vec![0xaa, 0xbb]);
    assert_eq!(transaction.network, 1);
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.inputs[0].signatures.len(), 1);
    assert_eq!(transaction.inputs[0].redeem_script, vec![0x51, 0xae]);
    assert_eq!(transaction.inputs[0].derivation, Some((1, 17)));
    assert_eq!(transaction.inputs[0].ms45_derivation, Some((2, 1, 19)));
    assert_eq!(transaction.outputs[0].derivation, Some((1, 17)));
    assert_eq!(transaction.outputs[0].ms45_derivation, Some((2, 1, 19)));
    assert_eq!(transaction.outputs[0].covenant, Some((0, [0x55; 32])));
    assert_eq!(transaction.stealth_tweak, Some([0x66; 32]));
}

#[test]
fn canonical_kassee_decode_error_adapter_preserves_wire_and_sink_errors() {
    use super::super::kspt_bridge::decode_error_for_test;
    use kassigner_protocol::wire::kspt::{DecodeError, WireError};

    assert_eq!(
        decode_error_for_test(DecodeError::Wire(WireError::InvalidMagic)),
        "invalid KSPT magic",
    );
    assert_eq!(
        decode_error_for_test(DecodeError::Sink("sink boundary".to_string())),
        "sink boundary",
    );
}
