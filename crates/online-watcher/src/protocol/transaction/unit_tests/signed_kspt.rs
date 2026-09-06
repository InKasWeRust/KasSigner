use crate::protocol::transaction::{
    consensus::InputEncoding,
    signed_kspt::{decode_signed_kspt, ConsensusSink},
};

use kassigner_protocol::wire::kspt::{
    self as canonical_kspt, DecodeSink, Derivation, EncodeSource, Global, Input, Ms45Derivation,
    Output, Signature,
};

struct OneInputSource<'a> {
    script_public_key: &'a [u8],
    signature_count: u8,
    redeem: &'a [u8],
}

impl EncodeSource for OneInputSource<'_> {
    fn global(&self) -> Global<'_> {
        Global {
            flags: canonical_kspt::FLAG_SIGNED_OR_COMPLETE,
            version: 0,
            input_count: 1,
            output_count: 0,
            locktime: 0,
            subnetwork_id: [0; 20],
            gas: 0,
            payload: &[],
        }
    }

    fn input(&self, index: usize) -> Input<'_> {
        assert_eq!(index, 0);
        Input {
            previous_tx_id: [0x31; 32],
            previous_index: 7,
            amount: 99,
            sequence: 11,
            sig_op_count: 1,
            script_version: 0,
            script: self.script_public_key,
        }
    }

    fn signature_count(&self, input: usize) -> usize {
        assert_eq!(input, 0);
        usize::from(self.signature_count)
    }

    fn signature(&self, input: usize, slot: usize) -> Signature {
        assert_eq!(input, 0);
        Signature {
            position: u8::try_from(slot).expect("signature position"),
            sighash: 0x01,
            bytes: [0x40u8.saturating_add(u8::try_from(slot).expect("signature slot")); 64],
        }
    }

    fn redeem(&self, input: usize) -> &[u8] {
        assert_eq!(input, 0);
        self.redeem
    }

    fn output(&self, _index: usize) -> Output<'_> {
        unreachable!("fixture has no outputs")
    }

    fn network(&self) -> u8 {
        1
    }
    fn stealth(&self) -> Option<[u8; 32]> {
        None
    }
    fn input_derivation(&self, _index: usize) -> Option<canonical_kspt::Derivation> {
        None
    }
    fn output_derivation(&self, _index: usize) -> Option<canonical_kspt::Derivation> {
        None
    }
    fn input_ms45(&self, _index: usize) -> Option<canonical_kspt::Ms45Derivation> {
        None
    }
    fn output_ms45(&self, _index: usize) -> Option<canonical_kspt::Ms45Derivation> {
        None
    }
    fn covenant(&self, _index: usize) -> Option<canonical_kspt::Covenant> {
        None
    }
}

fn compact_one_input(script_public_key: &[u8], signature_count: u8, redeem: &[u8]) -> String {
    let source = OneInputSource {
        script_public_key,
        signature_count,
        redeem,
    };
    let mut bytes = [0u8; 4096];
    let written = canonical_kspt::encode(&source, &mut bytes).expect("canonical KSPT fixture");
    hex::encode(&bytes[..written])
}

fn p2sh_spk() -> Vec<u8> {
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(&[0x55; 32]);
    script.push(0x87);
    script
}

fn two_of_two_script() -> Vec<u8> {
    let mut script = vec![0x52, 0x20];
    script.extend_from_slice(&[0x11; 32]);
    script.push(0x20);
    script.extend_from_slice(&[0x22; 32]);
    script.extend_from_slice(&[0x52, 0xae]);
    script
}

const SIGNED_COMPACT_KSPT: &str = "4b53505404010000010000000100000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111010000006400000000000000000000000000000001000022204444444444444444444444444444444444444444444444444444444444444444ac0100012222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222200005a00000000000000000022205555555555555555555555555555555555555555555555555555555555555555ac4e01";

#[test]
fn signed_compact_kspt_decodes_to_consensus_transaction() {
    let transaction = decode_signed_kspt(SIGNED_COMPACT_KSPT).expect("KSPT should decode");
    assert_eq!(transaction.tx_version, 0);
    assert_eq!(transaction.input_encoding, InputEncoding::Compact);
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.inputs[0].prev_tx_id, [0x11; 32]);
    assert_eq!(transaction.inputs[0].prev_index, 1);
    assert_eq!(transaction.inputs[0].sig_script.len(), 66);
    assert_eq!(transaction.inputs[0].sig_script[0], 65);
    assert_eq!(transaction.inputs[0].sig_script[65], 1);
    assert_eq!(transaction.outputs[0].value, 90);
    assert_eq!(transaction.storage_mass, 1_111_111_111);
}

#[test]
fn old_kspt_generations_are_rejected() {
    for generation in [1u8, 2u8, 3u8] {
        let mut bytes = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
        bytes[4] = generation;
        assert!(decode_signed_kspt(&hex::encode(bytes)).is_err());
    }
}

#[test]
fn signed_kspt_script_classification_and_extra_signature_boundaries_are_exact() {
    let p2pk = {
        let mut script = vec![0x20];
        script.extend_from_slice(&[0x44; 32]);
        script.push(0xac);
        script
    };
    for count in [2u8, 3] {
        let tx = decode_signed_kspt(&compact_one_input(&p2pk, count, &[]))
            .expect("P2PK with redundant compact signatures");
        assert_eq!(tx.inputs[0].sig_script.len(), 66);
        assert_eq!(tx.inputs[0].sig_script[1], 0x40);
        assert_eq!(tx.inputs[0].sig_script[65], 1);
    }

    let p2sh = p2sh_spk();
    let redeem = vec![0x51, 0x20, 0x11, 0xae];
    let tx =
        decode_signed_kspt(&compact_one_input(&p2sh, 1, &redeem)).expect("P2SH signature route");
    assert!(tx.inputs[0].sig_script.ends_with(&redeem));
    assert!(tx.inputs[0].sig_script.len() > 66);

    // A non-small-int first opcode is not a threshold declaration: retain all
    // supplied signatures and append the redeem script rather than truncating.
    let no_threshold_redeem = vec![0x50, 0x20, 0x11, 0xae];
    let tx = decode_signed_kspt(&compact_one_input(&p2sh, 2, &no_threshold_redeem))
        .expect("P2SH non-threshold redeem route");
    assert_eq!(tx.inputs[0].sig_script[0], 65);
    assert_eq!(tx.inputs[0].sig_script[66], 65);
    assert!(tx.inputs[0].sig_script.ends_with(&no_threshold_redeem));

    let multisig = two_of_two_script();
    let tx = decode_signed_kspt(&compact_one_input(&multisig, 2, &[]))
        .expect("multisig signature route");
    assert_eq!(tx.inputs[0].sig_script.len(), 132);
    assert_eq!(tx.inputs[0].sig_script[1], 0x40);
    assert_eq!(tx.inputs[0].sig_script[67], 0x41);

    for index in [0usize, 1, 34] {
        let mut malformed = p2sh.clone();
        malformed[index] ^= 1;
        let tx = decode_signed_kspt(&compact_one_input(&malformed, 2, &[]))
            .expect("near-P2SH must route as P2PK");
        assert_eq!(tx.inputs[0].sig_script.len(), 66, "P2SH byte {index}");
    }
    let tx = decode_signed_kspt(&compact_one_input(&p2sh[..34], 2, &[]))
        .expect("short P2SH must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);

    let mut wrong_last = multisig.clone();
    *wrong_last.last_mut().unwrap() = 0xad;
    let tx = decode_signed_kspt(&compact_one_input(&wrong_last, 2, &[]))
        .expect("near-multisig last opcode must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
    let mut wrong_first = multisig.clone();
    wrong_first[0] = 0x50;
    let tx = decode_signed_kspt(&compact_one_input(&wrong_first, 2, &[]))
        .expect("near-multisig threshold must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
    let tx = decode_signed_kspt(&compact_one_input(&multisig[..36], 2, &[]))
        .expect("short multisig must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
}

#[test]
fn signed_kspt_global_fields_cover_payload_and_truncation_boundaries() {
    let mut bytes = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
    // The compact-v4 global payload length is the final u16 before the first input.
    // Replace the zero-length payload with two bytes and keep the remaining transaction intact.
    let payload_len_offset = 6 + 2 + 4 + 1 + 8 + 20 + 8;
    bytes[payload_len_offset..payload_len_offset + 2].copy_from_slice(&2u16.to_le_bytes());
    bytes.splice(payload_len_offset + 2..payload_len_offset + 2, [0xaa, 0xbb]);
    let transaction = decode_signed_kspt(&hex::encode(bytes)).expect("non-empty payload KSPT");
    assert_eq!(transaction.payload, vec![0xaa, 0xbb]);

    let global_start = 6usize;
    for end in [
        global_start + 1,                  // tx version
        global_start + 2 + 3,              // input count
        global_start + 2 + 4 + 1 + 8 + 19, // subnetwork id
        payload_len_offset + 1,            // payload length
    ] {
        let bytes = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
        assert!(decode_signed_kspt(&hex::encode(&bytes[..end])).is_err());
    }

    let mut truncated_payload = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
    truncated_payload.truncate(payload_len_offset + 2);
    truncated_payload[payload_len_offset..payload_len_offset + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    truncated_payload.extend_from_slice(&[0xaa, 0xbb]);
    assert_eq!(
        decode_signed_kspt(&hex::encode(truncated_payload)).unwrap_err(),
        "KSPT is truncated",
    );
}

#[test]
fn signed_kspt_exact_header_boundary_preserves_wire_error() {
    assert_eq!(
        decode_signed_kspt(&hex::encode(b"KSPT\x04\x01")).unwrap_err(),
        "KSPT is truncated",
    );
}

#[test]
fn signed_kspt_rejects_short_wrong_magic_incomplete_and_unsigned_inputs() {
    assert_eq!(decode_signed_kspt("").unwrap_err(), "KSPT is truncated");
    assert_eq!(
        decode_signed_kspt(&hex::encode(b"NOPE\x04\x01")).unwrap_err(),
        "invalid KSPT magic",
    );

    let mut incomplete = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
    incomplete[5] = 0;
    assert_eq!(
        decode_signed_kspt(&hex::encode(incomplete)).unwrap_err(),
        "Compact KSPT is not fully signed"
    );

    let mut p2pk = vec![0x20];
    p2pk.extend_from_slice(&[0x44; 32]);
    p2pk.push(0xac);
    assert_eq!(
        decode_signed_kspt(&compact_one_input(&p2pk, 0, &[])).unwrap_err(),
        "Input has no signatures"
    );
}

#[test]
fn p2sh_compact_signature_without_redeem_does_not_append_one() {
    let p2sh = p2sh_spk();
    let tx = decode_signed_kspt(&compact_one_input(&p2sh, 1, &[]))
        .expect("P2SH compact signature without redeem");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
    assert_eq!(tx.inputs[0].sig_script[0], 65);
}
#[test]
fn signed_kspt_rejects_non_hex_before_wire_decode() {
    assert!(decode_signed_kspt("zz")
        .unwrap_err()
        .starts_with("Invalid hex:"));
}

#[test]
fn consensus_sink_defensive_callbacks_and_trailers_are_characterized() {
    assert_eq!(
        ConsensusSink::default().finish().unwrap_err(),
        "KSPT global record is missing",
    );

    let global = Global {
        flags: canonical_kspt::FLAG_SIGNED_OR_COMPLETE,
        version: 0,
        input_count: 1,
        output_count: 1,
        locktime: 7,
        subnetwork_id: [0x10; 20],
        gas: 9,
        payload: &[0xaa, 0xbb],
    };
    let mut p2pk = vec![0x20];
    p2pk.extend_from_slice(&[0x11; 32]);
    p2pk.push(0xac);
    let input = Input {
        previous_tx_id: [0x22; 32],
        previous_index: 3,
        amount: 100,
        sequence: 4,
        sig_op_count: 1,
        script_version: 0,
        script: &p2pk,
    };
    let output = Output {
        amount: 90,
        script_version: 0,
        script: &[0x51],
    };
    let signature = Signature {
        position: 0,
        sighash: 1,
        bytes: [0x33; 64],
    };

    let mut sink = ConsensusSink::default();
    sink.global(global).expect("global");
    assert_eq!(
        sink.input(1, input, 1).unwrap_err(),
        "KSPT input order is invalid"
    );
    assert_eq!(
        sink.input(u32::MAX, input, 1).unwrap_err(),
        "KSPT input order is invalid"
    );
    sink.input(0, input, 1).expect("input");
    assert_eq!(
        sink.signature(1, 0, signature).unwrap_err(),
        "KSPT signature input is invalid"
    );
    assert_eq!(
        sink.signature(u32::MAX, 0, signature).unwrap_err(),
        "KSPT signature input is invalid"
    );
    sink.signature(0, 0, signature).expect("signature");
    assert_eq!(
        sink.redeem(1, &[]).unwrap_err(),
        "KSPT redeem input is invalid"
    );
    assert_eq!(
        sink.redeem(u32::MAX, &[]).unwrap_err(),
        "KSPT redeem input is invalid"
    );
    sink.redeem(0, &[]).expect("redeem");
    assert_eq!(
        sink.output(1, output).unwrap_err(),
        "KSPT output order is invalid"
    );
    sink.output(0, output).expect("output");
    assert_eq!(
        sink.covenant(1, 0, [0x44; 32]).unwrap_err(),
        "invalid compact KSPT covenant trailer",
    );
    sink.covenant(0, 0, [0x44; 32]).expect("covenant");

    sink.network(4).expect("network");
    sink.stealth([0x55; 32]).expect("stealth");
    sink.input_derivation(
        0,
        Derivation {
            branch: 1,
            index: 7,
        },
    )
    .expect("input derivation");
    sink.output_derivation(
        0,
        Derivation {
            branch: 0,
            index: 8,
        },
    )
    .expect("output derivation");
    sink.input_ms45(
        0,
        Ms45Derivation {
            cosigner: 2,
            chain: 1,
            index: 9,
        },
    )
    .expect("input ms45");
    sink.output_ms45(
        0,
        Ms45Derivation {
            cosigner: 3,
            chain: 0,
            index: 10,
        },
    )
    .expect("output ms45");

    let transaction = sink.finish().expect("consensus transaction");
    assert_eq!(transaction.tx_version, 0);
    assert_eq!(transaction.locktime, 7);
    assert_eq!(transaction.gas, 9);
    assert_eq!(transaction.payload, vec![0xaa, 0xbb]);
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.outputs[0].covenant, Some((0, [0x44; 32])));
}

#[test]
fn signed_kspt_decode_error_adapter_preserves_wire_and_sink_errors() {
    use super::super::signed_kspt::decode_error;
    use kassigner_protocol::wire::kspt::{DecodeError, WireError};

    assert_eq!(
        decode_error(DecodeError::Wire(WireError::InvalidMagic)),
        "invalid KSPT magic",
    );
    assert_eq!(
        decode_error(DecodeError::Sink("sink boundary".to_string())),
        "sink boundary",
    );
}

#[test]
fn p2sh_threshold_opcode_uses_exact_declared_signature_count() {
    let redeem = vec![0x52, 0x20, 0x11, 0xae];
    let tx = decode_signed_kspt(&compact_one_input(&p2sh_spk(), 3, &redeem)).expect("2-of-N P2SH");
    // Two 66-byte signature pushes plus one-byte direct redeem push and four redeem bytes.
    assert_eq!(tx.inputs[0].sig_script.len(), 137);
    assert_eq!(tx.inputs[0].sig_script[0], 65);
    assert_eq!(tx.inputs[0].sig_script[66], 65);
    assert!(tx.inputs[0].sig_script.ends_with(&redeem));
}
