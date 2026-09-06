use crate::transaction::model::{Transaction, MAX_OUTPUTS, MAX_PAYLOAD_SIZE, MAX_SCRIPT_SIZE};
use alloc::{vec, vec::Vec};

use super::super::{
    parse_compact_kspt, serialize_compact_kspt, serialize_compact_kspt_vec, PsktError,
};
use super::common::{add_single_signature, set_p2sh_script, transaction};

#[test]
fn canonical_wire_error_adapter_maps_every_wire_category() {
    use super::super::wire_adapter::map_wire_error;
    use kassigner_protocol::wire::kspt::WireError;

    for (wire, expected) in [
        (WireError::BufferTooShort, PsktError::BufferTooShort),
        (
            WireError::OutputBufferTooSmall,
            PsktError::OutputBufferTooSmall,
        ),
        (WireError::InvalidMagic, PsktError::InvalidMagic),
        (WireError::UnsupportedVersion, PsktError::UnsupportedVersion),
        (WireError::InvalidFlags, PsktError::InvalidFlags),
        (WireError::CountOverflow, PsktError::InvalidModel),
        (WireError::ScriptTooLong, PsktError::ScriptTooLong),
        (WireError::RedeemTooLong, PsktError::ScriptTooLong),
        (WireError::TooManySignatures, PsktError::TooManySignatures),
        (
            WireError::DuplicateSignaturePosition,
            PsktError::InvalidSignatureState,
        ),
        (WireError::InvalidSigHashType, PsktError::InvalidSigHashType),
        (WireError::InvalidNetwork, PsktError::InvalidTrailer),
        (WireError::MissingNetwork, PsktError::InvalidTrailer),
        (WireError::InvalidTrailer, PsktError::InvalidTrailer),
        (WireError::TrailingData, PsktError::TrailingData),
        (WireError::TooManyInputs, PsktError::TooManyInputs),
        (WireError::TooManyOutputs, PsktError::TooManyOutputs),
        (WireError::PayloadTooLong, PsktError::PayloadTooLong),
    ] {
        assert_eq!(map_wire_error(wire), expected, "{wire:?}");
    }
}

#[test]
fn heap_compact_serializer_is_covered_by_round_trip_fixture() {
    let mut tx = transaction();
    tx.network = crate::address::KaspaNetwork::Mainnet;
    let wire = serialize_compact_kspt_vec(&tx).expect("heap compact serialization");
    assert_eq!(&wire[..5], b"KSPT\x04");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire, &mut parsed).expect("parse heap compact KSPT");
    assert_eq!(parsed.num_inputs, tx.num_inputs);
    assert_eq!(parsed.num_outputs, tx.num_outputs);
}

#[test]
fn compact_redeem_script_round_trips() {
    let mut tx = transaction();
    let redeem = [0x51, 0x20, 0x77, 0xac];
    set_p2sh_script(&mut tx, &redeem);
    add_single_signature(&mut tx, 0, [0x33; 64]);

    let mut wire = [0u8; 2048];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize compact KSPT");
    assert_eq!(&wire[..5], b"KSPT\x04");

    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse compact KSPT");
    assert_eq!(parsed.redeem_bytes(0), redeem);
    assert_eq!(parsed.inputs[0].sig_count, 1);
}

#[test]
fn compact_codec_accepts_exact_maximum_signature_slots() {
    use crate::transaction::model::MAX_SIGS_PER_INPUT;

    let mut tx = transaction();
    tx.inputs[0].sig_count = MAX_SIGS_PER_INPUT as u8;
    tx.inputs[0].sighash_type = 1;
    for (position, slot) in tx.inputs[0].sigs.iter_mut().enumerate() {
        slot.present = true;
        slot.pubkey_pos = position as u8;
        slot.sighash_type = 1;
        slot.signature = [position as u8 + 1; 64];
    }

    let mut wire = vec![0u8; 16_384];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize exact signature capacity");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse exact signature capacity");
    assert_eq!(parsed.inputs[0].sig_count as usize, MAX_SIGS_PER_INPUT);
    for (position, slot) in parsed.inputs[0].sigs.iter().enumerate() {
        assert!(slot.present);
        assert_eq!(slot.pubkey_pos, position as u8);
        assert_eq!(slot.signature, [position as u8 + 1; 64]);
    }
}

#[test]
fn compact_covenant_binding_round_trips() {
    let mut tx = transaction();
    add_single_signature(&mut tx, 0, [0x44; 64]);
    tx.outputs[0].has_covenant = true;
    tx.outputs[0].covenant_auth_input = 0;
    tx.outputs[0].covenant_id = [0x42; 32];

    let mut wire = [0u8; 2048];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize compact KSPT");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse compact KSPT");
    assert!(parsed.outputs[0].has_covenant);
    assert_eq!(parsed.outputs[0].covenant_id, [0x42; 32]);
}

#[test]
fn compact_v4_binds_network_and_output_derivation_hint() {
    let mut tx = transaction();
    tx.network = crate::address::KaspaNetwork::Testnet;
    tx.outputs[0].has_derivation_hint = true;
    tx.outputs[0].derivation_branch = 1;
    tx.outputs[0].derivation_index = 37;

    let mut wire = [0u8; 4096];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize v4 KSPT");
    assert_eq!(&wire[..5], b"KSPT\x04");

    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse v4 KSPT");
    assert_eq!(parsed.network, crate::address::KaspaNetwork::Testnet);
    assert!(parsed.outputs[0].has_derivation_hint);
    assert_eq!(parsed.outputs[0].derivation_branch, 1);
    assert_eq!(parsed.outputs[0].derivation_index, 37);
}

#[test]
fn compact_parser_rejects_old_generations() {
    let mut tx = transaction();
    add_single_signature(&mut tx, 0, [0x55; 64]);
    let mut wire = [0u8; 2048];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize compact KSPT");
    for generation in [1u8, 2u8, 3u8] {
        wire[4] = generation;
        let mut parsed = Transaction::try_new().expect("transaction test allocation");
        assert_eq!(
            parse_compact_kspt(&wire[..len], &mut parsed),
            Err(PsktError::UnsupportedVersion)
        );
    }
}

#[test]
fn compact_parser_does_not_preallocate_untrusted_v4_input_count() {
    // libFuzzer/ASan regression: this v4 corpus entry declares 2,046,820,367
    // inputs and zero outputs. The parser must reject the untrusted input count
    // at the global-count boundary before allocating or parsing input records.
    let crash = [
        75, 83, 80, 84, 4, 0, 176, 167, 15, 0, 0, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 66, 0, 0, 0,
        3, 75, 54, 54, 54, 54, 54, 0, 83, 80, 84, 3, 83, 80, 0,
    ];
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&crash, &mut parsed),
        Err(PsktError::TooManyInputs)
    );
    assert_eq!(
        parsed.inputs.len(),
        crate::transaction::model::DEFAULT_INPUT_CAPACITY
    );
}

#[test]
fn compact_parser_grows_inputs_only_as_wire_records_are_consumed() {
    // Complete v4 global section with one output, but no input body at all.
    // A declared u32::MAX count must fail at the bounded global-count check
    // without attempting to reserve or consume any TransactionInput records.
    let mut wire = [0u8; 51];
    wire[..4].copy_from_slice(b"KSPT");
    wire[4] = 4;
    wire[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    wire[12] = 1;

    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire, &mut parsed),
        Err(PsktError::TooManyInputs)
    );
    assert_eq!(
        parsed.inputs.len(),
        crate::transaction::model::DEFAULT_INPUT_CAPACITY
    );
    assert_eq!(parsed.num_inputs, 0);
}

#[test]
fn compact_parser_rejects_unknown_flags_and_trailing_bytes() {
    let mut tx = transaction();
    add_single_signature(&mut tx, 0, [0x66; 64]);
    let mut wire = [0u8; 2048];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize compact KSPT");

    wire[5] |= 0x80;
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire[..len], &mut parsed),
        Err(PsktError::InvalidFlags)
    );

    wire[5] &= !0x80;
    wire[len] = 0;
    assert_eq!(
        parse_compact_kspt(&wire[..len + 1], &mut parsed),
        Err(PsktError::TrailingData)
    );
}

#[test]
fn compact_serializer_accepts_more_than_the_historical_eight_inputs() {
    const MANY_INPUTS: usize = 16;
    let mut tx = transaction();
    tx.ensure_input_slots(MANY_INPUTS).expect("grow inputs");
    let template = tx.inputs[0].clone();
    for input in &mut tx.inputs[..MANY_INPUTS] {
        *input = template.clone();
    }
    tx.num_inputs = MANY_INPUTS;
    let mut wire = vec![0u8; 16_384];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("dynamic input KSPT");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse dynamic input KSPT");
    assert_eq!(parsed.num_inputs, MANY_INPUTS);
}

#[test]
fn compact_codec_accepts_dynamic_inputs_and_fixed_global_boundaries() {
    const MANY_INPUTS: usize = 16;
    let mut tx = transaction();
    tx.ensure_input_slots(MANY_INPUTS).expect("grow inputs");
    let template = tx.inputs[0].clone();
    for input in &mut tx.inputs[..MANY_INPUTS] {
        *input = template.clone();
    }
    tx.num_inputs = MANY_INPUTS;
    tx.num_outputs = MAX_OUTPUTS;
    tx.payload_len = MAX_PAYLOAD_SIZE;
    tx.payload[..MAX_PAYLOAD_SIZE].fill(0x5a);
    tx.inputs[0].utxo_entry.script_public_key.script_len = MAX_SCRIPT_SIZE;
    tx.inputs[0].utxo_entry.script_public_key.script[..MAX_SCRIPT_SIZE].fill(0x61);
    tx.outputs[0].script_public_key.script_len = MAX_SCRIPT_SIZE;
    tx.outputs[0].script_public_key.script[..MAX_SCRIPT_SIZE].fill(0x62);
    add_single_signature(&mut tx, 0, [0x63; 64]);

    let mut wire = [0u8; 16_384];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize exact limits");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse exact limits");
    assert_eq!(parsed.num_inputs, MANY_INPUTS);
    assert_eq!(parsed.num_outputs, MAX_OUTPUTS);
    assert_eq!(parsed.payload_len, MAX_PAYLOAD_SIZE);
    assert_eq!(
        &parsed.payload[..MAX_PAYLOAD_SIZE],
        &[0x5a; MAX_PAYLOAD_SIZE]
    );
    assert_eq!(
        parsed.inputs[0].utxo_entry.script_public_key.script_len,
        MAX_SCRIPT_SIZE
    );
    assert_eq!(
        parsed.outputs[0].script_public_key.script_len,
        MAX_SCRIPT_SIZE
    );
}

fn unsigned_compact_wire() -> (Vec<u8>, usize) {
    let tx = transaction();
    let mut wire = vec![0u8; 4096];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize unsigned compact KSPT");
    (wire, len)
}

// Generation 4 uses a u32 input count. Keep the mutation offsets derived from
// the wire layout so these boundary tests do not silently retain v3 offsets.
const V4_INPUT_COUNT_OFFSET: usize = 4 + 1 + 1 + 2;
const V4_OUTPUT_COUNT_OFFSET: usize = V4_INPUT_COUNT_OFFSET + 4;
const V4_PAYLOAD_LEN_OFFSET: usize = V4_OUTPUT_COUNT_OFFSET + 1 + 8 + 20 + 8;
const V4_FIRST_INPUT_OFFSET: usize = V4_PAYLOAD_LEN_OFFSET + 2;
const V4_FIRST_INPUT_SPK_LEN_OFFSET: usize = V4_FIRST_INPUT_OFFSET + 32 + 4 + 8 + 8 + 1 + 2;
const FIXTURE_INPUT_SPK_LEN: usize = 34;
const V4_FIRST_OUTPUT_OFFSET: usize =
    V4_FIRST_INPUT_SPK_LEN_OFFSET + 1 + FIXTURE_INPUT_SPK_LEN + 1 + 2;
const V4_FIRST_OUTPUT_SPK_LEN_OFFSET: usize = V4_FIRST_OUTPUT_OFFSET + 8 + 2;
const V4_INPUT_AMOUNT_OFFSET_WITHIN_RECORD: usize = 32 + 4;
const V4_UNSIGNED_FIXTURE_INPUT_RECORD_LEN: usize =
    32 + 4 + 8 + 8 + 1 + 2 + 1 + FIXTURE_INPUT_SPK_LEN + 1 + 2;
const V4_FIXTURE_OUTPUT_RECORD_LEN: usize = 8 + 2 + 1 + FIXTURE_INPUT_SPK_LEN;

#[test]
fn compact_parser_rejects_monetary_overflow_and_accepts_exact_u64_max_boundary() {
    let mut exact_max = transaction();
    exact_max.ensure_input_slots(2).expect("second input slot");
    exact_max.inputs[1] = exact_max.inputs[0].clone();
    exact_max.num_inputs = 2;
    exact_max.inputs[0].utxo_entry.amount = u64::MAX;
    exact_max.inputs[1].utxo_entry.amount = 0;
    exact_max.outputs[0].value = u64::MAX;

    let mut wire = vec![0u8; 4096];
    let len = serialize_compact_kspt(&exact_max, &mut wire).expect("serialize exact max boundary");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(parse_compact_kspt(&wire[..len], &mut parsed), Ok(()));
    assert_eq!(
        parsed
            .checked_amounts()
            .expect("exact max totals")
            .input_total,
        u64::MAX
    );
    assert_eq!(parsed.checked_amounts().expect("exact max totals").fee, 0);

    let second_input_amount = V4_FIRST_INPUT_OFFSET
        + V4_UNSIGNED_FIXTURE_INPUT_RECORD_LEN
        + V4_INPUT_AMOUNT_OFFSET_WITHIN_RECORD;
    wire[second_input_amount..second_input_amount + 8].copy_from_slice(&1u64.to_le_bytes());
    let mut input_overflow = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire[..len], &mut input_overflow),
        Err(PsktError::InputAmountOverflow)
    );

    let mut output_overflow = transaction();
    output_overflow.num_outputs = 2;
    output_overflow.inputs[0].utxo_entry.amount = u64::MAX;
    output_overflow.outputs[0].value = u64::MAX;
    output_overflow.outputs[1] = output_overflow.outputs[0].clone();
    output_overflow.outputs[1].value = 0;
    let output_len = serialize_compact_kspt(&output_overflow, &mut wire)
        .expect("serialize output overflow precursor");
    let second_output_amount = V4_FIRST_OUTPUT_OFFSET + V4_FIXTURE_OUTPUT_RECORD_LEN;
    wire[second_output_amount..second_output_amount + 8].copy_from_slice(&1u64.to_le_bytes());
    let mut parsed_output_overflow = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire[..output_len], &mut parsed_output_overflow),
        Err(PsktError::OutputAmountOverflow)
    );

    let negative_fee = transaction();
    let negative_len =
        serialize_compact_kspt(&negative_fee, &mut wire).expect("serialize negative fee precursor");
    wire[V4_FIRST_OUTPUT_OFFSET..V4_FIRST_OUTPUT_OFFSET + 8]
        .copy_from_slice(&(negative_fee.inputs[0].utxo_entry.amount + 1).to_le_bytes());
    let mut parsed_negative_fee = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire[..negative_len], &mut parsed_negative_fee),
        Err(PsktError::OutputsExceedInputs)
    );
}

#[test]
fn compact_parser_rejects_each_global_count_and_payload_overflow_boundary() {
    for (offset, value, expected) in [
        (V4_INPUT_COUNT_OFFSET, 0u8, PsktError::NoInputs),
        (V4_OUTPUT_COUNT_OFFSET, 0, PsktError::NoOutputs),
        (
            V4_OUTPUT_COUNT_OFFSET,
            (MAX_OUTPUTS + 1) as u8,
            PsktError::TooManyOutputs,
        ),
    ] {
        let (mut wire, len) = unsigned_compact_wire();
        wire[offset] = value;
        let mut parsed = Transaction::try_new().expect("transaction test allocation");
        assert_eq!(parse_compact_kspt(&wire[..len], &mut parsed), Err(expected));
    }

    let (mut wire, len) = unsigned_compact_wire();
    wire[V4_PAYLOAD_LEN_OFFSET..V4_PAYLOAD_LEN_OFFSET + 2]
        .copy_from_slice(&((MAX_PAYLOAD_SIZE + 1) as u16).to_le_bytes());
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire[..len], &mut parsed),
        Err(PsktError::PayloadTooLong)
    );
}

#[test]
fn compact_parser_rejects_oversized_input_and_output_scripts_before_copying() {
    let oversized = (MAX_SCRIPT_SIZE + 1) as u16;

    let (mut input_wire, input_len) = unsigned_compact_wire();
    input_wire[V4_FIRST_INPUT_SPK_LEN_OFFSET] = 0xff;
    input_wire[V4_FIRST_INPUT_SPK_LEN_OFFSET + 1..V4_FIRST_INPUT_SPK_LEN_OFFSET + 3]
        .copy_from_slice(&oversized.to_le_bytes());
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&input_wire[..input_len], &mut parsed),
        Err(PsktError::ScriptTooLong)
    );

    let (mut output_wire, output_len) = unsigned_compact_wire();
    output_wire[V4_FIRST_OUTPUT_SPK_LEN_OFFSET] = 0xff;
    output_wire[V4_FIRST_OUTPUT_SPK_LEN_OFFSET + 1..V4_FIRST_OUTPUT_SPK_LEN_OFFSET + 3]
        .copy_from_slice(&oversized.to_le_bytes());
    assert_eq!(
        parse_compact_kspt(&output_wire[..output_len], &mut parsed),
        Err(PsktError::ScriptTooLong)
    );
}

fn append_covenant_trailer(
    wire: &mut [u8],
    mut pos: usize,
    output: u8,
    authorizer: u16,
    id: u8,
) -> usize {
    wire[pos] = b'C';
    pos += 1;
    wire[pos] = output;
    pos += 1;
    wire[pos..pos + 2].copy_from_slice(&authorizer.to_le_bytes());
    pos += 2;
    wire[pos..pos + 32].fill(id);
    pos + 32
}

#[test]
fn compact_trailers_cover_stealth_serialization_duplicates_and_covenant_validation() {
    let mut tx = transaction();
    tx.has_stealth_tweak = true;
    tx.stealth_tweak = [0x77; 32];
    let mut wire = vec![0u8; 4096];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("stealth trailer serialize");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("stealth trailer parse");
    assert!(parsed.has_stealth_tweak);
    assert_eq!(parsed.stealth_tweak, [0x77; 32]);

    let (mut duplicate_stealth, base_len) = unsigned_compact_wire();
    let mut pos = base_len;
    for value in [0x11u8, 0x22] {
        duplicate_stealth[pos] = b'S';
        pos += 1;
        duplicate_stealth[pos..pos + 32].fill(value);
        pos += 32;
    }
    assert_eq!(
        parse_compact_kspt(&duplicate_stealth[..pos], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );

    let (mut bad_output, base_len) = unsigned_compact_wire();
    let end = append_covenant_trailer(&mut bad_output, base_len, 1, 0, 0x31);
    assert_eq!(
        parse_compact_kspt(&bad_output[..end], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );

    let (mut duplicate_covenant, base_len) = unsigned_compact_wire();
    let first = append_covenant_trailer(&mut duplicate_covenant, base_len, 0, 0, 0x41);
    let end = append_covenant_trailer(&mut duplicate_covenant, first, 0, 0, 0x42);
    assert_eq!(
        parse_compact_kspt(&duplicate_covenant[..end], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );

    let (mut bad_authorizer, base_len) = unsigned_compact_wire();
    let end = append_covenant_trailer(&mut bad_authorizer, base_len, 0, 1, 0x51);
    assert_eq!(
        parse_compact_kspt(&bad_authorizer[..end], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );
}

fn v4_network_wire(network: crate::address::KaspaNetwork) -> (Vec<u8>, usize) {
    let mut tx = transaction();
    tx.network = network;
    let mut wire = vec![0u8; 4096];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize v4 network fixture");
    assert_eq!(&wire[..5], b"KSPT\x04");
    assert_eq!(&wire[len - 2..len], &[b'N', network as u8]);
    (wire, len)
}

fn append_derivation_trailer(
    wire: &mut [u8],
    mut pos: usize,
    output: u8,
    branch: u8,
    index: u32,
) -> usize {
    wire[pos] = b'D';
    pos += 1;
    wire[pos] = output;
    pos += 1;
    wire[pos] = branch;
    pos += 1;
    wire[pos..pos + 4].copy_from_slice(&index.to_le_bytes());
    pos + 4
}

fn append_input_derivation_trailer(
    wire: &mut [u8],
    mut pos: usize,
    input: u8,
    branch: u8,
    index: u32,
) -> usize {
    wire[pos] = b'A';
    pos += 1;
    wire[pos] = input;
    pos += 1;
    wire[pos] = branch;
    pos += 1;
    wire[pos..pos + 4].copy_from_slice(&index.to_le_bytes());
    pos + 4
}

#[test]
fn compact_v4_input_derivation_hint_round_trips_and_rejects_untrusted_values() {
    let mut tx = transaction();
    tx.inputs[0].has_derivation_hint = true;
    tx.inputs[0].derivation_branch = 1;
    tx.inputs[0].derivation_index = 500;
    let mut wire = [0u8; 4096];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize input hint");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse input hint");
    assert!(parsed.inputs[0].has_derivation_hint);
    assert_eq!(parsed.inputs[0].derivation_branch, 1);
    assert_eq!(parsed.inputs[0].derivation_index, 500);

    let (mut bad_branch, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let end = append_input_derivation_trailer(&mut bad_branch, len, 0, 2, 1);
    assert_eq!(
        parse_compact_kspt(&bad_branch[..end], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );

    let (mut hardened, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let end = append_input_derivation_trailer(&mut hardened, len, 0, 0, 0x8000_0000);
    assert_eq!(
        parse_compact_kspt(&hardened[..end], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );

    let (mut duplicate, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let first = append_input_derivation_trailer(&mut duplicate, len, 0, 0, 1);
    let end = append_input_derivation_trailer(&mut duplicate, first, 0, 0, 2);
    assert_eq!(
        parse_compact_kspt(&duplicate[..end], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );
}

#[test]
fn compact_v4_requires_one_valid_network_trailer() {
    let (mut wire, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let mut parsed = Transaction::try_new().expect("transaction test allocation");

    assert_eq!(
        parse_compact_kspt(&wire[..len - 2], &mut parsed),
        Err(PsktError::InvalidTrailer),
    );

    wire[len - 1] = 0xff;
    assert_eq!(
        parse_compact_kspt(&wire[..len], &mut parsed),
        Err(PsktError::InvalidTrailer),
    );

    let (mut duplicate, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    duplicate[len] = b'N';
    duplicate[len + 1] = crate::address::KaspaNetwork::Testnet as u8;
    assert_eq!(
        parse_compact_kspt(&duplicate[..len + 2], &mut parsed),
        Err(PsktError::InvalidTrailer),
    );

    let (mut trailing, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    trailing[len] = b'X';
    assert_eq!(
        parse_compact_kspt(&trailing[..len + 1], &mut parsed),
        Err(PsktError::TrailingData),
    );
}

#[test]
fn compact_v4_derivation_trailers_reject_bad_position_branch_and_duplicates() {
    let mut parsed = Transaction::try_new().expect("transaction test allocation");

    let (mut bad_output, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let end = append_derivation_trailer(&mut bad_output, len, 1, 0, 9);
    assert_eq!(
        parse_compact_kspt(&bad_output[..end], &mut parsed),
        Err(PsktError::InvalidTrailer),
    );

    let (mut bad_branch, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let end = append_derivation_trailer(&mut bad_branch, len, 0, 2, 9);
    assert_eq!(
        parse_compact_kspt(&bad_branch[..end], &mut parsed),
        Err(PsktError::InvalidTrailer),
    );

    let (mut duplicate, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let first = append_derivation_trailer(&mut duplicate, len, 0, 0, 9);
    let end = append_derivation_trailer(&mut duplicate, first, 0, 1, 10);
    assert_eq!(
        parse_compact_kspt(&duplicate[..end], &mut parsed),
        Err(PsktError::InvalidTrailer),
    );

    let (mut hardened, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    let end = append_derivation_trailer(&mut hardened, len, 0, 0, 0x8000_0000);
    assert_eq!(
        parse_compact_kspt(&hardened[..end], &mut parsed),
        Err(PsktError::InvalidTrailer)
    );
}

#[test]
fn compact_v4_serializer_refuses_derivation_hint_without_network_binding() {
    let mut tx = transaction();
    tx.network = crate::address::KaspaNetwork::Unknown;
    tx.outputs[0].has_derivation_hint = true;
    tx.outputs[0].derivation_branch = 1;
    tx.outputs[0].derivation_index = 8;
    let mut wire = [0u8; 4096];
    assert_eq!(
        serialize_compact_kspt(&tx, &mut wire),
        Err(PsktError::InvalidModel)
    );
}

#[test]
fn compact_unknown_trailer_is_rejected_by_canonical_codec() {
    let (mut wire, len) = v4_network_wire(crate::address::KaspaNetwork::Mainnet);
    wire[len] = b'Z';
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire[..len + 1], &mut parsed),
        Err(PsktError::TrailingData)
    );
}

#[test]
fn compact_v4_hd45_input_and_change_hints_round_trip_and_reject_duplicates() {
    use crate::transaction::model::Ms45Hint;
    let mut tx = transaction();
    tx.inputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 2,
        chain: 0,
        index: 17,
    };
    tx.outputs[0].ms45_hint = Ms45Hint {
        present: true,
        cosigner: 2,
        chain: 1,
        index: 9,
    };
    let mut wire = vec![0u8; 4096];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize 45' v4 hints");
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..len], &mut parsed).expect("parse 45' v4 hints");
    assert_eq!(parsed.inputs[0].ms45_hint, tx.inputs[0].ms45_hint);
    assert_eq!(parsed.outputs[0].ms45_hint, tx.outputs[0].ms45_hint);

    wire.truncate(len);
    wire.push(b'I');
    wire.push(0);
    wire.extend_from_slice(&2u32.to_le_bytes());
    wire.extend_from_slice(&0u32.to_le_bytes());
    wire.extend_from_slice(&17u32.to_le_bytes());
    let mut duplicate = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire, &mut duplicate),
        Err(PsktError::InvalidTrailer)
    );
}

#[test]
fn compact_v4_rejects_invalid_hd45_chain_without_trusting_the_hint() {
    let tx = transaction();
    let mut wire = vec![0u8; 4096];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize v4 base");
    wire.truncate(len);
    wire.push(b'I');
    wire.push(0);
    wire.extend_from_slice(&1u32.to_le_bytes());
    wire.extend_from_slice(&2u32.to_le_bytes());
    wire.extend_from_slice(&0u32.to_le_bytes());
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire, &mut parsed),
        Err(PsktError::InvalidTrailer)
    );
}

#[test]
fn canonical_decode_adapter_and_heap_retry_arms_are_characterized() {
    use super::super::wire_adapter::{map_decode_error, serialize_vec_with_capacity};
    use kassigner_protocol::wire::kspt::{DecodeError, WireError};

    assert_eq!(
        map_decode_error(DecodeError::Wire(WireError::InvalidMagic)),
        PsktError::InvalidMagic,
    );
    assert_eq!(
        map_decode_error(DecodeError::Sink(PsktError::NoInputs)),
        PsktError::NoInputs,
    );

    // Start deliberately below the minimum wire size so the heap serializer must
    // take its OutputBufferTooSmall growth/retry arm before succeeding.
    let tx = transaction();
    let wire = serialize_vec_with_capacity(&tx, 1).expect("heap retry must grow to fit KSPT");
    assert_eq!(&wire[..5], b"KSPT\x04");

    // A non-buffer serialization error must take the terminal Err(error) arm,
    // rather than being mistaken for a reason to keep growing the allocation.
    let mut invalid = transaction();
    invalid.network = crate::address::KaspaNetwork::Unknown;
    assert_eq!(
        serialize_vec_with_capacity(&invalid, 4096).unwrap_err(),
        PsktError::InvalidModel,
    );
}

#[test]
fn compact_parser_rejects_signed_flag_when_transaction_is_not_fully_signed() {
    let tx = transaction();
    let mut wire = [0u8; 2048];
    let len = serialize_compact_kspt(&tx, &mut wire).expect("serialize unsigned compact KSPT");
    assert_eq!(
        wire[5] & kassigner_protocol::wire::kspt::FLAG_SIGNED_OR_COMPLETE,
        0
    );

    wire[5] |= kassigner_protocol::wire::kspt::FLAG_SIGNED_OR_COMPLETE;
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    assert_eq!(
        parse_compact_kspt(&wire[..len], &mut parsed),
        Err(PsktError::InvalidSignatureState),
    );
}
