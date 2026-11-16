// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KSPT. Payloads are built field by field, not pasted as hex.

use kassigner_protocol::kspt::{
    legacy, parse, script_len_size, write_script_len, Field, KsptError, Record, Shape, MAGIC,
    VERSION,
};
use kassigner_protocol::profile::Profile;

const P: Profile = Profile::ESP32S3;

/// Builds a payload field by field.
#[derive(Default)]
struct Build {
    version: u8,
    flags: u8,
    tx_version: u16,
    lock_time: u64,
    subnetwork: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    records: Vec<u8>,
    /// Overrides the input count byte, for testing a lying header.
    ni_override: Option<u8>,
    no_override: Option<u8>,
}

fn spk_len_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; script_len_size(n)];
    let w = write_script_len(Field::Script, n, &mut b).unwrap();
    b.truncate(w);
    b
}

/// A canonical `0x06` input; unsigned, its signature count and redeem length
/// are zero.
fn input(spk: &[u8], signed: Option<(usize, &[u8], usize)>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0x11u8; 32]); // prev_tx_id
    b.extend_from_slice(&7u32.to_le_bytes()); // prev_index
    b.extend_from_slice(&100_000_000u64.to_le_bytes()); // amount
    b.extend_from_slice(&0u64.to_le_bytes()); // sequence
    b.push(1); // sig_op_count
    b.extend_from_slice(&0u16.to_le_bytes()); // spk_version
    b.extend_from_slice(&spk_len_bytes(spk.len()));
    b.extend_from_slice(spk);
    let (sig_count, redeem) = signed.map_or((0usize, &[][..]), |(n, r, _)| (n, r));
    b.push(sig_count as u8);
    for i in 0..sig_count {
        b.push(i as u8); // pubkey_pos
        b.push(0x01); // sighash_type
        b.extend_from_slice(&[0xAA; 64]);
    }
    b.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
    b.extend_from_slice(redeem);
    b
}

fn output(spk: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&50_000_000u64.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&spk_len_bytes(spk.len()));
    b.extend_from_slice(spk);
    b
}

impl Build {
    fn v(version: u8) -> Self {
        Self {
            version,
            ..Default::default()
        }
    }
    fn canonical() -> Self {
        Self::v(VERSION)
    }
    fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&MAGIC);
        b.push(self.version);
        b.push(self.flags);
        b.extend_from_slice(&self.tx_version.to_le_bytes());
        b.push(self.ni_override.unwrap_or(self.inputs.len() as u8));
        b.push(self.no_override.unwrap_or(self.outputs.len() as u8));
        b.extend_from_slice(&self.lock_time.to_le_bytes());
        b.extend_from_slice(&self.subnetwork);
        b.extend_from_slice(&self.gas.to_le_bytes());
        b.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.payload);
        for i in &self.inputs {
            b.extend_from_slice(i);
        }
        for o in &self.outputs {
            b.extend_from_slice(o);
        }
        b.extend_from_slice(&self.records);
        b
    }
}

fn minimal() -> Build {
    let mut b = Build::canonical();
    b.inputs.push(input(&[0xAA; 34], None));
    b.outputs.push(output(&[0xBB; 34]));
    b
}

/// The smallest well-formed payload parses, and every field comes back.
#[test]
fn a_minimal_payload_round_trips() {
    let bytes = minimal().bytes();
    let k = parse(&bytes, &P).expect("parse");

    assert_eq!(k.version, VERSION);
    assert_eq!(k.shape(), Shape::Canonical);
    assert_eq!(k.num_inputs, 1);
    assert_eq!(k.num_outputs, 1);
    assert!(k.payload.is_empty());

    let ins: Vec<_> = k.inputs().collect();
    assert_eq!(ins.len(), 1);
    assert_eq!(ins[0].prev_index, 7);
    assert_eq!(ins[0].amount, 100_000_000);
    assert_eq!(ins[0].spk, &[0xAA; 34][..]);
    assert_eq!(
        ins[0].sig_count, 0,
        "an unsigned version carries no signatures"
    );

    let outs: Vec<_> = k.outputs().collect();
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0].value, 50_000_000);
    assert_eq!(outs[0].spk, &[0xBB; 34][..]);
}

/// Signatures and the redeem script are always present on `0x06`, empty when
/// there is nothing to carry: no header bit decides a field's width.
#[test]
fn the_signature_and_redeem_fields_are_unconditional() {
    let bytes = minimal().bytes();
    let k = parse(&bytes, &P).expect("parse");
    let ins: Vec<_> = k.inputs().collect();
    assert_eq!(ins[0].sig_count, 0);
    assert!(ins[0].redeem.is_empty());
    assert_eq!(ins[0].signatures().count(), 0);

    // Signed, with a redeem script longer than a byte can count.
    let redeem = vec![0xCCu8; 300];
    let mut b = Build::canonical();
    b.inputs.push(input(&[0xAA; 34], Some((2, &redeem, 2))));
    b.outputs.push(output(&[0xBB; 34]));
    let bytes = b.bytes();

    let k = parse(&bytes, &P).expect("parse");
    let ins: Vec<_> = k.inputs().collect();
    assert_eq!(ins[0].sig_count, 2);
    assert_eq!(ins[0].redeem, &redeem[..]);

    let sigs: Vec<_> = ins[0].signatures().collect();
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].pubkey_pos, 0);
    assert_eq!(sigs[1].pubkey_pos, 1);
    assert_eq!(sigs[0].sighash_type, 0x01);
    assert_eq!(sigs[0].bytes, &[0xAA; 64][..]);
}

/// A key position holds one signature, and `0x06` holds them ascending, as
/// the writer emits them. Older versions are held only to one a position:
/// v1.0.7 appended signatures, so its replies can be descending.
#[test]
fn a_key_position_holds_one_signature() {
    let spk = [0xAA; 34];
    let redeem = [0xCC; 40];
    // An input as built, its signatures' positions put to `positions`.
    let placed = |mut input: Vec<u8>, positions: &[u8]| {
        let count_at = 32 + 4 + 8 + 8 + 1 + 2 + spk_len_bytes(spk.len()).len() + spk.len();
        assert_eq!(usize::from(input[count_at]), positions.len());
        for (k, p) in positions.iter().enumerate() {
            input[count_at + 1 + k * 66] = *p;
        }
        input
    };
    let canonical = |positions: &[u8]| {
        let mut b = Build::canonical();
        let signed = input(&spk, Some((positions.len(), &redeem[..], 0)));
        b.inputs.push(placed(signed, positions));
        b.outputs.push(output(&[0xBB; 34]));
        parse(&b.bytes(), &P).map(|k| {
            let i = k.inputs().next().unwrap();
            i.signatures().map(|s| s.pubkey_pos).collect::<Vec<_>>()
        })
    };
    assert_eq!(canonical(&[0, 2]), Ok(vec![0, 2]));
    assert_eq!(
        canonical(&[1, 1]),
        Err(KsptError::DuplicateSignature {
            input: 0,
            pubkey_pos: 1
        })
    );
    assert_eq!(
        canonical(&[2, 0]),
        Err(KsptError::SignaturesOutOfOrder {
            input: 0,
            pubkey_pos: 0
        })
    );

    for (version, width) in [(0x02u8, 1usize), (0x03, 2), (0x05, 2)] {
        let legacy = |positions: &[u8]| {
            let mut b = Build::v(version);
            let signed = legacy_multisig_input(&spk, positions.len(), &redeem, width);
            b.inputs.push(placed(signed, positions));
            b.outputs.push(output(&[0xBB; 34]));
            legacy::parse(&b.bytes(), &P).map(|k| {
                let i = k.inputs().next().unwrap();
                i.signatures().map(|s| s.pubkey_pos).collect::<Vec<_>>()
            })
        };
        assert_eq!(legacy(&[2, 0]), Ok(vec![2, 0]), "{version:#04x}");
        assert_eq!(
            legacy(&[0, 2, 0]),
            Err(KsptError::DuplicateSignature {
                input: 0,
                pubkey_pos: 0
            }),
            "{version:#04x}"
        );
    }
}

/// Flags are reserved on `0x06`, whose body shows signatures, a redeem and a
/// covenant itself: any bit set is refused.
#[test]
fn flags_are_reserved_on_the_canonical_version() {
    for bit in [0x01u8, 0x02, 0x04, 0x08, 0x80] {
        let mut b = minimal();
        b.flags = bit;
        assert_eq!(parse(&b.bytes(), &P), Err(KsptError::ReservedFlags(bit)));
    }
}

/// A legacy version gets `UseLegacyParser`, not `UnsupportedVersion`: a
/// reader exists.
#[test]
fn legacy_versions_are_routed_to_their_reader() {
    for v in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
        let mut b = minimal();
        b.version = v;
        assert_eq!(parse(&b.bytes(), &P), Err(KsptError::UseLegacyParser(v)));
    }
    for v in [0x00u8, 0x07, 0xFF] {
        let mut b = minimal();
        b.version = v;
        assert_eq!(parse(&b.bytes(), &P), Err(KsptError::UnsupportedVersion(v)));
    }
}

/// `parse_any` reads whichever version arrived.
#[test]
fn parse_any_reads_either() {
    let canonical = minimal().bytes();
    assert_eq!(legacy::parse_any(&canonical, &P).unwrap().version, VERSION);

    let mut b = Build::v(0x03);
    b.inputs
        .push(legacy_multisig_input(&[0xAA; 34], 1, &[0xCC; 40], 2));
    b.outputs.push(output(&[0xBB; 34]));
    let bytes = b.bytes();

    let k = legacy::parse_any(&bytes, &P).expect("legacy parses");
    assert_eq!(k.version, 0x03);
    assert_eq!(k.shape(), Shape::LegacyMultiSig { redeem_width: 2 });
    assert_eq!(k.inputs().next().unwrap().sig_count, 1);
}

/// The unsigned legacy shape reads its optional fields from the flags:
/// `0x02` adds a `u8` redeem to every input, `0x04` a covenant binding inside
/// every output.
#[test]
fn the_unsigned_legacy_shape_reads_its_flag_driven_fields() {
    let mut b = Build::v(0x01);
    b.flags = 0x02 | 0x04;
    // Four inputs: the binding below names the fourth, and must name one the
    // payload has.
    for _ in 0..4 {
        b.inputs
            .push(legacy_unsigned_input(&[0xAA; 34], Some(&[0xEE; 20])));
    }
    b.outputs.push(legacy_output_with_covenant(
        &[0xBB; 34],
        Some(([0x77; 32], 3)),
    ));
    b.outputs
        .push(legacy_output_with_covenant(&[0xBB; 20], None));
    let bytes = b.bytes();

    let k = legacy::parse(&bytes, &P).expect("parse");
    assert_eq!(
        k.shape(),
        Shape::LegacyUnsigned {
            has_redeem: true,
            has_covenant: true
        }
    );

    let ins: Vec<_> = k.inputs().collect();
    assert_eq!(ins[0].sig_count, 0, "this shape carries no signatures");
    assert_eq!(ins[0].redeem, &[0xEE; 20][..]);

    let outs: Vec<_> = k.outputs().collect();
    let cov = outs[0].covenant.expect("first output has a binding");
    assert_eq!(cov.authorizing_input, 3);
    assert_eq!(cov.covenant_id, [0x77; 32]);
    assert!(outs[1].covenant.is_none(), "second output has none");
}

/// The single-signature legacy shape carries one signature, as a length
/// rather than a count, and no redeem.
#[test]
fn the_single_signature_legacy_shape_reads_its_one_signature() {
    let mut b = Build::v(0x01);
    b.flags = 0x01;
    b.inputs.push(legacy_single_sig_input(&[0xAA; 34], true));
    b.inputs.push(legacy_single_sig_input(&[0xAA; 34], false));
    b.outputs.push(output(&[0xBB; 34]));
    let bytes = b.bytes();

    let k = legacy::parse(&bytes, &P).expect("parse");
    assert_eq!(
        k.shape(),
        Shape::LegacySingleSig {
            has_covenant: false
        }
    );

    let ins: Vec<_> = k.inputs().collect();
    assert_eq!(ins[0].sig_count, 1);
    assert!(
        ins[0].redeem.is_empty(),
        "this shape never carries a redeem"
    );
    assert_eq!(ins[1].sig_count, 0, "an unsigned input in a signed payload");

    // The raw field is as on the wire: the signature, then its sighash byte.
    assert_eq!(ins[0].signatures.len(), 65);
    assert_eq!(&ins[0].signatures[..64], &[0x5A; 64][..]);
    assert_eq!(ins[0].signatures[64], 0x01);

    // The accessor gives it as every other shape does, sighash type
    // included, and as many as `sig_count` says.
    let sigs: Vec<_> = ins[0].signatures().collect();
    assert_eq!(sigs.len(), ins[0].sig_count);
    assert_eq!(sigs[0].bytes, &[0x5A; 64][..]);
    assert_eq!(sigs[0].sighash_type, 0x01);
    assert_eq!(sigs[0].pubkey_pos, 0, "one signature, one key, no position");
    assert_eq!(ins[1].signatures().count(), 0);
}

/// A record cannot bind a legacy output already bound inline, only one that
/// is not.
#[test]
fn a_record_cannot_bind_a_legacy_output_bound_inline() {
    let covenant = |output: u8| {
        let mut r = vec![0x43u8, output];
        r.extend_from_slice(&0u16.to_le_bytes());
        r.extend_from_slice(&[0x44; 32]);
        r
    };
    let build = |record: Vec<u8>| {
        let mut b = Build::v(0x01);
        b.flags = 0x04;
        b.inputs.push(legacy_unsigned_input(&[0xAA; 34], None));
        b.outputs.push(legacy_output_with_covenant(
            &[0xBB; 34],
            Some(([0x77; 32], 0)),
        ));
        b.outputs
            .push(legacy_output_with_covenant(&[0xCC; 34], None));
        b.records.extend_from_slice(&record);
        b.bytes()
    };

    let unbound = build(covenant(1));
    let k = legacy::parse(&unbound, &P).expect("a record for the unbound output");
    assert!(k.records().any(|r| matches!(
        r,
        Record::Covenant {
            output_index: 1,
            ..
        }
    )));

    match legacy::parse(&build(covenant(0)), &P) {
        Err(KsptError::RepeatedRecord { marker, .. }) => assert_eq!(marker, 0x43),
        other => panic!("a second binding for output 0 was accepted: {other:?}"),
    }
}

/// A covenant present-flag that is neither zero nor one is refused.
#[test]
fn a_malformed_covenant_flag_is_refused() {
    let mut b = Build::v(0x01);
    b.flags = 0x04;
    b.inputs.push(legacy_unsigned_input(&[0xAA; 34], None));
    let mut out = output(&[0xBB; 34]);
    out.push(2);
    b.outputs.push(out);
    let bytes = b.bytes();

    assert!(matches!(
        legacy::parse(&bytes, &P),
        Err(KsptError::BadCovenantFlag { value: 2, .. })
    ));
}

/// A flag bit no version ever defined is refused.
#[test]
fn an_undefined_legacy_flag_is_refused() {
    let mut b = Build::v(0x01);
    b.flags = 0x08;
    b.inputs.push(legacy_unsigned_input(&[0xAA; 34], None));
    b.outputs.push(output(&[0xBB; 34]));
    assert_eq!(
        legacy::parse(&b.bytes(), &P),
        Err(KsptError::ReservedFlags(0x08))
    );
}

// ── Legacy body builders ─────────────────────────────────────────────────────
//
// Kept apart from `input` and `output` above so the canonical shape and the
// three legacy ones are not confused.

fn legacy_input_head(spk: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0x11u8; 32]);
    b.extend_from_slice(&7u32.to_le_bytes());
    b.extend_from_slice(&100_000_000u64.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes());
    b.push(1);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&spk_len_bytes(spk.len()));
    b.extend_from_slice(spk);
    b
}

fn legacy_unsigned_input(spk: &[u8], redeem: Option<&[u8]>) -> Vec<u8> {
    let mut b = legacy_input_head(spk);
    if let Some(r) = redeem {
        b.push(r.len() as u8); // a u8 length, not a u16
        b.extend_from_slice(r);
    }
    b
}

fn legacy_single_sig_input(spk: &[u8], signed: bool) -> Vec<u8> {
    let mut b = legacy_input_head(spk);
    if signed {
        b.push(64); // a length, not a count
        b.extend_from_slice(&[0x5A; 64]);
        b.push(0x01); // sighash type, after the signature
    } else {
        b.push(0);
    }
    b
}

fn legacy_multisig_input(spk: &[u8], sig_count: usize, redeem: &[u8], width: usize) -> Vec<u8> {
    let mut b = legacy_input_head(spk);
    b.push(sig_count as u8);
    for i in 0..sig_count {
        b.push(i as u8);
        b.push(0x01);
        b.extend_from_slice(&[0xAA; 64]);
    }
    match width {
        1 => b.push(redeem.len() as u8),
        _ => b.extend_from_slice(&(redeem.len() as u16).to_le_bytes()),
    }
    b.extend_from_slice(redeem);
    b
}

fn legacy_output_with_covenant(spk: &[u8], cov: Option<([u8; 32], u16)>) -> Vec<u8> {
    let mut b = output(spk);
    match cov {
        Some((id, auth)) => {
            b.push(1);
            b.extend_from_slice(&auth.to_le_bytes());
            b.extend_from_slice(&id);
        }
        None => b.push(0),
    }
    b
}

/// Records are read whatever order they arrive in.
#[test]
fn records_are_order_independent() {
    let change = {
        let mut r = vec![0x45u8, 0];
        r.extend_from_slice(&1u32.to_le_bytes());
        r.extend_from_slice(&1u32.to_le_bytes());
        r.extend_from_slice(&9u32.to_le_bytes());
        r
    };
    let covenant = {
        let mut r = vec![0x43u8, 0];
        r.extend_from_slice(&0u16.to_le_bytes());
        r.extend_from_slice(&[0x33; 32]);
        r
    };
    let hint = {
        let mut r = vec![0x44u8, 0];
        r.extend_from_slice(&1u32.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&7u32.to_le_bytes());
        r
    };

    let orders: [Vec<&Vec<u8>>; 4] = [
        vec![&change, &covenant, &hint],
        vec![&covenant, &change, &hint],
        vec![&hint, &covenant, &change],
        vec![&covenant, &hint, &change],
    ];

    for order in orders {
        let mut b = Build::canonical();
        b.inputs.push(input(&[0xAA; 34], None));
        b.outputs.push(output(&[0xBB; 34]));
        for r in &order {
            b.records.extend_from_slice(r);
        }
        let bytes = b.bytes();
        let k = parse(&bytes, &P).expect("every order must parse");

        let recs: Vec<_> = k.records().collect();
        assert_eq!(recs.len(), 3);
        assert!(recs
            .iter()
            .any(|r| matches!(r, Record::OutputHint(h) if h.addr_index == 9)));
        assert!(recs.iter().any(|r| matches!(r, Record::Covenant { .. })));
        assert!(recs
            .iter()
            .any(|r| matches!(r, Record::InputHint(h) if h.addr_index == 7)));
    }
}

/// A hint record is refused on a version that does not define one.
#[test]
fn a_record_outside_its_version_is_refused() {
    // Hints are defined on 0x04, 0x05 and 0x06, not on 0x01, 0x02 or 0x03.
    let mut b = Build::v(0x02);
    b.inputs.push(legacy_multisig_input(&[0xAA; 34], 0, &[], 1));
    b.outputs.push(output(&[0xBB; 34]));
    b.records.push(0x44);
    b.records.extend_from_slice(&[0u8; 13]);
    let bytes = b.bytes();
    assert!(matches!(
        legacy::parse(&bytes, &P),
        Err(KsptError::UnknownRecord { marker: 0x44, .. })
    ));
}

/// A KCC-3 input hint, `0x46`, reads back as written on `0x06`: one hint an
/// input, of either kind, for an input the payload has. Unknown before
/// `0x06`, even on `0x05`, which knows `0x44`.
#[test]
fn a_kcc3_input_hint_is_the_canonical_versions() {
    use kassigner_protocol::kspt::Kcc3Hint;
    let kcc3 = |index: u8| {
        let mut r = vec![0x46u8, index];
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&57u32.to_le_bytes());
        r
    };
    let hint = |index: u8| {
        let mut r = vec![0x44u8, index];
        r.extend_from_slice(&[0u8; 12]);
        r
    };
    let build = |records: &[Vec<u8>]| {
        let mut b = Build::canonical();
        b.inputs.push(input(&[0xAA; 34], None));
        b.inputs.push(input(&[0xAB; 34], None));
        b.outputs.push(output(&[0xBB; 34]));
        for r in records {
            b.records.extend_from_slice(r);
        }
        b.bytes()
    };

    let bytes = build(&[hint(0), kcc3(1)]);
    let k = parse(&bytes, &P).expect("one of each kind, for two inputs");
    let recs: Vec<_> = k.records().collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(
        recs[1],
        Record::Kcc3InputHint(Kcc3Hint {
            index: 1,
            chain: 0,
            addr_index: 57
        })
    );

    for (records, why) in [
        (vec![kcc3(0), kcc3(0)], "twice"),
        (vec![hint(0), kcc3(0)], "after a 0x44 for the input"),
    ] {
        match parse(&build(&records), &P) {
            Err(KsptError::RepeatedRecord { marker: 0x46, .. }) => {}
            other => panic!("{why}: {other:?}"),
        }
    }
    match parse(&build(&[kcc3(0), hint(0)]), &P) {
        Err(KsptError::RepeatedRecord { marker: 0x44, .. }) => {}
        other => panic!("a 0x44 after it: {other:?}"),
    }
    assert!(matches!(
        parse(&build(&[kcc3(2)]), &P),
        Err(KsptError::RecordIndexOutOfRange {
            marker: 0x46,
            index: 2,
            ..
        })
    ));

    for (marker, known) in [(0x44u8, true), (0x46, false)] {
        let mut b = Build::v(0x05);
        b.inputs.push(legacy_multisig_input(&[0xAA; 34], 0, &[], 2));
        b.outputs.push(output(&[0xBB; 34]));
        b.records
            .extend_from_slice(&if marker == 0x44 { hint(0) } else { kcc3(0) });
        let bytes = b.bytes();
        let read = legacy::parse(&bytes, &P);
        if known {
            assert!(read.is_ok(), "0x44 on 0x05: {read:?}");
        } else {
            assert!(
                matches!(read, Err(KsptError::UnknownRecord { marker: 0x46, .. })),
                "{read:?}"
            );
        }
    }
}

/// A coin's covenant, `0x49`, reads back as written on `0x06`: the covenant
/// the coin an input spends is bound to, once an input, for an input the
/// payload has. It is no hint, so an input may have one of each. Unknown
/// before `0x06`. [`transaction::coins`] gives each input's, `None` for an
/// input with no record.
///
/// [`transaction::coins`]: kassigner_protocol::kspt::transaction::coins
#[test]
fn a_coins_covenant_is_the_canonical_versions() {
    use kassigner_protocol::kspt::transaction::coins;
    let coin = |index: u8, id: u8| {
        let mut r = vec![0x49u8, index];
        r.extend_from_slice(&[id; 32]);
        r
    };
    let hint = |index: u8| {
        let mut r = vec![0x44u8, index];
        r.extend_from_slice(&[0u8; 12]);
        r
    };
    let build = |records: &[Vec<u8>]| {
        let mut b = Build::canonical();
        b.inputs.push(input(&[0xAA; 34], None));
        b.inputs.push(input(&[0xAB; 34], None));
        b.outputs.push(output(&[0xBB; 34]));
        for r in records {
            b.records.extend_from_slice(r);
        }
        b.bytes()
    };

    // A hint and a covenant for input 1; input 0's coin is unbound.
    let bytes = build(&[hint(1), coin(1, 0x77)]);
    assert_eq!(bytes.len(), build(&[hint(1)]).len() + 34);
    let k = parse(&bytes, &P).expect("a hint and a covenant for one input");
    let recs: Vec<_> = k.records().collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(
        recs[1],
        Record::CoinCovenant {
            input_index: 1,
            covenant_id: &[0x77; 32],
        }
    );
    let mut ids = [Some([0u8; 32]); 3];
    coins(&k, &mut ids[..2]);
    assert_eq!(ids, [None, Some([0x77; 32]), Some([0; 32])]);

    // With no record every coin is unbound.
    let plain = build(&[]);
    let mut ids = [Some([0u8; 32]); 2];
    coins(&parse(&plain, &P).unwrap(), &mut ids);
    assert_eq!(ids, [None, None]);

    match parse(&build(&[coin(0, 1), coin(0, 2)]), &P) {
        Err(KsptError::RepeatedRecord { marker: 0x49, .. }) => {}
        other => panic!("twice for one input: {other:?}"),
    }
    assert!(matches!(
        parse(&build(&[coin(2, 1)]), &P),
        Err(KsptError::RecordIndexOutOfRange {
            marker: 0x49,
            index: 2,
            ..
        })
    ));
    // Cut short, it is not a record.
    let mut cut = build(&[coin(0, 1)]);
    cut.pop();
    assert!(parse(&cut, &P).is_err());

    let mut b = Build::v(0x05);
    b.inputs.push(legacy_multisig_input(&[0xAA; 34], 0, &[], 2));
    b.outputs.push(output(&[0xBB; 34]));
    b.records.extend_from_slice(&coin(0, 1));
    let bytes = b.bytes();
    let read = legacy::parse(&bytes, &P);
    assert!(
        matches!(read, Err(KsptError::UnknownRecord { marker: 0x49, .. })),
        "{read:?}"
    );
}

/// The single-key account's hints, `0x47` for an input and `0x48` for an
/// output, read back as written on `0x06`: one hint an input or output, of
/// any kind, for one the payload has. Unknown before `0x06`.
#[test]
fn the_single_key_hints_are_the_canonical_versions() {
    use kassigner_protocol::kspt::AccountHint;
    let account = |marker: u8, index: u8, at: u32| {
        let mut r = vec![marker, index];
        r.extend_from_slice(&1u32.to_le_bytes());
        r.extend_from_slice(&at.to_le_bytes());
        r
    };
    let kcc3 = |index: u8| {
        let mut r = vec![0x46u8, index];
        r.extend_from_slice(&[0u8; 8]);
        r
    };
    let hint = |marker: u8, index: u8| {
        let mut r = vec![marker, index];
        r.extend_from_slice(&[0u8; 12]);
        r
    };
    let build = |records: &[Vec<u8>]| {
        let mut b = Build::canonical();
        b.inputs.push(input(&[0xAA; 34], None));
        b.inputs.push(input(&[0xAB; 34], None));
        b.outputs.push(output(&[0xBB; 34]));
        b.outputs.push(output(&[0xBC; 34]));
        for r in records {
            b.records.extend_from_slice(r);
        }
        b.bytes()
    };

    let bytes = build(&[account(0x47, 1, 1500), account(0x48, 1, 560)]);
    let k = parse(&bytes, &P).expect("an input's and an output's");
    let recs: Vec<_> = k.records().collect();
    assert_eq!(
        recs,
        [
            Record::AccountInputHint(AccountHint {
                index: 1,
                chain: 1,
                addr_index: 1500
            }),
            Record::AccountOutputHint(AccountHint {
                index: 1,
                chain: 1,
                addr_index: 560
            }),
        ]
    );

    for (records, marker, why) in [
        (
            vec![account(0x47, 0, 1), account(0x47, 0, 2)],
            0x47,
            "twice",
        ),
        (
            vec![hint(0x44, 0), account(0x47, 0, 1)],
            0x47,
            "after a 0x44",
        ),
        (vec![kcc3(0), account(0x47, 0, 1)], 0x47, "after a 0x46"),
        (vec![account(0x47, 0, 1), kcc3(0)], 0x46, "a 0x46 after it"),
        (
            vec![account(0x48, 0, 1), account(0x48, 0, 2)],
            0x48,
            "twice out",
        ),
        (
            vec![hint(0x45, 0), account(0x48, 0, 1)],
            0x48,
            "after a 0x45",
        ),
        (
            vec![account(0x48, 0, 1), hint(0x45, 0)],
            0x45,
            "a 0x45 after it",
        ),
    ] {
        match parse(&build(&records), &P) {
            Err(KsptError::RepeatedRecord { marker: m, .. }) if m == marker => {}
            other => panic!("{why}: {other:?}"),
        }
    }
    // An input's hint and an output's of the same number are two things.
    assert!(parse(&build(&[account(0x47, 0, 1), account(0x48, 0, 1)]), &P).is_ok());
    for marker in [0x47u8, 0x48] {
        assert!(matches!(
            parse(&build(&[account(marker, 2, 1)]), &P),
            Err(KsptError::RecordIndexOutOfRange { marker: m, index: 2, .. }) if m == marker
        ));
        let mut b = Build::v(0x05);
        b.inputs.push(legacy_multisig_input(&[0xAA; 34], 0, &[], 2));
        b.outputs.push(output(&[0xBB; 34]));
        b.records.extend_from_slice(&account(marker, 0, 1));
        let bytes = b.bytes();
        assert!(
            matches!(
                legacy::parse(&bytes, &P),
                Err(KsptError::UnknownRecord { marker: m, .. }) if m == marker
            ),
            "{marker:#04x} on 0x05"
        );
    }
}

/// Unknown bytes after the last record are refused: a signer must not sign
/// a payload it only partly understood.
#[test]
fn trailing_bytes_are_refused() {
    let mut bytes = minimal().bytes();
    let at = bytes.len();
    bytes.extend_from_slice(&[0x00, 0x01]);
    assert_eq!(
        parse(&bytes, &P),
        Err(KsptError::UnknownRecord { marker: 0x00, at })
    );

    // Another byte that is no marker.
    let mut bytes = minimal().bytes();
    let at = bytes.len();
    bytes.push(0x99);
    assert_eq!(
        parse(&bytes, &P),
        Err(KsptError::UnknownRecord { marker: 0x99, at })
    );
}

/// The escape may not be used where the short form fits: two encodings of
/// one length would make two byte strings of one transaction.
#[test]
fn a_non_canonical_length_is_refused() {
    let mut b = Build::canonical();
    // Hand-build an input whose spk_len uses the escape for a length of 34.
    let mut inp = Vec::new();
    inp.extend_from_slice(&[0x11u8; 32]);
    inp.extend_from_slice(&0u32.to_le_bytes());
    inp.extend_from_slice(&0u64.to_le_bytes());
    inp.extend_from_slice(&0u64.to_le_bytes());
    inp.push(1);
    inp.extend_from_slice(&0u16.to_le_bytes());
    inp.push(0xFF);
    inp.extend_from_slice(&34u16.to_le_bytes());
    inp.extend_from_slice(&[0xAA; 34]);
    b.inputs.push(inp);
    b.outputs.push(output(&[0xBB; 34]));
    let bytes = b.bytes();
    assert!(matches!(
        parse(&bytes, &P),
        Err(KsptError::NonCanonicalLength { .. })
    ));
}

/// The escape is required, and works, past 254 bytes.
#[test]
fn long_scripts_use_the_escape() {
    assert_eq!(script_len_size(0), 1);
    assert_eq!(script_len_size(254), 1);
    assert_eq!(script_len_size(255), 3);

    let long = vec![0xAAu8; 300];
    let mut b = Build::canonical();
    b.inputs.push(input(&long, None));
    b.outputs.push(output(&[0xBB; 34]));
    let bytes = b.bytes();
    let k = parse(&bytes, &P).expect("parse");
    assert_eq!(k.inputs().next().unwrap().spk, &long[..]);
}

/// Every bound is checked against the caller's profile, not a constant.
#[test]
fn bounds_come_from_the_profile() {
    // A payload with three inputs, read by a profile that allows two.
    let mut b = Build::canonical();
    for _ in 0..3 {
        b.inputs.push(input(&[0xAA; 34], None));
    }
    b.outputs.push(output(&[0xBB; 34]));
    let bytes = b.bytes();

    assert!(parse(&bytes, &P).is_ok(), "the device profile allows three");

    let small = Profile {
        max_inputs: 2,
        ..Profile::ESP32S3
    };
    assert_eq!(
        parse(&bytes, &small),
        Err(KsptError::OverProfile {
            field: Field::Inputs,
            value: 3,
            limit: 2
        })
    );

    // A script longer than the profile's script bound.
    let mut b = Build::canonical();
    b.inputs.push(input(&vec![0xAA; 300], None));
    b.outputs.push(output(&[0xBB; 34]));
    let bytes = b.bytes();
    let tight = Profile {
        max_script: 256,
        ..Profile::ESP32S3
    };
    assert_eq!(
        parse(&bytes, &tight),
        Err(KsptError::OverProfile {
            field: Field::Script,
            value: 300,
            limit: 256
        })
    );
}

/// Each header fault has its own error.
#[test]
fn header_faults_are_distinguished() {
    let good = minimal().bytes();

    let mut bad = good.clone();
    bad[0] = b'X';
    assert_eq!(parse(&bad, &P), Err(KsptError::BadMagic));

    let mut bad = good.clone();
    bad[4] = 0x09;
    assert_eq!(parse(&bad, &P), Err(KsptError::UnsupportedVersion(0x09)));

    let mut bad = good.clone();
    bad[5] = 0x01;
    assert_eq!(parse(&bad, &P), Err(KsptError::ReservedFlags(0x01)));
    let _ = VERSION;

    // Zero inputs, and zero outputs.
    let mut b = minimal();
    b.ni_override = Some(0);
    assert_eq!(
        parse(&b.bytes(), &P),
        Err(KsptError::Empty {
            field: Field::Inputs
        })
    );
    let mut b = minimal();
    b.no_override = Some(0);
    assert_eq!(
        parse(&b.bytes(), &P),
        Err(KsptError::Empty {
            field: Field::Outputs
        })
    );
}

/// Truncation at any point is refused, and never panics: a partial scan is
/// ordinary on a camera.
#[test]
fn truncation_anywhere_is_refused_without_panicking() {
    let full = {
        let mut b = Build::canonical();
        b.payload = vec![0x77; 20];
        b.inputs
            .push(input(&[0xAA; 34], Some((2, &[0xCC; 300], 2))));
        b.inputs.push(input(&[0xAA; 40], Some((1, &[0xCC; 10], 2))));
        b.outputs.push(output(&[0xBB; 34]));
        b.outputs.push(output(&[0xBB; 300]));
        b.records.extend_from_slice(&[0x43, 0]);
        b.records.extend_from_slice(&0u16.to_le_bytes());
        b.records.extend_from_slice(&[0x22; 32]);
        b.bytes()
    };
    assert!(parse(&full, &P).is_ok(), "the full payload must parse");

    // Records are optional, so a cut where they begin is a whole payload.
    let records_start = full.len() - 36; // one 0x43 record
    assert!(
        parse(&full[..records_start], &P).is_ok(),
        "the body alone must parse"
    );

    let mut refused = 0usize;
    let mut accepted = 0usize;
    for n in 0..full.len() {
        // None of these may panic.
        match parse(&full[..n], &P) {
            Ok(_) => accepted += 1,
            Err(_) => refused += 1,
        }
        // Anything cut inside the body is incomplete and must be refused.
        if n < records_start {
            assert!(
                parse(&full[..n], &P).is_err(),
                "prefix of {n} bytes parsed mid-body"
            );
        }
    }
    assert_eq!(refused + accepted, full.len());
    assert!(
        refused > 0 && accepted > 0,
        "expected both outcomes across the prefixes"
    );
}

/// A truncated payload reports where it stopped making sense.
#[test]
fn truncation_reports_an_offset() {
    let full = minimal().bytes();
    match parse(&full[..full.len() - 4], &P) {
        Err(KsptError::Truncated { at }) => {
            assert!(at < full.len(), "offset {at} is past the payload");
        }
        other => panic!("expected Truncated, got {other:?}"),
    }
}

/// A script length past 65,535, the most the escape's `u16` holds, is
/// refused rather than wrapped.
#[test]
fn a_length_the_field_cannot_hold_is_refused() {
    use kassigner_protocol::kspt::MAX_SCRIPT_LEN;
    let mut out = [0u8; 3];

    assert_eq!(write_script_len(Field::Script, 0xFE, &mut out), Ok(1));
    assert_eq!(out[0], 0xFE);
    assert_eq!(
        write_script_len(Field::Redeem, MAX_SCRIPT_LEN, &mut out),
        Ok(3)
    );
    assert_eq!(&out[..3], &[0xFF, 0xFF, 0xFF]);

    assert_eq!(
        write_script_len(Field::Script, MAX_SCRIPT_LEN + 1, &mut out),
        Err(KsptError::Unencodable {
            field: Field::Script,
            value: MAX_SCRIPT_LEN + 1
        })
    );
    assert_eq!(
        write_script_len(Field::Redeem, 1 << 20, &mut out),
        Err(KsptError::Unencodable {
            field: Field::Redeem,
            value: 1 << 20
        })
    );
    assert_eq!(
        write_script_len(Field::Script, 0xFF, &mut [0u8; 2]),
        Err(KsptError::BufferTooSmall)
    );
}

/// A covenant binding, a `0x43` record or inline on a legacy shape, names an
/// output and an authorizing input the payload has.
#[test]
fn a_covenant_binding_names_what_the_payload_has() {
    let covenant = |output: u8, input: u16| {
        let mut r = vec![0x43u8, output];
        r.extend_from_slice(&input.to_le_bytes());
        r.extend_from_slice(&[0x33; 32]);
        r
    };
    // Two inputs, two outputs.
    let build = |record: Vec<u8>| {
        let mut b = Build::canonical();
        b.inputs.push(input(&[0xAA; 34], None));
        b.inputs.push(input(&[0xAA; 34], None));
        b.outputs.push(output(&[0xBB; 34]));
        b.outputs.push(output(&[0xCC; 34]));
        b.records.extend_from_slice(&record);
        b.bytes()
    };
    assert!(
        parse(&build(covenant(1, 1)), &P).is_ok(),
        "the last of each"
    );
    assert!(matches!(
        parse(&build(covenant(2, 0)), &P),
        Err(KsptError::RecordIndexOutOfRange {
            marker: 0x43,
            index: 2,
            ..
        })
    ));
    assert!(matches!(
        parse(&build(covenant(0, 2)), &P),
        Err(KsptError::AuthorizingInputOutOfRange {
            output: 0,
            input: 2,
            ..
        })
    ));
    assert!(matches!(
        parse(&build(covenant(0, u16::MAX)), &P),
        Err(KsptError::AuthorizingInputOutOfRange {
            input: u16::MAX,
            ..
        })
    ));

    // Inline, on the unsigned legacy shape: one input.
    let inline = |auth: u16| {
        let mut b = Build::v(0x01);
        b.flags = 0x04;
        b.inputs.push(legacy_unsigned_input(&[0xAA; 34], None));
        b.outputs.push(legacy_output_with_covenant(
            &[0xBB; 34],
            Some(([0x77; 32], auth)),
        ));
        b.bytes()
    };
    assert!(legacy::parse(&inline(0), &P).is_ok());
    assert!(matches!(
        legacy::parse(&inline(1), &P),
        Err(KsptError::AuthorizingInputOutOfRange { input: 1, .. })
    ));
}

/// A second record naming the same thing is refused, as is a hint naming
/// what the payload lacks: picking one of two is not a signer's choice.
#[test]
fn a_record_naming_something_twice_is_refused() {
    let covenant = |output: u8, id: u8| {
        let mut r = vec![0x43u8, output];
        r.extend_from_slice(&0u16.to_le_bytes());
        r.extend_from_slice(&[id; 32]);
        r
    };
    let hint = |marker: u8, index: u8| {
        let mut r = vec![marker, index];
        r.extend_from_slice(&1u32.to_le_bytes());
        r.extend_from_slice(&0u32.to_le_bytes());
        r.extend_from_slice(&7u32.to_le_bytes());
        r
    };
    let build = |records: Vec<Vec<u8>>| {
        let mut b = Build::canonical();
        b.inputs.push(input(&[0xAA; 34], None));
        b.outputs.push(output(&[0xBB; 34]));
        b.outputs.push(output(&[0xCC; 34]));
        for r in records {
            b.records.extend_from_slice(&r);
        }
        b.bytes()
    };

    // One each is fine, and so are two bindings for two outputs.
    let ok = build(vec![
        covenant(0, 0x33),
        covenant(1, 0x44),
        hint(0x44, 0),
        hint(0x45, 0),
    ]);
    assert!(parse(&ok, &P).is_ok());

    // A hint naming an input or output there is not: one input, two
    // outputs.
    for (record, marker, index) in [(hint(0x44, 1), 0x44u8, 1u8), (hint(0x45, 2), 0x45, 2)] {
        match parse(&build(vec![record]), &P) {
            Err(KsptError::RecordIndexOutOfRange {
                marker: m,
                index: i,
                ..
            }) => assert_eq!((m, i), (marker, index)),
            other => panic!("{marker:#04x} for index {index} was accepted: {other:?}"),
        }
    }

    for (records, marker) in [
        (vec![covenant(0, 0x33), covenant(0, 0x44)], 0x43u8),
        (vec![hint(0x44, 0), hint(0x44, 0)], 0x44),
        (vec![hint(0x45, 1), hint(0x45, 1)], 0x45),
    ] {
        let bytes = build(records);
        match parse(&bytes, &P) {
            Err(KsptError::RepeatedRecord { marker: m, .. }) => assert_eq!(m, marker),
            other => panic!("{marker:#04x} twice was accepted: {other:?}"),
        }
    }
}

/// The stealth record, `0x53`, is refused wherever it sits: no signer
/// applied its key tweak. Legacy versions refuse it too (`tests/device.rs`).
#[test]
fn the_stealth_record_is_refused() {
    let stealth = {
        let mut r = vec![0x53u8];
        r.extend_from_slice(&[0x22; 32]);
        r
    };
    let covenant = {
        let mut r = vec![0x43u8, 0];
        r.extend_from_slice(&0u16.to_le_bytes());
        r.extend_from_slice(&[0x33; 32]);
        r
    };
    for records in [
        vec![&stealth],
        vec![&stealth, &covenant],
        vec![&covenant, &stealth],
    ] {
        let mut b = Build::canonical();
        b.inputs.push(input(&[0xAA; 34], None));
        b.outputs.push(output(&[0xBB; 34]));
        for r in records {
            b.records.extend_from_slice(r);
        }
        assert!(
            matches!(
                parse(&b.bytes(), &P),
                Err(KsptError::UnknownRecord { marker: 0x53, .. })
            ),
            "a stealth record was accepted"
        );
    }
}
