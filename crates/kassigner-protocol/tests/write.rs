// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Writing a KSPT. Everything written is read back through the parser and
//! the mapping, so what is checked is what a reader gets.

use kassigner_kaspa::sighash::{schnorr_signature_hash, Hash, SIG_HASH_ALL};
use kassigner_kaspa::tx::{CovenantBinding, Transaction};
use kassigner_protocol::kspt::transaction::{build, fill};
use kassigner_protocol::kspt::{
    self, legacy, write, written_len, Field, InputSignature, Kspt, KsptError, Mismatch, Record,
    MAGIC, VERSION,
};
use kassigner_protocol::profile::Profile;

#[path = "../../../testkit/kspt_bytes.rs"]
pub mod kspt_bytes;
use kspt_bytes::spk_len;
#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::arrays;

const P: Profile = Profile::ESP32S3;
const SPK: [u8; 34] = [0x20u8; 34];

/// Map a payload and hand the transaction to `f`.
fn with_tx<R>(k: &Kspt<'_>, f: impl FnOnce(&Transaction<'_>) -> R) -> R {
    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(k, &mut ins, &mut outs).expect("fill");
    let tx = build(k, &ins[..ni], &outs[..no]);
    f(&tx)
}

/// Write `source` back with `added`, checking the length first.
fn write_vec(source: &Kspt<'_>, added: &[InputSignature]) -> Result<Vec<u8>, KsptError> {
    with_tx(source, |tx| {
        let n = written_len(source, tx, added, &P)?;
        let mut out = vec![0u8; n];
        let w = write(source, tx, added, &P, &mut out)?;
        assert_eq!(w, n, "written_len and write disagree");
        Ok(out)
    })
}

/// Every input's signature hash under SIGHASH_ALL, as the device signs.
fn sighashes(k: &Kspt<'_>) -> Vec<Hash> {
    with_tx(k, |tx| {
        (0..tx.inputs.len())
            .map(|i| schnorr_signature_hash(tx, i, SIG_HASH_ALL).expect("an input"))
            .collect()
    })
}

fn sig(input: usize, pubkey_pos: u8, fill: u8) -> InputSignature {
    InputSignature {
        input,
        pubkey_pos,
        sighash_type: 0x01,
        signature: [fill; 64],
        redeem: None,
    }
}

type HintSpec = (u8, u32, u32, u32);
/// A KCC-3 or single-key account hint: input or output, chain, index.
type ChainHint = (u8, u32, u32);

/// A covenant binding: authorizing input, id.
type Binding = (u16, [u8; 32]);

#[derive(Clone, Default)]
struct In {
    amount: u64,
    /// Position, sighash type, signature: written in this order.
    sigs: Vec<(u8, u8, [u8; 64])>,
    redeem: Vec<u8>,
    /// The locking script, [`SPK`] when empty.
    spk: Vec<u8>,
}

/// A canonical payload, laid out field by field. Its records are in the
/// writer's order unless `reverse_records` is set, so with signatures
/// ascending it is what the writer should reproduce.
#[derive(Clone)]
struct Canon {
    lock_time: u64,
    payload: Vec<u8>,
    inputs: Vec<In>,
    /// Value, and an optional binding as authorizing input and id.
    outputs: Vec<(u64, Option<Binding>)>,
    in_hints: Vec<HintSpec>,
    /// KCC-3 input hints: input, chain, index.
    kcc3_hints: Vec<ChainHint>,
    /// Single-key account input hints: input, chain, index.
    account_hints: Vec<ChainHint>,
    out_hints: Vec<HintSpec>,
    /// Single-key account output hints: output, chain, index.
    account_out_hints: Vec<ChainHint>,
    reverse_records: bool,
}

impl Canon {
    fn new(inputs: &[u64], outputs: &[u64]) -> Self {
        Self {
            lock_time: 0,
            payload: Vec::new(),
            inputs: inputs
                .iter()
                .map(|&amount| In {
                    amount,
                    ..Default::default()
                })
                .collect(),
            outputs: outputs.iter().map(|&v| (v, None)).collect(),
            in_hints: Vec::new(),
            kcc3_hints: Vec::new(),
            account_hints: Vec::new(),
            out_hints: Vec::new(),
            account_out_hints: Vec::new(),
            reverse_records: false,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&MAGIC);
        b.push(VERSION);
        b.push(0);
        b.extend_from_slice(&1u16.to_le_bytes()); // tx_version
        b.push(self.inputs.len() as u8);
        b.push(self.outputs.len() as u8);
        b.extend_from_slice(&self.lock_time.to_le_bytes());
        b.extend_from_slice(&[0u8; 20]);
        b.extend_from_slice(&0u64.to_le_bytes()); // gas
        b.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.payload);
        for (i, inp) in self.inputs.iter().enumerate() {
            b.extend_from_slice(&[0x11u8; 32]);
            b.extend_from_slice(&(i as u32).to_le_bytes());
            b.extend_from_slice(&inp.amount.to_le_bytes());
            b.extend_from_slice(&0u64.to_le_bytes()); // sequence
            b.push(1); // sig_op_count
            b.extend_from_slice(&0u16.to_le_bytes());
            let spk = if inp.spk.is_empty() {
                &SPK[..]
            } else {
                &inp.spk
            };
            b.extend_from_slice(&spk_len(spk.len()));
            b.extend_from_slice(spk);
            b.push(inp.sigs.len() as u8);
            for (pos, ty, s) in &inp.sigs {
                b.push(*pos);
                b.push(*ty);
                b.extend_from_slice(s);
            }
            b.extend_from_slice(&(inp.redeem.len() as u16).to_le_bytes());
            b.extend_from_slice(&inp.redeem);
        }
        for (value, _) in &self.outputs {
            b.extend_from_slice(&value.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&spk_len(SPK.len()));
            b.extend_from_slice(&SPK);
        }

        let mut groups: Vec<Vec<u8>> = Vec::new();
        let mut g = Vec::new();
        for (k, (_, c)) in self.outputs.iter().enumerate() {
            if let Some((auth, id)) = c {
                g.push(0x43);
                g.push(k as u8);
                g.extend_from_slice(&auth.to_le_bytes());
                g.extend_from_slice(id);
            }
        }
        groups.push(g);
        for (marker, hints) in [(0x44u8, &self.in_hints), (0x45u8, &self.out_hints)] {
            let mut g = Vec::new();
            for (index, cosigner, chain, addr) in hints {
                g.push(marker);
                g.push(*index);
                g.extend_from_slice(&cosigner.to_le_bytes());
                g.extend_from_slice(&chain.to_le_bytes());
                g.extend_from_slice(&addr.to_le_bytes());
            }
            groups.push(g);
            // The writer's order: KCC-3's and the single-key account's input
            // hints after `0x44`, the account's output hints after `0x45`.
            let after: &[(u8, &Vec<ChainHint>)] = if marker == 0x44 {
                &[(0x46, &self.kcc3_hints), (0x47, &self.account_hints)]
            } else {
                &[(0x48, &self.account_out_hints)]
            };
            for &(m, hints) in after {
                let mut g = Vec::new();
                for (index, chain, addr) in hints {
                    g.push(m);
                    g.push(*index);
                    g.extend_from_slice(&chain.to_le_bytes());
                    g.extend_from_slice(&addr.to_le_bytes());
                }
                groups.push(g);
            }
        }
        if self.reverse_records {
            groups.reverse();
        }
        for g in groups {
            b.extend_from_slice(&g);
        }
        b
    }
}

/// A `0x01` payload with one input and one output. `flags`: `0x01` signed
/// (length, signature, sighash byte), `0x04` covenant inline.
fn legacy_01(flags: u8, sig: Option<(&[u8], u8)>, covenant: Option<Binding>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(0x01);
    b.push(flags);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.push(1);
    b.push(1);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());

    b.extend_from_slice(&[0x11u8; 32]);
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&90_000u64.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes());
    b.push(1);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&spk_len(SPK.len()));
    b.extend_from_slice(&SPK);
    if flags & 0x01 != 0 {
        match sig {
            Some((bytes, ty)) => {
                b.push(bytes.len() as u8);
                b.extend_from_slice(bytes);
                b.push(ty);
            }
            None => b.push(0),
        }
    }

    b.extend_from_slice(&80_000u64.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&spk_len(SPK.len()));
    b.extend_from_slice(&SPK);
    if flags & 0x04 != 0 {
        match covenant {
            Some((auth, id)) => {
                b.push(1);
                b.extend_from_slice(&auth.to_le_bytes());
                b.extend_from_slice(&id);
            }
            None => b.push(0),
        }
    }
    b
}

/// A canonical payload with nothing added comes back byte for byte: it
/// holds signatures, a redeem script, a binding and both kinds of hint.
#[test]
fn a_canonical_payload_writes_back_unchanged() {
    let mut c = Canon::new(&[100_000, 50_000], &[120_000, 20_000]);
    c.lock_time = 7;
    c.payload = vec![0xD0, 0xD1];
    c.inputs[0].sigs = vec![(1, 0x01, [0x5A; 64])];
    c.inputs[0].redeem = vec![0x51, 0xAE];
    c.outputs[1].1 = Some((1, [0xC0; 32]));
    c.in_hints = vec![(0, 1, 0, 5)];
    c.out_hints = vec![(1, 1, 1, 9)];
    let bytes = c.bytes();

    let k = kspt::parse(&bytes, &P).expect("parse");
    assert_eq!(write_vec(&k, &[]).expect("write"), bytes);
}

/// An added signature reads back where it was put, and nothing else moves.
#[test]
fn an_added_signature_reads_back() {
    let c = Canon::new(&[100_000, 50_000], &[140_000]);
    let bytes = c.bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");

    let out = write_vec(&k, &[sig(1, 0, 0x42)]).expect("write");

    let r = kspt::parse(&out, &P).expect("reply parses");
    let ins: Vec<_> = r.inputs().collect();
    assert_eq!(ins[0].sig_count, 0);
    assert_eq!(ins[1].sig_count, 1);
    let s = ins[1].signatures().next().expect("a signature");
    assert_eq!(
        (s.pubkey_pos, s.sighash_type, s.bytes),
        (0, 0x01, &[0x42u8; 64][..])
    );

    // The reply describes the transaction that was signed.
    assert_eq!(sighashes(&r), sighashes(&k));

    // It is the source with one signature added, nothing more.
    let mut want = c.clone();
    want.inputs[1].sigs.push((0, 0x01, [0x42; 64]));
    assert_eq!(out, want.bytes());
}

/// A redeem script the signer supplies (KCC-3) goes into the input that came
/// without one: the result is the source plus that script and signature, the
/// same transaction. It is a mismatch when the input already had one, when
/// its lock is not a script hash or not this script's, or when one input
/// gets two different scripts.
#[test]
fn a_supplied_redeem_is_written_where_none_was() {
    use kassigner_kaspa::script::{kcc3_redeem, kcc3_script_hash};

    let key = [0x5a; 32];
    let redeem = kcc3_redeem(&key);
    let mut lock = vec![0xaa, 0x20];
    lock.extend_from_slice(&kcc3_script_hash(&key));
    lock.push(0x87);
    let mut c = Canon::new(&[100_000, 50_000], &[140_000]);
    c.inputs[1].spk = lock;
    let bytes = c.bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    let supplying = |input: usize, pos: u8, redeem: [u8; 34]| InputSignature {
        redeem: Some(redeem),
        ..sig(input, pos, 0x42)
    };

    let out = write_vec(&k, &[supplying(1, 0, redeem)]).expect("write");
    let r = kspt::parse(&out, &P).expect("reply parses");
    let ins: Vec<_> = r.inputs().collect();
    assert_eq!(ins[1].redeem, &redeem[..]);
    assert!(ins[0].redeem.is_empty());
    assert_eq!(sighashes(&r), sighashes(&k));
    let mut want = c.clone();
    want.inputs[1].sigs.push((0, 0x01, [0x42; 64]));
    want.inputs[1].redeem = redeem.to_vec();
    assert_eq!(out, want.bytes());

    let mismatch = |i| {
        Some(KsptError::SourceMismatch {
            at: Mismatch::Input(i),
        })
    };
    let other = kcc3_redeem(&[0x5b; 32]);
    let had = want.bytes();
    let had = kspt::parse(&had, &P).expect("parse");
    assert_eq!(
        write_vec(&had, &[supplying(1, 1, redeem)]).err(),
        mismatch(1),
        "it came with one"
    );
    assert_eq!(
        write_vec(&k, &[supplying(1, 0, other)]).err(),
        mismatch(1),
        "not the lock's script"
    );
    assert_eq!(
        write_vec(&k, &[supplying(0, 0, redeem)]).err(),
        mismatch(0),
        "no script hash"
    );
    assert_eq!(
        write_vec(&k, &[supplying(1, 0, redeem), supplying(1, 1, other)]).err(),
        mismatch(1),
        "two different"
    );
}

/// A KCC-3 input hint writes back in its place, however it arrived.
#[test]
fn a_kcc3_hint_writes_back_in_its_place() {
    let mut c = Canon::new(&[100_000, 50_000], &[140_000]);
    c.in_hints.push((0, 1, 0, 3));
    c.kcc3_hints.push((1, 0, 57));
    c.out_hints.push((0, 1, 1, 4));
    let canonical = c.bytes();
    let k = kspt::parse(&canonical, &P).expect("parse");
    assert_eq!(write_vec(&k, &[]).expect("write"), canonical);

    c.reverse_records = true;
    let reversed = c.bytes();
    assert_ne!(reversed, canonical);
    let k = kspt::parse(&reversed, &P).expect("parse");
    assert_eq!(write_vec(&k, &[]).expect("write"), canonical);
}

/// Signatures come out ascending by key position, whether already there or
/// added, in any order.
#[test]
fn signatures_come_out_by_position() {
    let mut c = Canon::new(&[100_000], &[90_000]);
    c.inputs[0].sigs = vec![(2, 0x01, [0x22; 64])];
    let bytes = c.bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");

    let out = write_vec(&k, &[sig(0, 1, 0x11), sig(0, 0, 0x00)]).expect("write");

    let r = kspt::parse(&out, &P).expect("reply parses");
    let input = r.inputs().next().expect("input");
    let got: Vec<(u8, u8)> = input
        .signatures()
        .map(|s| (s.pubkey_pos, s.bytes[0]))
        .collect();
    assert_eq!(got, vec![(0, 0x00), (1, 0x11), (2, 0x22)]);
}

/// One key position holds one signature, whether the second was there or
/// added.
#[test]
fn one_position_holds_one_signature() {
    let mut c = Canon::new(&[100_000], &[90_000]);
    c.inputs[0].sigs = vec![(0, 0x01, [0x22; 64])];
    let bytes = c.bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    assert_eq!(
        write_vec(&k, &[sig(0, 0, 0x33)]).err(),
        Some(KsptError::DuplicateSignature {
            input: 0,
            pubkey_pos: 0
        })
    );

    let bytes = Canon::new(&[100_000], &[90_000]).bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    assert_eq!(
        write_vec(&k, &[sig(0, 1, 0x33), sig(0, 1, 0x44)]).err(),
        Some(KsptError::DuplicateSignature {
            input: 0,
            pubkey_pos: 1
        })
    );
}

/// A signature for an input that does not exist is refused, not dropped.
#[test]
fn a_signature_for_no_input_is_refused() {
    let bytes = Canon::new(&[100_000, 50_000], &[140_000]).bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    assert_eq!(
        write_vec(&k, &[sig(2, 0, 0x42)]).err(),
        Some(KsptError::NoSuchInput { index: 2 })
    );
}

/// A legacy payload comes out as `0x06`, its inline binding as a record, and
/// the signature hash does not move.
#[test]
fn a_legacy_payload_comes_out_canonical() {
    let bytes = legacy_01(0x04, None, Some((0, [0xB1; 32])));
    let k = legacy::parse(&bytes, &P).expect("legacy parse");

    let out = write_vec(&k, &[]).expect("write");

    let r = kspt::parse(&out, &P).expect("canonical parse");
    assert_eq!(r.version, VERSION);
    let records: Vec<_> = r.records().collect();
    assert_eq!(
        records,
        vec![Record::Covenant {
            output_index: 0,
            authorizing_input: 0,
            covenant_id: &[0xB1; 32],
        }]
    );
    assert_eq!(sighashes(&r), sighashes(&k));
}

/// The legacy single-signature shape's signature becomes a record at
/// position zero.
#[test]
fn a_legacy_signature_becomes_a_record() {
    let s = [0x33u8; 64];
    let bytes = legacy_01(0x01, Some((&s, 0x01)), None);
    let k = legacy::parse(&bytes, &P).expect("legacy parse");

    let out = write_vec(&k, &[]).expect("write");

    let r = kspt::parse(&out, &P).expect("canonical parse");
    let input = r.inputs().next().expect("input");
    let got: Vec<_> = input
        .signatures()
        .map(|g| (g.pubkey_pos, g.sighash_type, g.bytes.to_vec()))
        .collect();
    assert_eq!(got, vec![(0, 0x01, s.to_vec())]);
}

/// A legacy signature of another length than 64 is refused, not cut or
/// padded.
#[test]
fn a_legacy_signature_of_another_length_is_refused() {
    let s = [0x33u8; 63];
    let bytes = legacy_01(0x01, Some((&s, 0x01)), None);
    let k = legacy::parse(&bytes, &P).expect("legacy parse");
    assert_eq!(
        write_vec(&k, &[]).err(),
        Some(KsptError::SignatureLength { input: 0, len: 63 })
    );
}

/// A transaction other than the payload's is refused, the error saying
/// where they part.
#[test]
fn a_different_transaction_is_refused() {
    let bytes = Canon::new(&[100_000, 50_000], &[120_000, 20_000]).bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(&k, &mut ins, &mut outs).expect("fill");
    let tx = build(&k, &ins[..ni], &outs[..no]);
    let refusal = |t: &Transaction<'_>| written_len(&k, t, &[], &P).err();

    assert_eq!(refusal(&tx), None, "the real one is accepted");

    let mut o2 = outs;
    o2[1].value += 1;
    assert_eq!(
        refusal(&Transaction {
            outputs: &o2[..no],
            ..tx
        }),
        Some(KsptError::SourceMismatch {
            at: Mismatch::Output(1)
        })
    );

    let mut i2 = ins;
    i2[0].utxo_entry.amount += 1;
    assert_eq!(
        refusal(&Transaction {
            inputs: &i2[..ni],
            ..tx
        }),
        Some(KsptError::SourceMismatch {
            at: Mismatch::Input(0)
        })
    );

    assert_eq!(
        refusal(&Transaction { lock_time: 1, ..tx }),
        Some(KsptError::SourceMismatch {
            at: Mismatch::Global
        })
    );

    assert_eq!(
        refusal(&Transaction {
            outputs: &outs[..1],
            ..tx
        }),
        Some(KsptError::SourceMismatch {
            at: Mismatch::Counts
        })
    );
}

/// A covenant binding other than the source's is refused: changed, dropped,
/// added, or with an authorizing input past the inputs. On a record and
/// inline on a legacy shape alike.
#[test]
fn a_binding_that_is_not_the_sources_is_refused() {
    let mut c = Canon::new(&[100_000, 50_000], &[120_000, 20_000]);
    c.outputs[0].1 = Some((1, [0xC1; 32]));
    let canonical = c.bytes();
    let legacy = legacy_01(0x04, None, Some((0, [0xB1; 32])));
    let sources = [
        kspt::parse(&canonical, &P).expect("parse"),
        legacy::parse(&legacy, &P).expect("legacy parse"),
    ];
    for k in &sources {
        let (mut ins, mut outs) = arrays();
        let (ni, no) = fill(k, &mut ins, &mut outs).expect("fill");
        let tx = build(k, &ins[..ni], &outs[..no]);
        let held = outs[0].covenant.expect("output 0 is bound");
        assert_eq!(written_len(k, &tx, &[], &P).err(), None, "the source's own");

        let changed = [
            Some(CovenantBinding {
                covenant_id: [0xDD; 32],
                ..held
            }),
            Some(CovenantBinding {
                authorizing_input: held.authorizing_input ^ 1,
                ..held
            }),
            Some(CovenantBinding {
                authorizing_input: 9,
                ..held
            }),
            None,
        ];
        for binding in changed {
            let mut o2 = outs;
            o2[0].covenant = binding;
            let t = Transaction {
                outputs: &o2[..no],
                ..tx
            };
            assert_eq!(
                written_len(k, &t, &[], &P).err(),
                Some(KsptError::SourceMismatch {
                    at: Mismatch::Output(0)
                }),
                "{binding:?}"
            );
        }
    }

    // One added to an output the source leaves unbound.
    let k = &sources[0];
    let (mut ins, mut outs) = arrays();
    let (ni, no) = fill(k, &mut ins, &mut outs).expect("fill");
    let tx = build(k, &ins[..ni], &outs[..no]);
    let mut o2 = outs;
    o2[1].covenant = o2[0].covenant;
    let t = Transaction {
        outputs: &o2[..no],
        ..tx
    };
    assert_eq!(
        written_len(k, &t, &[], &P).err(),
        Some(KsptError::SourceMismatch {
            at: Mismatch::Output(1)
        })
    );
}

/// A buffer one byte short is refused and left as it was.
#[test]
fn a_short_buffer_is_left_untouched() {
    let bytes = Canon::new(&[100_000], &[90_000]).bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    with_tx(&k, |tx| {
        let n = written_len(&k, tx, &[sig(0, 0, 0x42)], &P).expect("len");
        let mut out = vec![0xEEu8; n - 1];
        assert_eq!(
            write(&k, tx, &[sig(0, 0, 0x42)], &P, &mut out),
            Err(KsptError::BufferTooSmall)
        );
        assert!(out.iter().all(|&b| b == 0xEE));
    });
}

/// What is written stays inside its profile, so a device with that profile
/// parses it.
#[test]
fn the_result_stays_inside_the_profile() {
    let mut c = Canon::new(&[100_000], &[90_000]);
    c.inputs[0].sigs = (0..5u8).map(|p| (p, 0x01, [p; 64])).collect();
    let bytes = c.bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    assert_eq!(
        write_vec(&k, &[sig(0, 5, 0x55)]).err(),
        Some(KsptError::OverProfile {
            field: Field::Signatures,
            value: 6,
            limit: P.max_sigs_per_input,
        })
    );
}

/// Records arriving in another order come out in the writer's order, all
/// kept.
#[test]
fn records_come_out_in_one_order() {
    let mut c = Canon::new(&[100_000, 50_000], &[120_000, 20_000]);
    c.outputs[0].1 = Some((0, [0xC1; 32]));
    c.in_hints = vec![(1, 2, 0, 3)];
    c.out_hints = vec![(0, 2, 1, 4)];
    c.reverse_records = true;
    let reversed = c.bytes();
    c.reverse_records = false;
    let ordered = c.bytes();
    assert_ne!(reversed, ordered);

    let k = kspt::parse(&reversed, &P).expect("parse");
    assert_eq!(write_vec(&k, &[]).expect("write"), ordered);
}

/// A draft writes what a parsed source of the same transaction writes: byte
/// for byte the request built by hand, with a redeem script and every kind
/// of hint, at the length `draft_len` gives. Too few redeems, a redeem not
/// its lock's, and a hint past the inputs or outputs are refused.
#[test]
fn a_draft_writes_what_a_source_writes() {
    use kassigner_kaspa::script::{redeem_hash, redeem_matches};
    use kassigner_protocol::kspt::{draft_len, write_draft, AccountHint, Draft, Hint, Kcc3Hint};

    let redeem = vec![0x51, 0x20, 0x11, 0x51, 0xae];
    let mut p2sh = vec![0xaa, 0x20];
    p2sh.extend_from_slice(&redeem_hash(&redeem));
    p2sh.push(0x87);
    let mut c = Canon::new(&[100_000, 50_000, 30_000], &[120_000, 20_000]);
    c.inputs[1].redeem = redeem.clone();
    c.inputs[1].spk = p2sh.clone();
    c.in_hints = vec![(1, 2, 0, 3)];
    c.kcc3_hints = vec![(0, 1, 9)];
    c.account_hints = vec![(2, 0, 1500)];
    c.out_hints = vec![(1, 2, 1, 4)];
    c.account_out_hints = vec![(0, 1, 560)];
    let by_hand = c.bytes();
    let k = kspt::parse(&by_hand, &P).expect("parse");

    let redeems: [&[u8]; 3] = [&[], &redeem, &[]];
    let draft = Draft {
        redeems: &redeems,
        input_hints: &[Hint {
            index: 1,
            cosigner: 2,
            chain: 0,
            addr_index: 3,
        }],
        kcc3_hints: &[Kcc3Hint {
            index: 0,
            chain: 1,
            addr_index: 9,
        }],
        account_hints: &[AccountHint {
            index: 2,
            chain: 0,
            addr_index: 1500,
        }],
        output_hints: &[Hint {
            index: 1,
            cosigner: 2,
            chain: 1,
            addr_index: 4,
        }],
        account_output_hints: &[AccountHint {
            index: 0,
            chain: 1,
            addr_index: 560,
        }],
        coin_covenants: &[],
    };
    with_tx(&k, |tx| {
        assert!(redeem_matches(
            &tx.inputs[1].utxo_entry.script_public_key,
            &redeem
        ));
        let n = draft_len(&draft, tx, &P).expect("len");
        let mut out = vec![0u8; n];
        assert_eq!(write_draft(&draft, tx, &P, &mut out), Ok(n));
        assert_eq!(out, by_hand);
        assert_eq!(out, write_vec(&k, &[]).expect("the source's"));

        let one: [&[u8]; 1] = [&[]];
        let short = Draft {
            redeems: &one,
            ..draft
        };
        assert_eq!(
            draft_len(&short, tx, &P),
            Err(KsptError::SourceMismatch {
                at: Mismatch::Counts
            })
        );
        let wrong: [&[u8]; 3] = [&[], &[0x51, 0x20, 0x22, 0x51, 0xae], &[]];
        let other = Draft {
            redeems: &wrong,
            ..draft
        };
        assert_eq!(
            draft_len(&other, tx, &P),
            Err(KsptError::SourceMismatch {
                at: Mismatch::Input(1)
            })
        );
        let past = Draft {
            output_hints: &[Hint {
                index: 2,
                cosigner: 0,
                chain: 0,
                addr_index: 0,
            }],
            ..draft
        };
        assert_eq!(
            draft_len(&past, tx, &P),
            Err(KsptError::NoSuchInput { index: 2 })
        );
        let beyond = AccountHint {
            index: 3,
            chain: 0,
            addr_index: 0,
        };
        let past_in = Draft {
            account_hints: &[beyond],
            ..draft
        };
        assert_eq!(
            draft_len(&past_in, tx, &P),
            Err(KsptError::NoSuchInput { index: 3 })
        );
        let past_out = Draft {
            account_output_hints: &[AccountHint { index: 2, ..beyond }],
            ..draft
        };
        assert_eq!(
            draft_len(&past_out, tx, &P),
            Err(KsptError::NoSuchInput { index: 2 })
        );
        assert_eq!(
            write_draft(&draft, tx, &P, &mut vec![0u8; n - 1]),
            Err(KsptError::BufferTooSmall)
        );
    });
}

/// A draft hinting one input or output twice is refused as the parser would
/// refuse it, at the same offset, and nothing is written.
#[test]
fn a_draft_naming_one_input_or_output_twice_is_refused() {
    use kassigner_protocol::kspt::{draft_len, write_draft, AccountHint, Draft, Hint, Kcc3Hint};

    let c = Canon::new(&[100_000, 50_000], &[120_000, 20_000]);
    let bytes = c.bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    let redeems: [&[u8]; 2] = [&[], &[]];
    let none = Draft {
        redeems: &redeems,
        input_hints: &[],
        kcc3_hints: &[],
        account_hints: &[],
        output_hints: &[],
        account_output_hints: &[],
        coin_covenants: &[],
    };
    let group = |index| Hint {
        index,
        cosigner: 1,
        chain: 0,
        addr_index: 3,
    };
    let kcc3 = |index| Kcc3Hint {
        index,
        chain: 0,
        addr_index: 4,
    };
    let account = |index| AccountHint {
        index,
        chain: 1,
        addr_index: 5,
    };
    let twice_in = [group(1), group(1)];
    let twice_out = [group(0), group(0)];
    let one_in = [group(1)];
    let one_out = [group(0)];
    let kcc3_1 = [kcc3(1)];
    let account_1 = [account(1)];
    let account_0 = [account(0)];
    let cases: [(Draft<'_>, u8); 5] = [
        (
            Draft {
                input_hints: &twice_in,
                ..none
            },
            0x44,
        ),
        (
            Draft {
                input_hints: &one_in,
                kcc3_hints: &kcc3_1,
                ..none
            },
            0x46,
        ),
        (
            Draft {
                kcc3_hints: &kcc3_1,
                account_hints: &account_1,
                ..none
            },
            0x47,
        ),
        (
            Draft {
                output_hints: &twice_out,
                ..none
            },
            0x45,
        ),
        (
            Draft {
                output_hints: &one_out,
                account_output_hints: &account_0,
                ..none
            },
            0x48,
        ),
    ];
    with_tx(&k, |tx| {
        let body = draft_len(&none, tx, &P).expect("no hints");
        for (draft, marker) in cases {
            match draft_len(&draft, tx, &P) {
                Err(KsptError::RepeatedRecord { marker: m, at }) => {
                    assert_eq!(m, marker);
                    assert!(at > body, "{marker:#04x}: {at} is not past the body");
                }
                other => panic!("{marker:#04x}: a second hint was written: {other:?}"),
            }
            let mut out = vec![0xEEu8; 1024];
            assert!(write_draft(&draft, tx, &P, &mut out).is_err());
            assert!(
                out.iter().all(|&b| b == 0xEE),
                "{marker:#04x}: bytes written"
            );
        }

        // The parser refuses the same records, written by hand, at the same
        // offset.
        let mut by_hand = c.clone();
        by_hand.in_hints = vec![(1, 1, 0, 3), (1, 1, 0, 3)];
        let at = match draft_len(&cases[0].0, tx, &P) {
            Err(KsptError::RepeatedRecord { at, .. }) => at,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            kspt::parse(&by_hand.bytes(), &P).map(|_| ()),
            Err(KsptError::RepeatedRecord { marker: 0x44, at })
        );
    });
}

/// A draft the parser would refuse is not written: no input, no output, or
/// a covenant binding naming an input the transaction lacks. The binding is
/// refused at the offset where the parser refuses the same payload written
/// by hand, and nothing is written.
#[test]
fn a_draft_the_parser_would_refuse_is_not_written() {
    use kassigner_protocol::kspt::{draft_len, write_draft, Draft};

    let c = Canon::new(&[100_000, 50_000], &[120_000, 20_000]);
    let bytes = c.bytes();
    let k = kspt::parse(&bytes, &P).expect("parse");
    let redeems: [&[u8]; 2] = [&[], &[]];
    let draft = Draft {
        redeems: &redeems,
        input_hints: &[],
        kcc3_hints: &[],
        account_hints: &[],
        output_hints: &[],
        account_output_hints: &[],
        coin_covenants: &[],
    };
    let refused = |tx: &Transaction<'_>, d: &Draft<'_>| {
        let measured = draft_len(d, tx, &P).expect_err("measured");
        let mut out = vec![0xEEu8; 1024];
        assert_eq!(write_draft(d, tx, &P, &mut out), Err(measured));
        assert!(out.iter().all(|&b| b == 0xEE), "bytes written");
        measured
    };

    with_tx(&k, |tx| {
        assert!(draft_len(&draft, tx, &P).is_ok());

        let no_redeems: [&[u8]; 0] = [];
        let no_inputs = Transaction { inputs: &[], ..*tx };
        let d = Draft {
            redeems: &no_redeems,
            ..draft
        };
        assert_eq!(
            refused(&no_inputs, &d),
            KsptError::Empty {
                field: Field::Inputs
            }
        );

        let no_outputs = Transaction {
            outputs: &[],
            ..*tx
        };
        assert_eq!(
            refused(&no_outputs, &draft),
            KsptError::Empty {
                field: Field::Outputs
            }
        );

        let mut outs = tx.outputs.to_vec();
        outs[1].covenant = Some(CovenantBinding {
            authorizing_input: 2,
            covenant_id: [0xC5; 32],
        });
        let bound = Transaction {
            outputs: &outs,
            ..*tx
        };
        let e = refused(&bound, &draft);
        assert!(
            matches!(
                e,
                KsptError::AuthorizingInputOutOfRange {
                    output: 1,
                    input: 2,
                    ..
                }
            ),
            "{e:?}"
        );
        let mut by_hand = c.clone();
        by_hand.outputs[1].1 = Some((2, [0xC5; 32]));
        assert_eq!(kspt::parse(&by_hand.bytes(), &P).map(|_| ()), Err(e));

        // A binding naming an input the transaction has is written.
        outs[1].covenant = Some(CovenantBinding {
            authorizing_input: 1,
            covenant_id: [0xC5; 32],
        });
        let bound = Transaction {
            outputs: &outs,
            ..*tx
        };
        assert!(draft_len(&draft, &bound, &P).is_ok());
    });
}

/// A coin's covenant, `0x49`, is written from a draft and kept by a reply:
/// right after the outputs' covenants, 34 bytes for each bound coin and none
/// for an unbound one, and a signed reply still carries it, so the next
/// cosigner reads the same coin. A draft naming an input the transaction
/// lacks, or one input's coin twice, is refused and nothing written.
#[test]
fn a_coins_covenant_is_written_and_kept() {
    use kassigner_protocol::kspt::transaction::coins;
    use kassigner_protocol::kspt::{draft_len, write_draft, CoinCovenant, Draft, Hint, Record};

    let c = Canon::new(&[100_000, 50_000], &[140_000]);
    let plain = c.bytes();
    let k = kspt::parse(&plain, &P).expect("parse");
    let redeems: [&[u8]; 2] = [&[], &[]];
    let hints = [Hint {
        index: 1,
        cosigner: 0,
        chain: 0,
        addr_index: 3,
    }];
    let bound = [CoinCovenant {
        index: 1,
        covenant_id: [0x77; 32],
    }];
    let draft = Draft {
        redeems: &redeems,
        input_hints: &hints,
        kcc3_hints: &[],
        account_hints: &[],
        output_hints: &[],
        account_output_hints: &[],
        coin_covenants: &bound,
    };

    with_tx(&k, |tx| {
        let none = Draft {
            coin_covenants: &[],
            ..draft
        };
        let without = draft_len(&none, tx, &P).expect("len");
        let n = draft_len(&draft, tx, &P).expect("len");
        assert_eq!(n, without + 34, "34 bytes for the one bound coin");
        let mut request = vec![0u8; n];
        assert_eq!(write_draft(&draft, tx, &P, &mut request), Ok(n));

        // Before the hint, as the one order has it.
        let r = kspt::parse(&request, &P).expect("the request parses");
        let recs: Vec<_> = r.records().collect();
        assert_eq!(
            recs,
            [
                Record::CoinCovenant {
                    input_index: 1,
                    covenant_id: &[0x77; 32],
                },
                Record::InputHint(hints[0]),
            ]
        );
        let mut ids = [None; 2];
        coins(&r, &mut ids);
        assert_eq!(ids, [None, Some([0x77; 32])]);

        // A reply is the request and a signature: the record stays.
        assert_eq!(write_vec(&r, &[]).expect("re-encoded"), request);
        let reply = write_vec(&r, &[sig(1, 0, 0x42)]).expect("signed");
        let signed = kspt::parse(&reply, &P).expect("the reply parses");
        assert_eq!(signed.inputs().nth(1).unwrap().sig_count, 1);
        let mut ids = [None; 2];
        coins(&signed, &mut ids);
        assert_eq!(ids, [None, Some([0x77; 32])]);
        assert_eq!(sighashes(&signed), sighashes(&k), "no signature covers it");

        let refused = |d: &Draft<'_>| {
            let measured = draft_len(d, tx, &P).expect_err("measured");
            let mut out = vec![0xEEu8; 1024];
            assert_eq!(write_draft(d, tx, &P, &mut out), Err(measured));
            assert!(out.iter().all(|&b| b == 0xEE), "bytes written");
            measured
        };
        let past = [CoinCovenant {
            index: 2,
            covenant_id: [0x77; 32],
        }];
        assert_eq!(
            refused(&Draft {
                coin_covenants: &past,
                ..draft
            }),
            KsptError::NoSuchInput { index: 2 }
        );
        let twice = [bound[0], bound[0]];
        assert!(matches!(
            refused(&Draft {
                coin_covenants: &twice,
                ..draft
            }),
            KsptError::RepeatedRecord { marker: 0x49, .. }
        ));
    });
}
