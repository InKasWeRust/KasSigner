// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! PSKB against upstream: reading a bundle's transaction, signing into a
//! bundle, and writing one. Every bundle is built by upstream's crate, and
//! every check is against what upstream computes or writes.

use std::panic::{catch_unwind, AssertUnwindSafe};

use kaspa_bip32::DerivationPath;
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE as UP_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction as UpTransaction, TransactionOutpoint, UtxoEntry,
};
use kaspa_hashes::Hash as UpHash;
use kaspa_wallet_pskt::bundle::Bundle;
use kaspa_wallet_pskt::input::InputBuilder;
use kaspa_wallet_pskt::output::OutputBuilder;
use kaspa_wallet_pskt::pskt::{KeySource, SignInputOk, Signature as UpSignature, Version, PSKT};
use kaspa_wallet_pskt::role::{Creator, Signer};
use secp256k1::{Keypair, Message, Secp256k1};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::hex;
#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::p2pk;

use kassigner_kaspa::pskb::signature::{splices, text_len, Derivation, EditError, PartialSig};
use kassigner_kaspa::pskb::transaction::{
    build, counts, fill, input_covenant_id, input_extras, Filled, ReadError,
};
use kassigner_kaspa::pskb::write::{
    self as pskb_write, key_source, key_source_max, Global, Input as WriteInput, Member,
    Output as WriteOutput, Version as WriteVersion, WriteError,
};
use kassigner_kaspa::pskb::{
    check, decode_envelope, emit, emitted_len, encode_envelope, walk, Field, LexError, Lexer,
    ParseError, Scope, Span, Splice, Visitor,
};
use kassigner_kaspa::sighash::{schnorr_signature_hash, Hash, SIG_HASH_ALL};
use kassigner_kaspa::tx::{
    CovenantBinding as OurBinding, EntryDetails, Outpoint, ScriptPublicKey as OurScript,
    Transaction, TransactionInput, TransactionOutput, UtxoEntry as OurEntry,
};

const BLANK_IN: TransactionInput<'static> = TransactionInput {
    previous_outpoint: Outpoint {
        transaction_id: [0; 32],
        index: 0,
    },
    sequence: 0,
    sig_op_count: 0,
    compute_budget: 0,
    signature_script: &[],
    utxo_entry: OurEntry {
        amount: 0,
        script_public_key: OurScript {
            version: 0,
            script: &[],
        },
    },
};

const BLANK_OUT: TransactionOutput<'static> = TransactionOutput {
    value: 0,
    script_public_key: OurScript {
        version: 0,
        script: &[],
    },
    covenant: None,
};

// ── Bundles, built by upstream ──────────────────────────────────────────────

#[derive(Clone)]
struct In {
    amount: u64,
    script: Vec<u8>,
    script_version: u16,
    min_time: Option<u64>,
    sig_ops: Option<u8>,
    entry: bool,
    redeem: Option<Vec<u8>>,
}

impl In {
    fn new(amount: u64, script: Vec<u8>) -> Self {
        Self {
            amount,
            script,
            script_version: 0,
            min_time: None,
            sig_ops: None,
            entry: true,
            redeem: None,
        }
    }
}

/// A covenant binding: authorizing input and id.
type Binding = (u16, [u8; 32]);

#[derive(Clone)]
struct Out {
    amount: u64,
    script: Vec<u8>,
    covenant: Option<Binding>,
}

#[derive(Clone)]
struct Spec {
    version: Version,
    tx_version: u16,
    fallback: Option<u64>,
    payload: Option<Vec<u8>>,
    inputs: Vec<In>,
    outputs: Vec<Out>,
    /// Input and sequence, set through upstream's updater.
    sequences: Vec<(usize, u64)>,
}

fn p2sh(b: u8) -> Vec<u8> {
    let mut v = vec![0xaa, 0x20];
    v.extend_from_slice(&[b; 32]);
    v.push(0x87);
    v
}

/// Bundle and transaction version zero: signature operation counts hashed.
fn plain() -> Spec {
    let mut a = In::new(150_000, p2pk(&[0x31; 32]));
    a.sig_ops = Some(1);
    a.min_time = Some(1_000);
    let mut b = In::new(90_000, p2pk(&[0x32; 32]));
    b.sig_ops = Some(2);
    Spec {
        version: Version::Zero,
        tx_version: 0,
        fallback: None,
        payload: None,
        inputs: vec![a, b],
        outputs: vec![Out {
            amount: 230_000,
            script: p2pk(&[0x41; 32]),
            covenant: None,
        }],
        sequences: vec![(1, 7)],
    }
}

/// Every field the extraction reads.
fn rich() -> Spec {
    let mut a = In::new(150_000, p2pk(&[0x31; 32]));
    a.min_time = Some(1_700_000_000);
    a.sig_ops = Some(1);
    let mut b = In::new(90_000, p2sh(0x32));
    b.min_time = Some(1_700_000_500);
    b.redeem = Some(vec![0x51, 0x21, 0x02, 0xac]);
    let mut c = In::new(60_000, p2pk(&[0x33; 32]));
    c.script_version = 1;
    Spec {
        version: Version::Two,
        tx_version: 1,
        fallback: Some(12),
        payload: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        inputs: vec![a, b, c],
        outputs: vec![
            Out {
                amount: 200_000,
                script: p2pk(&[0x41; 32]),
                covenant: None,
            },
            Out {
                amount: 50_000,
                script: p2sh(0x42),
                covenant: Some((1, [0xc5; 32])),
            },
            Out {
                amount: 40_000,
                script: p2pk(&[0x43; 32]),
                covenant: None,
            },
        ],
        sequences: vec![(1, 7)],
    }
}

fn pskt(s: &Spec) -> PSKT<Signer> {
    let mut creator = PSKT::<Creator>::default().set_version(s.version);
    if let Some(f) = s.fallback {
        creator = creator.fallback_lock_time(f);
    }
    let mut k = creator.constructor().set_tx_version(s.tx_version);
    for (i, spec) in s.inputs.iter().enumerate() {
        let mut b = InputBuilder::default();
        b.previous_outpoint(TransactionOutpoint::new(
            UpHash::from_bytes([i as u8 + 1; 32]),
            i as u32 * 3,
        ));
        b.min_time(spec.min_time);
        if spec.entry {
            b.utxo_entry(UtxoEntry::new(
                spec.amount,
                ScriptPublicKey::from_vec(spec.script_version, spec.script.clone()),
                100,
                false,
                None,
            ));
        }
        if let Some(n) = spec.sig_ops {
            b.sig_op_count(n);
        }
        if let Some(r) = &spec.redeem {
            b.redeem_script(r.clone());
        }
        k = k.input(b.build().expect("input"));
    }
    for o in &s.outputs {
        let covenant = o.covenant.map(|(authorizing_input, id)| CovenantBinding {
            authorizing_input,
            covenant_id: UpHash::from_bytes(id),
        });
        let out = OutputBuilder::default()
            .amount(o.amount)
            .script_public_key(ScriptPublicKey::from_vec(0, o.script.clone()))
            .covenant(covenant)
            .build()
            .expect("output");
        k = k.output(out).expect("upstream accepts the output");
    }
    k = k
        .payload(s.payload.clone())
        .expect("upstream accepts the payload");
    let mut u = k.updater();
    for &(i, n) in &s.sequences {
        u = u.set_sequence(n, i).expect("sequence");
    }
    u.signer()
}

fn key(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32]).expect("valid key")
}

fn schnorr(digest: Hash, key: &Keypair, aux: Option<[u8; 32]>) -> [u8; 64] {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(digest);
    match aux {
        None => secp.sign_schnorr_no_aux_rand(&msg, key),
        Some(a) => secp.sign_schnorr_with_aux_rand(&msg, key, &a),
    }
    .serialize()
}

struct Upstream {
    signed: PSKT<Signer>,
    tx: UpTransaction,
    entries: Vec<Option<UtxoEntry>>,
    hashes: Vec<Hash>,
}

/// Have upstream sign every input with `key`, keeping what it hashed.
fn upstream_sign(
    p: PSKT<Signer>,
    key: &Keypair,
    aux: Option<[u8; 32]>,
    source: Option<KeySource>,
) -> Upstream {
    let mut seen = None;
    let signed = p
        .pass_signature_sync(|tx, types| -> Result<Vec<SignInputOk>, String> {
            let reused = SigHashReusedValuesUnsync::new();
            let v = tx.as_verifiable();
            let mut hashes = Vec::new();
            let mut out = Vec::new();
            for (i, ty) in types.iter().enumerate() {
                let h = calc_schnorr_signature_hash(&v, i, *ty, &reused).as_bytes();
                out.push(SignInputOk {
                    signature: UpSignature::Schnorr(
                        secp256k1::schnorr::Signature::from_slice(&schnorr(h, key, aux))
                            .expect("signature"),
                    ),
                    pub_key: key.public_key(),
                    key_source: source.clone(),
                });
                hashes.push(h);
            }
            seen = Some((tx.tx.clone(), tx.entries.clone(), hashes));
            Ok(out)
        })
        .expect("upstream signs");
    let (tx, entries, hashes) = seen.expect("the signer ran");
    Upstream {
        signed,
        tx,
        entries,
        hashes,
    }
}

fn envelope(p: PSKT<Signer>) -> String {
    Bundle::from(p).serialize().expect("upstream serializes")
}

fn doc_of(bundle: &str) -> Vec<u8> {
    let mut json = vec![0u8; bundle.len()];
    let n = decode_envelope(bundle.as_bytes(), &mut json).expect("envelope");
    json.truncate(n);
    json
}

fn to_envelope(json: &[u8]) -> String {
    let mut env = vec![0u8; 4 + 2 * json.len()];
    let e = encode_envelope(json, &mut env).expect("envelope");
    String::from_utf8(env[..e].to_vec()).expect("ascii")
}

// ── Our side ────────────────────────────────────────────────────────────────

/// Read transaction `index` with our reader and hand it to `f`.
fn ours<R>(doc: &[u8], index: usize, f: impl FnOnce(Filled<'_>, &Transaction<'_>) -> R) -> R {
    let mut ins = [BLANK_IN; 8];
    let mut outs = [BLANK_OUT; 8];
    let mut buf = [0u8; 2048];
    let filled = fill(doc, index, &mut ins, &mut outs, &mut buf).expect("our reader");
    let tx = build(
        &filled.header,
        &ins[..filled.inputs],
        &outs[..filled.outputs],
    );
    f(filled, &tx)
}

fn our_hashes(doc: &[u8]) -> Vec<Hash> {
    ours(doc, 0, |_, tx| {
        (0..tx.inputs.len())
            .map(|i| schnorr_signature_hash(tx, i, SIG_HASH_ALL).expect("an input"))
            .collect()
    })
}

/// Run our edit and apply it, returning the envelope.
fn apply(doc: &[u8], sigs: &[PartialSig<'_>]) -> Result<String, EditError> {
    let mut text = vec![0u8; text_len(sigs)];
    let mut edits = vec![Splice::insert_at(0, &[]); sigs.len() * 2];
    let n = splices(check(doc)?, 0, sigs, &mut text, &mut edits)?;
    let len = emitted_len(doc, &edits[..n]).expect("ordered splices");
    let mut json = vec![0u8; len];
    assert_eq!(emit(doc, &edits[..n], &mut json).expect("emit"), len);
    Ok(to_envelope(&json))
}

/// Sign every input from our hashes and put the signatures in with our edit.
fn our_sign(
    doc: &[u8],
    key: &Keypair,
    aux: Option<[u8; 32]>,
    derivation: Derivation<'_>,
) -> String {
    let pk = key.public_key().serialize();
    let sigs: Vec<[u8; 64]> = our_hashes(doc)
        .into_iter()
        .map(|h| schnorr(h, key, aux))
        .collect();
    let partial: Vec<PartialSig<'_>> = sigs
        .iter()
        .enumerate()
        .map(|(input, signature)| PartialSig {
            input,
            public_key: &pk,
            signature,
            derivation,
        })
        .collect();
    apply(doc, &partial).expect("our edit")
}

// ── Reading ─────────────────────────────────────────────────────────────────

fn assert_same(ours: &Transaction<'_>, up: &Upstream) {
    let theirs = &up.tx;
    assert_eq!(ours.version, theirs.version, "version");
    assert_eq!(ours.lock_time, theirs.lock_time, "lock time");
    assert_eq!(ours.subnetwork_id, [0u8; 20]);
    assert_eq!(theirs.subnetwork_id, UP_NATIVE);
    assert_eq!(ours.gas, theirs.gas, "gas");
    assert_eq!(ours.payload, &theirs.payload[..], "payload");
    assert_eq!(ours.inputs.len(), theirs.inputs.len());
    for (i, (o, t)) in ours.inputs.iter().zip(&theirs.inputs).enumerate() {
        assert_eq!(
            o.previous_outpoint.transaction_id,
            t.previous_outpoint.transaction_id.as_bytes(),
            "input {i}"
        );
        assert_eq!(o.previous_outpoint.index, t.previous_outpoint.index);
        assert_eq!(o.sequence, t.sequence, "input {i} sequence");
        assert!(o.signature_script.is_empty() && t.signature_script.is_empty());
        let e = up.entries[i].as_ref().expect("an entry");
        assert_eq!(o.utxo_entry.amount, e.amount, "input {i} amount");
        assert_eq!(
            o.utxo_entry.script_public_key.version,
            e.script_public_key.version()
        );
        assert_eq!(
            o.utxo_entry.script_public_key.script,
            e.script_public_key.script()
        );
    }
    assert_eq!(ours.outputs.len(), theirs.outputs.len());
    for (k, (o, t)) in ours.outputs.iter().zip(&theirs.outputs).enumerate() {
        assert_eq!(o.value, t.value, "output {k}");
        assert_eq!(o.script_public_key.version, t.script_public_key.version());
        assert_eq!(o.script_public_key.script, t.script_public_key.script());
        assert_eq!(
            o.covenant.map(|c| (c.authorizing_input, c.covenant_id)),
            t.covenant
                .map(|c| (c.authorizing_input, c.covenant_id.as_bytes())),
            "output {k} covenant"
        );
    }
}

/// A bundle reads as upstream extracts it, field by field and hash by hash.
#[test]
fn a_bundle_reads_as_upstream_extracts_it() {
    for spec in [plain(), rich()] {
        let doc = doc_of(&envelope(pskt(&spec)));
        let up = upstream_sign(pskt(&spec), &key(3), None, None);
        ours(&doc, 0, |filled, tx| {
            assert_eq!(
                (filled.inputs, filled.outputs),
                (spec.inputs.len(), spec.outputs.len())
            );
            assert_same(tx, &up);
        });
        assert_eq!(our_hashes(&doc), up.hashes);
    }

    // What those fields came from, so the comparison is not of two empty
    // things.
    let up = upstream_sign(pskt(&rich()), &key(3), None, None);
    assert_eq!(up.tx.lock_time, 1_700_000_500, "the largest minTime");
    assert_eq!(up.tx.inputs[1].sequence, 7, "a sequence that was set");
    assert_eq!(up.tx.inputs[0].sequence, u64::MAX, "one that was not");
    assert_eq!(up.tx.payload, vec![0xde, 0xad, 0xbe, 0xef]);
    assert!(up.tx.outputs[1].covenant.is_some());
}

/// `fallbackLockTime` counts only for a bundle with no inputs.
#[test]
fn the_fallback_lock_time_only_counts_without_inputs() {
    let mut s = plain();
    s.fallback = Some(99);
    for i in &mut s.inputs {
        i.min_time = None;
    }
    let doc = doc_of(&envelope(pskt(&s)));
    let up = upstream_sign(pskt(&s), &key(3), None, None);
    assert_eq!(up.tx.lock_time, 0);
    ours(&doc, 0, |_, tx| assert_eq!(tx.lock_time, 0));

    s.inputs.clear();
    s.sequences.clear();
    let doc = doc_of(&envelope(pskt(&s)));
    let up = upstream_sign(pskt(&s), &key(3), None, None);
    assert_eq!(up.tx.lock_time, 99);
    ours(&doc, 0, |filled, tx| {
        assert_eq!(filled.inputs, 0);
        assert_eq!(tx.lock_time, 99);
    });
}

/// A payload is carried only from bundle version One: lowered to zero, the
/// bundle reads without it, here and upstream.
#[test]
fn the_payload_needs_bundle_version_one() {
    let mut s = plain();
    s.version = Version::One;
    s.payload = Some(vec![1, 2, 3]);
    let doc = doc_of(&envelope(pskt(&s)));
    ours(&doc, 0, |_, tx| assert_eq!(tx.payload, &[1, 2, 3]));

    let text = String::from_utf8(doc).expect("utf-8");
    let lowered = text.replacen("\"version\":1", "\"version\":0", 1);
    assert_ne!(lowered, text);
    let bundle = Bundle::deserialize(&to_envelope(lowered.as_bytes())).expect("upstream reads it");
    let inner = bundle.0.into_iter().next().expect("one transaction");
    let up = upstream_sign(PSKT::<Signer>::from(inner), &key(3), None, None);
    assert!(up.tx.payload.is_empty());
    ours(lowered.as_bytes(), 0, |_, tx| {
        assert!(tx.payload.is_empty())
    });
}

/// An input without its entry stops both readers.
#[test]
fn an_input_without_its_entry_stops_both_readers() {
    let mut s = plain();
    s.inputs[1].entry = false;
    let doc = doc_of(&envelope(pskt(&s)));
    let mut ins = [BLANK_IN; 8];
    let mut outs = [BLANK_OUT; 8];
    let mut buf = [0u8; 1024];
    assert_eq!(
        fill(&doc, 0, &mut ins, &mut outs, &mut buf).err(),
        Some(ReadError::NoUtxoEntry { input: 1 })
    );

    let p = pskt(&s);
    let k = key(3);
    let r = catch_unwind(AssertUnwindSafe(|| upstream_sign(p, &k, None, None)));
    assert!(r.is_err(), "upstream went past an input with no entry");
}

/// One bundle, two transactions: each reads as its own.
#[test]
fn a_bundle_of_two_reads_by_index() {
    let bundle = Bundle::from(vec![pskt(&plain()), pskt(&rich())])
        .serialize()
        .expect("upstream serializes");
    let doc = doc_of(&bundle);
    assert_eq!(counts(&doc, 0), Ok((2, 1)));
    assert_eq!(counts(&doc, 1), Ok((3, 3)));
    assert_eq!(
        counts(&doc, 2),
        Err(ReadError::NoSuchTransaction { index: 2, count: 2 })
    );
    let up = upstream_sign(pskt(&rich()), &key(3), None, None);
    ours(&doc, 1, |_, tx| assert_same(tx, &up));
}

/// What upstream's extraction would not produce, refused, and said where.
#[test]
fn the_reader_refuses_what_upstream_would_not_extract() {
    const OUTPOINT: &str = "{\"transactionId\":\"0101010101010101010101010101010101010101010101010101010101010101\",\"index\":0}";
    // The rest of an input, a whole output and the rest of a global map, as
    // upstream requires them: each case changes one thing.
    const INPUT_REST: &str = ",\"partialSigs\":{},\"sighashType\":1,\"redeemScript\":null,\
                              \"bip32Derivations\":{},\"finalScriptSig\":null,\"proprietaries\":{}";
    const OUTPUT: &str = "{\"amount\":1,\"scriptPublicKey\":\"0000\",\"redeemScript\":null,\
                          \"bip32Derivations\":{},\"proprietaries\":{}}";
    const GLOBAL_REST: &str = ",\"inputsModifiable\":false,\"outputsModifiable\":false,\
                               \"inputCount\":1,\"outputCount\":1,\"xpubs\":{},\"proprietaries\":{},\
                               \"payload\":null";
    let input = |entry: &str| {
        format!("{{\"previousOutpoint\":{OUTPOINT},\"utxoEntry\":{entry}{INPUT_REST}}}")
    };
    let good_entry =
        "{\"amount\":5,\"scriptPublicKey\":\"0000aa\",\"blockDaaScore\":0,\"isCoinbase\":false}";
    let tx = |global: &str, inputs: &str| {
        format!("[{{\"global\":{global},\"inputs\":{inputs},\"outputs\":[{OUTPUT}]}}]")
    };
    let global = format!("{{\"version\":0,\"txVersion\":0{GLOBAL_REST}}}");
    let global = global.as_str();
    let read = |doc: &str, room: usize, buf_len: usize| {
        let mut ins = [BLANK_IN; 4];
        let mut outs = [BLANK_OUT; 4];
        let mut buf = [0u8; 64];
        fill(
            doc.as_bytes(),
            0,
            &mut ins[..room],
            &mut outs,
            &mut buf[..buf_len],
        )
        .map(|f| f.inputs)
    };

    let one = format!("[{}]", input(good_entry));
    assert_eq!(read(&tx(global, &one), 4, 64), Ok(1));

    assert_eq!(
        read(&tx(global, "[{}]"), 4, 64),
        Err(ReadError::Missing {
            scope: Scope::Input(0),
            field: Field::PreviousOutpoint
        }),
        "an empty input is still an input"
    );
    let twice = format!(
        "[{{\"previousOutpoint\":{OUTPOINT},\"utxoEntry\":{good_entry},\"sequence\":1,\"sequence\":2{INPUT_REST}}}]"
    );
    assert_eq!(
        read(&tx(global, &twice), 4, 64),
        Err(ReadError::Duplicate {
            scope: Scope::Input(0),
            field: Field::Sequence
        })
    );
    let upper = format!(
        "[{}]",
        input("{\"amount\":5,\"scriptPublicKey\":\"0000AA\",\"blockDaaScore\":0,\"isCoinbase\":false}")
    );
    assert_eq!(
        read(&tx(global, &upper), 4, 64),
        Ok(1),
        "upstream reads hex in either case"
    );
    let zero_led = format!(
        "[{}]",
        input("{\"amount\":05,\"scriptPublicKey\":\"0000aa\",\"blockDaaScore\":0,\"isCoinbase\":false}")
    );
    assert!(
        matches!(
            read(&tx(global, &zero_led), 4, 64),
            Err(ReadError::Parse(ParseError::Lex(
                LexError::BadNumber { .. }
            )))
        ),
        "a number JSON does not have is refused wherever it stands"
    );
    let sig_ops = format!(
        "[{{\"previousOutpoint\":{OUTPOINT},\"utxoEntry\":{good_entry},\"sigOpCount\":256{INPUT_REST}}}]"
    );
    assert_eq!(
        read(&tx(global, &sig_ops), 4, 64),
        Err(ReadError::Malformed {
            scope: Scope::Input(0),
            field: Field::SigOpCount
        })
    );
    assert_eq!(
        read(&tx(&format!("{{\"version\":0{GLOBAL_REST}}}"), &one), 4, 64),
        Err(ReadError::Missing {
            scope: Scope::Global,
            field: Field::TxVersion
        })
    );
    assert_eq!(
        read(
            &tx(
                &format!("{{\"version\":3,\"txVersion\":0{GLOBAL_REST}}}"),
                &one
            ),
            4,
            64
        ),
        Err(ReadError::Malformed {
            scope: Scope::Global,
            field: Field::Version
        })
    );
    let repeated =
        format!("[{{\"global\":{global},\"inputs\":{one},\"inputs\":{one},\"outputs\":[]}}]");
    assert_eq!(read(&repeated, 4, 64), Err(ReadError::RepeatedSection));

    let five = format!("[{}]", vec![input(good_entry); 5].join(","));
    assert_eq!(
        read(&tx(global, &five), 4, 64),
        Err(ReadError::TooManyInputs { needed: 5, room: 4 })
    );
    assert_eq!(
        read(&tx(global, &one), 4, 0),
        Err(ReadError::BufferTooSmall)
    );
}

// ── Signing ─────────────────────────────────────────────────────────────────

/// A bundle signed here is, byte for byte, the bundle upstream's signer writes.
#[test]
fn a_signed_bundle_is_the_one_upstream_writes() {
    for spec in [plain(), rich()] {
        let doc = doc_of(&envelope(pskt(&spec)));
        let k = key(5);
        let up = upstream_sign(pskt(&spec), &k, None, None);
        assert_eq!(
            our_sign(&doc, &k, None, Derivation::Null),
            envelope(up.signed)
        );
    }
}

/// A second key goes in at its place in key order, before or after the first.
#[test]
fn a_second_key_lands_in_key_order() {
    let (a, b) = (key(5), key(6));
    let (lo, hi) = if a.public_key().serialize() < b.public_key().serialize() {
        (a, b)
    } else {
        (b, a)
    };
    for (first, second) in [(&lo, &hi), (&hi, &lo)] {
        let spec = rich();
        let once = doc_of(&envelope(
            upstream_sign(pskt(&spec), first, None, None).signed,
        ));
        let twice = envelope(
            upstream_sign(
                upstream_sign(pskt(&spec), first, None, None).signed,
                second,
                None,
                None,
            )
            .signed,
        );
        assert_eq!(our_sign(&once, second, None, Derivation::Null), twice);
    }
}

/// Two keys in one call, in any order, land as upstream writes two signers.
#[test]
fn two_keys_in_one_call_land_as_upstream_puts_them() {
    let spec = plain();
    let doc = doc_of(&envelope(pskt(&spec)));
    let (a, b) = (key(5), key(6));
    let twice = envelope(
        upstream_sign(
            upstream_sign(pskt(&spec), &a, None, None).signed,
            &b,
            None,
            None,
        )
        .signed,
    );

    let hashes = our_hashes(&doc);
    let (pa, pb) = (a.public_key().serialize(), b.public_key().serialize());
    let sa: Vec<[u8; 64]> = hashes.iter().map(|h| schnorr(*h, &a, None)).collect();
    let sb: Vec<[u8; 64]> = hashes.iter().map(|h| schnorr(*h, &b, None)).collect();
    let (p1, s1, p2, s2) = if pa > pb {
        (&pa, &sa, &pb, &sb)
    } else {
        (&pb, &sb, &pa, &sa)
    };
    let mut sigs = Vec::new();
    for i in (0..hashes.len()).rev() {
        for (public_key, s) in [(p1, s1), (p2, s2)] {
            sigs.push(PartialSig {
                input: i,
                public_key,
                signature: &s[i],
                derivation: Derivation::Null,
            });
        }
    }
    assert_eq!(apply(&doc, &sigs).expect("our edit"), twice);
}

/// Signing again with a key replaces its signature, as upstream's map does.
#[test]
fn signing_again_with_one_key_replaces_its_signature() {
    let spec = plain();
    let k = key(5);
    let first = || upstream_sign(pskt(&spec), &k, Some([1; 32]), None).signed;
    let once = doc_of(&envelope(first()));
    let twice = envelope(upstream_sign(first(), &k, Some([2; 32]), None).signed);
    assert_ne!(envelope(first()), twice, "the second signature differs");
    assert_eq!(our_sign(&once, &k, Some([2; 32]), Derivation::Null), twice);
}

/// The value upstream wrote for a key under `bip32Derivations`.
fn derivation_value(doc: &[u8], input: usize, pk: &[u8; 33]) -> Vec<u8> {
    struct Find {
        input: usize,
        span: Option<Span>,
    }
    impl Visitor for Find {
        fn field(&mut self, scope: Scope, field: Field, value: Span) -> Result<(), ParseError> {
            if scope == Scope::Input(self.input) && field == Field::Bip32Derivations {
                self.span = Some(value);
            }
            Ok(())
        }
    }
    let mut f = Find { input, span: None };
    walk(doc, &mut f).expect("walk");
    let map = f.span.expect("a derivation map");
    let text = &doc[map.start..map.end];
    let member = format!("\"{}\":", hex(pk));
    let at = text
        .windows(member.len())
        .position(|w| w == member.as_bytes())
        .expect("the key is in the map")
        + member.len();
    let mut lex = Lexer::new(&text[at..]);
    let (s, e) = lex.skip_value().expect("a value");
    text[at + s..at + e].to_vec()
}

/// A key source handed back is written as it was.
#[test]
fn a_key_source_passed_back_is_written_as_it_was() {
    let spec = plain();
    let k = key(5);
    let path: DerivationPath = "m/45'/111111'/0'/0/3".parse().expect("path");
    let source = KeySource::new([0xab, 0xcd, 0xef, 0x01], path);
    let with_source = envelope(upstream_sign(pskt(&spec), &k, None, Some(source)).signed);
    let value = derivation_value(&doc_of(&with_source), 0, &k.public_key().serialize());
    assert_ne!(value, b"null".to_vec());

    let unsigned = doc_of(&envelope(pskt(&spec)));
    assert_eq!(
        our_sign(&unsigned, &k, None, Derivation::Value(&value)),
        with_source
    );
}

/// What the edit cannot place, refused, and said where.
#[test]
fn the_edit_refuses_what_it_cannot_place() {
    let spec = plain();
    let doc = doc_of(&envelope(pskt(&spec)));
    let pk = key(5).public_key().serialize();
    let sig = [7u8; 64];
    let one = |input| PartialSig {
        input,
        public_key: &pk,
        signature: &sig,
        derivation: Derivation::Null,
    };
    let edit = |doc: &[u8], index: usize, sigs: &[PartialSig<'_>]| {
        let mut text = vec![0u8; text_len(sigs)];
        let mut edits = vec![Splice::insert_at(0, &[]); sigs.len() * 2];
        splices(check(doc)?, index, sigs, &mut text, &mut edits).map(|_| ())
    };

    assert_eq!(edit(&doc, 0, &[one(0)]), Ok(()));
    assert_eq!(
        edit(&doc, 0, &[one(9)]),
        Err(EditError::NoSuchInput { index: 9 })
    );
    assert_eq!(
        edit(&doc, 1, &[one(0)]),
        Err(EditError::NoSuchTransaction { index: 1, count: 1 })
    );
    assert_eq!(
        edit(&doc, 0, &[one(1), one(1)]),
        Err(EditError::SameKeyTwice { input: 1 })
    );
    let open = PartialSig {
        derivation: Derivation::Value(b"{\"open\":"),
        ..one(0)
    };
    assert_eq!(
        edit(&doc, 0, &[open]),
        Err(EditError::BadDerivation { input: 0 })
    );

    let mut short = vec![0u8; text_len(&[one(0)]) - 1];
    let mut edits = vec![Splice::insert_at(0, &[]); 2];
    assert_eq!(
        splices(check(&doc).unwrap(), 0, &[one(0)], &mut short, &mut edits),
        Err(EditError::TextTooSmall)
    );
    let mut text = vec![0u8; text_len(&[one(0)])];
    let mut few = vec![Splice::insert_at(0, &[]); 1];
    assert_eq!(
        splices(check(&doc).unwrap(), 0, &[one(0)], &mut text, &mut few),
        Err(EditError::SplicesTooSmall)
    );

    // An input with no `partialSigs` map.
    let text = String::from_utf8(doc.clone()).expect("utf-8");
    let renamed = text.replace("\"partialSigs\"", "\"partialSignatures\"");
    assert_eq!(
        edit(renamed.as_bytes(), 0, &[one(0)]),
        Err(EditError::Missing {
            input: 0,
            field: Field::PartialSigs
        })
    );
}

// ── Derivations, base58 and paths ───────────────────────────────────────────

use kaspa_bip32::{ExtendedPrivateKey as UpXPrv, Prefix as UpPrefix, SecretKey};
use kassigner_kaspa::base58::{decode_check, encode_check, encoded_max, Base58Error};
use kassigner_kaspa::bip32_public::{parse_path, Bip32Error, ChildNumber, HARDENED_OFFSET};
use kassigner_kaspa::pskb::signature::derivations;

/// Base58Check is upstream's, both ways.
#[test]
fn base58check_is_upstreams() {
    let k = UpXPrv::<SecretKey>::new([3u8; 64]).unwrap();
    for (prefix, up) in [
        (
            UpPrefix::KPUB,
            k.public_key().to_string(Some(UpPrefix::KPUB)),
        ),
        (
            UpPrefix::KTUB,
            k.public_key().to_string(Some(UpPrefix::KTUB)),
        ),
    ] {
        let _ = prefix;
        let mut body = [0u8; 82];
        let n = decode_check(up.as_bytes(), &mut body).expect("decodes");
        assert_eq!(n, 78);
        let mut scratch = [0u8; 82];
        let mut text = [0u8; encoded_max(78)];
        let m = encode_check(&body[..n], &mut scratch, &mut text).expect("encodes");
        assert_eq!(&text[..m], up.as_bytes());
    }

    // Leading zeros survive, and refusals are named.
    let mut scratch = [0u8; 8];
    let mut text = [0u8; 16];
    let m = encode_check(&[0, 0, 1], &mut scratch, &mut text).unwrap();
    assert!(text[..m].starts_with(b"11"));
    let mut back = [0u8; 8];
    assert_eq!(decode_check(&text[..m], &mut back), Ok(3));
    assert_eq!(&back[..3], &[0, 0, 1]);
    text[m - 1] ^= 1;
    let r = decode_check(&text[..m], &mut back);
    assert!(matches!(
        r,
        Err(Base58Error::BadChecksum) | Err(Base58Error::BadCharacter { .. })
    ));
    assert_eq!(
        decode_check(b"1O", &mut back),
        Err(Base58Error::BadCharacter { at: 1 })
    );
    assert_eq!(decode_check(b"1", &mut back), Err(Base58Error::TooShort));
}

/// A derivation path parses, or is refused, as upstream's.
#[test]
fn derivation_paths_parse_as_upstreams() {
    for text in [
        "m",
        "m/0",
        "m/44'/111111'/0'/1/7",
        "m/45'/111111'/0'/2/0/2147483647",
        "m/01/+2'",
    ] {
        let up: DerivationPath = text.parse().expect("upstream parses");
        let mut ours = [ChildNumber(0); 8];
        let n = parse_path(text.as_bytes(), &mut ours).expect("ours parses");
        let theirs: Vec<u32> = up.iter().map(|c| c.0).collect();
        let mine: Vec<u32> = ours[..n].iter().map(|c| c.0).collect();
        assert_eq!(mine, theirs, "{text}");
    }
    for text in [
        "",
        "44'/0",
        "m/",
        "m//0",
        "m/0/",
        "m/x",
        "m/-1",
        "m/2147483648",
        "M/0",
    ] {
        assert!(
            text.parse::<DerivationPath>().is_err(),
            "upstream refuses {text:?}"
        );
        let mut ours = [ChildNumber(0); 8];
        assert_eq!(
            parse_path(text.as_bytes(), &mut ours),
            Err(Bip32Error::InvalidChild),
            "{text:?}"
        );
    }
    let mut one = [ChildNumber(0); 1];
    assert_eq!(
        parse_path(b"m/0/1", &mut one),
        Err(Bip32Error::BufferTooSmall)
    );
    let _ = HARDENED_OFFSET;
}

/// An input's `sighashType` reads back as its byte, as upstream reads it,
/// never as an absent type a signer could take for ALL.
#[test]
fn a_sighash_type_reads_back_as_its_byte() {
    let text = String::from_utf8(doc_of(&envelope(pskt(&plain())))).unwrap();
    assert!(
        text.contains("\"sighashType\":1,"),
        "upstream writes ALL as 1"
    );
    for byte in [0x01u8, 0x02, 0x04, 0x81, 0x82, 0x84, 0x00, 0x07, 0xFF] {
        let doc = text.replacen("\"sighashType\":1,", &format!("\"sighashType\":{byte},"), 1);
        let up = Bundle::deserialize(&to_envelope(doc.as_bytes())).expect("upstream reads it");
        assert_eq!(up.0[0].inputs[0].sighash_type.to_u8(), byte);
        let mut buf = [0u8; 64];
        let read = input_extras(check(doc.as_bytes()).unwrap(), 0, 0, &mut buf);
        assert_eq!(read.map(|x| x.sighash_type), Ok(byte), "{byte:#04x}");
        // The other input keeps its own.
        let read = input_extras(check(doc.as_bytes()).unwrap(), 0, 1, &mut buf);
        assert_eq!(read.map(|x| x.sighash_type), Ok(0x01));
    }
}

/// A spent coin's covenant id reads back as upstream reads it; `null` is
/// none.
#[test]
fn a_coins_covenant_id_reads_back() {
    let text = String::from_utf8(doc_of(&envelope(pskt(&plain())))).unwrap();
    let null = "\"covenantId\":null";
    assert!(
        text.matches(null).count() >= 2,
        "every input's entry has one"
    );
    let id = [0xc5u8; 32];
    let doc = text.replacen(null, &format!("\"covenantId\":\"{}\"", hex(&id)), 1);
    let up = Bundle::deserialize(&to_envelope(doc.as_bytes())).expect("upstream reads it");
    assert_eq!(
        up.0[0].inputs[0]
            .utxo_entry
            .as_ref()
            .unwrap()
            .covenant_id
            .map(|h| h.as_bytes()),
        Some(id)
    );
    let mut buf = [0u8; 64];
    let read = input_extras(check(doc.as_bytes()).unwrap(), 0, 0, &mut buf);
    assert_eq!(read.map(|x| x.covenant_id), Ok(Some(id)));
    let read = input_extras(check(doc.as_bytes()).unwrap(), 0, 1, &mut buf);
    assert_eq!(read.map(|x| x.covenant_id), Ok(None));
    // As written by upstream, every input's is none.
    let read = input_extras(check(text.as_bytes()).unwrap(), 0, 0, &mut buf);
    assert_eq!(read.map(|x| x.covenant_id), Ok(None));

    // The same with no room for a redeem script, as a signer reads it for
    // every input.
    let bound = check(doc.as_bytes()).unwrap();
    assert_eq!(input_covenant_id(bound, 0, 0), Ok(Some(id)));
    assert_eq!(input_covenant_id(bound, 0, 1), Ok(None));
    assert_eq!(
        input_covenant_id(check(text.as_bytes()).unwrap(), 0, 0),
        Ok(None)
    );
    let (inputs, _) = counts(doc.as_bytes(), 0).unwrap();
    assert_eq!(
        input_covenant_id(bound, 0, inputs),
        Err(ReadError::NoSuchInput { input: inputs })
    );
    assert!(matches!(
        input_covenant_id(bound, 1, 0),
        Err(ReadError::NoSuchTransaction { index: 1, .. })
    ));
}

/// An input's `bip32Derivations` reads back key by key, in written order.
#[test]
fn derivations_read_back_as_written() {
    let spec = plain();
    let (a, b) = (key(5), key(6));
    let path: DerivationPath = "m/45'/111111'/0'/1/0/4".parse().unwrap();
    let with_a = upstream_sign(
        pskt(&spec),
        &a,
        None,
        Some(KeySource::new([0xde, 0xad, 0xbe, 0xef], path)),
    )
    .signed;
    let both = upstream_sign(with_a, &b, None, None).signed;
    let doc = doc_of(&envelope(both));

    let mut seen = Vec::new();
    derivations(check(&doc).unwrap(), 0, 0, |e| {
        seen.push((
            e.public_key,
            e.source.map(|(f, p)| (f.to_vec(), p.to_vec())),
        ));
        true
    })
    .expect("reads");
    let (pa, pb) = (a.public_key().serialize(), b.public_key().serialize());
    let mut want = vec![
        (
            pa,
            Some((b"deadbeef".to_vec(), b"m/45'/111111'/0'/1/0/4".to_vec())),
        ),
        (pb, None),
    ];
    want.sort_by_key(|x| x.0);
    assert_eq!(seen, want);

    // Stopping early stops.
    let mut count = 0;
    derivations(check(&doc).unwrap(), 0, 0, |_| {
        count += 1;
        false
    })
    .unwrap();
    assert_eq!(count, 1);

    // An input past the end, and a value neither null nor a source.
    assert!(matches!(
        derivations(check(&doc).unwrap(), 0, 9, |_| true),
        Err(EditError::NoSuchInput { index: 9 })
    ));
    let text = String::from_utf8(doc).unwrap();
    let broken = text.replacen("\"keyFingerprint\"", "\"fingerprint\"", 1);
    assert!(Bundle::deserialize(&to_envelope(broken.as_bytes())).is_err());
    assert_eq!(
        check(broken.as_bytes()),
        Err(ParseError::Malformed {
            scope: Scope::Input(0),
            field: Field::Bip32Derivations
        })
    );
}

/// An input's `partialSigs` reads back as upstream's signer put them.
#[test]
fn signers_read_back_as_upstream_wrote_them() {
    use kassigner_kaspa::pskb::signature::signers;

    let spec = plain();
    let (a, b) = (key(5), key(6));
    let unsigned = doc_of(&envelope(pskt(&spec)));
    let mut none = 0;
    signers(check(&unsigned).unwrap(), 0, 0, |_| {
        none += 1;
        true
    })
    .expect("reads");
    assert_eq!(none, 0, "nothing signed yet");

    let with_a = upstream_sign(pskt(&spec), &a, None, None).signed;
    let both = upstream_sign(with_a, &b, None, None).signed;
    let doc = doc_of(&envelope(both));
    for input in 0..2 {
        let mut seen = Vec::new();
        signers(check(&doc).unwrap(), 0, input, |k| {
            seen.push(k);
            true
        })
        .expect("reads");
        let mut want = vec![a.public_key().serialize(), b.public_key().serialize()];
        want.sort();
        assert_eq!(seen, want, "input {input}");
    }

    // Stopping early stops.
    let mut count = 0;
    signers(check(&doc).unwrap(), 0, 0, |_| {
        count += 1;
        false
    })
    .unwrap();
    assert_eq!(count, 1);

    // An input past the end, and a key that is not 66 hex characters.
    assert!(matches!(
        signers(check(&doc).unwrap(), 0, 9, |_| true),
        Err(EditError::NoSuchInput { index: 9 })
    ));
    let mut broken = String::from_utf8(doc).unwrap();
    let map = "\"partialSigs\":{\"";
    let at = broken.find(map).expect("the first input's map") + map.len();
    broken.replace_range(at..at + 2, "");
    assert!(Bundle::deserialize(&to_envelope(broken.as_bytes())).is_err());
    assert_eq!(
        check(broken.as_bytes()),
        Err(ParseError::Malformed {
            scope: Scope::Input(0),
            field: Field::PartialSigs
        })
    );
}

// ── Either case, and a repeated key ─────────────────────────────────────────

use kassigner_kaspa::pskb::signature::presence;

/// The bundle in an envelope, as upstream reads and writes it back.
fn upstream_round_trip(env: &str) -> String {
    Bundle::deserialize(env)
        .expect("upstream reads it")
        .serialize()
        .expect("upstream writes it")
}

/// A bundle in uppercase hex reads as the lowercase one, here and upstream.
#[test]
fn an_uppercase_bundle_reads_as_the_lowercase_one() {
    let lower = envelope(pskb_of_plain());
    let upper = format!("PSKB{}", lower[4..].to_uppercase());
    assert_ne!(lower, upper);
    assert_eq!(
        doc_of(&lower),
        doc_of(&upper),
        "the envelope takes either case"
    );
    assert_eq!(upstream_round_trip(&upper), lower, "upstream takes it too");

    // Inside the document: every hex string in capitals.
    let doc = String::from_utf8(doc_of(&lower)).unwrap();
    let shouted = uppercase_hex_strings(&doc);
    assert_ne!(shouted, doc);
    assert_eq!(upstream_round_trip(&to_envelope(shouted.as_bytes())), lower);
    let a: Vec<Hash> = our_hashes(doc.as_bytes());
    let b: Vec<Hash> = our_hashes(shouted.as_bytes());
    assert_eq!(a, b);
}

fn pskb_of_plain() -> PSKT<Signer> {
    pskt(&plain())
}

/// Every JSON string made only of hex characters, in capitals.
fn uppercase_hex_strings(doc: &str) -> String {
    let mut out = String::new();
    for (i, part) in doc.split('"').enumerate() {
        if i > 0 {
            out.push('"');
        }
        let hexy = i % 2 == 1 && !part.is_empty() && part.bytes().all(|c| c.is_ascii_hexdigit());
        if hexy {
            out.push_str(&part.to_uppercase());
        } else {
            out.push_str(part);
        }
    }
    out
}

/// A key written in capitals is the same key: a new key lands around it, its
/// value is replaced in place, and upstream reads the result as its own.
#[test]
fn a_key_in_either_case_is_the_same_key() {
    let spec = plain();
    let (a, b) = (key(5), key(6));
    let signed_b = String::from_utf8(doc_of(&envelope(
        upstream_sign(pskt(&spec), &b, None, None).signed,
    )))
    .unwrap();
    let hb = hex(&b.public_key().serialize());
    let upper = signed_b.replace(&hb, &hb.to_uppercase());
    assert_ne!(upper, signed_b);

    let held = presence(
        check(upper.as_bytes()).unwrap(),
        0,
        0,
        &b.public_key().serialize(),
    )
    .unwrap();
    assert!(held.signed, "the capitals are the same key");

    let ours = our_sign(upper.as_bytes(), &a, None, Derivation::Null);
    let theirs = envelope(
        upstream_sign(
            upstream_sign(pskt(&spec), &b, None, None).signed,
            &a,
            None,
            None,
        )
        .signed,
    );
    assert_eq!(upstream_round_trip(&ours), theirs);

    // Signing again with the capitalised key replaces it, not adds to it.
    let again = our_sign(upper.as_bytes(), &b, Some([9; 32]), Derivation::Null);
    let re = envelope(
        upstream_sign(
            upstream_sign(pskt(&spec), &b, None, None).signed,
            &b,
            Some([9; 32]),
            None,
        )
        .signed,
    );
    assert_eq!(upstream_round_trip(&again), re);
    assert_eq!(
        String::from_utf8(doc_of(&again))
            .unwrap()
            .to_lowercase()
            .matches(&hb)
            .count(),
        4,
        "one member per map per input, two inputs"
    );
}

/// A key written twice reads as upstream reads it, the later value, and our
/// edit replaces that one.
#[test]
fn a_repeated_key_reads_as_upstream_keeps_it() {
    let spec = plain();
    let k = key(5);
    let hk = hex(&k.public_key().serialize());
    let signed = String::from_utf8(doc_of(&envelope(
        upstream_sign(pskt(&spec), &k, None, None).signed,
    )))
    .unwrap();
    let member = format!("\"{hk}\":{{\"schnorr\":\"");
    let at = signed.find(&member).expect("our member");
    let decoy = format!("\"{hk}\":{{\"schnorr\":\"{}\"}},", "11".repeat(64));
    let twice = format!("{}{}{}", &signed[..at], decoy, &signed[at..]);

    // Upstream keeps the later, real signature.
    let kept = upstream_round_trip(&to_envelope(twice.as_bytes()));
    assert_eq!(kept, to_envelope(signed.as_bytes()));
    let held = presence(
        check(twice.as_bytes()).unwrap(),
        0,
        0,
        &k.public_key().serialize(),
    )
    .unwrap();
    assert!(held.signed);
    // And the signature read is the later one, as a signer reading back its
    // own reply needs.
    let real = &signed[at + member.len()..at + member.len() + 128];
    assert_eq!(
        held.schnorr.map(|s| hex(&s)),
        Some(real.to_ascii_lowercase())
    );

    // Re-signing replaces the later one, so upstream reads the new signature.
    let again = our_sign(twice.as_bytes(), &k, Some([7; 32]), Derivation::Null);
    let want = envelope(
        upstream_sign(
            upstream_sign(pskt(&spec), &k, None, None).signed,
            &k,
            Some([7; 32]),
            None,
        )
        .signed,
    );
    assert_eq!(upstream_round_trip(&again), want);
}

// ── JSON as upstream reads it ───────────────────────────────────────────────

/// A visitor that only lets the walk run.
struct Quiet;
impl Visitor for Quiet {}

/// A bundle with its separators out of place is refused, as upstream's
/// parser refuses it.
#[test]
fn malformed_json_is_refused_as_upstream_refuses_it() {
    let good = doc_of(&envelope(pskt(&plain())));
    let text = String::from_utf8(good.clone()).expect("ascii");
    assert!(
        walk(&good, &mut Quiet).is_ok(),
        "the untouched bundle reads"
    );
    assert!(Bundle::deserialize(&to_envelope(&good)).is_ok());
    assert!(
        text.contains("\"proprietaries\":{}"),
        "an unread value to break"
    );

    let cases: [(&str, String); 8] = [
        ("a leading comma", text.replacen('[', "[,", 1)),
        ("a doubled comma", text.replacen(",\"", ",,\"", 1)),
        ("a trailing comma", text.replacen('}', ",}", 1)),
        ("a missing comma", text.replacen(",\"", " \"", 1)),
        ("a second document after the first", format!("{text}[]")),
        (
            "brackets of different kinds in an unread value",
            text.replacen("\"proprietaries\":{}", "\"proprietaries\":{]", 1),
        ),
        (
            "a lone comma in an unread value",
            text.replacen("\"proprietaries\":{}", "\"proprietaries\":{,}", 1),
        ),
        (
            "a member with no value",
            text.replacen("\"proprietaries\":{}", "\"proprietaries\":,", 1),
        ),
    ];
    for (what, bad) in &cases {
        assert_ne!(bad, &text, "{what}: the case changed nothing");
        assert!(
            walk(bad.as_bytes(), &mut Quiet).is_err(),
            "{what}: read here"
        );
        assert!(
            Bundle::deserialize(&to_envelope(bad.as_bytes())).is_err(),
            "{what}: upstream reads it, so refusing it is not matching upstream"
        );
    }
}

/// A value nested past the limit is refused, not followed.
#[test]
fn skip_value_refuses_nesting_past_its_limit() {
    use kassigner_kaspa::pskb::lexer::MAX_DEPTH;
    let at_limit = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    assert!(Lexer::new(at_limit.as_bytes()).skip_value().is_ok());
    let past = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
    assert!(matches!(
        Lexer::new(past.as_bytes()).skip_value(),
        Err(LexError::TooDeep { .. })
    ));
}

// ── Keys and sections as upstream reads them ────────────────────────────────

/// Our reader over transaction `index` of `doc`.
fn read_at(doc: &[u8], index: usize) -> Result<(usize, usize), ReadError> {
    let mut ins = [BLANK_IN; 8];
    let mut outs = [BLANK_OUT; 8];
    let mut buf = [0u8; 2048];
    fill(doc, index, &mut ins, &mut outs, &mut buf).map(|f| (f.inputs, f.outputs))
}

/// The three sections of `doc`'s one transaction, as upstream wrote them.
fn sections(doc: &str) -> (&str, &str, &str) {
    let g = doc.find("\"global\":").expect("global") + "\"global\":".len();
    let i = doc.find(",\"inputs\":").expect("inputs");
    let o = doc.find(",\"outputs\":").expect("outputs");
    assert!(doc.ends_with("}]"));
    (
        &doc[g..i],
        &doc[i + ",\"inputs\":".len()..o],
        &doc[o + ",\"outputs\":".len()..doc.len() - 2],
    )
}

/// A transaction object of these members, in this order.
fn transaction_of(members: &[(&str, &str)]) -> String {
    let body: Vec<String> = members
        .iter()
        .map(|(k, v)| format!("\"{k}\":{v}"))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// A transaction naming a section twice is refused, as upstream refuses the
/// whole bundle: serde will not read a field of its `Inner` twice. Empty
/// repeats and repeats outside the transaction read included.
#[test]
fn a_section_written_twice_is_refused_as_upstream_refuses_it() {
    let text = String::from_utf8(doc_of(&envelope(pskt(&plain())))).unwrap();
    let (g, i, o) = sections(&text);
    let whole = transaction_of(&[("global", g), ("inputs", i), ("outputs", o)]);
    assert_eq!(
        format!("[{whole}]"),
        text,
        "the sections put back are the bundle"
    );
    assert_eq!(read_at(text.as_bytes(), 0), Ok((2, 1)));

    // The global map in two halves: both readers stop at the first, for the
    // field it lacks.
    let cut = g.find(',').expect("a second field");
    let (g1, g2) = (format!("{}}}", &g[..cut]), format!("{{{}", &g[cut + 1..]));
    let halves = format!(
        "[{}]",
        transaction_of(&[
            ("global", &g1),
            ("global", &g2),
            ("inputs", i),
            ("outputs", o),
        ])
    );
    assert!(Bundle::deserialize(&to_envelope(halves.as_bytes())).is_err());
    assert_eq!(
        read_at(halves.as_bytes(), 0),
        Err(ReadError::Missing {
            scope: Scope::Global,
            field: Field::TxVersion
        })
    );

    let cases: [(&str, String); 5] = [
        (
            "the global map twice",
            transaction_of(&[("global", g), ("global", g), ("inputs", i), ("outputs", o)]),
        ),
        (
            "no inputs, then the inputs",
            transaction_of(&[
                ("global", g),
                ("inputs", "[]"),
                ("inputs", i),
                ("outputs", o),
            ]),
        ),
        (
            "the inputs, then none",
            transaction_of(&[
                ("global", g),
                ("inputs", i),
                ("inputs", "[]"),
                ("outputs", o),
            ]),
        ),
        (
            "the outputs, then none",
            transaction_of(&[
                ("global", g),
                ("inputs", i),
                ("outputs", o),
                ("outputs", "[]"),
            ]),
        ),
        (
            "a section repeated under a name spelled with escapes",
            transaction_of(&[
                ("global", g),
                ("inputs", i),
                ("outputs", o),
                ("outp\\u0075ts", "[]"),
            ]),
        ),
    ];
    let pk = key(5).public_key().serialize();
    let sig = PartialSig {
        input: 0,
        public_key: &pk,
        signature: &[1; 64],
        derivation: Derivation::Null,
    };
    for (what, bad) in &cases {
        let bundle = format!("[{bad}]");
        assert!(
            Bundle::deserialize(&to_envelope(bundle.as_bytes())).is_err(),
            "{what}: upstream reads it, so refusing it is not matching upstream"
        );
        assert_eq!(
            counts(bundle.as_bytes(), 0),
            Err(ReadError::RepeatedSection),
            "{what}"
        );
        assert_eq!(
            read_at(bundle.as_bytes(), 0),
            Err(ReadError::RepeatedSection),
            "{what}"
        );
        assert_eq!(
            apply(bundle.as_bytes(), &[sig]),
            Err(EditError::RepeatedSection),
            "{what}: signed"
        );

        // Upstream refuses the bundle, not the transaction: so does this.
        let two = format!("[{bad},{whole}]");
        assert!(Bundle::deserialize(&to_envelope(two.as_bytes())).is_err());
        assert_eq!(
            read_at(two.as_bytes(), 1),
            Err(ReadError::RepeatedSection),
            "{what}, in the transaction before the one read"
        );
    }
}

/// A transaction without a section is refused, as upstream refuses it (no
/// serde default). Read as empty, a missing `outputs` would be all fee.
#[test]
fn a_transaction_without_a_section_is_refused_as_upstream_refuses_it() {
    let text = String::from_utf8(doc_of(&envelope(pskt(&plain())))).unwrap();
    let (g, i, o) = sections(&text);
    let whole = transaction_of(&[("global", g), ("inputs", i), ("outputs", o)]);
    let cases: [(&str, String); 6] = [
        (
            "no inputs",
            transaction_of(&[("global", g), ("outputs", o)]),
        ),
        (
            "no outputs",
            transaction_of(&[("global", g), ("inputs", i)]),
        ),
        ("only the global map", transaction_of(&[("global", g)])),
        (
            "no global map",
            transaction_of(&[("inputs", i), ("outputs", o)]),
        ),
        ("nothing at all", "{}".to_string()),
        (
            "the outputs under a name that is not theirs",
            transaction_of(&[("global", g), ("inputs", i), ("Outputs", o)]),
        ),
    ];
    let pk = key(5).public_key().serialize();
    let sig = PartialSig {
        input: 0,
        public_key: &pk,
        signature: &[1; 64],
        derivation: Derivation::Null,
    };
    for (what, bad) in &cases {
        let bundle = format!("[{bad}]");
        assert!(
            Bundle::deserialize(&to_envelope(bundle.as_bytes())).is_err(),
            "{what}: upstream reads it, so refusing it is not matching upstream"
        );
        let missing = ParseError::MissingSection;
        assert_eq!(
            counts(bundle.as_bytes(), 0),
            Err(ReadError::Parse(missing)),
            "{what}"
        );
        assert_eq!(
            read_at(bundle.as_bytes(), 0),
            Err(ReadError::Parse(missing)),
            "{what}"
        );
        assert_eq!(
            apply(bundle.as_bytes(), &[sig]),
            Err(EditError::Parse(missing)),
            "{what}: signed"
        );

        // Upstream refuses the bundle, not the transaction: so does this.
        let two = format!("[{bad},{whole}]");
        assert!(Bundle::deserialize(&to_envelope(two.as_bytes())).is_err());
        assert_eq!(
            read_at(two.as_bytes(), 1),
            Err(ReadError::Parse(missing)),
            "{what}, in the transaction before the one read"
        );
    }
}

/// The object at the start of `text`, as written: its value's span.
fn object_at(text: &str) -> &str {
    let (start, end) = Lexer::new(text.as_bytes()).skip_value().expect("a value");
    &text[start..end]
}

/// `object` with its member `key` taken out, and the comma that went with it.
fn without(object: &str, key: &str) -> String {
    let name = format!("\"{key}\":");
    assert_eq!(object.matches(&name).count(), 1, "one {key} in the object");
    let at = object.find(&name).unwrap();
    let from = at + name.len();
    let (_, len) = Lexer::new(&object.as_bytes()[from..])
        .skip_value()
        .expect("its value");
    let end = from + len;
    if object[end..].starts_with(',') {
        format!("{}{}", &object[..at], &object[end + 1..])
    } else {
        format!("{}{}", object[..at].trim_end_matches(','), &object[end..])
    }
}

/// A field upstream requires (no serde default) is refused when missing,
/// named as upstream names it, an entry's field by its entry. A field it does
/// not require still reads when left out.
#[test]
fn a_field_upstream_requires_is_refused_when_missing() {
    let text = String::from_utf8(doc_of(&envelope(pskt(&plain())))).unwrap();
    let (g, i, o) = sections(&text);
    let (input, output) = (object_at(&i[1..]), object_at(&o[1..]));
    let entry = {
        let at = input.find("\"utxoEntry\":").unwrap() + "\"utxoEntry\":".len();
        object_at(&input[at..])
    };
    let changed = |object: &str, key: &str| text.replacen(object, &without(object, key), 1);

    let required: [(Scope, &str, &str, Field); 21] = [
        (Scope::Global, g, "version", Field::Version),
        (Scope::Global, g, "txVersion", Field::TxVersion),
        (
            Scope::Global,
            g,
            "inputsModifiable",
            Field::InputsModifiable,
        ),
        (
            Scope::Global,
            g,
            "outputsModifiable",
            Field::OutputsModifiable,
        ),
        (Scope::Global, g, "inputCount", Field::InputCount),
        (Scope::Global, g, "outputCount", Field::OutputCount),
        (Scope::Global, g, "xpubs", Field::Xpubs),
        (Scope::Global, g, "proprietaries", Field::Proprietaries),
        (Scope::Global, g, "payload", Field::Payload),
        (
            Scope::Input(0),
            input,
            "previousOutpoint",
            Field::PreviousOutpoint,
        ),
        (Scope::Input(0), input, "partialSigs", Field::PartialSigs),
        (Scope::Input(0), input, "sighashType", Field::SighashType),
        (Scope::Input(0), input, "redeemScript", Field::RedeemScript),
        (
            Scope::Input(0),
            input,
            "bip32Derivations",
            Field::Bip32Derivations,
        ),
        (
            Scope::Input(0),
            input,
            "finalScriptSig",
            Field::FinalScriptSig,
        ),
        (
            Scope::Input(0),
            input,
            "proprietaries",
            Field::Proprietaries,
        ),
        (Scope::Output(0), output, "amount", Field::Amount),
        (
            Scope::Output(0),
            output,
            "scriptPublicKey",
            Field::ScriptPublicKey,
        ),
        (
            Scope::Output(0),
            output,
            "redeemScript",
            Field::RedeemScript,
        ),
        (
            Scope::Output(0),
            output,
            "bip32Derivations",
            Field::Bip32Derivations,
        ),
        (
            Scope::Output(0),
            output,
            "proprietaries",
            Field::Proprietaries,
        ),
    ];
    let pk = key(5).public_key().serialize();
    let sig = PartialSig {
        input: 0,
        public_key: &pk,
        signature: &[1; 64],
        derivation: Derivation::Null,
    };
    for (scope, object, name, field) in required {
        let bad = changed(object, name);
        assert_ne!(bad, text, "{name}: the case changed nothing");
        let up = Bundle::deserialize(&to_envelope(bad.as_bytes())).map(|_| ());
        let said = up.expect_err("upstream reads it").to_string();
        assert!(
            said.contains(&format!("missing field `{name}`")),
            "{name}: upstream says {said}"
        );
        assert_eq!(
            read_at(bad.as_bytes(), 0),
            Err(ReadError::Missing { scope, field }),
            "{name}"
        );
        let edit = match scope {
            Scope::Input(input) => EditError::Missing { input, field },
            _ => EditError::Parse(ParseError::MissingField { scope, field }),
        };
        assert_eq!(apply(bad.as_bytes(), &[sig]), Err(edit), "{name}: signed");
    }

    for key in ["blockDaaScore", "isCoinbase"] {
        let bad = text.replacen(entry, &without(entry, key), 1);
        let said = Bundle::deserialize(&to_envelope(bad.as_bytes()))
            .map(|_| ())
            .expect_err("upstream reads it")
            .to_string();
        assert!(
            said.contains(&format!("missing field `{key}`")),
            "{key}: {said}"
        );
        assert_eq!(
            read_at(bad.as_bytes(), 0),
            Err(ReadError::Malformed {
                scope: Scope::Input(0),
                field: Field::UtxoEntry
            }),
            "{key}"
        );
    }

    // What upstream does not require reads without it, the same transaction
    // both sides.
    let optional: [(&str, &str); 7] = [
        (g, "fallbackLockTime"),
        (g, "id"),
        (input, "sequence"),
        (input, "minTime"),
        (input, "sigOpCount"),
        (output, "covenant"),
        (entry, "covenantId"),
    ];
    for (object, name) in optional {
        let good = changed(object, name);
        assert_ne!(good, text, "{name}: the case changed nothing");
        let bundle = Bundle::deserialize(&to_envelope(good.as_bytes()))
            .unwrap_or_else(|e| panic!("{name}: upstream refuses it: {e}"));
        let inner = bundle.0.into_iter().next().expect("one transaction");
        let up = upstream_sign(PSKT::<Signer>::from(inner), &key(3), None, None);
        assert_eq!(our_hashes(good.as_bytes()), up.hashes, "{name}");
    }
}

/// A key written with escapes is the field it spells: serde_json decodes a
/// key before matching it, so `"seq\u0075ence"` is the sequence. Read raw,
/// the device would sign a transaction other than the one upstream reads.
#[test]
fn a_key_written_with_escapes_is_the_field_it_spells() {
    let text = String::from_utf8(doc_of(&envelope(pskt(&rich())))).unwrap();
    let normal = upstream_round_trip(&to_envelope(text.as_bytes()));
    let up = upstream_sign(pskt(&rich()), &key(3), None, None);
    let cases: [(&str, &str, &str); 8] = [
        ("a sequence", "\"sequence\":7", "\"seq\\u0075ence\":7"),
        (
            "a lock time",
            "\"minTime\":1700000500",
            "\"min\\u0054ime\":1700000500",
        ),
        ("the global map", "\"global\":", "\"glob\\u0061l\":"),
        ("the outputs", "\"outputs\":", "\"o\\u0075tputs\":"),
        (
            "an entry's amount, in capital hex",
            "{\"amount\":90000",
            "{\"am\\u006Funt\":90000",
        ),
        (
            "an output's amount",
            "{\"amount\":50000",
            "{\"\\u0061mount\":50000",
        ),
        (
            "an outpoint's id",
            "{\"transactionId\":\"02",
            "{\"transaction\\u0049d\":\"02",
        ),
        (
            "a covenant's id",
            "\"covenantId\":\"c5",
            "\"covenant\\u0049d\":\"c5",
        ),
    ];
    for (what, from, to) in cases {
        assert_eq!(text.matches(from).count(), 1, "{what}: one place to change");
        let escaped = text.replacen(from, to, 1);
        assert_eq!(
            upstream_round_trip(&to_envelope(escaped.as_bytes())),
            normal,
            "{what}: upstream reads the same bundle"
        );
        assert!(
            read_at(escaped.as_bytes(), 0).is_ok(),
            "{what}: refused here, {:?}",
            read_at(escaped.as_bytes(), 0)
        );
        ours(escaped.as_bytes(), 0, |_, tx| assert_same(tx, &up));
        assert_eq!(our_hashes(escaped.as_bytes()), up.hashes, "{what}");
    }
}

/// A bundle with escaped keys is signed as upstream signs it, the keys kept
/// as written; a new signature goes into an escaped `partialSigs`, not a
/// second one beside it.
#[test]
fn a_bundle_with_escaped_keys_is_signed_as_upstream_signs_it() {
    let (a, b) = (key(5), key(6));
    let once = String::from_utf8(doc_of(&envelope(
        upstream_sign(pskt(&rich()), &a, None, None).signed,
    )))
    .unwrap();
    let escaped = once
        .replacen("\"sequence\":7", "\"seq\\u0075ence\":7", 1)
        .replace("\"partialSigs\":", "\"partial\\u0053igs\":")
        .replace("\"bip32Derivations\":", "\"bip32\\u0044erivations\":");
    assert_eq!(escaped.matches("partial\\u0053igs").count(), 3);
    let want = envelope(
        upstream_sign(
            upstream_sign(pskt(&rich()), &a, None, None).signed,
            &b,
            None,
            None,
        )
        .signed,
    );
    let signed = our_sign(escaped.as_bytes(), &b, None, Derivation::Null);
    assert_eq!(upstream_round_trip(&signed), want);
}

/// A key upstream cannot decode is refused: serde_json holds escapes to
/// JSON's forms, and keys to paired surrogates and UTF-8. A field written
/// twice is refused however each is spelled.
#[test]
fn a_key_upstream_cannot_decode_is_refused() {
    let text = doc_of(&envelope(pskt(&plain())));
    let at_in = |what: &[u8]| {
        text.windows(what.len())
            .position(|w| w == what)
            .expect("in the bundle")
    };
    // A member put into the second input, ahead of its sequence.
    let at = at_in(b"\"sequence\":7");
    let with = |member: &[u8]| -> Vec<u8> { [&text[..at], member, b",", &text[at..]].concat() };
    let entry = at_in(b"{\"amount\":90000") + 1;

    let cases: [(&str, Vec<u8>); 10] = [
        ("an escape JSON does not have, in a key", with(br#""\q":1"#)),
        (
            "an escape JSON does not have, in a value",
            with(br#""note":"\q""#),
        ),
        ("a \\u without four hex digits", with(br#""\u12g4":1"#)),
        ("a \\u cut short by the quote", with(br#""\u12":1"#)),
        ("a leading surrogate alone", with(br#""\ud800":1"#)),
        (
            "a leading surrogate before a letter",
            with(br#""\ud800\u0041":1"#),
        ),
        ("a trailing surrogate alone", with(br#""\udc00":1"#)),
        ("a key that is not UTF-8", with(b"\"\xff\":1")),
        (
            "a field written with escapes and plainly",
            with(br#""seq\u0075ence":7"#),
        ),
        (
            "a nested field written plainly and with escapes",
            [&text[..entry], br#""am\u006funt":90000,"#, &text[entry..]].concat(),
        ),
    ];
    for (what, bad) in &cases {
        assert!(
            Bundle::deserialize(&to_envelope(bad)).is_err(),
            "{what}: upstream reads it, so refusing it is not matching upstream"
        );
        assert!(read_at(bad, 0).is_err(), "{what}: read here");
    }
    assert_eq!(
        read_at(&cases[8].1, 0),
        Err(ReadError::Duplicate {
            scope: Scope::Input(1),
            field: Field::Sequence
        })
    );
    assert_eq!(
        read_at(&cases[9].1, 0),
        Err(ReadError::Malformed {
            scope: Scope::Input(1),
            field: Field::UtxoEntry
        })
    );
    let lexed = |doc: &[u8]| match read_at(doc, 0) {
        Err(ReadError::Parse(ParseError::Lex(e))) => Some(e),
        _ => None,
    };
    for (what, bad) in &cases[..7] {
        assert!(
            matches!(lexed(bad), Some(LexError::BadEscape { .. })),
            "{what}: {:?}",
            read_at(bad, 0)
        );
    }
    assert!(matches!(lexed(&cases[7].1), Some(LexError::NotUtf8 { .. })));

    // What upstream does decode reads here too, as the same transaction.
    for member in [
        br#""\ud83d\ude00":1"#.as_slice(),
        br#""note":"\"\\\/\b\f\n\r\t\u00e9\uD83D\uDE00""#,
    ] {
        let good = with(member);
        assert!(Bundle::deserialize(&to_envelope(&good)).is_ok());
        assert_eq!(our_hashes(&good), our_hashes(&text));
    }
}

// ── Values upstream reads ───────────────────────────────────────────────────

/// A value upstream cannot read is refused, as upstream refuses it.
///
/// Upstream deserializes every field and keeps `proprietaries` and unknowns
/// as values: a number there must fit a double, a string must be text. A
/// value it only skips needs JSON's grammar only. Each case changes one value
/// of a rich signed bundle and is asked of upstream first.
#[test]
fn a_value_upstream_cannot_read_is_refused_as_upstream_refuses_it() {
    let path: DerivationPath = "m/44'/111111'/0'/0/1".parse().unwrap();
    let signer = key(5);
    let signed = String::from_utf8(doc_of(&envelope(
        upstream_sign(
            pskt(&rich()),
            &signer,
            None,
            Some(KeySource::new([0xde, 0xad, 0xbe, 0xef], path)),
        )
        .signed,
    )))
    .unwrap();

    let pk = hex(&signer.public_key().serialize());
    let xpub = UpXPrv::<SecretKey>::new([3u8; 64])
        .unwrap()
        .public_key()
        .to_string(Some(UpPrefix::KPUB));
    let source = r#"{"keyFingerprint":"deadbeef","derivationPath":"m/44'/111111'/0'"}"#;
    let kept = r#"{"p":[1,-2,3.5e10,-0,1e-999,"t\u00e9\ud83d\ude00",null,true,{"x":{}}]}"#;
    let one = |text: String, from: &str, to: &str| {
        assert!(text.contains(from), "{from}: not in the bundle");
        text.replacen(from, to, 1)
    };
    let base = one(
        signed,
        r#""xpubs":{}"#,
        &format!(r#""xpubs":{{"{xpub}":{source}}}"#),
    );
    let base = one(
        base,
        r#""proprietaries":{},"payload""#,
        &format!(r#""proprietaries":{kept},"note":{kept},"payload""#),
    );
    let base = one(
        base,
        r#""finalScriptSig":null,"proprietaries":{}"#,
        &format!(r#""finalScriptSig":null,"proprietaries":{kept},"note":{kept}"#),
    );
    let base = one(
        base,
        r#""bip32Derivations":{},"covenant":null,"proprietaries":{}"#,
        &format!(
            r#""bip32Derivations":{{"{pk}":null}},"covenant":null,"proprietaries":{kept},"note":{kept}"#
        ),
    );
    let base = one(
        base,
        r#"[{"global":"#,
        r#"[{"extra":[1e999,"\ud800",{"y":1e5}],"global":"#,
    );
    assert!(
        Bundle::deserialize(&to_envelope(base.as_bytes())).is_ok(),
        "upstream reads the base"
    );
    assert!(read_at(base.as_bytes(), 0).is_ok(), "the base reads here");

    // Text for keys and signatures.
    let uncompressed = hex(&signer.public_key().serialize_uncompressed());
    let point = signer.public_key().serialize_uncompressed();
    let (even, odd) = if point[64].is_multiple_of(2) {
        ("06", "07")
    } else {
        ("07", "06")
    };
    let hybrid = |tag: &str| format!("{tag}{}", &uncompressed[2..]);
    let off_curve = format!("02{}", "ff".repeat(32));
    let ecdsa = hex(&Secp256k1::new()
        .sign_ecdsa(&Message::from_digest([1; 32]), &signer.secret_key())
        .serialize_der());
    let xpub_off_curve = {
        let mut raw = [0u8; 82];
        assert_eq!(decode_check(xpub.as_bytes(), &mut raw), Ok(78));
        raw[45] = 0x02;
        raw[46..78].fill(0xff);
        let mut scratch = [0u8; 82];
        let mut text = [0u8; encoded_max(78)];
        let n = encode_check(&raw[..78], &mut scratch, &mut text).unwrap();
        String::from_utf8(text[..n].to_vec()).unwrap()
    };
    let xpub_bad_sum = {
        let mut t = xpub.clone().into_bytes();
        let last = t.len() - 1;
        t[last] = if t[last] == b'2' { b'3' } else { b'2' };
        String::from_utf8(t).unwrap()
    };
    let ktub = UpXPrv::<SecretKey>::new([3u8; 64])
        .unwrap()
        .public_key()
        .to_string(Some(UpPrefix::KTUB));

    let sig_key = format!(r#""partialSigs":{{"{pk}""#);
    let derivation_key = format!(r#""bip32Derivations":{{"{pk}""#);
    let schnorr_at = r#"{"schnorr":"125a446f"#;
    let first_sig = {
        let at = base.find(&sig_key).unwrap() + sig_key.len() + 1;
        object_at(&base[at..]).to_string()
    };
    let derivation = r#"{"keyFingerprint":"deadbeef","derivationPath":"m/44'/111111'/0'/0/1"}"#;
    let xpub_source = format!(r#""{xpub}":{source}"#);
    let out0_key = format!(r#"{{"{pk}":null}},"covenant":null"#);
    let entry = r#""blockDaaScore":100,"isCoinbase":false,"covenantId":null"#;
    let output_script = format!(r#""scriptPublicKey":"000020{}ac""#, "41".repeat(32));

    use Field as F;
    use Scope as S;
    let g = |field| Some((S::Global, field));
    let i0 = |field| Some((S::Input(0), field));
    let o0 = |field| Some((S::Output(0), field));
    // A case's name, the text it changes and to what, and where upstream
    // refuses it (`None` where it reads).
    type Case = (&'static str, String, String, Option<(Scope, Field)>);
    let cases: Vec<Case> = vec![
        // The global map.
        (
            "a flag as a number",
            r#""inputsModifiable":false"#.into(),
            r#""inputsModifiable":0"#.into(),
            g(F::InputsModifiable),
        ),
        (
            "a flag as text",
            r#""outputsModifiable":false"#.into(),
            r#""outputsModifiable":"false""#.into(),
            g(F::OutputsModifiable),
        ),
        (
            "a count with a fraction",
            r#""inputCount":3"#.into(),
            r#""inputCount":3.0"#.into(),
            g(F::InputCount),
        ),
        (
            "a count below zero",
            r#""inputCount":3"#.into(),
            r#""inputCount":-1"#.into(),
            g(F::InputCount),
        ),
        (
            "a count with an exponent",
            r#""outputCount":3"#.into(),
            r#""outputCount":3e0"#.into(),
            g(F::OutputCount),
        ),
        (
            "a count of null",
            r#""outputCount":3"#.into(),
            r#""outputCount":null"#.into(),
            g(F::OutputCount),
        ),
        (
            "a count that is not the inputs'",
            r#""inputCount":3"#.into(),
            r#""inputCount":99"#.into(),
            None,
        ),
        (
            "an id too short",
            r#""id":null"#.into(),
            r#""id":"00""#.into(),
            g(F::Id),
        ),
        (
            "an id",
            r#""id":null"#.into(),
            format!(r#""id":"{}""#, "ab".repeat(32)),
            None,
        ),
        (
            "an id in capitals",
            r#""id":null"#.into(),
            format!(r#""id":"{}""#, "AB".repeat(32)),
            None,
        ),
        (
            "an id as a number",
            r#""id":null"#.into(),
            r#""id":1"#.into(),
            g(F::Id),
        ),
        (
            "a fallback below zero",
            r#""fallbackLockTime":12"#.into(),
            r#""fallbackLockTime":-1"#.into(),
            g(F::FallbackLockTime),
        ),
        (
            "a payload of odd length",
            r#""payload":"deadbeef""#.into(),
            r#""payload":"deadbee""#.into(),
            g(F::Payload),
        ),
        (
            "a bundle version past two",
            r#""version":2"#.into(),
            r#""version":3"#.into(),
            g(F::Version),
        ),
        (
            "a transaction version past u16",
            r#""txVersion":1"#.into(),
            r#""txVersion":65536"#.into(),
            g(F::TxVersion),
        ),
        (
            "an xpub with a bad checksum",
            xpub_source.clone(),
            format!(r#""{xpub_bad_sum}":{source}"#),
            g(F::Xpubs),
        ),
        (
            "an xpub off the curve",
            xpub_source.clone(),
            format!(r#""{xpub_off_curve}":{source}"#),
            g(F::Xpubs),
        ),
        (
            "an xpub for testnet",
            xpub_source.clone(),
            format!(r#""{ktub}":{source}"#),
            None,
        ),
        (
            "an xpub without a key source",
            xpub_source.clone(),
            format!(r#""{xpub}":null"#),
            g(F::Xpubs),
        ),
        (
            "a fingerprint too short",
            xpub_source.clone(),
            format!(r#""{xpub}":{{"keyFingerprint":"deadbe","derivationPath":"m/0"}}"#),
            g(F::Xpubs),
        ),
        (
            "a fingerprint in capitals",
            xpub_source.clone(),
            format!(r#""{xpub}":{{"keyFingerprint":"DEADBEEF","derivationPath":"m/0"}}"#),
            None,
        ),
        (
            "a path that is not one",
            xpub_source.clone(),
            format!(r#""{xpub}":{{"keyFingerprint":"deadbeef","derivationPath":"m/x"}}"#),
            g(F::Xpubs),
        ),
        (
            "a path upstream reads loosely",
            xpub_source.clone(),
            format!(r#""{xpub}":{{"keyFingerprint":"deadbeef","derivationPath":"m/01/+2'"}}"#),
            None,
        ),
        (
            "a key source without its path",
            xpub_source.clone(),
            format!(r#""{xpub}":{{"keyFingerprint":"deadbeef"}}"#),
            g(F::Xpubs),
        ),
        (
            "a key source with its fingerprint twice",
            xpub_source.clone(),
            format!(
                r#""{xpub}":{{"keyFingerprint":"deadbeef","keyFingerprint":"deadbeef","derivationPath":"m/0"}}"#
            ),
            g(F::Xpubs),
        ),
        (
            "a key source with more, skipped",
            xpub_source.clone(),
            format!(
                r#""{xpub}":{{"keyFingerprint":"deadbeef","derivationPath":"m/0","more":[1e999,"\ud800"]}}"#
            ),
            None,
        ),
        (
            "xpubs as a list",
            format!(r#""xpubs":{{{xpub_source}}}"#),
            r#""xpubs":[]"#.into(),
            g(F::Xpubs),
        ),
        (
            "a proprietary number past a double",
            r#""p":[1,"#.into(),
            r#""p":[1e999,"#.into(),
            g(F::Proprietaries),
        ),
        (
            "a proprietary string with half a pair",
            r#""p":[1,"#.into(),
            r#""p":["\ud800","#.into(),
            g(F::Proprietaries),
        ),
        (
            "a proprietary key with half a pair",
            r#""proprietaries":{"p""#.into(),
            r#""proprietaries":{"\udc00""#.into(),
            g(F::Proprietaries),
        ),
        (
            "proprietaries as a list",
            format!(r#""proprietaries":{kept},"note""#),
            r#""proprietaries":[],"note""#.into(),
            g(F::Proprietaries),
        ),
        (
            "an unknown past a double",
            r#""note":{"p":[1,"#.into(),
            r#""note":{"p":[-1e400,"#.into(),
            g(F::Unknowns),
        ),
        (
            "an unknown named unknowns",
            r#""note":{"#.into(),
            r#""unknowns":1e999,"note":{"#.into(),
            g(F::Unknowns),
        ),
        (
            "an input's name at the top, kept",
            r#""note":{"#.into(),
            r#""redeemScript":"zz","note":{"#.into(),
            None,
        ),
        (
            "a double at its largest",
            r#""p":[1,"#.into(),
            r#""p":[1.7976931348623157e308,"#.into(),
            None,
        ),
        (
            "a double past its largest",
            r#""p":[1,"#.into(),
            r#""p":[1.8e308,"#.into(),
            g(F::Proprietaries),
        ),
        (
            "an integer past u64, kept as a double",
            r#""p":[1,"#.into(),
            r#""p":[123456789012345678901234567890,"#.into(),
            None,
        ),
        // The first input.
        (
            "a sighash type past a byte",
            r#""sighashType":1"#.into(),
            r#""sighashType":300"#.into(),
            i0(F::SighashType),
        ),
        (
            "a sighash type of no kind",
            r#""sighashType":1"#.into(),
            r#""sighashType":3"#.into(),
            None,
        ),
        (
            "a sighash type of null",
            r#""sighashType":1"#.into(),
            r#""sighashType":null"#.into(),
            i0(F::SighashType),
        ),
        (
            "a sighash type with a fraction",
            r#""sighashType":1"#.into(),
            r#""sighashType":1.0"#.into(),
            i0(F::SighashType),
        ),
        (
            "a sighash type of minus zero",
            r#""sighashType":1"#.into(),
            r#""sighashType":-0"#.into(),
            i0(F::SighashType),
        ),
        (
            "a final script that is not hex",
            r#""finalScriptSig":null"#.into(),
            r#""finalScriptSig":"zz""#.into(),
            i0(F::FinalScriptSig),
        ),
        (
            "a final script of odd length",
            r#""finalScriptSig":null"#.into(),
            r#""finalScriptSig":"abc""#.into(),
            i0(F::FinalScriptSig),
        ),
        (
            "a final script, empty",
            r#""finalScriptSig":null"#.into(),
            r#""finalScriptSig":"""#.into(),
            None,
        ),
        (
            "a final script in capitals",
            r#""finalScriptSig":null"#.into(),
            r#""finalScriptSig":"AB""#.into(),
            None,
        ),
        (
            "a redeem script as a number",
            r#""redeemScript":null"#.into(),
            r#""redeemScript":1"#.into(),
            i0(F::RedeemScript),
        ),
        (
            "a signer's key too short",
            sig_key.clone(),
            format!(r#""partialSigs":{{"{}""#, &pk[2..]),
            i0(F::PartialSigs),
        ),
        (
            "a signer's key off the curve",
            sig_key.clone(),
            format!(r#""partialSigs":{{"{off_curve}""#),
            i0(F::PartialSigs),
        ),
        (
            "a signer's key with tag 5",
            sig_key.clone(),
            format!(r#""partialSigs":{{"05{}""#, &pk[2..]),
            i0(F::PartialSigs),
        ),
        (
            "a signer's key in capitals",
            sig_key.clone(),
            format!(r#""partialSigs":{{"{}""#, pk.to_uppercase()),
            None,
        ),
        (
            "a signer's key uncompressed",
            sig_key.clone(),
            format!(r#""partialSigs":{{"{uncompressed}""#),
            None,
        ),
        (
            "a signer's key hybrid",
            sig_key.clone(),
            format!(r#""partialSigs":{{"{}""#, hybrid(even)),
            None,
        ),
        (
            "a signer's key hybrid, wrong parity",
            sig_key.clone(),
            format!(r#""partialSigs":{{"{}""#, hybrid(odd)),
            i0(F::PartialSigs),
        ),
        (
            "a signature of another kind",
            schnorr_at.into(),
            r#"{"ecdsa":"125a446f"#.into(),
            i0(F::PartialSigs),
        ),
        (
            "a schnorr signature too short",
            first_sig.clone(),
            format!(r#"{{"schnorr":"{}"}}"#, "11".repeat(63)),
            i0(F::PartialSigs),
        ),
        (
            "a signature of both kinds",
            first_sig.clone(),
            format!(r#"{{"schnorr":"{}","eCDSA":"{ecdsa}"}}"#, "11".repeat(64)),
            i0(F::PartialSigs),
        ),
        (
            "a signature of no kind",
            first_sig.clone(),
            "{}".into(),
            i0(F::PartialSigs),
        ),
        (
            "a signature as text",
            first_sig.clone(),
            r#""schnorr""#.into(),
            i0(F::PartialSigs),
        ),
        (
            "an ECDSA signature",
            first_sig.clone(),
            format!(r#"{{"eCDSA":"{ecdsa}"}}"#),
            None,
        ),
        (
            "an ECDSA signature at its longest",
            first_sig.clone(),
            format!(
                r#"{{"eCDSA":"3046022100{}022100{}"}}"#,
                "80".repeat(32),
                "80".repeat(32)
            ),
            None,
        ),
        (
            "an ECDSA signature of zeros",
            first_sig.clone(),
            r#"{"eCDSA":"3006020100020100"}"#.into(),
            None,
        ),
        (
            "an ECDSA signature below zero",
            first_sig.clone(),
            r#"{"eCDSA":"3006020180020101"}"#.into(),
            None,
        ),
        (
            "an ECDSA signature with more inside",
            first_sig.clone(),
            r#"{"eCDSA":"300702010102010100"}"#.into(),
            i0(F::PartialSigs),
        ),
        (
            "an ECDSA signature with a byte after",
            first_sig.clone(),
            r#"{"eCDSA":"300602010102010100"}"#.into(),
            i0(F::PartialSigs),
        ),
        (
            "an ECDSA signature padded",
            first_sig.clone(),
            r#"{"eCDSA":"300702020001020101"}"#.into(),
            i0(F::PartialSigs),
        ),
        (
            "an ECDSA length in long form",
            first_sig.clone(),
            r#"{"eCDSA":"308106020101020101"}"#.into(),
            i0(F::PartialSigs),
        ),
        (
            "an ECDSA integer empty",
            first_sig.clone(),
            r#"{"eCDSA":"300402000200"}"#.into(),
            i0(F::PartialSigs),
        ),
        (
            "an ECDSA signature past 72 bytes",
            first_sig.clone(),
            format!(r#"{{"eCDSA":"{}"}}"#, "00".repeat(73)),
            i0(F::PartialSigs),
        ),
        (
            "an ECDSA signature, empty",
            first_sig.clone(),
            r#"{"eCDSA":""}"#.into(),
            i0(F::PartialSigs),
        ),
        (
            "a derivation of null",
            derivation.into(),
            "null".into(),
            None,
        ),
        (
            "a fingerprint that is not hex",
            r#""keyFingerprint":"deadbeef","derivationPath":"m/44'/111111'/0'/0/1""#.into(),
            r#""keyFingerprint":"deadbeeg","derivationPath":"m/44'/111111'/0'/0/1""#.into(),
            i0(F::Bip32Derivations),
        ),
        (
            "a derivation path that is not one",
            derivation.into(),
            r#"{"keyFingerprint":"deadbeef","derivationPath":"m/44'/x"}"#.into(),
            i0(F::Bip32Derivations),
        ),
        (
            "a derivation without its fingerprint",
            derivation.into(),
            r#"{"derivationPath":"m/0"}"#.into(),
            i0(F::Bip32Derivations),
        ),
        (
            "a derivation's key off the curve",
            derivation_key.clone(),
            format!(r#""bip32Derivations":{{"{off_curve}""#),
            i0(F::Bip32Derivations),
        ),
        (
            "an input's proprietary past a double",
            r#""finalScriptSig":null,"proprietaries":{"p":[1,"#.into(),
            r#""finalScriptSig":null,"proprietaries":{"p":[1e999,"#.into(),
            i0(F::Proprietaries),
        ),
        (
            "an input's unknown with half a pair",
            format!(r#""finalScriptSig":null,"proprietaries":{kept},"note":{{"p":[1,"#),
            format!(r#""finalScriptSig":null,"proprietaries":{kept},"note":{{"p":["\ud800","#),
            i0(F::Unknowns),
        ),
        (
            "an input carrying a global name",
            r#""sighashType":1"#.into(),
            r#""version":1e999,"sighashType":1"#.into(),
            i0(F::Unknowns),
        ),
        (
            "an entry's score below zero",
            entry.into(),
            r#""blockDaaScore":-1,"isCoinbase":false,"covenantId":null"#.into(),
            i0(F::UtxoEntry),
        ),
        (
            "an entry's flag as a number",
            entry.into(),
            r#""blockDaaScore":100,"isCoinbase":0,"covenantId":null"#.into(),
            i0(F::UtxoEntry),
        ),
        (
            "an entry's covenant that is not a hash",
            entry.into(),
            r#""blockDaaScore":100,"isCoinbase":false,"covenantId":"zz""#.into(),
            i0(F::UtxoEntry),
        ),
        (
            "an entry's covenant",
            entry.into(),
            format!(
                r#""blockDaaScore":100,"isCoinbase":false,"covenantId":"{}""#,
                "C5".repeat(32)
            ),
            None,
        ),
        (
            "an entry's covenant twice",
            entry.into(),
            r#""blockDaaScore":100,"isCoinbase":false,"covenantId":null,"covenantId":null"#.into(),
            i0(F::UtxoEntry),
        ),
        (
            "an entry with more, skipped",
            entry.into(),
            r#""blockDaaScore":100,"isCoinbase":false,"covenantId":null,"more":[1e999,"\ud800"]"#
                .into(),
            None,
        ),
        (
            "an outpoint index with a fraction",
            r#""index":0"#.into(),
            r#""index":0.5"#.into(),
            i0(F::PreviousOutpoint),
        ),
        (
            "a sequence as text",
            r#""sequence":null"#.into(),
            r#""sequence":"7""#.into(),
            i0(F::Sequence),
        ),
        (
            "signature operations past a byte",
            r#""sigOpCount":1"#.into(),
            r#""sigOpCount":256"#.into(),
            i0(F::SigOpCount),
        ),
        // `hidden`, which upstream reads only as `null` and never writes.
        (
            "a hidden member that is not null",
            r#""sigOpCount":1"#.into(),
            r#""sigOpCount":1,"hidden":5"#.into(),
            i0(F::Hidden),
        ),
        (
            "a hidden member of null",
            r#""sigOpCount":1"#.into(),
            r#""sigOpCount":1,"hidden":null"#.into(),
            None,
        ),
        // The first output.
        (
            "an output's redeem script not hex",
            r#""redeemScript":null,"bip32Derivations":{"#.into(),
            r#""redeemScript":"z","bip32Derivations":{"#.into(),
            o0(F::RedeemScript),
        ),
        (
            "an output's derivation key too long",
            out0_key.clone(),
            format!(r#"{{"{pk}00":null}},"covenant":null"#),
            o0(F::Bip32Derivations),
        ),
        (
            "an output's derivation of a number",
            out0_key.clone(),
            format!(r#"{{"{pk}":1}},"covenant":null"#),
            o0(F::Bip32Derivations),
        ),
        (
            "an output's proprietary past a double",
            r#""covenant":null,"proprietaries":{"p":[1,"#.into(),
            r#""covenant":null,"proprietaries":{"p":[1e999,"#.into(),
            o0(F::Proprietaries),
        ),
        (
            "an output's unknown past a double",
            r#""covenant":null,"proprietaries":"#.into(),
            r#""covenant":null,"z":1e999,"proprietaries":"#.into(),
            o0(F::Unknowns),
        ),
        (
            "an output's amount below zero",
            r#""amount":200000"#.into(),
            r#""amount":-1"#.into(),
            o0(F::Amount),
        ),
        (
            "an output's script too short",
            output_script.clone(),
            r#""scriptPublicKey":"00""#.into(),
            o0(F::ScriptPublicKey),
        ),
        (
            "an output's script of odd length",
            output_script.clone(),
            r#""scriptPublicKey":"00000""#.into(),
            o0(F::ScriptPublicKey),
        ),
        (
            "an output's script with its version alone",
            output_script.clone(),
            r#""scriptPublicKey":"0000""#.into(),
            None,
        ),
    ];

    let sig = PartialSig {
        input: 0,
        public_key: &signer.public_key().serialize(),
        signature: &[1; 64],
        derivation: Derivation::Null,
    };
    for (what, from, to, want) in &cases {
        let doc = one(base.clone(), from, to);
        assert_ne!(doc, base, "{what}: the case changed nothing");
        let up = Bundle::deserialize(&to_envelope(doc.as_bytes())).map(|_| ());
        let ours = read_at(doc.as_bytes(), 0).map(|_| ());
        match want {
            None => {
                if let Err(e) = up {
                    panic!("{what}: upstream refuses it: {e}");
                }
                assert_eq!(ours, Ok(()), "{what}: refused here");
                assert!(
                    check(doc.as_bytes()).is_ok(),
                    "{what}: refused when checked"
                );
            }
            Some((scope, field)) => {
                assert!(up.is_err(), "{what}: upstream reads it");
                let (scope, field) = (*scope, *field);
                assert_eq!(ours, Err(ReadError::Malformed { scope, field }), "{what}");
                assert!(counts(doc.as_bytes(), 0).is_err(), "{what}: counted here");
                assert_eq!(
                    check(doc.as_bytes()),
                    Err(ParseError::Malformed { scope, field }),
                    "{what}: checked here"
                );
                assert!(
                    apply(doc.as_bytes(), &[sig]).is_err(),
                    "{what}: signed here"
                );
            }
        }
    }

    // A number JSON does not have, wherever it stands.
    let lexed: [(&str, &str, &str); 6] = [
        ("kept, led by a zero", r#""p":[1,"#, r#""p":[01,"#),
        ("kept, a fraction cut short", r#""p":[1,"#, r#""p":[1.,"#),
        ("kept, an exponent cut short", r#""p":[1,"#, r#""p":[1e+,"#),
        (
            "skipped in an entry",
            entry,
            r#""blockDaaScore":100,"isCoinbase":false,"covenantId":null,"more":-"#,
        ),
        (
            "skipped in a key source",
            r#""derivationPath":"m/44'/111111'/0'"}"#,
            r#""derivationPath":"m/44'/111111'/0'","more":00}"#,
        ),
        ("beside the sections", r#""y":1e5"#, r#""y":1.e5"#),
    ];
    for (what, from, to) in lexed {
        let doc = one(base.clone(), from, to);
        assert!(
            Bundle::deserialize(&to_envelope(doc.as_bytes())).is_err(),
            "{what}: upstream reads it"
        );
        let ours = read_at(doc.as_bytes(), 0);
        assert!(
            matches!(ours, Err(ReadError::Parse(ParseError::Lex(_)))),
            "{what}: {ours:?}"
        );
    }

    // A bad value in a transaction other than the one read: upstream refuses
    // the bundle, and so does every walk here but the one per input.
    let tx = &base[1..base.len() - 1];
    let two = |second: &str| format!("[{tx},{second}]");
    assert!(Bundle::deserialize(&to_envelope(two(tx).as_bytes())).is_ok());
    assert_eq!(read_at(two(tx).as_bytes(), 0), Ok((3, 3)));
    let off_key = format!(r#""partialSigs":{{"{off_curve}""#);
    let elsewhere: [(&str, &str, &str, Scope, Field); 4] = [
        (
            "a count below zero",
            r#""inputCount":3"#,
            r#""inputCount":-1"#,
            S::Global,
            F::InputCount,
        ),
        (
            "a sequence as text",
            r#""sequence":7"#,
            r#""sequence":"7""#,
            S::Input(1),
            F::Sequence,
        ),
        (
            "an amount below zero",
            r#""amount":40000"#,
            r#""amount":-1"#,
            S::Output(2),
            F::Amount,
        ),
        (
            "a signer's key off the curve",
            &sig_key,
            &off_key,
            S::Input(0),
            F::PartialSigs,
        ),
    ];
    for (what, from, to, scope, field) in elsewhere {
        let doc = two(&one(tx.to_string(), from, to));
        assert!(
            Bundle::deserialize(&to_envelope(doc.as_bytes())).is_err(),
            "{what}: upstream reads it"
        );
        let malformed = ReadError::Malformed { scope, field };
        assert_eq!(read_at(doc.as_bytes(), 0), Err(malformed), "{what}");
        assert_eq!(counts(doc.as_bytes(), 0), Err(malformed), "{what}: counted");
        assert!(apply(doc.as_bytes(), &[sig]).is_err(), "{what}: signed");
    }
}

/// A field written twice is refused as upstream refuses it, in any
/// transaction of the bundle, naming the field. What upstream keeps among
/// its unknowns may repeat, there as here.
#[test]
fn a_field_written_twice_is_refused_as_upstream_refuses_it() {
    let path: DerivationPath = "m/44'/111111'/0'/0/1".parse().unwrap();
    let text = String::from_utf8(doc_of(&envelope(
        upstream_sign(
            pskt(&rich()),
            &key(5),
            None,
            Some(KeySource::new([0xde, 0xad, 0xbe, 0xef], path)),
        )
        .signed,
    )))
    .unwrap();
    let (g, i, o) = sections(&text);
    let (input, output) = (object_at(&i[1..]), object_at(&o[1..]));
    // `object` with `member` written again ahead of the rest.
    let ahead = |object: &str, member: &str| format!("{{{member},{}", &object[1..]);
    let twice = |object: &str, name: &str| {
        let key = format!("\"{name}\":");
        let at = object
            .find(&key)
            .unwrap_or_else(|| panic!("{name}: in the object"));
        let from = at + key.len();
        let (_, len) = Lexer::new(&object.as_bytes()[from..])
            .skip_value()
            .expect("its value");
        ahead(object, &object[at..from + len])
    };
    let sig = PartialSig {
        input: 0,
        public_key: &key(5).public_key().serialize(),
        signature: &[1; 64],
        derivation: Derivation::Null,
    };

    use Field as F;
    let mut fields: Vec<(Scope, &str, &str, Field)> = Vec::new();
    for (name, field) in [
        ("version", F::Version),
        ("txVersion", F::TxVersion),
        ("fallbackLockTime", F::FallbackLockTime),
        ("inputsModifiable", F::InputsModifiable),
        ("outputsModifiable", F::OutputsModifiable),
        ("inputCount", F::InputCount),
        ("outputCount", F::OutputCount),
        ("xpubs", F::Xpubs),
        ("id", F::Id),
        ("proprietaries", F::Proprietaries),
        ("payload", F::Payload),
    ] {
        fields.push((Scope::Global, g, name, field));
    }
    for (name, field) in [
        ("utxoEntry", F::UtxoEntry),
        ("previousOutpoint", F::PreviousOutpoint),
        ("sequence", F::Sequence),
        ("minTime", F::MinTime),
        ("partialSigs", F::PartialSigs),
        ("sighashType", F::SighashType),
        ("redeemScript", F::RedeemScript),
        ("sigOpCount", F::SigOpCount),
        ("bip32Derivations", F::Bip32Derivations),
        ("finalScriptSig", F::FinalScriptSig),
        ("proprietaries", F::Proprietaries),
    ] {
        fields.push((Scope::Input(0), input, name, field));
    }
    for (name, field) in [
        ("amount", F::Amount),
        ("scriptPublicKey", F::ScriptPublicKey),
        ("redeemScript", F::RedeemScript),
        ("bip32Derivations", F::Bip32Derivations),
        ("covenant", F::Covenant),
        ("proprietaries", F::Proprietaries),
    ] {
        fields.push((Scope::Output(0), output, name, field));
    }

    let tx = &text[1..text.len() - 1];
    for (scope, object, name, field) in fields {
        let one = text.replacen(object, &twice(object, name), 1);
        let second = format!("[{tx},{}]", &one[1..one.len() - 1]);
        for (which, doc) in [("read", &one), ("after it", &second)] {
            let said = Bundle::deserialize(&to_envelope(doc.as_bytes()))
                .map(|_| ())
                .expect_err("upstream reads it")
                .to_string();
            assert!(
                said.contains(&format!("duplicate field `{name}`")),
                "{name}, {which}: upstream says {said}"
            );
            let dup = ParseError::Duplicate { scope, field };
            assert_eq!(check(doc.as_bytes()), Err(dup), "{name}, {which}");
            assert_eq!(
                read_at(doc.as_bytes(), 0),
                Err(ReadError::Duplicate { scope, field }),
                "{name}, {which}"
            );
            assert_eq!(
                counts(doc.as_bytes(), 0),
                Err(ReadError::Duplicate { scope, field }),
                "{name}, {which}: counted"
            );
            let edit = match scope {
                Scope::Input(input) => EditError::Malformed { input, field },
                _ => EditError::Parse(dup),
            };
            assert_eq!(apply(doc.as_bytes(), &[sig]), Err(edit), "{name}, {which}");
        }
    }

    // `hidden` written twice: named there as here.
    let field = F::Hidden;
    let hidden = r#""hidden":null,"hidden":null"#;
    let one = text.replacen(input, &ahead(input, hidden), 1);
    let said = Bundle::deserialize(&to_envelope(one.as_bytes()))
        .map(|_| ())
        .expect_err("upstream reads it")
        .to_string();
    assert!(
        said.contains("duplicate field `hidden`"),
        "hidden: upstream says {said}"
    );
    let scope = Scope::Input(0);
    let dup = ParseError::Duplicate { scope, field };
    assert_eq!(check(one.as_bytes()), Err(dup), "hidden");
    assert_eq!(
        read_at(one.as_bytes(), 0),
        Err(ReadError::Duplicate { scope, field }),
        "hidden"
    );
    assert_eq!(
        apply(one.as_bytes(), &[sig]),
        Err(EditError::Malformed { input: 0, field }),
        "hidden"
    );

    // Kept among upstream's unknowns, the last of each: the same transaction
    // both sides.
    let kept: [(&str, &str, &str); 8] = [
        ("unknowns, globally", g, r#""unknowns":1,"unknowns":2"#),
        (
            "a redeem script, globally",
            g,
            r#""redeemScript":"00","redeemScript":"01""#,
        ),
        (
            "derivations, globally",
            g,
            r#""bip32Derivations":{},"bip32Derivations":7"#,
        ),
        ("an unknown, globally", g, r#""note":1,"note":"two""#),
        (
            "unknowns on an input",
            input,
            r#""unknowns":1,"unknowns":2"#,
        ),
        (
            "a global name on an input",
            input,
            r#""version":1,"version":2"#,
        ),
        (
            "unknowns on an output",
            output,
            r#""unknowns":[],"unknowns":{}"#,
        ),
        (
            "an input's name on an output",
            output,
            r#""sequence":1,"sequence":2"#,
        ),
    ];
    for (what, object, members) in kept {
        let doc = text.replacen(object, &ahead(object, members), 1);
        let bundle = Bundle::deserialize(&to_envelope(doc.as_bytes()))
            .unwrap_or_else(|e| panic!("{what}: upstream refuses it: {e}"));
        assert!(check(doc.as_bytes()).is_ok(), "{what}: checked");
        assert!(read_at(doc.as_bytes(), 0).is_ok(), "{what}: read");
        assert!(apply(doc.as_bytes(), &[sig]).is_ok(), "{what}: signed");
        let inner = bundle.0.into_iter().next().expect("one transaction");
        let up = upstream_sign(PSKT::<Signer>::from(inner), &key(3), None, None);
        assert_eq!(our_hashes(doc.as_bytes()), up.hashes, "{what}");
    }
}

/// A bundle upstream reads is signed here however it is written: escaped
/// strings, keys uncompressed or hybrid, a key source with extra members.
/// Signed here, each reads back as upstream's own signer writes it.
#[test]
fn a_bundle_upstream_reads_is_signed_here_however_it_is_written() {
    let path: DerivationPath = "m/44'/111111'/0'/0/1".parse().unwrap();
    let (other, me) = (key(6), key(5));
    let text = String::from_utf8(doc_of(&envelope(
        upstream_sign(
            pskt(&rich()),
            &other,
            None,
            Some(KeySource::new([0xde, 0xad, 0xbe, 0xef], path)),
        )
        .signed,
    )))
    .unwrap();
    let one = |text: &str, from: &str, to: &str| {
        assert!(text.contains(from), "{from}: not in the bundle");
        text.replacen(from, to, 1)
    };
    // `value` after `before`, its first character as a `\u` escape.
    let escaped = |before: &str, value: &str| {
        let c = value.chars().next().expect("a character");
        (
            format!("{before}\"{value}\""),
            format!("{before}\"\\u{:04x}{}\"", c as u32, &value[1..]),
        )
    };
    let po = hex(&other.public_key().serialize());
    let unc = other.public_key().serialize_uncompressed();
    let hybrid = format!("{:02x}{}", 6 + (unc[64] & 1), hex(&unc[1..]));
    let unc = hex(&unc);
    let sig = &text[text.find("{\"schnorr\":\"").unwrap() + 12..][..128];
    let spk = format!("000020{}ac", "31".repeat(32));
    let out_spk = format!("000020{}ac", "41".repeat(32));

    let mut cases: Vec<(&str, String)> = Vec::new();
    let mut add = |what: &'static str, (from, to): (String, String)| {
        cases.push((what, one(&text, &from, &to)));
    };
    add("a payload", escaped("\"payload\":", "deadbeef"));
    add(
        "a payload in capitals",
        (
            "\"payload\":\"deadbeef\"".into(),
            "\"payload\":\"\\u0044EADBEEF\"".into(),
        ),
    );
    add("an entry's script", escaped("\"scriptPublicKey\":", &spk));
    add(
        "an output's script",
        escaped("\"scriptPublicKey\":", &out_spk),
    );
    add(
        "an outpoint's id",
        escaped("\"transactionId\":", &"01".repeat(32)),
    );
    add(
        "a covenant's id",
        escaped("\"covenantId\":", &"c5".repeat(32)),
    );
    add("a redeem script", escaped("\"redeemScript\":", "512102ac"));
    add("a fingerprint", escaped("\"keyFingerprint\":", "deadbeef"));
    add(
        "a path, its slashes",
        (
            "\"derivationPath\":\"m/44'/111111'/0'/0/1\"".into(),
            "\"derivationPath\":\"m\\/44'\\/111111'\\/0'\\/0\\/1\"".into(),
        ),
    );
    add(
        "a path, its letter",
        escaped("\"derivationPath\":", "m/44'/111111'/0'/0/1"),
    );
    add("a signer's key", escaped("\"partialSigs\":{", &po));
    add("a derivation's key", escaped("\"bip32Derivations\":{", &po));
    add("a signature", escaped("{\"schnorr\":", sig));
    add(
        "an id",
        (
            "\"id\":null".into(),
            format!("\"id\":\"\\u0061{}\"", &"ab".repeat(32)[1..]),
        ),
    );
    add(
        "a final script",
        (
            "\"finalScriptSig\":null".into(),
            "\"finalScriptSig\":\"\\u0061\\u0062\"".into(),
        ),
    );
    add(
        "a key source with more",
        (
            "\"derivationPath\":\"m/44'/111111'/0'/0/1\"}".into(),
            "\"derivationPath\":\"m/44'/111111'/0'/0/1\",\"note\":1,\"more\":{\"a\":[1,2]}}".into(),
        ),
    );
    cases.push(("a signer's key uncompressed", text.replace(&po, &unc)));
    cases.push(("a signer's key hybrid", text.replace(&po, &hybrid)));

    for (what, doc) in &cases {
        assert_ne!(doc, &text, "{what}: the case changed nothing");
        let read = Bundle::deserialize(&to_envelope(doc.as_bytes()))
            .unwrap_or_else(|e| panic!("{what}: upstream refuses it: {e}"));
        let inner = read.0.into_iter().next().expect("one transaction");
        let want = envelope(upstream_sign(PSKT::<Signer>::from(inner), &me, None, None).signed);
        assert!(check(doc.as_bytes()).is_ok(), "{what}: checked");
        assert!(read_at(doc.as_bytes(), 0).is_ok(), "{what}: read");
        let ours = our_sign(doc.as_bytes(), &me, None, Derivation::Null);
        assert_eq!(upstream_round_trip(&ours), want, "{what}: signed");
    }

    // The key source with more reads as its two strings.
    let more = &cases
        .iter()
        .find(|c| c.0 == "a key source with more")
        .unwrap()
        .1;
    let mut sources = Vec::new();
    derivations(check(more.as_bytes()).unwrap(), 0, 0, |e| {
        sources.push(e.source.map(|(f, p)| (f.to_vec(), p.to_vec())));
        true
    })
    .expect("reads");
    assert_eq!(
        sources,
        [Some((
            b"deadbeef".to_vec(),
            b"m/44'/111111'/0'/0/1".to_vec()
        ))]
    );

    // Our own key, written uncompressed, is ours: signed, and replaced when
    // signed again.
    let mine = String::from_utf8(doc_of(&envelope(
        upstream_sign(pskt(&rich()), &me, None, None).signed,
    )))
    .unwrap();
    let pm = hex(&me.public_key().serialize());
    let mine = mine.replace(&pm, &hex(&me.public_key().serialize_uncompressed()));
    let held = presence(
        check(mine.as_bytes()).unwrap(),
        0,
        0,
        &me.public_key().serialize(),
    )
    .unwrap();
    assert!(held.signed, "the uncompressed key is ours");
    let read = Bundle::deserialize(&to_envelope(mine.as_bytes())).expect("upstream reads it");
    let inner = read.0.into_iter().next().expect("one transaction");
    let want =
        envelope(upstream_sign(PSKT::<Signer>::from(inner), &me, Some([9; 32]), None).signed);
    let ours = our_sign(mine.as_bytes(), &me, Some([9; 32]), Derivation::Null);
    assert_eq!(upstream_round_trip(&ours), want, "signed again");
}

/// An output's key path: kassigner.org 1.0.7's 2-of-3 bundle names its
/// change's (output 1) keys at `m/45'/111111'/0'/0/1/0`, its payment's none.
#[test]
fn an_outputs_key_path_reads_as_written() {
    use kassigner_kaspa::pskb::signature::output_path;
    let request = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v107/site/pskb_multisig.bin"
    ));
    // As upstream reads 1.0.7's: the global `payload` it never writes, as null.
    let text = String::from_utf8(doc_of(core::str::from_utf8(request).unwrap())).unwrap();
    assert_eq!(text.matches("\"global\":{").count(), 1);
    let doc = text.replacen("\"global\":{", "\"global\":{\"payload\":null,", 1);
    let bundle = check(doc.as_bytes()).unwrap();
    assert_eq!(
        output_path(bundle, 0, 1),
        Some(&b"m/45'/111111'/0'/0/1/0"[..])
    );
    assert_eq!(output_path(bundle, 0, 0), None, "the payment");
    assert_eq!(output_path(bundle, 0, 2), None, "past the outputs");
    assert_eq!(output_path(bundle, 1, 1), None, "past the transactions");
}

// ── Writing ─────────────────────────────────────────────────────────────────

const HARD: u32 = 0x8000_0000;

fn write_version(v: Version) -> WriteVersion {
    match v {
        Version::Zero => WriteVersion::Zero,
        Version::One => WriteVersion::One,
        Version::Two => WriteVersion::Two,
    }
}

/// `s`'s bundle written here as [`pskt`] has upstream build it, with
/// `input0` and `output0` the first input's and output's derivations.
fn written(s: &Spec, input0: &[Member<'_>], output0: &[Member<'_>]) -> Result<String, WriteError> {
    let inputs: Vec<WriteInput<'_>> = s
        .inputs
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            assert!(spec.entry, "a bundle written here carries every entry");
            WriteInput {
                previous_outpoint: Outpoint {
                    transaction_id: [i as u8 + 1; 32],
                    index: i as u32 * 3,
                },
                utxo_entry: OurEntry {
                    amount: spec.amount,
                    script_public_key: OurScript {
                        version: spec.script_version,
                        script: &spec.script,
                    },
                },
                details: EntryDetails {
                    block_daa_score: 100,
                    is_coinbase: false,
                    covenant_id: None,
                },
                sequence: s.sequences.iter().find(|&&(k, _)| k == i).map(|&(_, n)| n),
                min_time: spec.min_time,
                sighash_type: 1,
                redeem_script: spec.redeem.as_deref(),
                sig_op_count: spec.sig_ops,
                derivations: if i == 0 { input0 } else { &[] },
            }
        })
        .collect();
    let outputs: Vec<WriteOutput<'_>> = s
        .outputs
        .iter()
        .enumerate()
        .map(|(k, o)| WriteOutput {
            amount: o.amount,
            script_public_key: OurScript {
                version: 0,
                script: &o.script,
            },
            covenant: o
                .covenant
                .map(|(authorizing_input, covenant_id)| OurBinding {
                    authorizing_input,
                    covenant_id,
                }),
            derivations: if k == 0 { output0 } else { &[] },
        })
        .collect();
    let global = Global {
        version: write_version(s.version),
        tx_version: s.tx_version,
        fallback_lock_time: s.fallback,
        payload: s.payload.as_deref(),
    };
    let n = pskb_write::written_len(&global, &inputs, &outputs)?;
    let mut doc = vec![0u8; n];
    assert_eq!(pskb_write::write(&global, &inputs, &outputs, &mut doc)?, n);
    Ok(to_envelope(&doc))
}

/// A bundle written here is, byte for byte, the one upstream writes: version
/// zero with nothing else in play, and version two with every field a new
/// bundle can carry.
#[test]
fn a_written_bundle_is_the_one_upstream_writes() {
    for s in [plain(), rich()] {
        let ours = written(&s, &[], &[]).expect("written");
        assert_eq!(ours, envelope(pskt(&s)));
        assert_eq!(upstream_round_trip(&ours), ours);
    }
}

/// Derivations are written as upstream writes them: in the keys' byte order,
/// a key source as `KeySource`, none as `null`.
#[test]
fn derivations_are_written_as_upstream_writes_them() {
    let s = plain();
    let fingerprint = [0x73, 0xc5, 0xda, 0x0a];
    let keys: Vec<[u8; 33]> = [0x51u8, 0x52, 0x53]
        .iter()
        .map(|&b| key(b).public_key().serialize())
        .collect();
    let sources: [Option<(&str, Vec<u32>)>; 3] = [
        Some((
            "m/45'/111111'/0'/2/1/7",
            vec![45 | HARD, 111_111 | HARD, HARD, 2, 1, 7],
        )),
        Some((
            "m/44'/111111'/0'/0/5",
            vec![44 | HARD, 111_111 | HARD, HARD, 0, 5],
        )),
        None,
    ];

    let mut bundle = Bundle::from(pskt(&s));
    for (k, source) in keys.iter().zip(&sources) {
        let pk = secp256k1::PublicKey::from_slice(k).expect("key");
        let up = source.as_ref().map(|(path, _)| {
            KeySource::new(fingerprint, path.parse::<DerivationPath>().expect("path"))
        });
        bundle.0[0].inputs[0]
            .bip32_derivations
            .insert(pk, up.clone());
        if up.is_some() {
            bundle.0[0].outputs[0].bip32_derivations.insert(pk, up);
        }
    }
    let theirs = bundle.serialize().expect("upstream serializes");

    let values: Vec<Vec<u8>> = sources
        .iter()
        .map(|source| match source {
            Some((_, levels)) => {
                let mut v = vec![0u8; key_source_max(levels.len())];
                let n = key_source(&fingerprint, levels, &mut v).expect("key source");
                v.truncate(n);
                v
            }
            None => b"null".to_vec(),
        })
        .collect();
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|&k| keys[k]);
    let input0: Vec<Member<'_>> = order
        .iter()
        .map(|&k| Member {
            public_key: &keys[k],
            value: &values[k],
        })
        .collect();
    let output0: Vec<Member<'_>> = input0
        .iter()
        .copied()
        .filter(|m| m.value != b"null")
        .collect();
    assert_eq!(
        written(&s, &input0, &output0).expect("written"),
        theirs,
        "upstream's bundle with the same derivations"
    );
}

/// A key source is upstream's `KeySource` as serde writes it; the longest
/// fills [`key_source_max`].
#[test]
fn a_key_source_is_upstreams() {
    let cases: [([u8; 4], Vec<u32>, &str); 4] = [
        (
            [0x73, 0xc5, 0xda, 0x0a],
            vec![44 | HARD, 111_111 | HARD, HARD, 0, 0],
            "m/44'/111111'/0'/0/0",
        ),
        ([0; 4], vec![], "m"),
        (
            [0xff; 4],
            vec![u32::MAX, u32::MAX, u32::MAX],
            "m/2147483647'/2147483647'/2147483647'",
        ),
        ([0xab, 0, 1, 0x10], vec![HARD - 1, 0], "m/2147483647/0"),
    ];
    for (fingerprint, levels, path) in cases {
        let up = KeySource::new(fingerprint, path.parse::<DerivationPath>().expect("path"));
        let want = serde_json::to_string(&up).expect("serde");
        let mut out = vec![0u8; key_source_max(levels.len())];
        let n = key_source(&fingerprint, &levels, &mut out).expect("written");
        assert_eq!(std::str::from_utf8(&out[..n]).unwrap(), want, "{path}");
        assert!(n <= key_source_max(levels.len()));
    }
    let mut full = vec![0u8; key_source_max(3)];
    assert_eq!(
        key_source(&[0; 4], &[u32::MAX; 3], &mut full),
        Ok(key_source_max(3)),
        "the longest path fills the bound"
    );
    assert_eq!(
        key_source(&[0; 4], &[u32::MAX; 3], &mut full[..10]),
        Err(WriteError::BufferTooSmall)
    );
}

/// What upstream would not build is not written: a payload below bundle
/// version One, a covenant binding below bundle version Two or the covenant
/// transaction version, derivations out of key order or repeated, and a
/// buffer short of the bundle.
#[test]
fn what_upstream_would_not_build_is_not_written() {
    let mut s = plain();
    s.payload = Some(vec![0xde]);
    assert_eq!(
        written(&s, &[], &[]),
        Err(WriteError::PayloadNeedsVersionOne)
    );
    assert!(PSKT::<Creator>::default()
        .set_version(Version::Zero)
        .constructor()
        .payload(Some(vec![0xde]))
        .is_err());

    let mut r = rich();
    r.version = Version::One;
    assert_eq!(
        written(&r, &[], &[]),
        Err(WriteError::CovenantNeedsVersionTwo { output: 1 })
    );
    let mut r = rich();
    r.tx_version = 0;
    assert_eq!(
        written(&r, &[], &[]),
        Err(WriteError::CovenantNeedsVersionTwo { output: 1 })
    );
    let binding = CovenantBinding {
        authorizing_input: 0,
        covenant_id: UpHash::from_bytes([0xc5; 32]),
    };
    let out = OutputBuilder::default()
        .amount(5)
        .script_public_key(ScriptPublicKey::from_vec(0, p2pk(&[0x41; 32])))
        .covenant(Some(binding))
        .build()
        .expect("output");
    assert!(PSKT::<Creator>::default()
        .set_version(Version::One)
        .constructor()
        .set_tx_version(1)
        .output(out)
        .is_err());

    let (low, high) = {
        let mut k = [
            key(0x51).public_key().serialize(),
            key(0x52).public_key().serialize(),
        ];
        k.sort();
        (k[0], k[1])
    };
    let a = Member {
        public_key: &low,
        value: b"null",
    };
    let b = Member {
        public_key: &high,
        value: b"null",
    };
    let s = plain();
    assert!(written(&s, &[a, b], &[a, b]).is_ok());
    assert_eq!(
        written(&s, &[b, a], &[]),
        Err(WriteError::InputKeyOrder { input: 0 })
    );
    assert_eq!(
        written(&s, &[a, a], &[]),
        Err(WriteError::InputKeyOrder { input: 0 })
    );
    assert_eq!(
        written(&s, &[], &[b, a]),
        Err(WriteError::OutputKeyOrder { output: 0 })
    );

    let global = Global {
        version: WriteVersion::Zero,
        tx_version: 0,
        fallback_lock_time: None,
        payload: None,
    };
    let need = pskb_write::written_len(&global, &[], &[]).expect("len");
    let mut short = vec![0u8; need - 1];
    assert_eq!(
        pskb_write::write(&global, &[], &[], &mut short),
        Err(WriteError::BufferTooSmall)
    );
}

/// The SDK's bundles in `spec/vectors/v110/sdk/`, requests and replies, are
/// upstream's to the byte; a request is a bundle no one has signed.
#[test]
fn the_sdks_bundles_read_back_as_upstream_writes_them() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/v110/sdk");
    for name in [
        "single.bundle",
        "single.bundle.reply.abandon12",
        "multisig.bundle",
        "multisig.bundle.reply.abandon12",
        "multisig.bundle.reply.zoo12",
        "savings.bundle",
        "savings.bundle.reply.abandon12",
        "savings.bundle.reply.zoo12",
    ] {
        let text =
            std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(upstream_round_trip(&text), text, "{name}");
        let bundle = Bundle::deserialize(&text).expect("upstream reads it");
        let signed = bundle.0[0]
            .inputs
            .iter()
            .any(|input| !input.partial_sigs.is_empty());
        assert_eq!(signed, name.contains(".reply."), "{name}");
    }
}
