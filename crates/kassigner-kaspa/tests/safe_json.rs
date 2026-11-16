// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The WASM SDK's transaction JSON against upstream: every transaction is
//! also written by the serializer `serializeToSafeJSON` runs, and every text
//! read by the one `deserializeFromSafeJSON` runs.

use kaspa_consensus_client::string::SerializableTransaction;
use kaspa_consensus_client::Transaction as ClientTransaction;
use kaspa_consensus_core::subnets::SubnetworkId as UpSubnetwork;
use kaspa_consensus_core::tx::{
    CovenantBinding as UpBinding, ScriptPublicKey as UpScript, SignableTransaction,
    Transaction as UpTransaction, TransactionInput as UpInput, TransactionOutpoint,
    TransactionOutput as UpOutput, UtxoEntry as UpEntry,
};
use kaspa_hashes::Hash as UpHash;

use kassigner_kaspa::safe_json::{build, fill, write, written_len, SafeJsonError};
use kassigner_kaspa::tx::{
    CovenantBinding, EntryDetails, Outpoint, ScriptPublicKey, Transaction, TransactionInput,
    TransactionOutput, UtxoEntry, SUBNETWORK_ID_NATIVE,
};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::hex;
#[path = "../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::p2pk;

/// One input: outpoint, sequence, signature operations (version 0) or
/// compute budget (version 1), unlocking script, and the output it spends.
struct In {
    id: [u8; 32],
    index: u32,
    sequence: u64,
    sig_ops: u8,
    budget: u16,
    unlock: Vec<u8>,
    amount: u64,
    script_version: u16,
    script: Vec<u8>,
    details: EntryDetails,
}

struct Out {
    value: u64,
    script: Vec<u8>,
    covenant: Option<(u16, [u8; 32])>,
}

struct Spec {
    version: u16,
    inputs: Vec<In>,
    outputs: Vec<Out>,
    lock_time: u64,
    subnetwork: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
    storage_mass: u64,
}

/// A request as the SDK writes one: unsigned, two coins, a payment and a
/// change.
fn unsigned() -> Spec {
    let coin = |n: u8, amount: u64| In {
        id: [n; 32],
        index: u32::from(n),
        sequence: 0,
        sig_ops: 1,
        budget: 0,
        unlock: vec![],
        amount,
        script_version: 0,
        script: p2pk(&[n; 32]),
        details: EntryDetails {
            block_daa_score: 90_000_000 + u64::from(n),
            is_coinbase: false,
            covenant_id: None,
        },
    };
    Spec {
        version: 0,
        inputs: vec![coin(1, 300_000_000), coin(2, 200_000_000)],
        outputs: vec![
            Out {
                value: 400_000_000,
                script: p2pk(&[0x41; 32]),
                covenant: None,
            },
            Out {
                value: 99_968_000,
                script: p2pk(&[0x42; 32]),
                covenant: None,
            },
        ],
        lock_time: 0,
        subnetwork: [0; 20],
        gas: 0,
        payload: vec![],
        storage_mass: 31_951,
    }
}

/// Every field set, values at the edges of a `u64`.
fn rich() -> Spec {
    let mut s = unsigned();
    s.inputs[0].unlock = vec![0x41; 66];
    s.inputs[0].sequence = u64::MAX;
    s.inputs[1].unlock = vec![0xab, 0xcd];
    s.inputs[1].details = EntryDetails {
        block_daa_score: u64::MAX,
        is_coinbase: true,
        covenant_id: Some([0xc0; 32]),
    };
    s.inputs[1].script_version = 1;
    s.inputs[1].amount = u64::MAX;
    s.outputs.push(Out {
        value: 0,
        script: vec![0xaa, 0x20, 0x01, 0x87],
        covenant: Some((1, [0xc5; 32])),
    });
    s.lock_time = 1_700_000_000;
    s.subnetwork = [7; 20];
    s.gas = 12;
    s.payload = vec![0xde, 0xad, 0xbe, 0xef];
    s.storage_mass = u64::MAX;
    s
}

/// A version 1 transaction as the SDK writes one: no signature operations,
/// a compute budget on each input, the first coin bound to a covenant its
/// first output continues, the second output starting another.
fn covenants() -> Spec {
    let mut s = unsigned();
    s.version = 1;
    for (i, budget) in s.inputs.iter_mut().zip([10, 30]) {
        i.sig_ops = 0;
        i.budget = budget;
    }
    s.inputs[0].details.covenant_id = Some([0xc0; 32]);
    s.outputs[0].covenant = Some((0, [0xc0; 32]));
    s.outputs[1].covenant = Some((1, [0xc5; 32]));
    s.outputs.push(Out {
        value: 1_000,
        script: p2pk(&[0x43; 32]),
        covenant: None,
    });
    s
}

/// [`covenants`] signed, with a payload: version 1's id is over the
/// payload's digest.
fn covenants_signed() -> Spec {
    let mut s = covenants();
    s.inputs[0].unlock = vec![0x41; 66];
    s.inputs[1].unlock = vec![0x42; 66];
    s.payload = vec![0xde, 0xad, 0xbe, 0xef];
    s.lock_time = 1_700_000_000;
    s
}

/// `s` as upstream writes it, through the SDK's serializer.
fn theirs(s: &Spec) -> String {
    let inputs = s
        .inputs
        .iter()
        .map(|i| {
            let outpoint = TransactionOutpoint::new(UpHash::from_bytes(i.id), i.index);
            if s.version == 0 {
                UpInput::new(outpoint, i.unlock.clone(), i.sequence, i.sig_ops)
            } else {
                UpInput::new_with_compute_budget(outpoint, i.unlock.clone(), i.sequence, i.budget)
            }
        })
        .collect();
    let outputs = s
        .outputs
        .iter()
        .map(|o| {
            let spk = UpScript::from_vec(0, o.script.clone());
            match o.covenant {
                Some((authorizing_input, id)) => UpOutput::with_covenant(
                    o.value,
                    spk,
                    Some(UpBinding {
                        authorizing_input,
                        covenant_id: UpHash::from_bytes(id),
                    }),
                ),
                None => UpOutput::new(o.value, spk),
            }
        })
        .collect();
    let tx = UpTransaction::new(
        s.version,
        inputs,
        outputs,
        s.lock_time,
        UpSubnetwork::from_bytes(s.subnetwork),
        s.gas,
        s.payload.clone(),
    )
    .with_storage_mass(s.storage_mass);
    let entries = s
        .inputs
        .iter()
        .map(|i| {
            UpEntry::new(
                i.amount,
                UpScript::from_vec(i.script_version, i.script.clone()),
                i.details.block_daa_score,
                i.details.is_coinbase,
                i.details.covenant_id.map(UpHash::from_bytes),
            )
        })
        .collect();
    SerializableTransaction::from_signable_transaction(&SignableTransaction::with_entries(
        tx, entries,
    ))
    .expect("upstream takes it")
    .serialize_to_json()
    .expect("upstream writes it")
}

/// `s` written here.
fn ours(s: &Spec) -> Result<String, SafeJsonError> {
    let inputs: Vec<TransactionInput<'_>> = s
        .inputs
        .iter()
        .map(|i| TransactionInput {
            previous_outpoint: Outpoint {
                transaction_id: i.id,
                index: i.index,
            },
            sequence: i.sequence,
            sig_op_count: i.sig_ops,
            compute_budget: i.budget,
            signature_script: &i.unlock,
            utxo_entry: UtxoEntry {
                amount: i.amount,
                script_public_key: ScriptPublicKey {
                    version: i.script_version,
                    script: &i.script,
                },
            },
        })
        .collect();
    let outputs: Vec<TransactionOutput<'_>> = s
        .outputs
        .iter()
        .map(|o| TransactionOutput {
            value: o.value,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &o.script,
            },
            covenant: o
                .covenant
                .map(|(authorizing_input, covenant_id)| CovenantBinding {
                    authorizing_input,
                    covenant_id,
                }),
        })
        .collect();
    let tx = Transaction {
        version: s.version,
        inputs: &inputs,
        outputs: &outputs,
        lock_time: s.lock_time,
        subnetwork_id: s.subnetwork,
        gas: s.gas,
        payload: &s.payload,
    };
    let details: Vec<EntryDetails> = s.inputs.iter().map(|i| i.details).collect();
    let n = written_len(&tx, &details, s.storage_mass)?;
    let mut out = vec![0u8; n];
    assert_eq!(write(&tx, &details, s.storage_mass, &mut out)?, n);
    Ok(String::from_utf8(out).expect("ascii"))
}

/// Read `text` here and write it back.
fn read_back(text: &str) -> Result<String, SafeJsonError> {
    let blank_in = TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [0; 32],
            index: 0,
        },
        sequence: 0,
        sig_op_count: 0,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: 0,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &[],
            },
        },
    };
    let blank_out = TransactionOutput {
        value: 0,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: &[],
        },
        covenant: None,
    };
    let blank_details = EntryDetails {
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    };
    let mut inputs = vec![blank_in; 8];
    let mut outputs = vec![blank_out; 8];
    let mut details = vec![blank_details; 8];
    let mut bytes = vec![0u8; text.len() / 2];
    let f = fill(
        text.as_bytes(),
        &mut inputs,
        &mut details,
        &mut outputs,
        &mut bytes,
    )?;
    let tx = build(&f.header, &inputs[..f.inputs], &outputs[..f.outputs]);
    let n = written_len(&tx, &details[..f.inputs], f.storage_mass)?;
    let mut out = vec![0u8; n];
    write(&tx, &details[..f.inputs], f.storage_mass, &mut out)?;
    let again = String::from_utf8(out).expect("ascii");
    // The id read is the id written: upstream takes it as is, and this writes
    // the one it computes.
    let id_at = again.find("\"id\":\"").expect("an id") + 6;
    assert_eq!(&again[id_at..id_at + 64], hex(&f.id), "the id as read");
    Ok(again)
}

/// Whether upstream's `deserializeFromSafeJSON` reads `text`.
fn upstream_reads(text: &str) -> bool {
    SerializableTransaction::deserialize_from_json(text)
        .map_err(|e| e.to_string())
        .and_then(|t| ClientTransaction::try_from(t).map_err(|e| e.to_string()))
        .is_ok()
}

/// A transaction written here is, byte for byte, upstream's
/// `serializeToSafeJSON` JSON, id included, unsigned or signed, version 0
/// or version 1 with its compute budgets and covenant bindings; both sides
/// read it back to the same bytes.
#[test]
fn a_written_transaction_is_the_one_upstream_writes() {
    for s in [unsigned(), rich(), covenants(), covenants_signed()] {
        let text = ours(&s).expect("written");
        assert_eq!(text, theirs(&s));
        let up = SerializableTransaction::deserialize_from_json(&text).expect("upstream reads it");
        assert_eq!(up.serialize_to_json().expect("upstream writes it"), text);
        assert!(upstream_reads(&text));
        assert_eq!(read_back(&text).expect("read here"), text);
    }
}

/// Not written: details not one per input, a transaction of a version
/// consensus does not know, a short buffer.
#[test]
fn what_cannot_be_written_is_refused() {
    let s = unsigned();
    let script = p2pk(&[1; 32]);
    let input = TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [1; 32],
            index: 1,
        },
        sequence: 0,
        sig_op_count: 1,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: 1,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &script,
            },
        },
    };
    let inputs = [input];
    let mut tx = Transaction {
        version: 0,
        inputs: &inputs,
        outputs: &[],
        lock_time: 0,
        subnetwork_id: SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: &[],
    };
    assert_eq!(written_len(&tx, &[], 0), Err(SafeJsonError::Details));
    let details = [s.inputs[0].details];
    let n = written_len(&tx, &details, 0).expect("len");
    let mut short = vec![0u8; n - 1];
    assert_eq!(
        write(&tx, &details, 0, &mut short),
        Err(SafeJsonError::BufferTooSmall)
    );
    tx.version = 2;
    assert_eq!(
        written_len(&tx, &details, 0),
        Err(SafeJsonError::Version { version: 2 })
    );
}

/// `text` with `from` replaced by `to`, which must occur once.
fn edit(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from}");
    text.replacen(from, to, 1)
}

/// What upstream reads, this reads; what it refuses, this refuses.
#[test]
fn the_reader_reads_what_upstream_reads() {
    let base = ours(&rich()).expect("written");
    let unsigned_text = ours(&unsigned()).expect("written");
    let address = "kaspa:pq02dzckvs0g6hhl9s9c484fv0wsd93sltwct9symfad4yw062w5y4v4mtlxa";
    let read = [
        edit(
            &base,
            "\"amount\":\"300000000\"",
            "\"amount\":\"+300000000\"",
        ),
        edit(
            &base,
            "\"lockTime\":\"1700000000\"",
            "\"lockTime\":\"0001700000000\"",
        ),
        base.replace("c0c0c0", "C0C0C0"),
        edit(
            &base,
            "\"signatureScript\":\"abcd\"",
            "\"signatureScript\":\"ABCD\"",
        ),
        edit(&base, "{\"id\":", "{\"note\":[1,{\"a\":null}],\"id\":"),
        edit(&base, "\"gas\":\"12\"", "\"gas\":\"12\",\"extra\":true"),
        base.replacen("\"utxo\":{", "\"utxo\":{\"x\":1,", 1),
        base.replacen("{\"value\":", "{\"y\":\"z\",\"value\":", 1),
        edit(&base, "\"storageMass\":", "\"mass\":"),
        edit(
            &base,
            "\"storageMass\":\"18446744073709551615\"",
            "\"storageMass\":\"not a number\"",
        ),
        edit(&unsigned_text, ",\"storageMass\":\"31951\"", ""),
        unsigned_text.replace(",\"computeBudget\":0", ""),
        unsigned_text.replace(",\"covenantId\":null", ""),
        unsigned_text.replace("\"address\":null,", ""),
        unsigned_text.replace(",\"covenant\":null", ""),
        unsigned_text.replacen("\"address\":null", &format!("\"address\":\"{address}\""), 1),
        unsigned_text
            .replace("\"inputs\":[", "\"inputs\": [ ")
            .replace(",\"", ", \""),
    ];
    for (k, text) in read.iter().enumerate() {
        assert!(upstream_reads(text), "{k}: upstream reads it");
        assert!(read_back(text).is_ok(), "{k}: read here: {text}");
    }

    let refused = [
        edit(
            &base,
            "\"amount\":\"300000000\"",
            "\"amount\":\"-300000000\"",
        ),
        edit(&base, "\"amount\":\"300000000\"", "\"amount\":\"\""),
        edit(&base, "\"amount\":\"300000000\"", "\"amount\":\"+\""),
        edit(&base, "\"amount\":\"300000000\"", "\"amount\":\"3e8\""),
        edit(&base, "\"amount\":\"300000000\"", "\"amount\":300000000"),
        edit(&base, "\"gas\":\"12\"", "\"gas\":\"18446744073709551616\""),
        edit(&base, ",\"lockTime\":\"1700000000\"", ""),
        edit(&base, "\"gas\":\"12\"", "\"gas\":\"12\",\"gas\":\"12\""),
        edit(&base, "\"storageMass\":", "\"mass\":\"1\",\"storageMass\":"),
        unsigned_text.replacen("\"sigOpCount\":1", "\"sigOpCount\":256", 1),
        unsigned_text.replacen("\"index\":1", "\"index\":-1", 1),
        unsigned_text.replacen("\"isCoinbase\":false", "\"isCoinbase\":\"false\"", 1),
        unsigned_text.replacen("\"transactionId\":\"01", "\"transactionId\":\"", 1),
        edit(
            &base,
            "\"signatureScript\":\"abcd\"",
            "\"signatureScript\":\"abc\"",
        ),
        edit(
            &base,
            "\"signatureScript\":\"abcd\"",
            "\"signatureScript\":\"abzz\"",
        ),
        edit(
            &unsigned_text,
            &format!("\"scriptPublicKey\":\"000020{}ac\"", "41".repeat(32)),
            "\"scriptPublicKey\":\"00\"",
        ),
        unsigned_text.replacen("\"address\":null", "\"address\":\"kaspa:notanaddress\"", 1),
        unsigned_text.replacen("\"address\":null", "\"address\":7", 1),
        unsigned_text.replacen("\"subnetworkId\":\"00", "\"subnetworkId\":\"", 1),
        unsigned_text.replacen("\"inputs\":[", "\"inputs\":{\"a\":", 1),
        "[]".to_string(),
        unsigned_text[..unsigned_text.len() - 1].to_string(),
    ];
    for (k, text) in refused.iter().enumerate() {
        assert!(!upstream_reads(text), "{k}: upstream refuses it: {text}");
        assert!(
            matches!(read_back(text), Err(SafeJsonError::Malformed { .. })),
            "{k}: refused here: {text}"
        );
    }
}

/// Stricter than upstream only here: an escaped string, which serde undoes
/// and no writer writes, the storage mass among them, and a transaction id
/// past 32 bytes, whose tail upstream's hex decoder drops.
#[test]
fn the_reader_is_stricter_only_where_it_says() {
    let base = ours(&unsigned()).expect("written");
    let stricter = [
        edit(&base, "\"gas\":\"0\"", "\"gas\":\"\\u0030\""),
        // A digit of the storage mass written as its escape: upstream reads
        // the number; read as it stood, it passed here for no number, a zero.
        base.replacen("\"storageMass\":\"", "\"storageMass\":\"\\u0031", 1),
        base.replacen(
            "\"transactionId\":\"0101",
            "\"transactionId\":\"ffff0101",
            1,
        ),
    ];
    for (k, text) in stricter.iter().enumerate() {
        assert!(upstream_reads(text), "{k}: upstream reads it");
        assert!(read_back(text).is_err(), "{k}: refused here");
    }
}

/// More than the caller's arrays hold is refused, not cut.
#[test]
fn the_reader_holds_to_the_callers_buffers() {
    let text = ours(&rich()).expect("written");
    let blank = |_| TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [0; 32],
            index: 0,
        },
        sequence: 0,
        sig_op_count: 0,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: 0,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &[],
            },
        },
    };
    let out = TransactionOutput {
        value: 0,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: &[],
        },
        covenant: None,
    };
    let d = EntryDetails {
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    };
    for (ni, no, nb) in [(1, 8, 4096), (8, 2, 4096), (8, 8, 16)] {
        let mut inputs: Vec<TransactionInput<'_>> = (0..ni).map(blank).collect();
        let mut outputs = vec![out; no];
        let mut details = vec![d; ni];
        let mut bytes = vec![0u8; nb];
        assert_eq!(
            fill(
                text.as_bytes(),
                &mut inputs,
                &mut details,
                &mut outputs,
                &mut bytes
            )
            .map(|f| f.inputs),
            Err(SafeJsonError::TooMany),
            "{ni} {no} {nb}"
        );
    }
}

/// The SDK's safe JSON in `spec/vectors/v110/sdk/` (requests, signed, and a
/// Time-Locked Savings claim and recovery) is upstream's to the byte, each
/// id the one upstream computes.
#[test]
fn the_sdks_safe_json_reads_back_as_upstream_writes_it() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/v110/sdk");
    for name in [
        "single.safe.json",
        "single.safe.signed.json",
        "multisig.safe.json",
        "multisig.safe.signed.json",
        "savings.claim.signed.json",
        "savings.recover.signed.json",
        // Version 1: compute budgets, covenant bindings.
        "covenant.start.signed.json",
        "covenant.continue.signed.json",
        "covenant.group.signed.json",
        "covenant.kcc3.signed.json",
        "covenant.card.signed.json",
    ] {
        let text =
            std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let up = SerializableTransaction::deserialize_from_json(&text).expect("upstream reads it");
        assert_eq!(up.serialize_to_json().unwrap(), text, "{name}");
        let id = up.id;
        let signable = SignableTransaction::try_from(up).expect("a transaction");
        assert_eq!(signable.tx.id(), id, "{name}: the id upstream computes");
        let signed = signable
            .tx
            .inputs
            .iter()
            .all(|i| !i.signature_script.is_empty());
        assert_eq!(signed, name.contains(".signed."), "{name}");
        assert_eq!(read_back(&text).expect("read here"), text, "{name}");
    }
}
