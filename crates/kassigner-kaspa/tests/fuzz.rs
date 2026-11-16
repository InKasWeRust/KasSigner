// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Every reader of outside bytes, under the mutation loop in
//! `testkit/mutate.rs`: addresses, paths, PSKB bundles and scripts, and what a
//! node sends. Each returns on any input, and what it accepts writes back
//! as read where a writer exists.

#[path = "../../../testkit/mutate.rs"]
mod mutate;
#[path = "../../../testkit/vectors.rs"]
mod vectors;

use kassigner_kaspa::address::{self, Prefix, Version, MAX_ADDRESS_LEN};
use kassigner_kaspa::base58::{decode_check, encode_check};
use kassigner_kaspa::bip32_public::{parse_path, parse_path_chars, ChildNumber, PUBLIC_KEY_SIZE};
use kassigner_kaspa::kcc::abi::DISPATCH_TAG_LEN;
use kassigner_kaspa::kcc::envelope;
use kassigner_kaspa::mass::{
    non_contextual_masses, plurality, storage_mass, wallet_storage_mass, Cell, MassRates,
};
use kassigner_kaspa::multisig::redeem_script;
use kassigner_kaspa::pskb::lexer::ascii;
use kassigner_kaspa::pskb::signature::{derivations, output_path, presence, signers};
use kassigner_kaspa::pskb::transaction::{build, fill, input_extras};
use kassigner_kaspa::pskb::{check, decode_envelope, decoded_len, encode_envelope};
use kassigner_kaspa::script::recognize::{parse_multisig, schnorr_keys};
use kassigner_kaspa::sighash::{schnorr_signature_hash, transaction_id, SIG_HASH_ALL};
use kassigner_kaspa::tx::{
    Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry,
};
use kassigner_kaspa::wrpc::{self, Encoding};

// ── Addresses, base58, paths ────────────────────────────────────────────────

fn addresses(data: &[u8]) {
    let mut payload = [0u8; 64];
    if let Ok((prefix, version, n)) = address::decode(data, &mut payload) {
        // What reads as an address writes back as the same text.
        let mut out = [0u8; MAX_ADDRESS_LEN];
        let w = address::encode(prefix, version, &payload[..n], &mut out).unwrap();
        assert_eq!(&out[..w], data, "an address that does not write back");
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn an_address_any_bytes() {
    let mut seeds = Vec::new();
    for prefix in [
        Prefix::Mainnet,
        Prefix::Testnet,
        Prefix::Simnet,
        Prefix::Devnet,
    ] {
        for (version, len) in [
            (Version::PubKey, 32),
            (Version::PubKeyEcdsa, 33),
            (Version::ScriptHash, 32),
        ] {
            for fill in [0x00, 0x5A, 0xFF] {
                let mut out = [0u8; MAX_ADDRESS_LEN];
                let n = address::encode(prefix, version, &vec![fill; len], &mut out).unwrap();
                seeds.push(out[..n].to_vec());
            }
        }
    }
    mutate::run("address", 6000, seeds, addresses);
}

fn base58(data: &[u8]) {
    let mut out = [0u8; 128];
    if let Ok(n) = decode_check(data, &mut out) {
        let (mut scratch, mut text) = ([0u8; 132], [0u8; 192]);
        let w = encode_check(&out[..n], &mut scratch, &mut text).unwrap();
        assert_eq!(&text[..w], data, "base58 that does not write back");
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn base58_any_bytes() {
    let seeds = [0usize, 1, 4, 32, 78, 82, 96]
        .iter()
        .map(|&len| {
            let payload: Vec<u8> = (0..len).map(|i| (i * 37 + 1) as u8).collect();
            let (mut scratch, mut text) = ([0u8; 132], [0u8; 192]);
            let n = encode_check(&payload, &mut scratch, &mut text).unwrap();
            text[..n].to_vec()
        })
        .collect();
    mutate::run("base58", 6000, seeds, base58);
}

fn paths(data: &[u8]) {
    let mut out = [ChildNumber(0); 16];
    let _ = parse_path(data, &mut out);
    let _ = parse_path_chars(ascii(data), &mut out);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_derivation_path_any_bytes() {
    let seeds = [
        &b"m"[..],
        b"m/0",
        b"m/44'/111111'/0'/0/0",
        b"m/45'/111111'/0'/1/19",
        b"m/22'/111111'/0'",
        b"m/2147483647'/2147483647",
        b"m/1h/2H/3",
        b"m/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15",
        b"m\\/44'\\u002f0",
    ]
    .iter()
    .map(|s| s.to_vec())
    .collect();
    mutate::run("path", 6000, seeds, paths);
}

// ── PSKB ────────────────────────────────────────────────────────────────────

/// The vectors' bundles, as recorded: the envelope, `PSKB` and hex.
fn bundles() -> Vec<Vec<u8>> {
    let mut out = vectors::files("v110/sdk", &[""]);
    out.extend(vectors::files("v107/site", &[".bin"]));
    out.extend(vectors::files("v107/device", &[".bin"]));
    out.retain(|b| b.starts_with(b"PSKB"));
    assert!(out.len() >= 20, "the vectors' bundles");
    out
}

fn envelopes(data: &[u8]) {
    let mut out = vec![0u8; data.len() / 2 + 1];
    let read = decode_envelope(data, &mut out);
    if let Ok(n) = read {
        assert_eq!(decoded_len(data), Ok(n), "two lengths for one envelope");
        let mut back = vec![0u8; 4 + 2 * n];
        encode_envelope(&out[..n], &mut back).unwrap();
        assert!(
            back.eq_ignore_ascii_case(data),
            "an envelope that does not write back"
        );
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_bundle_envelope_any_bytes() {
    mutate::run("pskb envelope", 2000, bundles(), envelopes);
}

const BLANK_IN: TransactionInput<'static> = TransactionInput {
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

const BLANK_OUT: TransactionOutput<'static> = TransactionOutput {
    value: 0,
    script_public_key: ScriptPublicKey {
        version: 0,
        script: &[],
    },
    covenant: None,
};

/// Room for a bundle's transaction, at least a unit's.
const ROOM: usize = 32;

/// A bundle's JSON read as a unit reads it: checked, each transaction filled,
/// hashed and its masses computed, each input's extras, keys and paths read.
fn documents(doc: &[u8]) {
    let Ok(bundle) = check(doc) else {
        return;
    };
    let key = [0x02; PUBLIC_KEY_SIZE];
    for index in 0..bundle.transactions().min(4) {
        let mut ins = [BLANK_IN; ROOM];
        let mut outs = [BLANK_OUT; ROOM];
        let mut bytes = vec![0u8; 16 * 1024];
        let Ok(filled) = fill(doc, index, &mut ins, &mut outs, &mut bytes) else {
            continue;
        };
        let tx = build(
            &filled.header,
            &ins[..filled.inputs],
            &outs[..filled.outputs],
        );
        for i in 0..tx.inputs.len() {
            let _ = schnorr_signature_hash(&tx, i, SIG_HASH_ALL);
            let mut extras = [0u8; 256];
            let _ = input_extras(bundle, index, i, &mut extras);
            let _ = presence(bundle, index, i, &key);
            let _ = signers(bundle, index, i, |_| true);
            let _ = derivations(bundle, index, i, |e| {
                if let Some((_, path)) = e.source {
                    let mut levels = [ChildNumber(0); 16];
                    let _ = parse_path_chars(ascii(path), &mut levels);
                }
                true
            });
        }
        for o in 0..tx.outputs.len() + 1 {
            let _ = output_path(bundle, index, o);
        }
        let _ = transaction_id(&tx);
        let _ = non_contextual_masses(&tx, &MassRates::MAINNET);
        let cells = |amounts: &mut dyn Iterator<Item = (u64, usize, bool)>| -> Vec<Cell> {
            amounts
                .map(|(amount, len, covenant)| Cell {
                    plurality: plurality(len, covenant),
                    amount,
                })
                .collect()
        };
        let inputs = cells(&mut tx.inputs.iter().map(|i| {
            (
                i.utxo_entry.amount,
                i.utxo_entry.script_public_key.script.len(),
                false,
            )
        }));
        let outputs = cells(&mut tx.outputs.iter().map(|o| {
            (
                o.value,
                o.script_public_key.script.len(),
                o.covenant.is_some(),
            )
        }));
        let parameter = MassRates::MAINNET.storage_mass_parameter;
        let _ = storage_mass(&inputs, &outputs, parameter);
        let total = tx
            .inputs
            .iter()
            .try_fold(0u64, |t, i| t.checked_add(i.utxo_entry.amount));
        if let Some(total) = total {
            let _ = wallet_storage_mass(
                tx.outputs.iter().map(|o| o.value),
                total,
                tx.inputs.len() as u64,
                parameter,
            );
        }
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_bundle_document_any_bytes() {
    // The JSON itself, mutated as text: a mutated envelope's hex reaches it
    // only a nibble at a time.
    let seeds = bundles()
        .iter()
        .map(|b| {
            let mut out = vec![0u8; b.len() / 2];
            let n = decode_envelope(b, &mut out).unwrap();
            out.truncate(n);
            out
        })
        .collect();
    mutate::run("pskb document", 3000, seeds, documents);
}

// ── Scripts ─────────────────────────────────────────────────────────────────

fn scripts(data: &[u8]) {
    let _ = parse_multisig(data);
    let _ = schnorr_keys(data).count();
    if let Ok(invocation) = envelope::read(data) {
        // What reads as an invocation writes back as the same script.
        let mut out = vec![0u8; data.len() + 64];
        let n = envelope::write(&invocation, &mut out).unwrap();
        assert_eq!(&out[..n], data, "an invocation that does not write back");
        let coin = ScriptPublicKey {
            version: 0,
            script: &envelope::locking_script(invocation.program),
        };
        assert!(envelope::read_spend(&coin, data).is_ok());
    }
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_script_any_bytes() {
    let keys: Vec<[u8; 32]> = (1..=20u8).map(|i| [i; 32]).collect();
    let mut seeds = Vec::new();
    for (m, n) in [(1, 1), (2, 3), (3, 5), (15, 20), (20, 20)] {
        let mut out = [0u8; 1024];
        let len = redeem_script(m, &keys[..n], &mut out).unwrap();
        seeds.push(out[..len].to_vec());
    }
    let mut p2pk = vec![0x20];
    p2pk.extend_from_slice(&[7; 32]);
    p2pk.push(0xAC);
    seeds.push(p2pk);
    let redeem = seeds[1].clone();
    for program in [&redeem[..], &[0x51][..], &[0u8; 300][..]] {
        let invocation = envelope::Invocation {
            arguments: &[0x01, 0x05, 0x02, 0x00, 0x01],
            dispatch_tag: [0x11; DISPATCH_TAG_LEN],
            program,
        };
        let mut out = vec![0u8; 1024];
        let n = envelope::write(&invocation, &mut out).unwrap();
        seeds.push(out[..n].to_vec());
    }
    mutate::run("script", 6000, seeds, scripts);
}

// ── What a node sends ───────────────────────────────────────────────────────

/// A node's message read and walked as the SDK walks it.
fn node(data: &[u8], encoding: Encoding) {
    let Ok(m) = wrpc::read(data, encoding) else {
        return;
    };
    if let Some(e) = m.error() {
        let _ = e.chars().count();
    }
    if let Ok(info) = m.server_info() {
        let _ = info.server_version.chars().count();
    }
    if let Ok(estimate) = m.fee_estimate() {
        let _ = estimate.priority.sompi_per_gram();
        for bucket in estimate.normal.chain(estimate.low) {
            let _ = bucket.sompi_per_gram();
        }
    }
    if let Ok(utxos) = m.utxos() {
        for u in utxos {
            let mut script = [0u8; 128];
            let _ = u.script.copy_to(&mut script);
            let _ = u.script.iter().count();
            if let Some(a) = u.address {
                let mut text = [0u8; MAX_ADDRESS_LEN];
                let _ = a.encode(&mut text);
            }
        }
    }
    let _ = m.transaction_id();
}

fn node_json(data: &[u8]) {
    node(data, Encoding::Json);
}

fn node_borsh(data: &[u8]) {
    node(data, Encoding::Borsh);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_node_message_in_json_any_bytes() {
    let mut seeds = vectors::files("v110/node", &[".reply.json", ".error.json"]);
    seeds.extend(vectors::files("v110/node/kaspad", &[".json"]));
    mutate::run("node json", 3000, seeds, node_json);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn a_node_message_in_borsh_any_bytes() {
    let mut seeds = vectors::files("v110/node", &[".reply.borsh", ".error.borsh"]);
    seeds.extend(vectors::files("v110/node/kaspad", &[".borsh"]));
    mutate::run("node borsh", 3000, seeds, node_borsh);
}
