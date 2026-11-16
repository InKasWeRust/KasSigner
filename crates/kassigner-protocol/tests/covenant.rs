// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The SDK's finished covenant transactions, version 1, as rusty-kaspa
//! takes them: the id, the covenant rule, the masses, and every input
//! through the script engine under the compute budget it commits.
//!
//! The transactions are the SDK's vectors (`spec/vectors/v110/sdk/`, from
//! `kassigner-fw`'s `the_sdk_vectors_are_current`), checked here because
//! this crate runs the engine and the SDK's tests cannot.

use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::{Gram, MassCalculator};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use kassigner_kaspa::mass::{minimum_relay_fee, relay_fee_mass};
use kassigner_kaspa::safe_json::{build, fill};
use kassigner_kaspa::tx::{
    EntryDetails, Outpoint, ScriptPublicKey as OurScript, TransactionInput as OurInput,
    TransactionOutput as OurOutput, UtxoEntry as OurEntry,
};
use kassigner_protocol::card::savings::SIG_OP_COUNT;

/// A finished transaction of the vectors, as upstream holds one: the
/// transaction, the entries its inputs spend, and what the file says of it.
struct Finished {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    id: [u8; 32],
    storage_mass: u64,
}

/// `name` of the SDK's vectors, read as the SDK reads the safe JSON and
/// rebuilt as upstream's types. `budget` gives input `i`'s compute budget
/// from the one the file commits.
fn finished(name: &str, budget: impl Fn(usize, u16) -> u16) -> Finished {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/v110/sdk/");
    let text = std::fs::read(format!("{dir}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"));
    let blank = OurScript {
        version: 0,
        script: &[],
    };
    let mut inputs = vec![
        OurInput {
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
                script_public_key: blank,
            },
        };
        8
    ];
    let mut outputs = vec![
        OurOutput {
            value: 0,
            script_public_key: blank,
            covenant: None,
        };
        8
    ];
    let mut details = vec![
        EntryDetails {
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        };
        8
    ];
    let mut bytes = vec![0u8; text.len() / 2];
    let f = fill(&text, &mut inputs, &mut details, &mut outputs, &mut bytes).expect(name);
    let ours = build(&f.header, &inputs[..f.inputs], &outputs[..f.outputs]);
    assert_eq!(ours.version, 1, "{name}: a binding needs version 1");
    let script = |s: &OurScript<'_>| ScriptPublicKey::from_vec(s.version, s.script.to_vec());
    let entries = ours
        .inputs
        .iter()
        .zip(&details)
        .map(|(i, d)| UtxoEntry {
            amount: i.utxo_entry.amount,
            script_public_key: script(&i.utxo_entry.script_public_key),
            block_daa_score: d.block_daa_score,
            is_coinbase: d.is_coinbase,
            covenant_id: d.covenant_id.map(TransactionId::from_bytes),
        })
        .collect();
    let tx = Transaction::new(
        ours.version,
        ours.inputs
            .iter()
            .enumerate()
            .map(|(n, i)| {
                // Consensus takes no signature operations in version 1.
                assert_eq!(i.sig_op_count, 0, "{name}: input {n}");
                TransactionInput::new_with_compute_budget(
                    TransactionOutpoint::new(
                        TransactionId::from_bytes(i.previous_outpoint.transaction_id),
                        i.previous_outpoint.index,
                    ),
                    i.signature_script.to_vec(),
                    i.sequence,
                    budget(n, i.compute_budget),
                )
            })
            .collect(),
        ours.outputs
            .iter()
            .map(|o| {
                TransactionOutput::with_covenant(
                    o.value,
                    script(&o.script_public_key),
                    o.covenant.map(|c| {
                        CovenantBinding::new(
                            c.authorizing_input,
                            TransactionId::from_bytes(c.covenant_id),
                        )
                    }),
                )
            })
            .collect(),
        ours.lock_time,
        SUBNETWORK_ID_NATIVE,
        ours.gas,
        ours.payload.to_vec(),
    );
    Finished {
        tx,
        entries,
        id: f.id,
        storage_mass: f.storage_mass,
    }
}

/// Every covenant binding against the spent entries, then every input run
/// as consensus's `check_scripts_sequential` runs it, under the script
/// units its compute budget allows: the first failure as rusty-kaspa names
/// it.
fn verify(tx: &Transaction, entries: &[UtxoEntry]) -> Result<(), String> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let covenants = CovenantsContext::from_tx(&populated).map_err(|e| format!("{e:?}"))?;
    let cache = Cache::new(10_000);
    let reused = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&cache)
        .with_reused(&reused)
        .with_covenants_ctx(&covenants);
    let flags = EngineFlags {
        sigop_script_units: Gram(MAINNET_PARAMS.mass_per_sig_op).into(),
    };
    for (i, (input, entry)) in populated.populated_inputs().enumerate() {
        let limit = input.compute_commit.allowed_script_units();
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated, input, i, entry, ctx, flags, limit,
        );
        vm.execute().map_err(|e| format!("input {i}: {e:?}"))?;
    }
    Ok(())
}

/// The file's own budgets.
fn as_committed(_: usize, budget: u16) -> u16 {
    budget
}

/// The SDK's finished covenant transactions are rusty-kaspa's: the id it
/// computes, the covenant rule passed, every input through the engine
/// under its committed budget, the storage mass it finds, and a fee over
/// the minimum a node relays for the compute mass it finds. One for each
/// script a unit signs: a single key, a multisig, KCC-3's redeem, a card.
#[test]
fn the_sdks_finished_covenant_transactions_pass_upstream() {
    let calc = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
    // The file, the budget each input commits, and the outputs bound.
    let card = 10 * u16::from(SIG_OP_COUNT);
    let cases: [(&str, &[u16], &[bool]); 5] = [
        (
            "covenant.start.signed.json",
            &[10, 10],
            &[true, true, false],
        ),
        ("covenant.continue.signed.json", &[10, 10], &[true, false]),
        // A 2-of-3: a signature operation a key.
        ("covenant.group.signed.json", &[30], &[true, false]),
        // KCC-3's redeem, one signature operation; a Time-Locked Savings
        // card's program, its own count.
        ("covenant.kcc3.signed.json", &[10], &[true, false]),
        ("covenant.card.signed.json", &[card], &[true, false]),
    ];
    for (name, budgets, bound) in cases {
        let f = finished(name, as_committed);
        assert_eq!(
            f.tx.id().as_bytes(),
            f.id,
            "{name}: the id upstream computes"
        );
        let committed: Vec<u16> =
            f.tx.inputs
                .iter()
                .map(|i| i.compute_commit.compute_budget().expect("a budget"))
                .collect();
        assert_eq!(committed, budgets, "{name}");
        let is_bound: Vec<bool> = f.tx.outputs.iter().map(|o| o.covenant.is_some()).collect();
        assert_eq!(is_bound, bound, "{name}: the change is not bound");
        assert_eq!(verify(&f.tx, &f.entries), Ok(()), "{name}");

        let populated = PopulatedTransaction::new(&f.tx, f.entries.clone());
        let storage = calc
            .calc_contextual_masses(&populated)
            .expect("storage mass")
            .storage_mass;
        assert_eq!(f.storage_mass, storage, "{name}: the storage mass");
        let masses = calc.calc_non_contextual_masses(&f.tx);
        let paid: u64 = f.entries.iter().map(|e| e.amount).sum::<u64>()
            - f.tx.outputs.iter().map(|o| o.value).sum::<u64>();
        let minimum = minimum_relay_fee(relay_fee_mass(masses.compute_mass, masses.transient_mass));
        assert!(paid >= minimum, "{name}: {paid} under {minimum}");
    }
}

/// The budget is what a signature check costs, no more: one unit less on a
/// single key's input and the engine stops it, as it stops a version 1
/// input that commits none. So the budgets the SDK writes are needed, and
/// a finished transaction without them is one no node takes.
#[test]
fn a_budget_short_of_a_signature_check_fails_the_engine() {
    for name in [
        "covenant.start.signed.json",
        "covenant.continue.signed.json",
    ] {
        for short in [9, 0] {
            let f = finished(name, |i, budget| if i == 0 { short } else { budget });
            let e = verify(&f.tx, &f.entries).expect_err("the engine stops it");
            assert!(
                e.starts_with("input 0: ExceededCommittedScriptUnits"),
                "{name}, budget {short}: {e}"
            );
        }
    }
    // The group's: its two signatures cost two checks at least, which the
    // budget of one does not cover.
    let f = finished("covenant.group.signed.json", |_, _| 10);
    let e = verify(&f.tx, &f.entries).expect_err("the engine stops it");
    assert!(
        e.starts_with("input 0: ExceededCommittedScriptUnits"),
        "{e}"
    );
}

/// The covenant rule is upstream's: the started covenant's id is the one
/// its authorizing input makes, so an id one bit off is no genesis; and the
/// continued covenant's is its coin's, so the same output with the coin
/// unbound is refused.
#[test]
fn the_bindings_are_held_to_upstreams_covenant_rule() {
    let mut f = finished("covenant.start.signed.json", as_committed);
    let mut off = f.tx.outputs[0].covenant.expect("bound");
    let mut id = off.covenant_id.as_bytes();
    id[0] ^= 1;
    off.covenant_id = TransactionId::from_bytes(id);
    f.tx.outputs[0].covenant = Some(off);
    f.tx.outputs[1].covenant = Some(off);
    let e = verify(&f.tx, &f.entries).expect_err("refused");
    assert!(e.contains("WrongGenesisCovenantId"), "{e}");

    let mut f = finished("covenant.continue.signed.json", as_committed);
    assert!(f.entries[0].covenant_id.is_some(), "the coin is bound");
    f.entries[0].covenant_id = None;
    let e = verify(&f.tx, &f.entries).expect_err("refused");
    assert!(e.contains("WrongGenesisCovenantId"), "{e}");
}
