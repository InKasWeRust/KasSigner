// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Our covenant cards: each source compiles (SilverScript 1.0.1) to the
//! crate's bytes; programs, state, addresses and spends are KCC-1's and
//! rusty-kaspa's layouts; spends, honest and hostile, pass or fail
//! rusty-kaspa's script engine as consensus runs it.

use std::collections::BTreeMap;

use kaspa_consensus_core::config::params::MAINNET_PARAMS;
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::{SigHashType, SIG_HASH_ALL};
use kaspa_consensus_core::mass::Gram;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use kassigner_kaspa::address::MAX_ADDRESS_LEN;
use kassigner_kaspa::constants::{LOCK_TIME_THRESHOLD, MAX_TX_IN_SEQUENCE_NUM};
use kassigner_kaspa::kcc::abi::{Entrypoint, Type};
use kassigner_kaspa::kcc::envelope::{self, Invocation};
use kassigner_kaspa::kcc::hash::template_hash;
use kassigner_kaspa::kcc::push::{push_explicit, push_minimal};
use kassigner_kaspa::kcc::value::int_payload;
use kassigner_protocol::card::savings::{
    CardError, Entry, Savings, UnlockAt, FIRST_MINUTE, MINUTES_PER_DAY, MS_PER_MINUTE, PREFIX,
    PROGRAM_LEN, SIGNATURE_SCRIPT_LEN, SIG_LEN, SIG_OP_COUNT, STATE, STATE_LEN, SUFFIX,
    TEMPLATE_HASH,
};
use kassigner_protocol::check::{self, Error as CheckError};
use secp256k1::{Keypair, Message, SECP256K1};
use silverscript_abi::{ArtifactValue as V, SilAbiArtifact, TypeArtifact};

const SOURCE: &str = include_str!("../sil/time_locked_savings.sil");
const CONTRACT: &str = "TimeLockedSavings";

/// 1 January 2027, 00:00 UTC, in minutes since the Unix epoch.
const NEW_YEAR_2027: u32 = 20_819 * MINUTES_PER_DAY;

/// 14:30 UTC, in minutes after midnight.
const HALF_PAST_TWO: u32 = 14 * 60 + 30;

/// 6 November 1985, the first whole day a card can open on, in days since
/// the Unix epoch.
const FIRST_WHOLE_DAY: u32 = 5_788;

/// Milliseconds in a day.
const DAY_MS: u64 = 86_400_000;

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).expect("a secret key")
}

fn x(kp: &Keypair) -> [u8; 32] {
    kp.x_only_public_key().0.serialize()
}

fn at(minutes: u32) -> UnlockAt {
    UnlockAt::new(minutes).expect("a minute")
}

/// Cards covering a recovery wallet or none, midnight and a time of day,
/// the first minute and the last.
fn cards() -> Vec<Savings> {
    let (a, b, c) = (x(&keypair(1)), x(&keypair(2)), x(&keypair(3)));
    vec![
        Savings::new(a, Some(b), at(NEW_YEAR_2027)).unwrap(),
        Savings::new(a, None, at(NEW_YEAR_2027)).unwrap(),
        Savings::new(c, Some(a), at(FIRST_MINUTE)).unwrap(),
        Savings::new(b, Some(c), at(u32::MAX)).unwrap(),
        Savings::new(b, Some(a), at(NEW_YEAR_2027 + HALF_PAST_TWO)).unwrap(),
    ]
}

fn compile(card: &Savings) -> SilAbiArtifact {
    let recovery = *card.recovery().unwrap_or(card.owner());
    let args = [
        V::Bytes(card.owner().to_vec()),
        V::Bytes(recovery.to_vec()),
        V::Int(i64::try_from(card.unlock().ms()).unwrap()),
    ];
    silverscript_lang::compiler::compile_to_sil_abi_artifact(SOURCE, &args)
        .expect("SilverScript compiles the card")
}

fn address_of(card: &Savings) -> String {
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = card.address(&mut out).expect("an address");
    String::from_utf8(out[..n].to_vec()).unwrap()
}

// ── The program ──────────────────────────────────────────────────────────────

/// The source compiles to this crate's template around this crate's state,
/// with the same tags, layout and template hash, whatever the values.
#[test]
fn the_source_compiles_to_the_cards_program() {
    for card in cards() {
        let artifact = compile(&card);
        assert_eq!(artifact.contracts.len(), 1);
        let contract = &artifact.contracts[CONTRACT];
        let compiled = &contract.compiled;
        assert_eq!(compiled.bytecode, card.program(), "{card:?}");
        assert_eq!(compiled.bytecode.len(), PROGRAM_LEN);
        assert_eq!(compiled.state_span.offset, PREFIX.len());
        assert_eq!(compiled.state_span.len, STATE_LEN);
        let (prefix, _, suffix) = compiled.script_parts(&compiled.bytecode).unwrap();
        assert_eq!((prefix, suffix), (&PREFIX[..], &SUFFIX[..]));
        assert_eq!(compiled.template_hash, TEMPLATE_HASH);
        assert_eq!(template_hash(&PREFIX, &SUFFIX), TEMPLATE_HASH);

        let fields: Vec<(&str, &TypeArtifact)> = contract
            .runtime_state
            .fields
            .iter()
            .map(|f| (f.name.as_str(), &f.ty))
            .collect();
        assert_eq!(
            fields,
            [
                ("owner", &TypeArtifact::Pubkey),
                ("recovery", &TypeArtifact::Pubkey),
                ("unlockAt", &TypeArtifact::Temporal),
            ]
        );
        let ours: Vec<(&str, Type<'_>)> = STATE.iter().map(|f| (f.name, f.ty)).collect();
        assert_eq!(
            ours,
            [
                ("owner", Type::Pubkey),
                ("recovery", Type::Pubkey),
                ("unlockAt", Type::Temporal),
            ]
        );

        let names: Vec<&str> = contract.entries.keys().map(String::as_str).collect();
        assert_eq!(names, ["claim", "recover"]);
        for (name, entry) in [("claim", Entry::Claim), ("recover", Entry::Recover)] {
            let theirs = &contract.entries[name];
            assert_eq!(theirs.params.len(), 1);
            assert_eq!(theirs.params[0].ty, TypeArtifact::Sig);
            assert_eq!(*theirs.dispatch_tag.as_bytes(), entry.tag(), "{name}");
            let kcc1 = Entrypoint {
                name,
                params: &[Type::Sig],
            };
            assert_eq!(kcc1.dispatch_tag(), Ok(entry.tag()), "{name}");
            assert_eq!(Entry::from_tag(entry.tag()), Some(entry));
        }
    }
    assert_eq!(Entry::from_tag([0; 4]), None);
}

/// The state is KCC-1's `PushExplicit` of each field, as SilverScript's
/// encoder writes it.
#[test]
fn the_state_is_written_as_kcc1_and_silverscript_write_it() {
    for card in cards() {
        let program = card.program();
        let state = &program[PREFIX.len()..PREFIX.len() + STATE_LEN];
        let recovery = *card.recovery().unwrap_or(card.owner());
        let ms = i64::try_from(card.unlock().ms()).unwrap();

        let mut kcc1 = vec![0u8; STATE_LEN];
        let mut at = push_explicit(card.owner(), &mut kcc1).unwrap();
        at += push_explicit(&recovery, &mut kcc1[at..]).unwrap();
        at += push_explicit(&int_payload(ms).unwrap(), &mut kcc1[at..]).unwrap();
        assert_eq!(at, STATE_LEN);
        assert_eq!(state, &kcc1[..], "{card:?}");

        let artifact = compile(&card);
        let runtime = artifact.contracts[CONTRACT].runtime_state.clone();
        let values: BTreeMap<String, V> = [
            ("owner".to_string(), V::Bytes(card.owner().to_vec())),
            ("recovery".to_string(), V::Bytes(recovery.to_vec())),
            ("unlockAt".to_string(), V::Int(ms)),
        ]
        .into();
        let theirs =
            silverscript_abi::encode_runtime_state_script(&artifact, &runtime, &values).unwrap();
        assert_eq!(state, &theirs[..], "{card:?}");
    }
}

/// With no recovery wallet the owner's key fills its slot, and the owner's
/// key as recovery is no recovery wallet.
#[test]
fn no_recovery_wallet_is_the_owners_key_twice() {
    let a = x(&keypair(1));
    let none = Savings::new(a, None, at(NEW_YEAR_2027)).unwrap();
    let same = Savings::new(a, Some(a), at(NEW_YEAR_2027)).unwrap();
    assert_eq!(none, same);
    assert_eq!(same.recovery(), None);
    let program = none.program();
    assert_eq!(program[2..34], a);
    assert_eq!(program[35..67], a);
}

/// Thirty-two bytes that are not a public key make no card.
#[test]
fn a_key_that_is_none_makes_no_card() {
    let a = x(&keypair(1));
    let off = [0u8; 32];
    let past_prime = [0xff; 32];
    for bad in [off, past_prime] {
        let d = at(NEW_YEAR_2027);
        assert_eq!(Savings::new(bad, None, d), Err(CardError::NotAKey));
        assert_eq!(Savings::new(bad, Some(a), d), Err(CardError::NotAKey));
        assert_eq!(Savings::new(a, Some(bad), d), Err(CardError::NotAKey));
    }
}

/// Whole minutes only, from the first that a lock time reads as a
/// timestamp: 5 November 1985, 00:54 UTC.
#[test]
fn an_unlock_time_is_a_whole_minute_read_as_a_time() {
    assert_eq!(UnlockAt::new(FIRST_MINUTE - 1), None);
    let first = at(FIRST_MINUTE);
    assert!(first.ms() >= LOCK_TIME_THRESHOLD);
    assert!(first.ms() - MS_PER_MINUTE < LOCK_TIME_THRESHOLD);
    assert_eq!(first.minutes(), 8_333_334);
    assert_eq!((first.date(), first.time()), ((1985, 11, 5), (0, 54)));

    let d = at(NEW_YEAR_2027);
    assert_eq!(d.ms(), 1_798_761_600_000, "2027-01-01T00:00:00Z");
    assert_eq!(UnlockAt::from_ms(d.ms()), Some(d));
    assert_eq!(UnlockAt::from_ms(d.ms() + 1), None);
    assert_eq!(UnlockAt::from_ms(d.ms() - 1), None);
    assert_eq!(UnlockAt::from_ms(d.ms() + 30_000), None);
    assert_eq!(
        UnlockAt::from_ms(d.ms() + MS_PER_MINUTE),
        Some(at(NEW_YEAR_2027 + 1))
    );
    assert_eq!(UnlockAt::from_ms(first.ms() - MS_PER_MINUTE), None);
    assert_eq!(UnlockAt::from_ms(0), None);
    assert_eq!(UnlockAt::from_ms(at(u32::MAX).ms()), Some(at(u32::MAX)));
    assert_eq!(UnlockAt::from_ms(at(u32::MAX).ms() + MS_PER_MINUTE), None);
    assert_eq!(UnlockAt::from_ms(u64::MAX), None);
}

/// Minutes to dates and times and back: fixed points from Python's calendar,
/// every leap year rule, invalid dates and times, every day of four centuries
/// and every minute of a day.
#[test]
fn an_unlock_time_is_a_date_and_time_and_back() {
    let day = |days: u32| at(days * MINUTES_PER_DAY);
    for (date, days) in [
        ((1985, 11, 6), FIRST_WHOLE_DAY),
        ((2000, 2, 29), 11_016),
        ((2000, 3, 1), 11_017),
        ((2027, 1, 1), NEW_YEAR_2027 / MINUTES_PER_DAY),
        ((2028, 2, 29), 21_243),
        ((2100, 2, 28), 47_540),
        ((2100, 3, 1), 47_541),
        ((2400, 2, 29), 157_113),
        ((9999, 12, 31), 2_932_896),
        ((10_136, 2, 16), 2_982_616),
    ] {
        let (y, m, d) = date;
        assert_eq!(
            UnlockAt::from_date_time(y, m, d, 0, 0),
            Some(day(days)),
            "{date:?}"
        );
        assert_eq!(
            (day(days).date(), day(days).time()),
            (date, (0, 0)),
            "{days}"
        );
    }
    // The first minute, and the last a `u32` of minutes holds.
    assert_eq!(
        UnlockAt::from_date_time(1985, 11, 5, 0, 54),
        Some(at(FIRST_MINUTE))
    );
    assert_eq!(
        UnlockAt::from_date_time(10_136, 2, 16, 4, 15),
        Some(at(u32::MAX))
    );
    assert_eq!(
        (at(u32::MAX).date(), at(u32::MAX).time()),
        ((10_136, 2, 16), (4, 15))
    );
    for (y, m, d, h, min) in [
        (1985, 11, 5, 0, 53),
        (1985, 11, 4, 23, 59),
        (1970, 1, 1, 0, 0),
        (1969, 12, 31, 0, 0),
        (0, 1, 1, 0, 0),
        (0, 2, 1, 0, 0),
        (2027, 2, 29, 0, 0),
        (2100, 2, 29, 0, 0),
        (2027, 4, 31, 0, 0),
        (2027, 13, 1, 0, 0),
        (2027, 0, 1, 0, 0),
        (2027, 1, 0, 0, 0),
        (2027, 1, 32, 0, 0),
        (2027, 1, 1, 24, 0),
        (2027, 1, 1, 0, 60),
        (2027, 1, 1, 255, 255),
        (10_136, 2, 16, 4, 16),
        (10_136, 2, 17, 0, 0),
        (u32::MAX, 12, 31, 0, 0),
    ] {
        assert_eq!(
            UnlockAt::from_date_time(y, m, d, h, min),
            None,
            "{y} {m} {d} {h}:{min}"
        );
    }

    let leap = |y: u32| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let (mut y, mut m, mut d) = (1985u32, 11u8, 6u8);
    for days in FIRST_WHOLE_DAY..FIRST_WHOLE_DAY + 146_097 {
        assert_eq!(day(days).date(), (y, m, d));
        assert_eq!(UnlockAt::from_date_time(y, m, d, 0, 0), Some(day(days)));
        let last = match m {
            2 if leap(y) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        (y, m, d) = match (d == last, m == 12) {
            (false, _) => (y, m, d + 1),
            (true, false) => (y, m + 1, 1),
            (true, true) => (y + 1, 1, 1),
        };
    }
    for minute in 0..MINUTES_PER_DAY {
        let t = at(NEW_YEAR_2027 + minute);
        let (h, min) = ((minute / 60) as u8, (minute % 60) as u8);
        assert_eq!((t.date(), t.time()), ((2027, 1, 1), (h, min)));
        assert_eq!(UnlockAt::from_date_time(2027, 1, 1, h, min), Some(t));
    }
    assert_eq!(at(NEW_YEAR_2027 + MINUTES_PER_DAY).date(), (2027, 1, 2));
}

/// A program reads back as the card that wrote it, and nothing else does.
#[test]
fn a_program_reads_back_as_its_card_and_nothing_else_does() {
    for card in cards() {
        let program = card.program();
        assert_eq!(Savings::from_program(&program), Ok(card));

        let not_this = Err(CardError::NotThisCard);
        assert_eq!(Savings::from_program(&program[..PROGRAM_LEN - 1]), not_this);
        assert_eq!(
            Savings::from_program(&[&program[..], &[0x51]].concat()),
            not_this
        );
        assert_eq!(Savings::from_program(&[]), not_this);
        for i in (0..PREFIX.len()).chain(PREFIX.len() + STATE_LEN..PROGRAM_LEN) {
            let mut p = program;
            p[i] ^= 0x01;
            assert_eq!(Savings::from_program(&p), not_this, "template byte {i}");
        }

        // A push that is not the field's.
        for i in [PREFIX.len(), PREFIX.len() + 33, PREFIX.len() + 66] {
            let mut p = program;
            p[i] ^= 0x01;
            assert_eq!(
                Savings::from_program(&p),
                Err(CardError::BadState),
                "op {i}"
            );
        }
    }

    // Times that are not a whole minute on or after the first.
    let card = &cards()[0];
    let time_at = PREFIX.len() + 67;
    for ms in [
        card.unlock().ms() + 1,
        card.unlock().ms() - 1,
        card.unlock().ms() + 30_000,
        u64::from(FIRST_MINUTE - 1) * MS_PER_MINUTE,
        0,
        1 << 63,
    ] {
        let mut p = card.program();
        p[time_at..time_at + 8].copy_from_slice(&ms.to_le_bytes());
        assert_eq!(Savings::from_program(&p), Err(CardError::BadState), "{ms}");
    }

    // A key that is none.
    let mut p = card.program();
    p[35..67].copy_from_slice(&[0xff; 32]);
    assert_eq!(Savings::from_program(&p), Err(CardError::NotAKey));

    // The owner's key in the recovery slot reads as no recovery wallet.
    let a = *card.owner();
    let mut p = card.program();
    p[35..67].copy_from_slice(&a);
    let read = Savings::from_program(&p).unwrap();
    assert_eq!(read.recovery(), None);
    assert_eq!(read.program(), p);
}

/// The card's locking script and `kaspa:p…` address are rusty-kaspa's.
#[test]
fn the_cards_address_is_upstreams() {
    for card in cards() {
        let program = card.program();
        let theirs = kaspa_txscript::pay_to_script_hash_script(&program);
        assert_eq!(card.locking_script()[..], theirs.script()[..]);
        assert_eq!(card.locking_script(), envelope::locking_script(&program));
        let address = kaspa_txscript::extract_script_pub_key_address(
            &theirs,
            kaspa_addresses::Prefix::Mainnet,
        )
        .unwrap();
        let ours = address_of(&card);
        assert_eq!(ours, address.to_string());
        assert!(ours.starts_with("kaspa:p"), "{ours}");
    }
    let mut short = [0u8; 10];
    assert!(cards()[0].address(&mut short).is_err());
}

/// A spend's signature script is KCC-1's envelope, as SilverScript encodes
/// it and `kassigner-kaspa` writes and reads it.
#[test]
fn a_spends_signature_script_is_the_envelope() {
    let sig = [0x5c; SIG_LEN];
    for card in cards() {
        let program = card.program();
        let artifact = compile(&card);
        let coin = kassigner_kaspa::tx::ScriptPublicKey {
            version: 0,
            script: &card.locking_script(),
        };
        for (name, entry) in [("claim", Entry::Claim), ("recover", Entry::Recover)] {
            let ours = card.signature_script(entry, &sig);
            assert_eq!(ours.len(), SIGNATURE_SCRIPT_LEN);

            let head = silverscript_abi::encode_contract_entry_sig_script(
                &artifact,
                CONTRACT,
                name,
                &[V::Bytes(sig.to_vec())],
            )
            .unwrap();
            let tail = ScriptBuilder::new().add_data(&program).unwrap().drain();
            assert_eq!(ours[..], [head, tail].concat()[..], "{name}");

            let mut argument = [0u8; 1 + SIG_LEN];
            push_minimal(&sig, &mut argument).unwrap();
            let invocation = Invocation {
                arguments: &argument,
                dispatch_tag: entry.tag(),
                program: &program,
            };
            let mut written = [0u8; SIGNATURE_SCRIPT_LEN];
            assert_eq!(
                envelope::write(&invocation, &mut written),
                Ok(SIGNATURE_SCRIPT_LEN)
            );
            assert_eq!(ours, written, "{name}");
            let read = envelope::read_spend(&coin, &ours).unwrap();
            assert_eq!(read, invocation, "{name}");
            assert_eq!(Entry::from_tag(read.dispatch_tag), Some(entry));
        }
    }
}

// ── Spends, through rusty-kaspa ──────────────────────────────────────────────

/// One coin of a card, spent through `entry`, signed by `signer`.
struct Coin<'a> {
    card: Savings,
    entry: Entry,
    signer: &'a Keypair,
}

/// A coin's value, in sompi.
const COIN: u64 = 100_000_000;

/// A version 0 transaction spending `coins` to a plain key, each input at
/// `sequence`, committing `sig_ops`, signed with `SIG_HASH_ALL`.
fn spend(
    coins: &[Coin<'_>],
    lock_time: u64,
    sequence: u64,
    sig_ops: u8,
) -> (Transaction, Vec<UtxoEntry>) {
    let entries: Vec<UtxoEntry> = coins
        .iter()
        .map(|c| UtxoEntry {
            amount: COIN,
            script_public_key: ScriptPublicKey::from_vec(0, c.card.locking_script().to_vec()),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        })
        .collect();
    let inputs: Vec<TransactionInput> = (0..coins.len())
        .map(|i| {
            let id = TransactionId::from_bytes([u8::try_from(i).unwrap() + 1; 32]);
            TransactionInput::new(TransactionOutpoint::new(id, 0), vec![], sequence, sig_ops)
        })
        .collect();
    let to = [&[0x20][..], &x(&keypair(9)), &[0xac]].concat();
    let paid = COIN * coins.len() as u64 - 10_000;
    let outputs = vec![TransactionOutput::new(
        paid,
        ScriptPublicKey::from_vec(0, to),
    )];
    let mut tx = Transaction::new(
        0,
        inputs,
        outputs,
        lock_time,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let sigs: Vec<[u8; SIG_LEN]> = {
        let populated = PopulatedTransaction::new(&tx, entries.clone());
        let reused = SigHashReusedValuesUnsync::new();
        coins
            .iter()
            .enumerate()
            .map(|(i, c)| sign(&populated, i, c.signer, SIG_HASH_ALL, &reused))
            .collect()
    };
    for ((input, c), sig) in tx.inputs.iter_mut().zip(coins).zip(&sigs) {
        input.signature_script = c.card.signature_script(c.entry, sig).to_vec();
    }
    tx.finalize();
    (tx, entries)
}

/// Input `i`'s signature by `signer`, as the program takes it: 64 bytes and
/// the sighash type.
fn sign(
    tx: &PopulatedTransaction<'_>,
    i: usize,
    signer: &Keypair,
    hash_type: SigHashType,
    reused: &SigHashReusedValuesUnsync,
) -> [u8; SIG_LEN] {
    let digest = calc_schnorr_signature_hash(tx, i, hash_type, reused);
    let msg = Message::from_digest(digest.as_bytes());
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&msg, signer);
    let mut out = [0u8; SIG_LEN];
    out[..64].copy_from_slice(sig.as_ref());
    out[64] = hash_type.to_u8();
    out
}

/// Runs every input as consensus's `check_scripts_sequential` does, and
/// returns the first failure as rusty-kaspa names it.
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

fn fails_with(result: Result<(), String>, what: &str) {
    match result {
        Ok(()) => panic!("spent; wanted {what}"),
        Err(e) => assert!(e.contains(what), "wanted {what}, got {e}"),
    }
}

/// The owner's and the recovery wallet's keys, and a card with both that
/// opens at 14:30 UTC.
fn both() -> (Keypair, Keypair, Savings) {
    let (owner, recovery) = (keypair(1), keypair(2));
    let opens = at(NEW_YEAR_2027 + HALF_PAST_TWO);
    let card = Savings::new(x(&owner), Some(x(&recovery)), opens).unwrap();
    (owner, recovery, card)
}

/// From its time on, the owner claims and the recovery wallet recovers, each
/// alone, with any sequence but final.
#[test]
fn from_its_time_on_either_key_spends_alone() {
    let (owner, recovery, card) = both();
    let opens = card.unlock().ms();
    for (entry, signer) in [(Entry::Claim, &owner), (Entry::Recover, &recovery)] {
        for lock_time in [opens, opens + 1, opens + 400 * DAY_MS] {
            for sequence in [0, 1, MAX_TX_IN_SEQUENCE_NUM - 1] {
                let coin = Coin {
                    card,
                    entry,
                    signer,
                };
                let (tx, entries) = spend(&[coin], lock_time, sequence, SIG_OP_COUNT);
                assert_eq!(
                    verify(&tx, &entries),
                    Ok(()),
                    "{entry:?} {lock_time} {sequence}"
                );
            }
        }
    }
}

/// Before its time nothing spends: a millisecond or a minute before, no lock
/// time, or a DAA score.
#[test]
fn before_its_time_nothing_spends() {
    let (owner, recovery, card) = both();
    let opens = card.unlock().ms();
    for (entry, signer) in [(Entry::Claim, &owner), (Entry::Recover, &recovery)] {
        for lock_time in [
            opens - 1,
            opens - MS_PER_MINUTE,
            opens - DAY_MS,
            0,
            400_000_000,
        ] {
            let coin = Coin {
                card,
                entry,
                signer,
            };
            let (tx, entries) = spend(&[coin], lock_time, 0, SIG_OP_COUNT);
            fails_with(verify(&tx, &entries), "UnsatisfiedLockTime");
        }
    }
}

/// A final input switches the lock time off, and the program refuses it.
#[test]
fn a_final_input_does_not_spend() {
    let (owner, _, card) = both();
    let coin = Coin {
        card,
        entry: Entry::Claim,
        signer: &owner,
    };
    let (tx, entries) = spend(
        &[coin],
        card.unlock().ms(),
        MAX_TX_IN_SEQUENCE_NUM,
        SIG_OP_COUNT,
    );
    fails_with(verify(&tx, &entries), "UnsatisfiedLockTime");
}

/// Each entry takes its own key: not the other's, not a stranger's.
#[test]
fn each_entry_takes_its_own_key_only() {
    let (owner, recovery, card) = both();
    let stranger = keypair(3);
    for (entry, signer) in [
        (Entry::Claim, &recovery),
        (Entry::Claim, &stranger),
        (Entry::Recover, &owner),
        (Entry::Recover, &stranger),
    ] {
        let coin = Coin {
            card,
            entry,
            signer,
        };
        let (tx, entries) = spend(&[coin], card.unlock().ms(), 0, SIG_OP_COUNT);
        fails_with(verify(&tx, &entries), "VerifyError");
    }
}

/// With no recovery wallet the owner spends through either entry, another
/// key through neither.
#[test]
fn with_no_recovery_wallet_only_the_owner_spends() {
    let (owner, other) = (keypair(1), keypair(2));
    let card = Savings::new(x(&owner), None, at(NEW_YEAR_2027)).unwrap();
    for entry in [Entry::Claim, Entry::Recover] {
        let coin = Coin {
            card,
            entry,
            signer: &owner,
        };
        let (tx, entries) = spend(&[coin], card.unlock().ms(), 0, SIG_OP_COUNT);
        assert_eq!(verify(&tx, &entries), Ok(()), "{entry:?}");
        let coin = Coin {
            card,
            entry,
            signer: &other,
        };
        let (tx, entries) = spend(&[coin], card.unlock().ms(), 0, SIG_OP_COUNT);
        fails_with(verify(&tx, &entries), "VerifyError");
    }
}

/// Coins of one card, and of another, spend together in one transaction,
/// up to the unit's 32 inputs, at a lock time past both times.
#[test]
fn coins_spend_together() {
    let (owner, recovery, card) = both();
    let later = Savings::new(x(&owner), None, at(NEW_YEAR_2027 + 365 * MINUTES_PER_DAY)).unwrap();
    let mut coins: Vec<Coin<'_>> = (0..31)
        .map(|i| Coin {
            card,
            entry: if i % 2 == 0 {
                Entry::Claim
            } else {
                Entry::Recover
            },
            signer: if i % 2 == 0 { &owner } else { &recovery },
        })
        .collect();
    coins.push(Coin {
        card: later,
        entry: Entry::Claim,
        signer: &owner,
    });
    let (tx, entries) = spend(&coins, later.unlock().ms(), 0, SIG_OP_COUNT);
    assert_eq!(verify(&tx, &entries), Ok(()));

    // The later card's day not reached: that input alone fails.
    let (tx, entries) = spend(&coins, card.unlock().ms(), 0, SIG_OP_COUNT);
    fails_with(verify(&tx, &entries), "input 31: UnsatisfiedLockTime");
}

/// A signature covers its spend: changing the amount paid or the lock time
/// after signing breaks it.
#[test]
fn a_signature_covers_the_spend() {
    let (owner, _, card) = both();
    let coin = || Coin {
        card,
        entry: Entry::Claim,
        signer: &owner,
    };
    let (mut tx, entries) = spend(&[coin()], card.unlock().ms(), 0, SIG_OP_COUNT);
    tx.outputs[0].value -= 1;
    tx.finalize();
    fails_with(verify(&tx, &entries), "VerifyError");

    let (mut tx, entries) = spend(&[coin()], card.unlock().ms(), 0, SIG_OP_COUNT);
    tx.lock_time += 1;
    tx.finalize();
    fails_with(verify(&tx, &entries), "VerifyError");
}

/// A tag the card does not have ends the program, and another card's program
/// does not open this card's coin.
#[test]
fn only_this_cards_program_and_tags_open_its_coins() {
    let (owner, _, card) = both();
    let coin = || Coin {
        card,
        entry: Entry::Claim,
        signer: &owner,
    };
    let tag_at = 1 + SIG_LEN + 1;
    let (mut tx, entries) = spend(&[coin()], card.unlock().ms(), 0, SIG_OP_COUNT);
    tx.inputs[0].signature_script[tag_at..tag_at + 4].copy_from_slice(&[0, 0, 0, 0]);
    tx.finalize();
    fails_with(verify(&tx, &entries), "EarlyReturn");

    let other = Savings::new(*card.owner(), None, card.unlock()).unwrap();
    let (mut tx, entries) = spend(&[coin()], card.unlock().ms(), 0, SIG_OP_COUNT);
    let at = tag_at + 4 + 2;
    tx.inputs[0].signature_script[at..].copy_from_slice(&other.program());
    tx.finalize();
    fails_with(verify(&tx, &entries), "EvalFalse");
}

/// The program takes its time as a timestamp: with a DAA score in
/// `unlockAt`, which no card of ours writes, a spend at a later DAA score is
/// refused by the program itself.
#[test]
fn the_program_refuses_a_daa_score_for_its_time() {
    let (owner, _, card) = both();
    let coin = Coin {
        card,
        entry: Entry::Claim,
        signer: &owner,
    };
    let (mut tx, mut entries) = spend(&[coin], 2_000, 0, SIG_OP_COUNT);
    let mut program = card.program();
    let at = PREFIX.len() + 67;
    program[at..at + 8].copy_from_slice(&1_000u64.to_le_bytes());
    assert_eq!(Savings::from_program(&program), Err(CardError::BadState));
    entries[0].script_public_key = kaspa_txscript::pay_to_script_hash_script(&program);
    let sig = {
        let populated = PopulatedTransaction::new(&tx, entries.clone());
        sign(
            &populated,
            0,
            &owner,
            SIG_HASH_ALL,
            &SigHashReusedValuesUnsync::new(),
        )
    };
    let script = &mut tx.inputs[0].signature_script;
    script[1..1 + SIG_LEN].copy_from_slice(&sig);
    script[SIGNATURE_SCRIPT_LEN - PROGRAM_LEN..].copy_from_slice(&program);
    tx.finalize();
    fails_with(verify(&tx, &entries), "VerifyError");
}

/// A spend runs one signature operation: an input that commits none has no
/// budget for it.
#[test]
fn a_spend_commits_its_signature_operation() {
    assert_eq!(SIG_OP_COUNT, 1);
    let (owner, _, card) = both();
    let coin = Coin {
        card,
        entry: Entry::Claim,
        signer: &owner,
    };
    let (tx, entries) = spend(&[coin], card.unlock().ms(), 0, SIG_OP_COUNT - 1);
    fails_with(verify(&tx, &entries), "Exceeded");
}

// ── The checks a unit makes on arrival ───────────────────────────────────────

/// One input spending `card`'s program, through `kassigner_protocol::check`.
fn checked(
    card: &Savings,
    version: u16,
    lock_time: u64,
    sequence: u64,
    sig_ops: u8,
) -> Result<(), CheckError> {
    use kassigner_kaspa::tx as ours;
    let program = card.program();
    let lock = card.locking_script();
    let inputs = [ours::TransactionInput {
        previous_outpoint: ours::Outpoint {
            transaction_id: [1; 32],
            index: 0,
        },
        sequence,
        sig_op_count: sig_ops,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: ours::UtxoEntry {
            amount: COIN,
            script_public_key: ours::ScriptPublicKey {
                version: 0,
                script: &lock,
            },
        },
    }];
    let tx = ours::Transaction {
        version,
        inputs: &inputs,
        outputs: &[],
        lock_time,
        subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: &[],
    };
    check::sequence(&tx, 0)?;
    check::sig_ops(&tx, 0, &program)?;
    check::card(&tx, 0, &program)
}

/// The card's checks agree with the engine, and name the reason, for lock
/// times around the card's time, none and a DAA score among them, on inputs
/// final or not.
#[test]
fn the_card_checks_agree_with_the_engine() {
    let (owner, _, card) = both();
    let opens = card.unlock().ms();
    for lock_time in [
        0,
        412_345_678,
        LOCK_TIME_THRESHOLD,
        opens - DAY_MS,
        opens - MS_PER_MINUTE,
        opens - 1,
        opens,
        opens + 1,
        opens + 400 * DAY_MS,
    ] {
        for sequence in [0, MAX_TX_IN_SEQUENCE_NUM] {
            let coin = Coin {
                card,
                entry: Entry::Claim,
                signer: &owner,
            };
            let (tx, entries) = spend(&[coin], lock_time, sequence, SIG_OP_COUNT);
            let engine = verify(&tx, &entries);
            let ours = checked(&card, 0, lock_time, sequence, SIG_OP_COUNT);
            assert_eq!(
                ours.is_ok(),
                engine.is_ok(),
                "{lock_time} {sequence}: {engine:?}"
            );
            let want = if sequence == MAX_TX_IN_SEQUENCE_NUM {
                Err(CheckError::CardFinal { input: 0 })
            } else if lock_time < opens {
                Err(CheckError::CardEarly { input: 0 })
            } else {
                Ok(())
            };
            assert_eq!(ours, want, "{lock_time} {sequence}");
        }
    }
}

/// A card's input commits its one signature operation under version 0, as
/// the engine needs; from version 1 the compute budget is not checked here.
#[test]
fn a_cards_input_commits_its_signature_operation() {
    let (_, _, card) = both();
    let day = card.unlock().ms();
    assert_eq!(
        checked(&card, 0, day, 0, 0),
        Err(CheckError::NoSigOp { input: 0 })
    );
    assert_eq!(checked(&card, 0, day, 0, SIG_OP_COUNT), Ok(()));
    assert_eq!(checked(&card, 1, day, 0, 0), Ok(()));
}

/// Only a sequence of 0 or final passes: anything else is a relative lock or
/// bits consensus does not read, which no page shows.
#[test]
fn only_a_sequence_of_zero_or_final_passes() {
    let (_, _, card) = both();
    let day = card.unlock().ms();
    for sequence in [
        1,
        2_592_000,
        u64::from(u32::MAX),
        1 << 32,
        1 << 62,
        1 << 63,
        (1 << 63) | 5,
        MAX_TX_IN_SEQUENCE_NUM - 1,
    ] {
        assert_eq!(
            checked(&card, 0, day, sequence, SIG_OP_COUNT),
            Err(CheckError::Sequence { input: 0 }),
            "{sequence:#x}"
        );
    }
    assert_eq!(checked(&card, 0, day, 0, SIG_OP_COUNT), Ok(()));
}

/// The card checks pass an input the transaction does not have, and a
/// program one bit off is not a card's: the check passes any other redeem.
#[test]
fn the_card_check_is_the_cards_alone() {
    use kassigner_kaspa::tx as ours;
    let tx = ours::Transaction {
        version: 0,
        inputs: &[],
        outputs: &[],
        lock_time: 0,
        subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: &[],
    };
    let card = cards()[0];
    assert_eq!(check::card(&tx, 0, &card.program()), Ok(()));
    assert_eq!(check::sequence(&tx, 3), Ok(()));
    let mut other = card.program();
    other[PREFIX.len() + STATE_LEN] ^= 1;
    assert_eq!(Savings::from_program(&other), Err(CardError::NotThisCard));
}

// ── The SDK's finished spends, through the engine ───────────────────────────

/// The SDK's finished claim and recovery of its bench card, two UTXOs each
/// (`spec/vectors/v110/sdk/`, from `kassigner-fw`'s
/// `the_sdk_vectors_are_current`), pass rusty-kaspa's engine through the
/// entry each tag names, with the id upstream computes. Checked here because
/// this crate runs the engine and the SDK's tests cannot.
#[test]
fn the_sdks_finished_card_spends_pass_the_engine() {
    use kassigner_kaspa::safe_json::{build, fill};
    use kassigner_kaspa::tx::{
        EntryDetails, ScriptPublicKey as OurScript, TransactionInput as OurInput,
        TransactionOutput as OurOutput, UtxoEntry as OurEntry,
    };
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/v110/sdk/");
    for (name, entry) in [
        ("savings.claim.signed.json", Entry::Claim),
        ("savings.recover.signed.json", Entry::Recover),
    ] {
        let text = std::fs::read(format!("{dir}{name}")).unwrap_or_else(|e| panic!("{name}: {e}"));
        let blank = OurScript {
            version: 0,
            script: &[],
        };
        let mut inputs = vec![
            OurInput {
                previous_outpoint: kassigner_kaspa::tx::Outpoint {
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
        let entries: Vec<UtxoEntry> = ours
            .inputs
            .iter()
            .zip(&details)
            .map(|(i, d)| UtxoEntry {
                amount: i.utxo_entry.amount,
                script_public_key: ScriptPublicKey::from_vec(
                    i.utxo_entry.script_public_key.version,
                    i.utxo_entry.script_public_key.script.to_vec(),
                ),
                block_daa_score: d.block_daa_score,
                is_coinbase: d.is_coinbase,
                covenant_id: None,
            })
            .collect();
        let tx = Transaction::new(
            ours.version,
            ours.inputs
                .iter()
                .map(|i| {
                    TransactionInput::new(
                        TransactionOutpoint::new(
                            TransactionId::from_bytes(i.previous_outpoint.transaction_id),
                            i.previous_outpoint.index,
                        ),
                        i.signature_script.to_vec(),
                        i.sequence,
                        i.sig_op_count,
                    )
                })
                .collect(),
            ours.outputs
                .iter()
                .map(|o| {
                    TransactionOutput::new(
                        o.value,
                        ScriptPublicKey::from_vec(
                            o.script_public_key.version,
                            o.script_public_key.script.to_vec(),
                        ),
                    )
                })
                .collect(),
            ours.lock_time,
            SUBNETWORK_ID_NATIVE,
            ours.gas,
            ours.payload.to_vec(),
        );
        assert_eq!(tx.id().as_bytes(), f.id, "{name}: the id upstream computes");
        assert_eq!(tx.inputs.len(), 2, "{name}");
        for (i, input) in tx.inputs.iter().enumerate() {
            let card = Savings::from_program(
                &input.signature_script[SIGNATURE_SCRIPT_LEN - PROGRAM_LEN..],
            )
            .unwrap_or_else(|_| panic!("{name}: input {i} carries the card's program"));
            assert_eq!(
                input.signature_script[..],
                card.signature_script(
                    entry,
                    input.signature_script[1..1 + SIG_LEN].try_into().unwrap()
                )[..],
                "{name}: input {i} spends by its {entry:?}"
            );
            assert_eq!(
                (input.sequence, input.compute_commit.sig_op_count()),
                (0, Some(SIG_OP_COUNT))
            );
        }
        assert_eq!(verify(&tx, &entries), Ok(()), "{name}");
    }
}
