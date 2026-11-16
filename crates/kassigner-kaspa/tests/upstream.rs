// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Upstream conformance: every rule in `kassigner-kaspa` restates
//! rusty-kaspa, and each check here builds one input, computes it upstream
//! and here, and asserts the bytes are equal. Constants are compared by
//! value only where fork-invariant.
//!
//! Host-only: `kaspa-consensus-core` is a dev-dependency, never built for a
//! device. Pinned to rev `01b532e8b553523216471682649693af92f0fd16` (v2.1.0).

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex_array;

/// The pinned source builds, links and yields upstream's `SOMPI_PER_KASPA`.
#[test]
fn upstream_pin_resolves_and_links() {
    assert_eq!(
        kaspa_consensus_core::constants::SOMPI_PER_KASPA,
        100_000_000,
        "pinned upstream does not hold the expected value; check the rev"
    );
}

/// Fork-invariant constants: nothing gates them on chain state.
#[test]
fn fork_invariant_constants_match_upstream() {
    use kaspa_consensus_core::constants as up;
    use kassigner_kaspa::constants as ours;

    assert_eq!(ours::SOMPI_PER_KASPA, up::SOMPI_PER_KASPA);
    assert_eq!(ours::MAX_SOMPI, up::MAX_SOMPI);
    assert_eq!(ours::LOCK_TIME_THRESHOLD, up::LOCK_TIME_THRESHOLD);
    assert_eq!(ours::STORAGE_MASS_PARAMETER, up::STORAGE_MASS_PARAMETER);
    assert_eq!(
        ours::TRANSIENT_BYTE_TO_MASS_FACTOR,
        up::TRANSIENT_BYTE_TO_MASS_FACTOR
    );
    assert_eq!(ours::TX_VERSION, up::TX_VERSION);
    assert_eq!(ours::TX_VERSION_COVENANTS, up::TX_VERSION_TOCCATA);
    assert_eq!(
        ours::MAX_SCRIPT_PUBLIC_KEY_VERSION,
        up::MAX_SCRIPT_PUBLIC_KEY_VERSION
    );
    assert_eq!(ours::MAX_TX_IN_SEQUENCE_NUM, up::MAX_TX_IN_SEQUENCE_NUM);
    assert_eq!(ours::SEQUENCE_LOCK_TIME_MASK, up::SEQUENCE_LOCK_TIME_MASK);
    assert_eq!(
        ours::SEQUENCE_LOCK_TIME_DISABLED,
        up::SEQUENCE_LOCK_TIME_DISABLED
    );
}

/// Coinbase maturity: mainnet's value, and the edge as
/// `check_transaction_coinbase_maturity` draws it, refused while
/// `block_daa_score + maturity > daa_score`. That check is in
/// `kaspa-consensus`, not built here, so the edge is stated from its source.
#[test]
fn coinbase_maturity_matches_upstream() {
    use kassigner_kaspa::tx::{EntryDetails, MAINNET_COINBASE_MATURITY};

    let up = kaspa_consensus_core::config::params::MAINNET_PARAMS.coinbase_maturity();
    assert_eq!(MAINNET_COINBASE_MATURITY, up);

    let at = 5_000_000;
    let reward = EntryDetails {
        block_daa_score: at,
        is_coinbase: true,
        covenant_id: None,
    };
    assert!(!reward.spendable_at(at), "not in its own block");
    assert!(!reward.spendable_at(at + up - 1), "one short");
    assert!(reward.spendable_at(at + up), "matured");
    assert!(reward.spendable_at(u64::MAX));
    let late = EntryDetails {
        block_daa_score: u64::MAX - 1,
        ..reward
    };
    assert!(!late.spendable_at(u64::MAX), "no overflow into spendable");
    let paid = EntryDetails {
        is_coinbase: false,
        ..reward
    };
    assert!(paid.spendable_at(at), "any other output, at once");
    assert!(paid.spendable_at(0));
}

/// Subnetwork identifiers match upstream's.
#[test]
fn subnetwork_ids_match_upstream() {
    use kaspa_consensus_core::subnets as up;
    use kassigner_kaspa::subnets as ours;

    assert_eq!(ours::SUBNETWORK_ID_SIZE, up::SUBNETWORK_ID_SIZE);
    assert_eq!(
        ours::SUBNETWORK_ID_NATIVE,
        up::SUBNETWORK_ID_NATIVE.as_ref()
    );
    assert_eq!(
        ours::SUBNETWORK_ID_COINBASE,
        up::SUBNETWORK_ID_COINBASE.as_ref()
    );
    assert_eq!(
        ours::SUBNETWORK_ID_REGISTRY,
        up::SUBNETWORK_ID_REGISTRY.as_ref()
    );

    assert!(ours::is_native(&ours::SUBNETWORK_ID_NATIVE));
    assert!(!ours::is_native(&ours::SUBNETWORK_ID_COINBASE));
    assert!(ours::is_builtin(&ours::SUBNETWORK_ID_COINBASE));
    assert!(ours::is_builtin(&ours::SUBNETWORK_ID_REGISTRY));
    assert!(!ours::is_builtin(&[9u8; 20]));
}

/// The supply cap holds on each value and on the running total.
#[test]
fn supply_cap_refuses_single_values_and_running_totals() {
    use kassigner_kaspa::constants::{checked_add_value, is_value_in_range, MAX_SOMPI};

    assert!(is_value_in_range(MAX_SOMPI));
    assert!(!is_value_in_range(MAX_SOMPI + 1));

    // Each legal on its own, illegal together.
    assert_eq!(checked_add_value(MAX_SOMPI - 1, 1), Some(MAX_SOMPI));
    assert_eq!(checked_add_value(MAX_SOMPI - 1, 2), None);

    // And no wrap.
    assert_eq!(checked_add_value(u64::MAX, 1), None);
}

/// Lock times fall on the side of the threshold upstream reads them on.
#[test]
fn lock_time_classification_follows_the_threshold() {
    use kassigner_kaspa::constants::{classify_lock_time, LockTime, LOCK_TIME_THRESHOLD};

    assert_eq!(classify_lock_time(0), LockTime::None);
    assert_eq!(classify_lock_time(1), LockTime::DaaScore(1));
    assert_eq!(
        classify_lock_time(LOCK_TIME_THRESHOLD - 1),
        LockTime::DaaScore(LOCK_TIME_THRESHOLD - 1)
    );
    assert_eq!(
        classify_lock_time(LOCK_TIME_THRESHOLD),
        LockTime::Timestamp(LOCK_TIME_THRESHOLD)
    );
}

/// A lock time binds unless every input's sequence is
/// `MAX_TX_IN_SEQUENCE_NUM`, as upstream's `check_tx_is_finalized` has it; a
/// zero one binds nothing. That check needs a validator and a block, so its
/// reading is pinned on these cases.
#[test]
fn a_lock_time_binds_unless_every_input_is_final() {
    use kaspa_consensus_core::constants::MAX_TX_IN_SEQUENCE_NUM as UP_FINAL;
    use kassigner_kaspa::tx as ours;

    let spk = [0x51u8];
    let input = |sequence: u64| ours::TransactionInput {
        previous_outpoint: ours::Outpoint {
            transaction_id: [1; 32],
            index: 0,
        },
        sequence,
        sig_op_count: 1,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: ours::UtxoEntry {
            amount: 1,
            script_public_key: ours::ScriptPublicKey {
                version: 0,
                script: &spk,
            },
        },
    };
    let binds = |sequences: &[u64], lock_time: u64| {
        let inputs: Vec<ours::TransactionInput<'_>> = sequences.iter().map(|&s| input(s)).collect();
        ours::Transaction {
            version: 0,
            inputs: &inputs,
            outputs: &[],
            lock_time,
            subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        }
        .lock_time_binds()
    };
    assert!(binds(&[0], 412_345_678));
    assert!(binds(&[UP_FINAL, 7], 412_345_678), "one input not final");
    assert!(binds(&[UP_FINAL - 1], 1_798_761_599_000));
    assert!(!binds(&[UP_FINAL], 412_345_678), "every input final");
    assert!(!binds(&[UP_FINAL, UP_FINAL], 1_798_761_599_000));
    assert!(!binds(&[0], 0), "no lock time");
}

// ── Signature hashing ────────────────────────────────────────────────────────

use kaspa_consensus_core::hashing::sighash::{
    calc_ecdsa_signature_hash, calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SigHashType as UpSigHashType;
use kaspa_consensus_core::subnets::{
    SubnetworkId as UpSubnetworkId, SUBNETWORK_ID_NATIVE as UP_NATIVE,
};
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction as UpTransaction,
    TransactionInput as UpInput, TransactionOutpoint, TransactionOutput as UpOutput, UtxoEntry,
};
use kaspa_hashes::Hash as UpHash;

use kassigner_kaspa::kat::{self, SighashCase as Case};
use kassigner_kaspa::sighash::{
    SigHashType as OurSigHashType, SIG_HASH_ALL, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE,
    SIG_HASH_SINGLE,
};
use kassigner_kaspa::tx as ours;

/// Build the same transaction on both sides and compare the digests, for
/// both sides of the version gate. Ours is `kat::sighash_digests`, the boot
/// builder, so this checks exactly what the boot set checks.
fn assert_sighash_agrees(case: Case) {
    let Case {
        version,
        n_inputs,
        n_outputs,
        covenants,
        hash_type,
        payload: has_payload,
        native_subnet,
    } = case;
    let theirs = upstream_digests(case);

    for (i, (theirs_schnorr, theirs_ecdsa)) in theirs.iter().enumerate() {
        let (ours_digest, ours_ecdsa) = kat::sighash_digests(case, i).expect("the case's input");
        assert_eq!(
            *theirs_schnorr, ours_digest,
            "version {version}, input {i} of {n_inputs}, {n_outputs} outputs, \
             covenants={covenants}, hash_type={hash_type:#04x}, \
             payload={has_payload}, native={native_subnet}. If EVERY case \
             fails, suspect the keyed hasher before the layout."
        );

        // The ECDSA digest: the Schnorr hash through a second hash.
        assert_eq!(
            *theirs_ecdsa, ours_ecdsa,
            "ECDSA: version {version}, input {i} of {n_inputs}, {n_outputs} \
             outputs, covenants={covenants}, hash_type={hash_type:#04x}. If \
             the Schnorr digest above passed and only this failed, the outer \
             hash is wrong, not the layout."
        );
        assert_ne!(
            ours_ecdsa, ours_digest,
            "the ECDSA digest is a second hash, not a copy"
        );
    }
}

/// rusty-kaspa's Schnorr and ECDSA digests for every input of a case, built
/// field for field from `kassigner_kaspa::kat`'s recipe constants.
fn upstream_digests(case: Case) -> Vec<([u8; 32], [u8; 32])> {
    let up_type = UpSigHashType::from_u8(case.hash_type).expect("a type upstream allows");
    let spk_script: Vec<u8> = kat::SIGHASH_SPK.to_vec();
    let payload: Vec<u8> = if case.payload {
        kat::SIGHASH_PAYLOAD.to_vec()
    } else {
        vec![]
    };
    let gas = if case.native_subnet {
        0
    } else {
        kat::SIGHASH_GAS
    };

    let up_inputs: Vec<UpInput> = (0..case.n_inputs)
        .map(|i| {
            UpInput::new(
                TransactionOutpoint::new(UpHash::from_bytes(kat::sighash_txid(i)), i as u32),
                vec![], // signature script: not committed to by the hash
                kat::sighash_sequence(i),
                kat::SIGHASH_SIG_OPS,
            )
        })
        .collect();
    let up_outputs: Vec<UpOutput> = (0..case.n_outputs)
        .map(|i| {
            let spk = ScriptPublicKey::from_vec(0, spk_script.clone());
            if case.covenants {
                UpOutput::with_covenant(
                    kat::sighash_value(i),
                    spk,
                    Some(CovenantBinding {
                        authorizing_input: 0,
                        covenant_id: UpHash::from_bytes(kat::SIGHASH_COVENANT_ID),
                    }),
                )
            } else {
                UpOutput::new(kat::sighash_value(i), spk)
            }
        })
        .collect();
    let up_subnet = if case.native_subnet {
        UP_NATIVE
    } else {
        UpSubnetworkId::from_bytes(kat::SIGHASH_SUBNET)
    };
    let up_tx = UpTransaction::new(
        case.version,
        up_inputs,
        up_outputs,
        kat::SIGHASH_LOCK_TIME,
        up_subnet,
        gas,
        payload,
    );
    let entries: Vec<UtxoEntry> = (0..case.n_inputs)
        .map(|i| {
            let (version, script) = kat::SIGHASH_INPUT_SPKS[i];
            UtxoEntry::new(
                kat::sighash_amount(i),
                ScriptPublicKey::from_vec(version, script.to_vec()),
                0,     // block DAA score: not committed to by the hash
                false, // coinbase: likewise
                None,
            )
        })
        .collect();
    let verifiable = PopulatedTransaction::new(&up_tx, entries);
    let reused = SigHashReusedValuesUnsync::new();

    (0..case.n_inputs)
        .map(|i| {
            let s = calc_schnorr_signature_hash(&verifiable, i, up_type, &reused);
            let e = calc_ecdsa_signature_hash(&verifiable, i, up_type, &reused);
            (s.as_bytes(), e.as_bytes())
        })
        .collect()
}

/// The boot set's frozen signature hashes are rusty-kaspa's.
/// `kat::SIGHASH_EXPECTED` is never written by hand:
///
/// ```text
/// KAT_REGENERATE=1 cargo +esp195 test -p kassigner-kaspa --test upstream boot_sighash
/// ```
///
/// rewrites `src/kat_sighash.rs`; every other run asserts it still matches.
#[test]
fn boot_sighash_answers_are_upstreams() {
    let fresh: Vec<[u8; 32]> = kat::SIGHASH_BOOT
        .iter()
        .map(|(case, input)| upstream_digests(*case)[*input].0)
        .collect();
    if std::env::var_os("KAT_REGENERATE").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/kat_sighash.rs");
        std::fs::write(path, render_sighash_table(&fresh)).expect("write the table");
        return;
    }
    assert_eq!(
        fresh.as_slice(),
        &kat::SIGHASH_EXPECTED[..],
        "the boot set's sighash table is stale or was never generated; run \
         KAT_REGENERATE=1 cargo +esp195 test -p kassigner-kaspa --test upstream boot_sighash"
    );
}

/// The generated file, in the one format it is ever written in.
fn render_sighash_table(hashes: &[[u8; 32]]) -> String {
    let header = include_str!("../src/kat_sighash.rs");
    let head = &header[..header
        .find("/// Expected digests")
        .expect("the table has its doc line")];
    let mut out = String::from(head);
    out.push_str("/// Expected digests for [`SIGHASH_BOOT`], from rusty-kaspa.\n");
    out.push_str("#[rustfmt::skip]\n");
    out.push_str(&format!(
        "pub const SIGHASH_EXPECTED: [Hash; {}] = [\n",
        hashes.len()
    ));
    for h in hashes {
        let bytes: Vec<String> = h.iter().map(|b| format!("0x{b:02x}")).collect();
        out.push_str(&format!("    [{}],\n", bytes.join(", ")));
    }
    out.push_str("];\n");
    out
}

/// Every sighash type upstream allows, on both versions: each branch that
/// drops or narrows the sequences, outputs, previous outputs or
/// signature-operation counts.
#[test]
fn sighash_agrees_on_every_hash_type() {
    let any = SIG_HASH_ANY_ONE_CAN_PAY.to_u8();
    for version in [0u16, 1] {
        for base in [SIG_HASH_ALL, SIG_HASH_NONE, SIG_HASH_SINGLE] {
            // Plain, then with ANYONECANPAY: the six upstream's `from_u8`
            // accepts.
            let with_any = OurSigHashType::from_u8(base.to_u8() | any).expect("allowed");
            for t in [base, with_any] {
                assert_sighash_agrees(Case::new(version, 2, 2).hash_type(t));
                assert_sighash_agrees(Case::new(version, 1, 3).hash_type(t));
            }
        }
    }
}

/// A sighash type is one of upstream's six or none, for every byte.
#[test]
fn sighash_types_are_upstreams_six() {
    let mut allowed = 0;
    for b in 0..=u8::MAX {
        let ours = OurSigHashType::from_u8(b);
        let theirs = UpSigHashType::from_u8(b);
        assert_eq!(ours.is_some(), theirs.is_ok(), "{b:#04x}");
        if let Some(t) = ours {
            assert_eq!(t.to_u8(), b);
            allowed += 1;
        }
    }
    assert_eq!(allowed, 6);
}

/// An input the transaction lacks has no signature hash (upstream panics).
#[test]
fn an_input_past_the_last_has_no_hash() {
    let case = Case::new(1, 2, 2);
    assert!(kat::sighash_digests(case, 1).is_some());
    assert!(kat::sighash_digests(case, 2).is_none());
    assert!(kat::sighash_digests(case, usize::MAX).is_none());
}

/// SIGHASH_SINGLE with no output at the input's index: upstream hashes zero,
/// so the signature commits to no output. It must agree byte for byte.
#[test]
fn sighash_single_past_the_last_output_agrees() {
    for version in [0u16, 1] {
        assert_sighash_agrees(Case::new(version, 3, 1).hash_type(SIG_HASH_SINGLE));
        let single_any =
            OurSigHashType::from_u8(SIG_HASH_SINGLE.to_u8() | SIG_HASH_ANY_ONE_CAN_PAY.to_u8())
                .expect("allowed");
        assert_sighash_agrees(Case::new(version, 4, 2).hash_type(single_any));
    }
}

/// The payload is hashed unless the subnetwork is native and the payload
/// empty; a non-native subnetwork also carries gas.
#[test]
fn sighash_agrees_on_the_payload_and_subnetwork_gate() {
    for version in [0u16, 1] {
        // Native, empty: the one shape that skips the payload hash.
        assert_sighash_agrees(Case {
            payload: false,
            ..Case::new(version, 2, 2)
        });
        // Non-native, empty: hashed anyway, and with gas set.
        assert_sighash_agrees(Case {
            payload: false,
            native_subnet: false,
            ..Case::new(version, 2, 2)
        });
        // Non-native with a payload, the remaining corner.
        assert_sighash_agrees(Case {
            native_subnet: false,
            ..Case::new(version, 1, 1)
        });
    }
}

/// Version 0: commits to the signature-operation counts, twice.
#[test]
fn sighash_agrees_on_version_0() {
    assert_sighash_agrees(Case::new(0, 1, 1));
    assert_sighash_agrees(Case::new(0, 3, 2));
}

/// Version 1: no signature-operation commitments, and every output's
/// covenant binding, present or not.
#[test]
fn sighash_agrees_on_version_1() {
    assert_sighash_agrees(Case::new(1, 1, 1));
    assert_sighash_agrees(Case::new(1, 2, 2).covenants());
    assert_sighash_agrees(Case::new(1, 3, 1).covenants());
}

// ── Address encoding ─────────────────────────────────────────────────────────

use kaspa_addresses::{Address as UpAddress, Prefix as UpPrefix, Version as UpVersion};
use kassigner_kaspa::address::{decode, encode, Prefix, Version, MAX_ADDRESS_LEN};

/// Encode on both sides and compare. The prefix feeds the checksum, so every
/// network is run.
fn assert_address_agrees(
    prefix: Prefix,
    up_prefix: UpPrefix,
    version: Version,
    up_version: UpVersion,
) {
    let payload: Vec<u8> = (0..version.payload_len())
        .map(|i| (i * 7 + 3) as u8)
        .collect();

    let theirs = UpAddress::new(up_prefix, up_version, &payload).to_string();

    let mut buf = [0u8; MAX_ADDRESS_LEN];
    let n = encode(prefix, version, &payload, &mut buf).expect("encode");
    let ours = core::str::from_utf8(&buf[..n]).expect("ascii");

    assert_eq!(theirs, ours, "{prefix:?} {version:?}");

    // And back, to the same bytes.
    let mut out = [0u8; 33];
    let (p, v, len) = decode(&buf[..n], &mut out).expect("decode");
    assert_eq!(p, prefix);
    assert_eq!(v, version);
    assert_eq!(&out[..len], &payload[..], "round trip lost the payload");
}

#[test]
fn address_agrees_with_upstream_on_every_network() {
    for (ours, theirs) in [
        (Prefix::Mainnet, UpPrefix::Mainnet),
        (Prefix::Testnet, UpPrefix::Testnet),
        (Prefix::Simnet, UpPrefix::Simnet),
        (Prefix::Devnet, UpPrefix::Devnet),
    ] {
        assert_address_agrees(ours, theirs, Version::PubKey, UpVersion::PubKey);
        assert_address_agrees(ours, theirs, Version::PubKeyEcdsa, UpVersion::PubKeyECDSA);
        assert_address_agrees(ours, theirs, Version::ScriptHash, UpVersion::ScriptHash);
    }
}

/// An address from one network does not decode as another: the prefix feeds
/// the checksum.
#[test]
fn wrong_network_fails_the_checksum() {
    let payload = [0x42u8; 32];
    let mut buf = [0u8; MAX_ADDRESS_LEN];
    let n = encode(Prefix::Mainnet, Version::PubKey, &payload, &mut buf).unwrap();

    // Same characters, testnet prefix spliced in front.
    let body = &buf[b"kaspa:".len()..n];
    let mut forged = Vec::from(&b"kaspatest:"[..]);
    forged.extend_from_slice(body);

    let mut out = [0u8; 33];
    assert!(
        decode(&forged, &mut out).is_err(),
        "a mainnet body decoded under a testnet prefix"
    );
}

// ── Script ───────────────────────────────────────────────────────────────────

use kaspa_txscript::opcodes::codes as up_codes;
use kassigner_kaspa::script::{DisasmError, Disassembler, OPCODE_NAMES};

/// The opcode table, copied from the pinned source, agrees with upstream's
/// constants across the pushes, crypto, covenant block and tail.
#[test]
fn opcode_table_matches_upstream() {
    let checks: &[(u8, &str)] = &[
        (up_codes::OpFalse, "OpFalse"),
        (up_codes::OpData1, "OpData1"),
        (up_codes::OpData75, "OpData75"),
        (up_codes::OpPushData1, "OpPushData1"),
        (up_codes::OpPushData2, "OpPushData2"),
        (up_codes::OpPushData4, "OpPushData4"),
        (up_codes::OpTrue, "OpTrue"),
        (up_codes::Op16, "Op16"),
        (up_codes::OpBlake2b, "OpBlake2b"),
        (up_codes::OpCheckSig, "OpCheckSig"),
        (up_codes::OpCheckMultiSig, "OpCheckMultiSig"),
        (up_codes::OpCheckLockTimeVerify, "OpCheckLockTimeVerify"),
        (up_codes::OpCheckSequenceVerify, "OpCheckSequenceVerify"),
        (up_codes::OpTxVersion, "OpTxVersion"),
        (up_codes::OpInputCovenantId, "OpInputCovenantId"),
        (up_codes::OpOutputCovenantId, "OpOutputCovenantId"),
        (up_codes::OpCheckSigFromStack, "OpCheckSigFromStack"),
        (up_codes::OpInvalidOpCode, "OpInvalidOpCode"),
    ];
    for &(code, name) in checks {
        assert_eq!(OPCODE_NAMES[code as usize], name, "opcode {code:#04x}");
    }
    // No gaps: every byte names something, so nothing renders as blank.
    assert!(OPCODE_NAMES.iter().all(|n| !n.is_empty()));
}

/// Every opcode's length is upstream's: all 256 bytes of
/// [`OPCODE_LENGTHS`], which the disassembler steps by. Each byte is followed
/// by a length of 2 in a variable push's width, then filler; upstream's
/// parser reads it back as long as the table says, and our first step
/// pushes the same data.
#[test]
fn opcode_lengths_match_upstream() {
    use kaspa_txscript::opcodes::deserialize_next_opcode;
    use kassigner_kaspa::script::OPCODE_LENGTHS;

    let mut tail = vec![2u8, 0, 0, 0];
    tail.extend([0xEE; 80]);
    for byte in 0..=255u8 {
        let mut script = vec![byte];
        script.extend_from_slice(&tail);
        let up = deserialize_next_opcode::<_, PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(
            &mut script.iter(),
        )
        .expect("a byte to read")
        .unwrap_or_else(|e| panic!("upstream reads {byte:#04x}: {e:?}"));
        let written = up.serialize().len();
        let declared = OPCODE_LENGTHS[byte as usize];
        let expected = if declared >= 0 {
            declared as usize
        } else {
            1 + (-declared) as usize + up.get_data().len()
        };
        assert_eq!(written, expected, "opcode {byte:#04x}'s length");

        let ours = Disassembler::new(&script)
            .next()
            .expect("a step")
            .unwrap_or_else(|e| panic!("ours reads {byte:#04x}: {e:?}"));
        assert_eq!(ours.data, up.get_data(), "opcode {byte:#04x}'s data");
    }
}

/// Disassembly walks a script built by upstream's `ScriptBuilder` at the
/// same step boundaries.
#[test]
fn disassembles_a_script_built_upstream() {
    use kaspa_txscript::script_builder::ScriptBuilder;

    let key = [0xABu8; 32];
    let big = vec![0xCDu8; 300]; // forces a two-byte push length
    let script = ScriptBuilder::new()
        .add_data(&key)
        .unwrap()
        .add_op(up_codes::OpCheckSig)
        .unwrap()
        .add_data(&big)
        .unwrap()
        .add_op(up_codes::OpBlake2b)
        .unwrap()
        .drain();

    let steps: Vec<_> = Disassembler::new(&script).map(|s| s.unwrap()).collect();
    assert_eq!(steps.len(), 4, "expected four steps, got {steps:?}");

    assert_eq!(steps[0].data, &key[..], "32-byte push lost its data");
    assert_eq!(steps[1].name, "OpCheckSig");
    assert_eq!(steps[2].data, &big[..], "300-byte push lost its data");
    assert_eq!(steps[3].name, "OpBlake2b");

    // Offsets are contiguous and cover the whole script.
    assert_eq!(steps[0].offset, 0);
    assert!(Disassembler::new(&script).all(|s| s.is_ok()));
}

/// A push claiming more bytes than exist is refused at its offset, not
/// guessed at.
#[test]
fn truncated_push_is_refused_not_guessed() {
    // OpData32 promising 32 bytes, followed by four.
    let script = [up_codes::OpData32, 1, 2, 3, 4];
    let steps: Vec<_> = Disassembler::new(&script).collect();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0], Err(DisasmError::Truncated { offset: 0 }));
    assert!(!Disassembler::new(&script).all(|s| s.is_ok()));
}

// ── Script recognition ───────────────────────────────────────────────────────

use kaspa_txscript::script_class::ScriptClass as UpScriptClass;
use kaspa_txscript::standard::multisig_redeem_script;
use kassigner_kaspa::script::{classify, multisig_shape, parse_multisig, ScriptClass};

/// Script classification agrees with upstream's on scripts its helpers
/// build, under every version; past version 0 neither names anything.
#[test]
fn script_class_agrees_with_upstream() {
    use kaspa_txscript::opcodes::codes as up_codes;
    use kaspa_txscript::script_builder::ScriptBuilder;

    // Pay to pubkey.
    let key32 = [0x11u8; 32];
    let p2pk = ScriptBuilder::new()
        .add_data(&key32)
        .unwrap()
        .add_op(up_codes::OpCheckSig)
        .unwrap()
        .drain();

    // Pay to pubkey, ECDSA.
    let key33 = [0x22u8; 33];
    let p2pk_ecdsa = ScriptBuilder::new()
        .add_data(&key33)
        .unwrap()
        .add_op(up_codes::OpCheckSigECDSA)
        .unwrap()
        .drain();

    // Pay to script hash.
    let hash32 = [0x33u8; 32];
    let p2sh = ScriptBuilder::new()
        .add_op(up_codes::OpBlake2b)
        .unwrap()
        .add_data(&hash32)
        .unwrap()
        .add_op(up_codes::OpEqual)
        .unwrap()
        .drain();

    let at = |version, script: &[u8]| classify(&ours::ScriptPublicKey { version, script });
    for (script, our_class, theirs) in [
        (&p2pk, ScriptClass::PubKey, UpScriptClass::PubKey),
        (
            &p2pk_ecdsa,
            ScriptClass::PubKeyEcdsa,
            UpScriptClass::PubKeyECDSA,
        ),
        (&p2sh, ScriptClass::ScriptHash, UpScriptClass::ScriptHash),
    ] {
        assert_eq!(at(0, script), our_class);
        assert_eq!(
            UpScriptClass::from_script(&ScriptPublicKey::from_vec(0, script.clone())),
            theirs
        );
        for version in [1u16, 2, u16::MAX] {
            assert_eq!(at(version, script), ScriptClass::NonStandard);
            assert_eq!(
                UpScriptClass::from_script(&ScriptPublicKey::from_vec(version, script.clone())),
                UpScriptClass::NonStandard,
                "upstream agrees at version {version}"
            );
        }
        // And upstream agrees on the class, so we are not both wrong the same
        // way.
        assert!(match theirs {
            UpScriptClass::PubKey => UpScriptClass::is_pay_to_pubkey(script),
            UpScriptClass::PubKeyECDSA => UpScriptClass::is_pay_to_pubkey_ecdsa(script),
            UpScriptClass::ScriptHash => UpScriptClass::is_pay_to_script_hash(script),
            UpScriptClass::NonStandard => false,
        });
    }

    // A covenant is valid and not standard.
    let covenant = ScriptBuilder::new()
        .add_op(up_codes::OpTxVersion)
        .unwrap()
        .add_op(up_codes::OpCheckSigFromStack)
        .unwrap()
        .drain();
    assert_eq!(at(0, &covenant), ScriptClass::NonStandard);
}

/// The transaction version rule: refused above `TX_VERSION_TOCCATA`.
#[test]
fn the_transaction_version_rule_agrees_with_upstream() {
    use kaspa_consensus_core::constants::TX_VERSION_TOCCATA;
    for version in [0u16, 1, 2, 3, u16::MAX] {
        let tx = ours::Transaction {
            version,
            inputs: &[],
            outputs: &[],
            lock_time: 0,
            subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        };
        let expected = if version > TX_VERSION_TOCCATA {
            Err(ours::TxRuleError::UnknownTxVersion(version))
        } else {
            Ok(())
        };
        assert_eq!(tx.check_version_fields(), expected, "version {version}");
    }
}

/// The fee is what the inputs leave after the outputs. More out is
/// `SpendTooHigh`, outputs' total first; the amount rules run first, as
/// upstream's do. Upstream's rule is in `kaspa-consensus`, so its message
/// stands in to fix which total is which.
#[test]
fn the_fee_rule_agrees_with_upstream() {
    use kaspa_consensus_core::errors::tx::TxRuleError as UpTxRuleError;
    use kassigner_kaspa::constants::MAX_SOMPI;
    let spk = ours::ScriptPublicKey {
        version: 0,
        script: &[0x20; 34],
    };
    let input = |amount| ours::TransactionInput {
        previous_outpoint: ours::Outpoint {
            transaction_id: [1; 32],
            index: 0,
        },
        sequence: 0,
        sig_op_count: 1,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: ours::UtxoEntry {
            amount,
            script_public_key: spk,
        },
    };
    let output = |value| ours::TransactionOutput {
        value,
        script_public_key: spk,
        covenant: None,
    };
    let fee = |ins: &[ours::TransactionInput<'_>], outs: &[ours::TransactionOutput<'_>]| {
        ours::Transaction {
            version: 0,
            inputs: ins,
            outputs: outs,
            lock_time: 0,
            subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        }
        .fee()
    };

    // What is left, over one input or several, and nothing left.
    assert_eq!(fee(&[input(100_000)], &[output(90_000)]), Ok(10_000));
    assert_eq!(
        fee(
            &[input(60_000), input(40_000)],
            &[output(30_000), output(69_000)]
        ),
        Ok(1_000)
    );
    assert_eq!(fee(&[input(100_000)], &[output(100_000)]), Ok(0));
    assert_eq!(fee(&[input(MAX_SOMPI)], &[output(MAX_SOMPI)]), Ok(0));
    // No outputs at all: the inputs are the fee, as upstream sums nothing.
    assert_eq!(fee(&[input(5)], &[]), Ok(5));

    // One sompi over, on either side of a split.
    let over = fee(&[input(100_000)], &[output(60_000), output(40_001)]);
    assert_eq!(over, Err(ours::TxRuleError::SpendTooHigh(100_001, 100_000)));
    assert_eq!(
        UpTxRuleError::SpendTooHigh(100_001, 100_000).to_string(),
        "transaction tries to spend 100001 while its total inputs amount is 100000",
        "upstream's first field is the outputs' total"
    );
    assert_eq!(
        fee(&[], &[output(1)]),
        Err(ours::TxRuleError::SpendTooHigh(1, 0))
    );

    // The amount rules first: their refusals, not a fee's.
    assert_eq!(
        fee(&[input(100_000)], &[output(0)]),
        Err(ours::TxRuleError::TxOutZero(0))
    );
    assert_eq!(
        fee(&[input(MAX_SOMPI), input(1)], &[output(1)]),
        Err(ours::TxRuleError::InputAmountTooHigh)
    );
    assert_eq!(
        fee(&[input(1)], &[output(MAX_SOMPI), output(1)]),
        Err(ours::TxRuleError::TotalTxOutTooHigh)
    );
    assert_eq!(
        fee(&[input(1), input(u64::MAX)], &[output(1)]),
        Err(ours::TxRuleError::InputAmountOverflow)
    );
}

/// An outpoint spent twice is refused as upstream's
/// `check_duplicate_transaction_inputs` refuses it; a set of upstream's
/// outpoints stands in for that rule, which is in `kaspa-consensus`.
#[test]
fn the_duplicate_input_rule_agrees_with_upstream() {
    use kaspa_consensus_core::errors::tx::TxRuleError as UpTxRuleError;
    use std::collections::HashSet;
    let spk = ours::ScriptPublicKey {
        version: 0,
        script: &[0x20; 34],
    };
    let input = |(id, index): (u8, u32)| ours::TransactionInput {
        previous_outpoint: ours::Outpoint {
            transaction_id: [id; 32],
            index,
        },
        sequence: 0,
        sig_op_count: 1,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: ours::UtxoEntry {
            amount: 1_000,
            script_public_key: spk,
        },
    };
    let upstream_refuses = |points: &[(u8, u32)]| {
        let mut seen = HashSet::new();
        !points.iter().all(|&(id, index)| {
            seen.insert(TransactionOutpoint::new(
                UpHash::from_bytes([id; 32]),
                index,
            ))
        })
    };
    // Eight outputs of one transaction, then the last spending the first again.
    let eight: Vec<(u8, u32)> = (0..8).map(|i| (9, i)).collect();
    let mut eight_again = eight.clone();
    eight_again[7] = (9, 0);
    let cases: [&[(u8, u32)]; 10] = [
        &[],
        &[(1, 0)],
        &[(1, 0), (1, 1)],
        &[(1, 0), (2, 0)],
        &[(1, 0), (1, 0)],
        &[(1, 0), (2, 0), (1, 0)],
        &[(1, 7), (2, 7), (3, 7), (2, 7)],
        &[(1, u32::MAX), (1, u32::MAX)],
        &eight,
        &eight_again,
    ];
    for points in cases {
        let ins: Vec<_> = points.iter().copied().map(input).collect();
        let tx = ours::Transaction {
            version: 0,
            inputs: &ins,
            outputs: &[],
            lock_time: 0,
            subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        };
        let expected = if upstream_refuses(points) {
            Err(ours::TxRuleError::TxDuplicateInputs)
        } else {
            Ok(())
        };
        assert_eq!(tx.check_duplicate_inputs(), expected, "{points:?}");
    }
    assert_eq!(
        UpTxRuleError::TxDuplicateInputs.to_string(),
        "transaction has duplicate inputs"
    );
}

/// An authorizing input past the last is refused by both, as upstream's
/// `CovenantsContext::from_tx` refuses it, naming the same output and input.
#[test]
fn the_authorizing_input_rule_agrees_with_upstream() {
    use kaspa_txscript::covenants::CovenantsContext;
    let spk = vec![0x20u8; 34];
    for (inputs, authorizing) in [(1usize, 0u16), (1, 1), (2, 1), (2, 2), (1, u16::MAX)] {
        let up_tx = UpTransaction::new(
            1,
            (0..inputs)
                .map(|i| {
                    UpInput::new(
                        TransactionOutpoint::new(UpHash::from_bytes([i as u8 + 1; 32]), 0),
                        vec![],
                        0,
                        0,
                    )
                })
                .collect(),
            vec![UpOutput::with_covenant(
                1_000,
                ScriptPublicKey::from_vec(0, spk.clone()),
                Some(CovenantBinding {
                    authorizing_input: authorizing,
                    covenant_id: UpHash::from_bytes([0x5a; 32]),
                }),
            )],
            0,
            UP_NATIVE,
            0,
            vec![],
        );
        let entries = (0..inputs)
            .map(|_| {
                UtxoEntry::new(
                    1_000,
                    ScriptPublicKey::from_vec(0, spk.clone()),
                    0,
                    false,
                    None,
                )
            })
            .collect();
        let theirs = CovenantsContext::from_tx(&PopulatedTransaction::new(&up_tx, entries))
            .err()
            .map(|e| format!("{e:?}"));

        let our_inputs: Vec<ours::TransactionInput<'_>> = (0..inputs)
            .map(|_| ours::TransactionInput {
                previous_outpoint: ours::Outpoint {
                    transaction_id: [0; 32],
                    index: 0,
                },
                sequence: 0,
                sig_op_count: 0,
                compute_budget: 0,
                signature_script: &[],
                utxo_entry: ours::UtxoEntry {
                    amount: 1_000,
                    script_public_key: ours::ScriptPublicKey {
                        version: 0,
                        script: &spk,
                    },
                },
            })
            .collect();
        let our_outputs = [ours::TransactionOutput {
            value: 1_000,
            script_public_key: ours::ScriptPublicKey {
                version: 0,
                script: &spk,
            },
            covenant: Some(ours::CovenantBinding {
                authorizing_input: authorizing,
                covenant_id: [0x5a; 32],
            }),
        }];
        let tx = ours::Transaction {
            version: 1,
            inputs: &our_inputs,
            outputs: &our_outputs,
            lock_time: 0,
            subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        };
        let out_of_bounds = format!("AuthInputOutOfBounds(0, {authorizing})");
        if usize::from(authorizing) >= inputs {
            assert_eq!(theirs.as_deref(), Some(out_of_bounds.as_str()));
            assert_eq!(
                tx.check_covenant_bindings(),
                Err(ours::TxRuleError::AuthInputOutOfBounds(0, authorizing))
            );
        } else {
            // In range, upstream goes on to the genesis id, which a request
            // cannot check.
            assert_ne!(theirs.as_deref(), Some(out_of_bounds.as_str()));
            assert_eq!(tx.check_covenant_bindings(), Ok(()));
        }
    }
}

/// Scripts of the lengths a covenant output may have: empty, a key's, a
/// script hash's, one past `OP_PUSHDATA1`'s reach, and a large program.
fn covenant_scripts() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x20; 34],
        vec![0xaa; 35],
        vec![0x51; 300],
        vec![0x07; 70_000],
    ]
}

/// A new covenant's id (KIP-20) as upstream makes it, over groups of one,
/// two and five outputs of every script length, under both script versions.
#[test]
fn the_covenant_id_is_upstreams() {
    use kaspa_consensus_core::hashing::covenant_id::covenant_id as up_covenant_id;
    use kassigner_kaspa::sighash::covenant_id;

    let scripts = covenant_scripts();
    for (n, take) in [1usize, 2, 5].into_iter().enumerate() {
        let outpoint = ours::Outpoint {
            transaction_id: [n as u8 + 0x11; 32],
            index: [0, 1, u32::MAX][n],
        };
        let up_outputs: Vec<UpOutput> = (0..take)
            .map(|k| {
                UpOutput::with_covenant(
                    1_000 + k as u64,
                    ScriptPublicKey::from_vec(k as u16 % 2, scripts[k % scripts.len()].clone()),
                    Some(CovenantBinding {
                        authorizing_input: 3,
                        covenant_id: UpHash::from_bytes([0x5a; 32]),
                    }),
                )
            })
            .collect();
        let our_outputs: Vec<ours::TransactionOutput<'_>> = (0..take)
            .map(|k| ours::TransactionOutput {
                value: 1_000 + k as u64,
                script_public_key: ours::ScriptPublicKey {
                    version: k as u16 % 2,
                    script: &scripts[k % scripts.len()],
                },
                covenant: None,
            })
            .collect();
        // An output's index in its transaction, not in the group.
        let at = |k: usize| (2 * k + 1) as u32;
        let theirs = up_covenant_id(
            TransactionOutpoint::new(UpHash::from_bytes(outpoint.transaction_id), outpoint.index),
            up_outputs.iter().enumerate().map(|(k, o)| (at(k), o)),
        );
        let mine = covenant_id(
            &outpoint,
            our_outputs.iter().enumerate().map(|(k, o)| (at(k), o)),
        );
        assert_eq!(mine, theirs.as_bytes(), "{take} outputs");
    }
}

/// One covenant scenario: each input's coin's covenant id, each output's
/// binding as (authorizing input, id), and how the ids are made.
struct Scenario {
    name: &'static str,
    coins: Vec<Option<[u8; 32]>>,
    bindings: Vec<Option<(u16, Id)>>,
}

/// An output's covenant id: a fixed one, or the one its group makes.
#[derive(Clone, Copy)]
enum Id {
    Fixed([u8; 32]),
    /// The id the outputs bound with this tag under this input make.
    Made(u8),
}

/// Every covenant binding against the coins it spends, as upstream's
/// `CovenantsContext::from_tx` holds it: both take each scenario, or refuse
/// it naming the same input and id.
#[test]
fn new_covenants_are_checked_as_upstream_checks_them() {
    use kaspa_consensus_core::hashing::covenant_id::covenant_id as up_covenant_id;
    use kaspa_txscript::covenants::CovenantsContext;

    let x = [0x71; 32];
    let y = [0x72; 32];
    let scenarios = [
        Scenario {
            name: "a continuation",
            coins: vec![Some(x)],
            bindings: vec![Some((0, Id::Fixed(x))), None],
        },
        Scenario {
            name: "a new covenant of one output",
            coins: vec![None],
            bindings: vec![None, Some((0, Id::Made(1)))],
        },
        Scenario {
            name: "a new covenant of two outputs",
            coins: vec![None, None],
            bindings: vec![Some((1, Id::Made(1))), None, Some((1, Id::Made(1)))],
        },
        Scenario {
            name: "two new covenants from two inputs",
            coins: vec![None, Some(y)],
            bindings: vec![Some((0, Id::Made(1))), Some((1, Id::Made(2)))],
        },
        Scenario {
            name: "a new covenant from a coin bound to another",
            coins: vec![Some(y)],
            bindings: vec![Some((0, Id::Made(1))), Some((0, Id::Fixed(y)))],
        },
        Scenario {
            name: "a wrong id",
            coins: vec![None],
            bindings: vec![Some((0, Id::Fixed([0x5a; 32])))],
        },
        Scenario {
            name: "a continuation claimed by a coin bound to none",
            coins: vec![None, Some(x)],
            bindings: vec![Some((0, Id::Fixed(x)))],
        },
        Scenario {
            name: "an authorizing input past the last",
            coins: vec![None],
            bindings: vec![Some((1, Id::Fixed(x)))],
        },
    ];
    let spk = vec![0xaa; 35];
    let mut refused = Vec::new();
    for s in scenarios {
        let outpoints: Vec<ours::Outpoint> = (0..s.coins.len())
            .map(|i| ours::Outpoint {
                transaction_id: [i as u8 + 1; 32],
                index: i as u32 * 7,
            })
            .collect();
        // Made ids: each group's outputs, in order, over its input's outpoint.
        let id_of = |at: usize| -> [u8; 32] {
            let (input, id) = s.bindings[at].unwrap();
            match id {
                Id::Fixed(id) => id,
                Id::Made(tag) => {
                    let group: Vec<(u32, UpOutput)> = s
                        .bindings
                        .iter()
                        .enumerate()
                        .filter(|(_, b)| matches!(b, Some((i, Id::Made(t))) if *i == input && *t == tag))
                        .map(|(j, _)| (j as u32, UpOutput::new(500 + j as u64, ScriptPublicKey::from_vec(0, spk.clone()))))
                        .collect();
                    let o = outpoints[usize::from(input)];
                    up_covenant_id(
                        TransactionOutpoint::new(UpHash::from_bytes(o.transaction_id), o.index),
                        group.iter().map(|(j, out)| (*j, out)),
                    )
                    .as_bytes()
                }
            }
        };
        let ids: Vec<Option<(u16, [u8; 32])>> = (0..s.bindings.len())
            .map(|j| s.bindings[j].map(|(input, _)| (input, id_of(j))))
            .collect();

        let up_tx = UpTransaction::new(
            1,
            outpoints
                .iter()
                .map(|o| {
                    UpInput::new(
                        TransactionOutpoint::new(UpHash::from_bytes(o.transaction_id), o.index),
                        vec![],
                        0,
                        0,
                    )
                })
                .collect(),
            ids.iter()
                .enumerate()
                .map(|(j, b)| {
                    UpOutput::with_covenant(
                        500 + j as u64,
                        ScriptPublicKey::from_vec(0, spk.clone()),
                        b.map(|(input, id)| CovenantBinding {
                            authorizing_input: input,
                            covenant_id: UpHash::from_bytes(id),
                        }),
                    )
                })
                .collect(),
            0,
            UP_NATIVE,
            0,
            vec![],
        );
        let entries = s
            .coins
            .iter()
            .map(|c| {
                UtxoEntry::new(
                    1_000,
                    ScriptPublicKey::from_vec(0, spk.clone()),
                    0,
                    false,
                    c.map(UpHash::from_bytes),
                )
            })
            .collect();
        let theirs = CovenantsContext::from_tx(&PopulatedTransaction::new(&up_tx, entries))
            .err()
            .map(|e| format!("{e:?}"));

        let our_inputs: Vec<ours::TransactionInput<'_>> = outpoints
            .iter()
            .map(|o| ours::TransactionInput {
                previous_outpoint: *o,
                sequence: 0,
                sig_op_count: 0,
                compute_budget: 0,
                signature_script: &[],
                utxo_entry: ours::UtxoEntry {
                    amount: 1_000,
                    script_public_key: ours::ScriptPublicKey {
                        version: 0,
                        script: &spk,
                    },
                },
            })
            .collect();
        let our_outputs: Vec<ours::TransactionOutput<'_>> = ids
            .iter()
            .enumerate()
            .map(|(j, b)| ours::TransactionOutput {
                value: 500 + j as u64,
                script_public_key: ours::ScriptPublicKey {
                    version: 0,
                    script: &spk,
                },
                covenant: b.map(|(input, id)| ours::CovenantBinding {
                    authorizing_input: input,
                    covenant_id: id,
                }),
            })
            .collect();
        let tx = ours::Transaction {
            version: 1,
            inputs: &our_inputs,
            outputs: &our_outputs,
            lock_time: 0,
            subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        };
        let mine = tx.check_covenant_ids(&s.coins).err().map(|e| match e {
            ours::TxRuleError::WrongGenesisCovenantId(i, id) => {
                format!("WrongGenesisCovenantId({i}, {:?})", UpHash::from_bytes(id))
            }
            other => format!("{other:?}"),
        });
        assert_eq!(mine, theirs, "{}", s.name);
        if mine.is_some() {
            refused.push(s.name);
        }
    }
    assert_eq!(
        refused,
        [
            "a wrong id",
            "a continuation claimed by a coin bound to none",
            "an authorizing input past the last"
        ]
    );
}

/// Multisig redeem scripts built by upstream parse back to the same m and n.
/// A 0-of-n has a multisig's shape but needs no signature: not a multisig.
#[test]
fn multisig_agrees_with_upstream() {
    for (m, n) in [
        (0usize, 1usize),
        (1, 1),
        (2, 3),
        (3, 5),
        (1, 16),
        (16, 16),
        (1, 17),
        (17, 17),
        (0, 20),
        (20, 20),
    ] {
        let keys: Vec<[u8; 32]> = (0..n).map(|i| [i as u8; 32]).collect();
        let script = multisig_redeem_script(keys.iter(), m).expect("upstream builds it");

        let shaped = multisig_shape(&script).unwrap_or_else(|| panic!("{m}-of-{n} not shaped"));
        let parsed = parse_multisig(&script);
        if m == 0 {
            assert!(parsed.is_none(), "0-of-{n} called a multisig");
        } else {
            assert_eq!(parsed, Some(shaped), "{m}-of-{n}");
        }
        let parsed = shaped;
        assert_eq!(parsed.required as usize, m);
        assert_eq!(parsed.total as usize, n);

        let got: Vec<&[u8]> = parsed.keys().collect();
        assert_eq!(got.len(), n, "{m}-of-{n} lost keys");
        for (i, k) in got.iter().enumerate() {
            assert_eq!(*k, &keys[i][..], "{m}-of-{n} key {i} came back wrong");
        }
    }
}

/// A redeem script matches its lock under version 0 only, and another
/// redeem script never does.
#[test]
fn a_redeem_script_matches_under_its_version() {
    use kaspa_txscript::pay_to_script_hash_script;
    use kassigner_kaspa::script::redeem_matches;
    use kassigner_kaspa::tx::ScriptPublicKey as OurSpk;

    let keys: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
    let redeem = multisig_redeem_script(keys.iter(), 2).expect("upstream builds it");
    let lock = pay_to_script_hash_script(&redeem);
    assert_eq!(lock.version(), 0);
    let under = |version| OurSpk {
        version,
        script: lock.script(),
    };
    assert!(redeem_matches(&under(0), &redeem));
    assert!(!redeem_matches(&under(1), &redeem), "another version");
    let other = multisig_redeem_script(keys.iter(), 3).expect("upstream builds it");
    assert!(!redeem_matches(&under(0), &other), "another redeem script");
}

/// KCC-3's redeem script, lock and address are upstream's for the same key.
/// `tests/kcc3.rs` holds a seed's vector.
#[test]
fn a_kcc3_lock_and_address_are_upstreams() {
    use kaspa_txscript::script_builder::ScriptBuilder;
    use kaspa_txscript::{extract_script_pub_key_address, pay_to_script_hash_script};
    use kassigner_kaspa::script::{kcc3_key, kcc3_redeem, kcc3_script_hash};

    let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    let theirs = ScriptBuilder::new()
        .add_data(&key)
        .unwrap()
        .add_op(up_codes::OpCheckSig)
        .unwrap()
        .drain();
    assert_eq!(&theirs[..], &kcc3_redeem(&key)[..]);
    assert_eq!(kcc3_key(&theirs), Some(&key[..]));

    let lock = pay_to_script_hash_script(&theirs);
    assert_eq!(&lock.script()[2..34], &kcc3_script_hash(&key)[..]);
    let address = extract_script_pub_key_address(&lock, UpPrefix::Mainnet).expect("an address");
    let mut text = [0u8; MAX_ADDRESS_LEN];
    let n = encode(
        Prefix::Mainnet,
        Version::ScriptHash,
        &kcc3_script_hash(&key),
        &mut text,
    )
    .expect("encode");
    assert_eq!(
        address.to_string(),
        core::str::from_utf8(&text[..n]).unwrap()
    );
}

/// The scripts paying a key and a script hash are upstream's.
#[test]
fn the_paying_scripts_are_upstreams() {
    use kaspa_txscript::{pay_to_address_script, pay_to_script_hash_script};
    use kassigner_kaspa::script::{pay_to_pubkey, pay_to_script_hash, redeem_hash};

    let key: [u8; 32] = core::array::from_fn(|i| (i * 5 + 1) as u8);
    let theirs = pay_to_address_script(&UpAddress::new(UpPrefix::Mainnet, UpVersion::PubKey, &key));
    assert_eq!(theirs.version(), 0);
    assert_eq!(theirs.script(), &pay_to_pubkey(&key)[..]);

    let keys: Vec<[u8; 32]> = (0..3).map(|i| [i as u8 + 1; 32]).collect();
    let redeem = multisig_redeem_script(keys.iter(), 2).expect("upstream builds it");
    let lock = pay_to_script_hash_script(&redeem);
    assert_eq!(lock.version(), 0);
    assert_eq!(
        lock.script(),
        &pay_to_script_hash(&redeem_hash(&redeem))[..]
    );
}

/// The address a locking script pays is upstream's, and both refuse a
/// non-standard script and a standard one past version 0.
#[test]
fn the_address_of_a_script_is_upstreams() {
    use kaspa_consensus_core::tx::ScriptPublicKey as UpSpk;
    use kaspa_txscript::extract_script_pub_key_address;
    use kassigner_kaspa::script::{address_payload, pay_to_pubkey, pay_to_script_hash};
    use kassigner_kaspa::tx::ScriptPublicKey;

    let key: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    let mut ecdsa = vec![0x21u8];
    ecdsa.extend_from_slice(&[0x02]);
    ecdsa.extend_from_slice(&key);
    ecdsa.push(0xab);
    let scripts: Vec<Vec<u8>> = vec![
        pay_to_pubkey(&key).to_vec(),
        ecdsa,
        pay_to_script_hash(&key).to_vec(),
    ];
    for script in &scripts {
        let theirs =
            extract_script_pub_key_address(&UpSpk::from_vec(0, script.clone()), UpPrefix::Mainnet)
                .expect("upstream reads a standard script");
        let spk = ScriptPublicKey { version: 0, script };
        let (version, payload) = address_payload(&spk).expect("ours reads it");
        let mut text = [0u8; MAX_ADDRESS_LEN];
        let n = encode(Prefix::Mainnet, version, payload, &mut text).expect("encode");
        assert_eq!(
            theirs.to_string(),
            core::str::from_utf8(&text[..n]).unwrap()
        );
    }
    let covenant = vec![0x51u8, 0x87];
    assert!(extract_script_pub_key_address(
        &UpSpk::from_vec(0, covenant.clone()),
        UpPrefix::Mainnet
    )
    .is_err());
    assert!(address_payload(&ScriptPublicKey {
        version: 0,
        script: &covenant
    })
    .is_none());
    let versioned = UpSpk::from_vec(1, scripts[0].clone());
    assert!(extract_script_pub_key_address(&versioned, UpPrefix::Mainnet).is_err());
    assert!(address_payload(&ScriptPublicKey {
        version: 1,
        script: &scripts[0]
    })
    .is_none());
}

/// A version 0 transaction's id is upstream's, without the signature
/// scripts and the mass.
#[test]
fn the_transaction_id_is_upstreams() {
    use kaspa_consensus_core::hashing::tx::id as up_id;
    use kassigner_kaspa::sighash::transaction_id;

    let spk = vec![0x20u8; 34];
    let sig = vec![0x41u8; 66];
    let our_inputs: Vec<ours::TransactionInput<'_>> = (0..2)
        .map(|i| ours::TransactionInput {
            previous_outpoint: ours::Outpoint {
                transaction_id: [i as u8 + 1; 32],
                index: i as u32,
            },
            sequence: 7,
            sig_op_count: 1,
            compute_budget: 0,
            signature_script: &sig,
            utxo_entry: ours::UtxoEntry {
                amount: 1,
                script_public_key: ours::ScriptPublicKey {
                    version: 0,
                    script: &spk,
                },
            },
        })
        .collect();
    let our_outputs: Vec<ours::TransactionOutput<'_>> = (0..2)
        .map(|k| ours::TransactionOutput {
            value: 10_000_000 + k,
            script_public_key: ours::ScriptPublicKey {
                version: 0,
                script: &spk,
            },
            covenant: None,
        })
        .collect();
    let payload = vec![9u8; 5];
    let our_tx = ours::Transaction {
        version: 0,
        inputs: &our_inputs,
        outputs: &our_outputs,
        lock_time: 11,
        subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
        gas: 0,
        payload: &payload,
    };
    let up_inputs: Vec<UpInput> = (0..2)
        .map(|i| {
            UpInput::new(
                TransactionOutpoint::new(UpHash::from_bytes([i as u8 + 1; 32]), i as u32),
                sig.clone(),
                7,
                1,
            )
        })
        .collect();
    let up_outputs: Vec<UpOutput> = (0..2)
        .map(|k| UpOutput::new(10_000_000 + k, ScriptPublicKey::from_vec(0, spk.clone())))
        .collect();
    let up_tx = UpTransaction::new(0, up_inputs, up_outputs, 11, UP_NATIVE, 0, payload.clone());
    assert_eq!(transaction_id(&our_tx), Some(up_id(&up_tx).as_bytes()));
    up_tx.set_storage_mass(4_209);
    assert_eq!(
        transaction_id(&our_tx),
        Some(up_id(&up_tx).as_bytes()),
        "the mass is not in the id"
    );
    let mut unsigned = our_tx;
    let bare: Vec<ours::TransactionInput<'_>> = our_inputs
        .iter()
        .map(|i| ours::TransactionInput {
            signature_script: &[],
            ..*i
        })
        .collect();
    unsigned.inputs = &bare;
    assert_eq!(
        transaction_id(&unsigned),
        transaction_id(&our_tx),
        "the signature scripts are not in the id"
    );
}

/// One input of a version 1 transaction both sides build.
#[derive(Clone)]
struct V1In {
    id: [u8; 32],
    index: u32,
    sequence: u64,
    sig_ops: u8,
    budget: u16,
    unlock: Vec<u8>,
}

/// One output, its binding as (authorizing input, covenant id).
#[derive(Clone)]
struct V1Out {
    value: u64,
    version: u16,
    script: Vec<u8>,
    binding: Option<(u16, [u8; 32])>,
}

/// A transaction both sides build, of any version.
#[derive(Clone)]
struct V1Tx {
    version: u16,
    inputs: Vec<V1In>,
    outputs: Vec<V1Out>,
    lock_time: u64,
    subnetwork: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
}

/// `t`'s id, as this crate names it.
fn our_id(t: &V1Tx) -> Option<[u8; 32]> {
    use kassigner_kaspa::sighash::transaction_id;

    let spk = [0x51u8];
    let inputs: Vec<ours::TransactionInput<'_>> = t
        .inputs
        .iter()
        .map(|i| ours::TransactionInput {
            previous_outpoint: ours::Outpoint {
                transaction_id: i.id,
                index: i.index,
            },
            sequence: i.sequence,
            sig_op_count: i.sig_ops,
            compute_budget: i.budget,
            signature_script: &i.unlock,
            utxo_entry: ours::UtxoEntry {
                amount: 1,
                script_public_key: ours::ScriptPublicKey {
                    version: 0,
                    script: &spk,
                },
            },
        })
        .collect();
    let outputs: Vec<ours::TransactionOutput<'_>> = t
        .outputs
        .iter()
        .map(|o| ours::TransactionOutput {
            value: o.value,
            script_public_key: ours::ScriptPublicKey {
                version: o.version,
                script: &o.script,
            },
            covenant: o
                .binding
                .map(|(authorizing_input, covenant_id)| ours::CovenantBinding {
                    authorizing_input,
                    covenant_id,
                }),
        })
        .collect();
    transaction_id(&ours::Transaction {
        version: t.version,
        inputs: &inputs,
        outputs: &outputs,
        lock_time: t.lock_time,
        subnetwork_id: t.subnetwork,
        gas: t.gas,
        payload: &t.payload,
    })
}

/// `t` built with upstream's types, each input's compute budget its
/// commitment.
fn their_tx(t: &V1Tx) -> UpTransaction {
    let inputs = t
        .inputs
        .iter()
        .map(|i| {
            UpInput::new_with_compute_budget(
                TransactionOutpoint::new(UpHash::from_bytes(i.id), i.index),
                i.unlock.clone(),
                i.sequence,
                i.budget,
            )
        })
        .collect();
    let outputs = t
        .outputs
        .iter()
        .map(|o| {
            UpOutput::with_covenant(
                o.value,
                ScriptPublicKey::from_vec(o.version, o.script.clone()),
                o.binding.map(|(authorizing_input, id)| CovenantBinding {
                    authorizing_input,
                    covenant_id: UpHash::from_bytes(id),
                }),
            )
        })
        .collect();
    UpTransaction::new(
        t.version,
        inputs,
        outputs,
        t.lock_time,
        UpSubnetworkId::from_bytes(t.subnetwork),
        t.gas,
        t.payload.clone(),
    )
}

/// A version 1 transaction's id is upstream's (`id_v1`, BLAKE3 over the
/// payload's digest and the rest's): upstream's vectors (`hashing/tx.rs`,
/// tests 10 to 14), then a sweep against `hashing::tx::id`. Signature
/// scripts, compute budgets, signature operation counts and mass are not in
/// it; the payload and every binding are. No id past version 1.
#[test]
fn the_version_1_transaction_id_is_upstreams() {
    use kaspa_consensus_core::hashing::tx::id as up_id;
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_REGISTRY as UP_REGISTRY;
    use std::collections::HashSet;
    use std::str::FromStr;

    let hex = |s: &str| UpHash::from_str(s).expect("a hash").as_bytes();
    let registry: &[u8] = UP_REGISTRY.as_ref();
    let registry: [u8; 20] = registry.try_into().unwrap();

    // Upstream's test 10: test 9's transaction under version 1.
    let ten = V1Tx {
        version: 1,
        inputs: vec![V1In {
            id: hex("59b3d6dc6cdc660c389c3fdb5704c48c598d279cdf1bab54182db586a4c95dd5"),
            index: 2,
            sequence: 7,
            sig_ops: 5,
            budget: 0,
            unlock: vec![1, 2],
        }],
        outputs: vec![V1Out {
            value: 1564,
            version: 7,
            script: vec![1, 2, 3, 4, 5],
            binding: None,
        }],
        lock_time: 54,
        subnetwork: registry,
        gas: 3,
        payload: vec![1, 2, 3],
    };
    assert_eq!(
        our_id(&ten),
        Some(hex(
            "a08a500b21be3e692c080b14e399fcfa2cfa01b25c08f2f8e7414d1c116e8d18"
        )),
        "upstream's test 10"
    );
    // Tests 11 to 14: one bare input, budget or signature operations 111 or
    // 222, one id; the empty payload is upstream's `ZERO_PAYLOAD_DIGEST`.
    for (sig_ops, budget) in [(0, 111), (0, 222), (111, 0), (222, 0)] {
        let bare = V1Tx {
            version: 1,
            inputs: vec![V1In {
                id: [0; 32],
                index: 0,
                sequence: 0,
                sig_ops,
                budget,
                unlock: vec![],
            }],
            outputs: vec![],
            lock_time: 0,
            subnetwork: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: vec![],
        };
        assert_eq!(
            our_id(&bare),
            Some(hex(
                "5978e7aa1a9ba8fdf12dae6aa39aa198a91985e91192b291e207d4d6246349e6"
            )),
            "upstream's tests 11 to 14: {sig_ops} {budget}"
        );
        assert_eq!(our_id(&bare), Some(up_id(&their_tx(&bare)).as_bytes()));
    }

    // The sweep: zero to two inputs, payloads of 0 to 300 bytes, outputs bound
    // or not, two subnetworks. Every case its own id.
    let scripts = covenant_scripts();
    let mut seen = HashSet::new();
    for inputs in 0..3usize {
        for len in [0usize, 1, 3, 300] {
            for bound in [false, true] {
                for (subnetwork, gas) in [(ours::SUBNETWORK_ID_NATIVE, 0), (registry, 3)] {
                    let t = V1Tx {
                        version: 1,
                        inputs: (0..inputs)
                            .map(|i| V1In {
                                id: [i as u8 + 0x21; 32],
                                index: 3 * i as u32,
                                sequence: u64::MAX - i as u64,
                                sig_ops: 0,
                                budget: 100 * (i as u16 + 1),
                                unlock: vec![0x41; 66],
                            })
                            .collect(),
                        outputs: (0..2usize)
                            .map(|k| V1Out {
                                value: 1_000_000 + k as u64,
                                version: k as u16 % 2,
                                script: scripts[k % scripts.len()].clone(),
                                binding: bound.then_some((k as u16, [0x5a + k as u8; 32])),
                            })
                            .collect(),
                        lock_time: 1_700_000_000 + inputs as u64,
                        subnetwork,
                        gas,
                        payload: (0..len).map(|b| b as u8).collect(),
                    };
                    let theirs = their_tx(&t);
                    let want = up_id(&theirs).as_bytes();
                    let name = format!("{inputs} inputs, {len} bytes, bound {bound}, gas {gas}");
                    assert_eq!(our_id(&t), Some(want), "{name}");
                    theirs.set_storage_mass(4_209);
                    assert_eq!(our_id(&t), Some(up_id(&theirs).as_bytes()), "{name}");
                    assert!(seen.insert(want), "{name}: an id twice");
                }
            }
        }
    }

    // What is not in it, and what is.
    let mut same = ten.clone();
    same.inputs[0].unlock = vec![0x41; 66];
    same.inputs[0].budget = 900;
    same.inputs[0].sig_ops = 0;
    assert_eq!(
        our_id(&same),
        our_id(&ten),
        "signing and mass are not in it"
    );
    let mut changed = Vec::new();
    let mut t = ten.clone();
    t.payload[2] ^= 1;
    changed.push(t);
    let mut t = ten.clone();
    t.payload.clear();
    changed.push(t);
    let mut t = ten.clone();
    t.outputs[0].binding = Some((0, [7; 32]));
    changed.push(t.clone());
    t.outputs[0].binding = Some((1, [7; 32]));
    changed.push(t.clone());
    t.outputs[0].binding = Some((0, [8; 32]));
    changed.push(t);
    for t in &changed {
        let id = our_id(t);
        assert_ne!(id, our_id(&ten));
        assert_eq!(id, Some(up_id(&their_tx(t)).as_bytes()));
    }

    let mut two = ten.clone();
    two.version = 2;
    assert_eq!(our_id(&two), None, "no id for a version no node accepts");
}

/// More keys than upstream's engine accepts is not a multisig.
#[test]
fn multisig_past_the_engine_limit_is_not_recognised() {
    let keys: Vec<[u8; 32]> = (0..21).map(|i| [i as u8; 32]).collect();
    let script = multisig_redeem_script(keys.iter(), 2).expect("upstream builds it");
    assert!(parse_multisig(&script).is_none());
}

/// A declared key count that disagrees with the keys is not a multisig: a
/// script must not describe itself to its signer.
#[test]
fn multisig_declared_count_is_checked_not_trusted() {
    let keys: Vec<[u8; 32]> = (0..3).map(|i| [i as u8; 32]).collect();
    let mut script = multisig_redeem_script(keys.iter(), 2).unwrap();

    // Claim four keys while carrying three.
    let n = script.len();
    script[n - 2] += 1;
    assert!(
        parse_multisig(&script).is_none(),
        "a lying key count was believed"
    );
}

// ── Mass ─────────────────────────────────────────────────────────────────────

use kaspa_consensus_core::mass::{calc_storage_mass, UtxoCell as UpCell};
use kassigner_kaspa::mass::{
    estimated_serialized_size, non_contextual_masses, plurality, storage_mass, Cell, MassRates,
};

/// Serialized size, compute and transient mass agree with upstream on both
/// versions.
#[test]
fn mass_agrees_with_upstream() {
    use kaspa_consensus_core::config::params::MAINNET_PARAMS;
    use kaspa_consensus_core::mass::MassCalculator;
    use kaspa_consensus_core::tx::{
        ScriptPublicKey, Transaction as UpTransaction, TransactionInput as UpInput,
        TransactionOutpoint, TransactionOutput as UpOutput,
    };
    use kaspa_hashes::Hash as UpHash;

    let calc = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
    let spk: Vec<u8> = vec![0xAA; 34];
    let payload: Vec<u8> = vec![0x11; 5];
    let sig_script: Vec<u8> = vec![0xBB; 66];

    for version in [0u16, 1u16] {
        for (n_in, n_out) in [(1usize, 1usize), (2, 3), (5, 2)] {
            let our_inputs: Vec<ours::TransactionInput> = (0..n_in)
                .map(|i| ours::TransactionInput {
                    previous_outpoint: ours::Outpoint {
                        transaction_id: [i as u8; 32],
                        index: i as u32,
                    },
                    sequence: 0,
                    sig_op_count: 1,
                    compute_budget: if version >= 1 { 3 } else { 0 },
                    signature_script: &sig_script,
                    utxo_entry: ours::UtxoEntry {
                        amount: 100_000_000,
                        script_public_key: ours::ScriptPublicKey {
                            version: 0,
                            script: &spk,
                        },
                    },
                })
                .collect();
            let our_outputs: Vec<ours::TransactionOutput> = (0..n_out)
                .map(|_| ours::TransactionOutput {
                    value: 10_000_000,
                    script_public_key: ours::ScriptPublicKey {
                        version: 0,
                        script: &spk,
                    },
                    covenant: None,
                })
                .collect();
            let our_tx = ours::Transaction {
                version,
                inputs: &our_inputs,
                outputs: &our_outputs,
                lock_time: 0,
                subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
                gas: 0,
                payload: &payload,
            };

            let up_inputs: Vec<UpInput> = (0..n_in)
                .map(|i| {
                    let outpoint =
                        TransactionOutpoint::new(UpHash::from_bytes([i as u8; 32]), i as u32);
                    // `new` takes a sigop count, `new_with_compute_budget` a
                    // budget.
                    if version >= 1 {
                        UpInput::new_with_compute_budget(outpoint, sig_script.clone(), 0, 3)
                    } else {
                        UpInput::new(outpoint, sig_script.clone(), 0, 1)
                    }
                })
                .collect();
            let up_outputs: Vec<UpOutput> = (0..n_out)
                .map(|_| UpOutput::new(10_000_000, ScriptPublicKey::from_vec(0, spk.clone())))
                .collect();
            let up_tx = UpTransaction::new(
                version,
                up_inputs,
                up_outputs,
                0,
                kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE,
                0,
                payload.clone(),
            );

            let theirs = calc.calc_non_contextual_masses(&up_tx);
            let (compute, transient) =
                non_contextual_masses(&our_tx, &MassRates::MAINNET).expect("mainnet's rates");

            assert_eq!(
                estimated_serialized_size(&our_tx),
                kaspa_consensus_core::mass::transaction_estimated_serialized_size(&up_tx),
                "size, version {version}, {n_in} in {n_out} out"
            );
            assert_eq!(compute, theirs.compute_mass, "compute, version {version}");
            assert_eq!(
                transient, theirs.transient_mass,
                "transient, version {version}"
            );
        }
    }
}

/// Storage mass agrees with upstream on both formula paths.
#[test]
fn storage_mass_agrees_with_upstream() {
    let c = kassigner_kaspa::constants::STORAGE_MASS_PARAMETER;

    // (plurality, amount) per cell; named, as clippy objects inline.
    type Cells<'a> = &'a [(u64, u64)];
    let cases: &[(Cells, Cells)] = &[
        (&[(1, 100_000_000)], &[(1, 99_000_000)]), // 1 in 1 out
        (&[(1, 100_000_000), (1, 50_000_000)], &[(1, 149_000_000)]), // 2 in 1 out
        (&[(1, 100_000_000)], &[(1, 60_000_000), (1, 39_000_000)]), // 1 in 2 out
        (
            &[(1, 100_000_000), (1, 100_000_000)],
            &[(1, 99_000_000), (1, 100_000_000)],
        ), // 2 in 2 out
        (
            &[(1, 100_000_000), (1, 100_000_000), (1, 100_000_000)],
            &[(1, 99_000_000), (1, 100_000_000), (1, 100_000_000)],
        ), // general path
        (&[(2, 100_000_000)], &[(1, 99_000_000)]), // plurality > 1
    ];

    for (ins, outs) in cases {
        let ours_cells: Vec<Cell> = ins
            .iter()
            .map(|&(p, a)| Cell {
                plurality: p,
                amount: a,
            })
            .collect();
        let ours_outs: Vec<Cell> = outs
            .iter()
            .map(|&(p, a)| Cell {
                plurality: p,
                amount: a,
            })
            .collect();
        let up_ins: Vec<UpCell> = ins.iter().map(|&(p, a)| UpCell::new(p, a)).collect();
        let up_outs: Vec<UpCell> = outs.iter().map(|&(p, a)| UpCell::new(p, a)).collect();

        let theirs = calc_storage_mass(false, up_ins.into_iter(), up_outs.into_iter(), c);
        let ours_val = storage_mass(&ours_cells, &ours_outs, c);
        assert_eq!(theirs, ours_val, "{ins:?} -> {outs:?}");
    }
}

/// A transaction's storage mass, from the coins its inputs spend, is what
/// upstream's `calc_contextual_masses` finds for the populated transaction:
/// coins bound to a covenant or not, outputs bound or not, on both formula
/// paths.
#[test]
fn a_transactions_storage_mass_agrees_with_upstream() {
    use kaspa_consensus_core::config::params::MAINNET_PARAMS;
    use kaspa_consensus_core::mass::MassCalculator;
    use kaspa_consensus_core::tx::{
        CovenantBinding as UpBinding, PopulatedTransaction, ScriptPublicKey,
        Transaction as UpTransaction, TransactionInput as UpInput, TransactionOutpoint,
        TransactionOutput as UpOutput, UtxoEntry,
    };
    use kaspa_hashes::Hash as UpHash;
    use kassigner_kaspa::mass::transaction_storage_mass;

    let calc = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
    let c = kassigner_kaspa::constants::STORAGE_MASS_PARAMETER;
    let p2pk: Vec<u8> = vec![0xAA; 34];
    let p2sh: Vec<u8> = vec![0xAB; 35];
    const ID: [u8; 32] = [0x77; 32];

    // (amount, the script is a script hash, bound to a covenant)
    type Side<'a> = &'a [(u64, bool, bool)];
    let cases: &[(&str, Side, Side)] = &[
        (
            "1 in 1 out, unbound",
            &[(100_000_000, false, false)],
            &[(99_000_000, false, false)],
        ),
        (
            "1 in 1 out, the coin bound",
            &[(100_000_000, false, true)],
            &[(99_000_000, false, false)],
        ),
        (
            "a small coin, unbound: over the limit",
            &[(100_000, false, false)],
            &[(90_000, false, false)],
        ),
        (
            "the same coin bound: under it",
            &[(100_000, false, true)],
            &[(90_000, false, false)],
        ),
        (
            "a bound script-hash coin continued",
            &[(500_000_000, true, true)],
            &[(300_000_000, true, true), (199_000_000, false, false)],
        ),
        (
            "2 in 2 out, one coin bound: the general path",
            &[(100_000_000, false, true), (100_000_000, false, false)],
            &[(99_000_000, false, false), (100_000_000, false, false)],
        ),
        (
            "2 in 2 out, unbound: the relaxed path",
            &[(100_000_000, false, false), (100_000_000, false, false)],
            &[(99_000_000, false, false), (100_000_000, false, false)],
        ),
        (
            "3 in 3 out, mixed",
            &[
                (100_000_000, false, true),
                (50_000_000, true, false),
                (2_000_000, true, true),
            ],
            &[
                (100_000_000, false, false),
                (50_000_000, true, true),
                (1_000_000, false, true),
            ],
        ),
    ];

    let mut over = Vec::new();
    for (name, ins, outs) in cases {
        let script = |hash: bool| if hash { &p2sh } else { &p2pk };
        let up_tx = UpTransaction::new(
            1,
            (0..ins.len() as u32)
                .map(|i| {
                    UpInput::new(
                        TransactionOutpoint::new(UpHash::from_bytes([1; 32]), i),
                        vec![],
                        0,
                        0,
                    )
                })
                .collect(),
            outs.iter()
                .map(|&(value, hash, bound)| {
                    UpOutput::with_covenant(
                        value,
                        ScriptPublicKey::from_vec(0, script(hash).clone()),
                        bound.then(|| UpBinding {
                            authorizing_input: 0,
                            covenant_id: UpHash::from_bytes(ID),
                        }),
                    )
                })
                .collect(),
            0,
            UP_NATIVE,
            0,
            vec![],
        );
        let entries = ins
            .iter()
            .map(|&(amount, hash, bound)| {
                UtxoEntry::new(
                    amount,
                    ScriptPublicKey::from_vec(0, script(hash).clone()),
                    0,
                    false,
                    bound.then(|| UpHash::from_bytes(ID)),
                )
            })
            .collect();
        let theirs = calc
            .calc_contextual_masses(&PopulatedTransaction::new(&up_tx, entries))
            .map(|m| m.storage_mass);

        let our_inputs: Vec<ours::TransactionInput<'_>> = ins
            .iter()
            .enumerate()
            .map(|(i, &(amount, hash, _))| ours::TransactionInput {
                previous_outpoint: ours::Outpoint {
                    transaction_id: [1; 32],
                    index: i as u32,
                },
                sequence: 0,
                sig_op_count: 0,
                compute_budget: 0,
                signature_script: &[],
                utxo_entry: ours::UtxoEntry {
                    amount,
                    script_public_key: ours::ScriptPublicKey {
                        version: 0,
                        script: script(hash),
                    },
                },
            })
            .collect();
        let our_outputs: Vec<ours::TransactionOutput<'_>> = outs
            .iter()
            .map(|&(value, hash, bound)| ours::TransactionOutput {
                value,
                script_public_key: ours::ScriptPublicKey {
                    version: 0,
                    script: script(hash),
                },
                covenant: bound.then_some(ours::CovenantBinding {
                    authorizing_input: 0,
                    covenant_id: ID,
                }),
            })
            .collect();
        let tx = ours::Transaction {
            version: 1,
            inputs: &our_inputs,
            outputs: &our_outputs,
            lock_time: 0,
            subnetwork_id: ours::SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: &[],
        };
        let coins: Vec<Option<[u8; 32]>> = ins.iter().map(|&(_, _, b)| b.then_some(ID)).collect();
        let mine = transaction_storage_mass(&tx, &coins, c);
        assert_eq!(mine, theirs, "{name}");
        // With the coins' covenants left out, every coin counts as unbound.
        if ins.iter().all(|&(_, _, bound)| !bound) {
            assert_eq!(transaction_storage_mass(&tx, &[], c), theirs, "{name}");
        }
        if mine.is_some_and(|m| m > kassigner_kaspa::mass::BLOCK_STORAGE_MASS_LIMIT) {
            over.push(*name);
        }
    }
    assert_eq!(
        over,
        ["a small coin, unbound: over the limit", "3 in 3 out, mixed"]
    );
}

/// On the general path a mean input under one sompi, and a product past
/// `u64`, have upstream's mass: it floors the mean at one and saturates.
#[test]
fn storage_mass_on_the_general_path_is_upstreams_at_its_edges() {
    let c = kassigner_kaspa::constants::STORAGE_MASS_PARAMETER;
    type Cells<'a> = &'a [(u64, u64)];
    let cases: &[(Cells, Cells, u64)] = &[
        // Three inputs worth nothing: a mean of zero.
        (&[(1, 0), (1, 0), (1, 0)], &[(1, 1_000), (1, 2_000)], c),
        // Worth two sompi over three units of storage.
        (
            &[(1, 1), (1, 1), (1, 0)],
            &[(1, 1_000), (1, 2_000), (1, 3_000)],
            c,
        ),
        // A mean of one under the largest parameter: three times it.
        (
            &[(1, 1), (1, 1), (1, 1)],
            &[(1, u64::MAX), (1, u64::MAX)],
            u64::MAX,
        ),
    ];
    for &(ins, outs, param) in cases {
        let cells = |v: Cells| -> Vec<Cell> {
            v.iter()
                .map(|&(p, a)| Cell {
                    plurality: p,
                    amount: a,
                })
                .collect()
        };
        let theirs = calc_storage_mass(
            false,
            ins.iter()
                .map(|&(p, a)| UpCell::new(p, a))
                .collect::<Vec<_>>()
                .into_iter(),
            outs.iter().map(|&(p, a)| UpCell::new(p, a)),
            param,
        );
        assert!(
            theirs.is_some(),
            "{ins:?} -> {outs:?}: upstream has a number"
        );
        assert_eq!(
            storage_mass(&cells(ins), &cells(outs), param),
            theirs,
            "{ins:?} -> {outs:?}"
        );
    }
}

/// No transaction the network accepts reaches the relaxed path's overflow.
///
/// Upstream computes `C * p * p / amount` unchecked
/// (`consensus/core/src/mass/mod.rs`), on a bound its
/// `verify_utxo_plurality_limits` test proves. This is that proof here,
/// against upstream's `Params`, so a change to the script limit or storage
/// parameter fails here, not on a device; and why this crate's checked
/// product refuses only what the network never accepts.
#[test]
fn the_relaxed_path_product_cannot_overflow() {
    use kaspa_consensus_core::config::params::Params;
    use kaspa_consensus_core::network::NetworkType;

    for net in [
        NetworkType::Mainnet,
        NetworkType::Testnet,
        NetworkType::Devnet,
        NetworkType::Simnet,
    ] {
        let params: Params = net.into();
        // The script limit, or what a block's compute budget pays for,
        // whichever binds first.
        let max_spk_len = (params.max_script_public_key_len as u64).min(
            params
                .block_mass_limits
                .compute
                .div_ceil(params.mass_per_script_pub_key_byte),
        );
        let max_plurality = plurality(max_spk_len as usize, true);
        let c = params.storage_mass_parameter;
        assert!(
            c.checked_mul(max_plurality)
                .and_then(|x| x.checked_mul(max_plurality))
                .is_some(),
            "{net:?}: C={c} and plurality={max_plurality} overflow the product"
        );

        // And our parameter is the one that bound was computed against.
        assert_eq!(
            c,
            kassigner_kaspa::constants::STORAGE_MASS_PARAMETER,
            "{net:?}: storage mass parameter"
        );
    }

    // Plurality 4,295 overflows. A KSPT script, capped at 512 bytes, is
    // plurality 7 with a covenant.
    let c = kassigner_kaspa::constants::STORAGE_MASS_PARAMETER;
    let first_overflow =
        (1u64..).find(|p| c.checked_mul(*p).and_then(|x| x.checked_mul(*p)).is_none());
    assert_eq!(first_overflow, Some(4_295));
    assert_eq!(plurality(512, true), 7);

    // Past the ceiling, no mass, not a wrapped one or a panic.
    let out = [Cell {
        plurality: 1,
        amount: 100_000_000,
    }];
    let input = |plurality| Cell {
        plurality,
        amount: 1,
    };
    assert_eq!(storage_mass(&[input(4_295)], &out, c), None);
    assert!(storage_mass(&[input(4_294)], &out, c).is_some());
    assert_eq!(
        storage_mass(&[input(u64::MAX), input(1)], &out, c),
        None,
        "the inputs' plurality overflowing"
    );
}

/// Plurality agrees with upstream, including the covenant case.
#[test]
fn plurality_agrees_with_upstream() {
    use kaspa_consensus_core::mass::utxo_plurality;
    use kaspa_consensus_core::tx::ScriptPublicKey;

    for len in [0usize, 33, 34, 37, 38, 100, 200, 512] {
        for covenant in [false, true] {
            let spk = ScriptPublicKey::from_vec(0, vec![0u8; len]);
            assert_eq!(
                plurality(len, covenant),
                utxo_plurality(&spk, covenant),
                "script len {len}, covenant {covenant}"
            );
        }
    }
}

// ── BIP32 public derivation ──────────────────────────────────────────────────

use kassigner_kaspa::bip32_public::{
    fingerprint as our_fingerprint, Bip32Error, ChildNumber, ExtendedPublicKey, Prefix as XPrefix,
    HARDENED_OFFSET,
};

/// Public derivation agrees with upstream at each level of a chain, where a
/// swapped chain code and key would diverge.
#[test]
fn public_derivation_agrees_with_upstream() {
    use kaspa_bip32::{ChildNumber as UpChild, ExtendedPrivateKey, SecretKey};

    // From a private key, so upstream gives a matching extended public key; the
    // private half never reaches our crate.
    let seed = [0x2Au8; 32];
    let xprv = ExtendedPrivateKey::<SecretKey>::new(seed).expect("upstream xprv");
    let up_root = xprv.public_key();

    let mut ours = ExtendedPublicKey {
        public_key: {
            let mut k = [0u8; 33];
            k.copy_from_slice(&up_root.public_key.serialize());
            k
        },
        chain_code: {
            let mut c = [0u8; 32];
            c.copy_from_slice(&up_root.attrs.chain_code);
            c
        },
        depth: up_root.attrs.depth,
        parent_fingerprint: up_root.attrs.parent_fingerprint,
        child_number: ChildNumber(up_root.attrs.child_number.into()),
    };
    let mut theirs = up_root;

    for index in [0u32, 1, 7, 1000, 0x7FFF_FFFF] {
        theirs = theirs
            .derive_child(UpChild::new(index, false).unwrap())
            .expect("upstream derives");
        ours = ours.derive_child(ChildNumber(index)).expect("we derive");

        assert_eq!(
            ours.public_key,
            theirs.public_key.serialize(),
            "public key diverged at index {index}"
        );
        assert_eq!(
            ours.chain_code,
            theirs.attrs.chain_code.as_slice(),
            "chain code diverged at index {index}"
        );
        assert_eq!(ours.depth, theirs.attrs.depth, "depth at {index}");
        assert_eq!(
            ours.parent_fingerprint, theirs.attrs.parent_fingerprint,
            "parent fingerprint at {index}"
        );
    }
}

/// Hardened derivation needs the private key: refused, not approximated.
#[test]
fn hardened_derivation_is_refused() {
    let xpub = ExtendedPublicKey {
        public_key: [2u8; 33],
        chain_code: [7u8; 32],
        depth: 0,
        parent_fingerprint: [0u8; 4],
        child_number: ChildNumber(0),
    };
    assert_eq!(
        xpub.derive_child(ChildNumber(HARDENED_OFFSET)),
        Err(Bip32Error::HardenedFromPublic)
    );
    assert_eq!(
        xpub.derive_child(ChildNumber(u32::MAX)),
        Err(Bip32Error::HardenedFromPublic)
    );
}

/// The fingerprint is `RIPEMD160(SHA256(key))[..4]`, as upstream computes it.
#[test]
fn fingerprint_agrees_with_upstream() {
    use kaspa_bip32::{ExtendedPrivateKey, SecretKey};

    let xprv = ExtendedPrivateKey::<SecretKey>::new([0x5Cu8; 32]).unwrap();
    let up = xprv.public_key();
    let mut key = [0u8; 33];
    key.copy_from_slice(&up.public_key.serialize());

    use kaspa_bip32::PublicKey as _;
    assert_eq!(our_fingerprint(&key), up.public_key.fingerprint());
}

/// Serialization round-trips with its network prefix. The key is the
/// generator, as reading one requires a point.
#[test]
fn extended_key_serialization_round_trips() {
    let generator: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    assert!(kaspa_bip32::secp256k1::PublicKey::from_slice(&generator).is_ok());
    let xpub = ExtendedPublicKey {
        public_key: generator,
        chain_code: [9u8; 32],
        depth: 4,
        parent_fingerprint: [1, 2, 3, 4],
        child_number: ChildNumber(42),
    };
    for prefix in [XPrefix::Kpub, XPrefix::Ktub] {
        let mut buf = [0u8; 78];
        let n = xpub.serialize(prefix, &mut buf).unwrap();
        assert_eq!(n, 78);
        let (got_prefix, got) = ExtendedPublicKey::deserialize(&buf).unwrap();
        assert_eq!(got_prefix, prefix);
        assert_eq!(got, xpub);
    }
}

// ── BIP340 ───────────────────────────────────────────────────────────────────

use kassigner_kaspa::bip340;

/// A BIP340 reference vector, recomputed from the specification.
#[test]
fn bip340_reference_vector() {
    let pk: [u8; 32] =
        unhex_array("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
    let msg: [u8; 32] =
        unhex_array("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    let sig: [u8; 64] = unhex_array(
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341\
         8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    );

    assert!(bip340::verify(&pk, &msg, &sig), "reference vector rejected");

    // Every single-bit change to any input must break it.
    for i in 0..32 {
        let mut m = msg;
        m[i] ^= 1;
        assert!(!bip340::verify(&pk, &m, &sig), "message bit {i} ignored");
    }
    for i in 0..64 {
        let mut t = sig;
        t[i] ^= 1;
        assert!(!bip340::verify(&pk, &msg, &t), "signature bit {i} ignored");
    }
    for i in 0..32 {
        let mut k = pk;
        k[i] ^= 1;
        assert!(!bip340::verify(&k, &msg, &sig), "key bit {i} ignored");
    }
}

/// Signatures from upstream's signing library verify here.
#[test]
fn bip340_accepts_signatures_from_upstreams_library() {
    use secp256k1::{Keypair, Message, Secp256k1};

    let secp = Secp256k1::new();
    for seed in 1u8..=8 {
        let kp = Keypair::from_seckey_slice(&secp, &[seed; 32]).expect("valid key");
        let (xonly, _) = kp.x_only_public_key();

        for m in 0u8..4 {
            let digest = [m.wrapping_mul(37).wrapping_add(11); 32];
            let msg = Message::from_digest(digest);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);

            assert!(
                bip340::verify(&xonly.serialize(), &digest, sig.as_ref()),
                "rejected a signature the reference library produced (seed {seed}, msg {m})"
            );

            // And it must not accept it for a different message.
            let mut other = digest;
            other[0] ^= 0xFF;
            assert!(!bip340::verify(&xonly.serialize(), &other, sig.as_ref()));
        }
    }
}

/// Malformed inputs return false rather than panicking.
#[test]
fn bip340_malformed_inputs_are_false_not_a_panic() {
    let zero32 = [0u8; 32];
    let zero64 = [0u8; 64];
    // All-zero x coordinate is not a point on the curve.
    assert!(!bip340::verify(&zero32, &zero32, &zero64));
    // Field-overflowing x coordinate.
    let mut big = [0xFFu8; 32];
    assert!(!bip340::verify(&big, &zero32, &zero64));
    big[31] = 0x2E;
    assert!(!bip340::verify(&big, &zero32, &zero64));
}

/// Whether 32 bytes are a public key, as upstream's signing library reads
/// them: on and off the curve, around the field's prime, and real keys.
#[test]
fn bip340_public_keys_are_upstreams() {
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    let theirs = |x: &[u8; 32]| XOnlyPublicKey::from_slice(x).is_ok();
    let mut xs: Vec<[u8; 32]> = Vec::new();
    for last in 0..=255u8 {
        let mut x = [0u8; 32];
        x[31] = last;
        xs.push(x);
        let mut y = [0x5au8; 32];
        y[31] = last;
        xs.push(y);
    }
    // p is FF..FF FFFFFFFE FFFFFC2F: p - 2 to p + 2, and the all-ones.
    for last in 0x2d..=0x31u8 {
        let mut p = [0xffu8; 32];
        p[27] = 0xfe;
        p[30] = 0xfc;
        p[31] = last;
        xs.push(p);
    }
    xs.push([0xff; 32]);
    let secp = Secp256k1::new();
    for seed in 1u8..=16 {
        let kp = Keypair::from_seckey_slice(&secp, &[seed; 32]).expect("valid key");
        xs.push(kp.x_only_public_key().0.serialize());
    }

    let (mut on, mut off) = (0, 0);
    for x in &xs {
        let ours = bip340::is_public_key(x);
        assert_eq!(ours, theirs(x), "{x:02x?}");
        if ours {
            on += 1;
        } else {
            off += 1;
        }
    }
    assert!(on > 16 && off > 16, "both kinds seen: {on} on, {off} off");
}

// ── PSKB envelope and lexer ──────────────────────────────────────────────────

use kassigner_kaspa::pskb::{
    decode_envelope, decoded_len, encode_envelope, EnvelopeError, LexError, Lexer, Token,
};

/// A bundle upstream serialized decodes, tokenizes and re-encodes to the
/// same string: a byte changed would be a field silently rewritten.
#[test]
fn pskb_envelope_round_trips_an_upstream_bundle() {
    let bundle = upstream_bundle_string();
    let raw = bundle.as_bytes();

    let want = decoded_len(raw).expect("length");
    let mut json = vec![0u8; want];
    let n = decode_envelope(raw, &mut json).expect("decode");
    assert_eq!(n, want);

    // A bundle's top level is an array (`Bundle(pub Vec<PSKTInner>)`): one
    // envelope can carry several transactions.
    assert_eq!(json[0], b'[', "decoded body is not a JSON array");
    let text = core::str::from_utf8(&json[..n]).expect("valid utf-8");
    assert!(
        text.contains("inputs"),
        "no inputs field in the decoded bundle"
    );

    // Tokenizes end to end with no error, and the tokens balance.
    let mut lex = Lexer::new(&json[..n]);
    let (mut depth, mut count) = (0i32, 0usize);
    while let Some(tok) = lex.next_token() {
        match tok.expect("token") {
            Token::ObjectStart | Token::ArrayStart => depth += 1,
            Token::ObjectEnd | Token::ArrayEnd => depth -= 1,
            _ => {}
        }
        count += 1;
        assert!(depth >= 0, "unbalanced at token {count}");
    }
    assert_eq!(depth, 0, "document did not close");
    assert!(count > 20, "suspiciously few tokens: {count}");

    // And back to the same envelope, byte for byte.
    let mut out = vec![0u8; 4 + n * 2];
    let m = encode_envelope(&json[..n], &mut out).expect("encode");
    assert_eq!(
        &out[..m],
        raw,
        "re-encoded envelope differs from upstream's"
    );
}

/// `skip_value` measures a region without parsing it, so unknown fields are
/// copied back untouched.
#[test]
fn skip_value_measures_nested_regions() {
    let doc = br#"{"a":{"b":[1,2,{"c":null}],"d":"x"},"e":3}"#;
    let mut lex = Lexer::new(doc);

    assert_eq!(lex.next_token().unwrap().unwrap(), Token::ObjectStart);
    match lex.next_token().unwrap().unwrap() {
        Token::String { raw, .. } => assert_eq!(raw, b"a"),
        t => panic!("expected a key, got {t:?}"),
    }
    assert_eq!(lex.next_token().unwrap().unwrap(), Token::Colon);

    let (start, end) = lex.skip_value().expect("skip");
    assert_eq!(
        &doc[start..end],
        &br#"{"b":[1,2,{"c":null}],"d":"x"}"#[..],
        "skipped span is not the whole nested value"
    );
}

/// Malformed envelopes are refused, each for its own reason.
#[test]
fn pskb_envelope_refuses_malformed_input() {
    let mut out = [0u8; 64];
    assert_eq!(
        decode_envelope(b"PS", &mut out),
        Err(EnvelopeError::TooShort)
    );
    assert_eq!(
        decode_envelope(b"XSKB00", &mut out),
        Err(EnvelopeError::BadMagic)
    );
    assert_eq!(
        decode_envelope(b"PSKB000", &mut out),
        Err(EnvelopeError::OddLength)
    );
    assert_eq!(
        decode_envelope(b"PSKB00zz", &mut out),
        Err(EnvelopeError::BadHexChar)
    );
    // Either case, as upstream's `hex::decode` reads it.
    assert_eq!(decode_envelope(b"PSKB00AB", &mut out), Ok(2));
    assert_eq!(&out[..2], &[0x00, 0xab]);
    assert_eq!(decode_envelope(b"PSKB00ab", &mut out), Ok(2));
    assert_eq!(&out[..2], &[0x00, 0xab]);
    let mut tiny = [0u8; 1];
    assert_eq!(
        decode_envelope(b"PSKB0011223344", &mut tiny),
        Err(EnvelopeError::BufferTooSmall)
    );
}

/// A truncated string does not run off the end of the document.
#[test]
fn lexer_refuses_truncated_input() {
    let mut lex = Lexer::new(br#"{"unterminated"#);
    assert_eq!(lex.next_token().unwrap().unwrap(), Token::ObjectStart);
    assert!(matches!(
        lex.next_token().unwrap(),
        Err(LexError::Truncated { .. })
    ));

    // Control characters inside a string are refused, as JSON requires.
    let mut lex = Lexer::new(b"\"a\x01b\"");
    assert!(matches!(
        lex.next_token().unwrap(),
        Err(LexError::ControlInString { .. })
    ));
}

/// Build a real bundle with upstream's own serializer.
fn upstream_bundle_string() -> String {
    use kaspa_wallet_pskt::bundle::Bundle;
    use kaspa_wallet_pskt::pskt::PSKT;
    use kaspa_wallet_pskt::role::Creator;

    let pskt: PSKT<Creator> = PSKT::default();
    let bundle = Bundle::from(pskt.constructor());
    bundle.serialize().expect("upstream serializes")
}

// ── PSKB schema walk ─────────────────────────────────────────────────────────

use kassigner_kaspa::pskb::{walk, Field, ParseError, Scope, Span, Visitor};

/// Collects everything the walk reports, so a test can assert on it.
#[derive(Default)]
struct Collector {
    transactions: usize,
    fields: Vec<(Scope, Field)>,
    unknowns: Vec<(Scope, String)>,
}

impl Visitor for Collector {
    fn transaction(&mut self, _index: usize) -> Result<(), ParseError> {
        self.transactions += 1;
        Ok(())
    }
    fn field(&mut self, scope: Scope, field: Field, _value: Span) -> Result<(), ParseError> {
        self.fields.push((scope, field));
        Ok(())
    }
    fn unknown(&mut self, scope: Scope, _key: Span, _value: Span) -> Result<(), ParseError> {
        self.unknowns.push((scope, String::new()));
        Ok(())
    }
}

/// A bundle upstream produced walks cleanly, every global field known: one
/// in `unknowns` means upstream's schema moved.
#[test]
fn pskb_schema_walks_an_upstream_bundle() {
    let bundle = upstream_bundle_string();
    let mut json = vec![0u8; bundle.len()];
    let n = decode_envelope(bundle.as_bytes(), &mut json).expect("decode");
    let doc = &json[..n];

    let mut c = Collector::default();
    let count = walk(doc, &mut c).expect("walk");

    assert_eq!(count, 1, "one transaction expected in this bundle");
    assert_eq!(c.transactions, 1);
    assert!(!c.fields.is_empty(), "no fields recognised at all");

    // Everything upstream emitted at global scope is a field we know.
    let unknown_global = c
        .unknowns
        .iter()
        .filter(|(s, _)| *s == Scope::Global)
        .count();
    assert_eq!(
        unknown_global, 0,
        "upstream emitted a global field this parser does not recognise; \
         its schema has moved"
    );

    // The version and transaction version are always present.
    assert!(c.fields.contains(&(Scope::Global, Field::Version)));
    assert!(c.fields.contains(&(Scope::Global, Field::TxVersion)));
}

/// Unknown keys are reported with their value's exact span, to come back
/// out unaltered.
#[test]
fn unknown_fields_are_reported_with_their_exact_span() {
    struct Spans<'a> {
        doc: &'a [u8],
        seen: Vec<(String, String)>,
    }
    impl Visitor for Spans<'_> {
        fn unknown(&mut self, _s: Scope, key: Span, value: Span) -> Result<(), ParseError> {
            self.seen.push((
                String::from_utf8_lossy(key.of(self.doc)).into_owned(),
                String::from_utf8_lossy(value.of(self.doc)).into_owned(),
            ));
            Ok(())
        }
    }

    let doc = format!(
        r#"[{{"global":{{"version":0,"futureThing":{{"a":[1,2]}},{GLOBAL_REST}}},"inputs":[],"outputs":[]}}]"#
    );
    let doc = doc.as_bytes();
    let mut v = Spans {
        doc,
        seen: Vec::new(),
    };
    walk(doc, &mut v).expect("walk");

    assert_eq!(v.seen.len(), 1, "expected exactly one unknown");
    assert_eq!(v.seen[0].0, "futureThing");
    assert_eq!(
        v.seen[0].1, r#"{"a":[1,2]}"#,
        "unknown value span is not the whole nested value"
    );
}

/// What upstream requires of a global map besides its `version`.
const GLOBAL_REST: &str = r#""txVersion":0,"inputsModifiable":false,"outputsModifiable":false,"inputCount":0,"outputCount":0,"xpubs":{},"proprietaries":{},"payload":null"#;
/// What upstream requires of an input besides its `redeemScript`.
const INPUT_REST: &str = r#""previousOutpoint":{"transactionId":"0101010101010101010101010101010101010101010101010101010101010101","index":0},"partialSigs":{},"sighashType":1,"bip32Derivations":{},"finalScriptSig":null,"proprietaries":{}"#;
/// What upstream requires of an output besides its `amount` and
/// `redeemScript`.
const OUTPUT_REST: &str = r#""scriptPublicKey":"0000","bip32Derivations":{},"proprietaries":{}"#;

/// Inputs and outputs are numbered, and a key shared by both resolves in each.
#[test]
fn scopes_are_numbered_and_shared_keys_resolve() {
    let doc = format!(
        r#"[{{"global":{{"version":0,{GLOBAL_REST}}},"inputs":[{{"sequence":1,"redeemScript":"aa",{INPUT_REST}}},{{"sequence":2,"redeemScript":null,{INPUT_REST}}}],"outputs":[{{"amount":5,"redeemScript":"bb",{OUTPUT_REST}}}]}}]"#
    );
    let doc = doc.as_bytes();
    let mut c = Collector::default();
    walk(doc, &mut c).expect("walk");

    assert!(c.fields.contains(&(Scope::Input(0), Field::Sequence)));
    assert!(c.fields.contains(&(Scope::Input(1), Field::Sequence)));
    assert!(c.fields.contains(&(Scope::Output(0), Field::Amount)));
    // redeemScript is valid on both, and means the same thing in each.
    assert!(c.fields.contains(&(Scope::Input(0), Field::RedeemScript)));
    assert!(c.fields.contains(&(Scope::Output(0), Field::RedeemScript)));
    assert!(c.unknowns.is_empty(), "nothing here should be unknown");
}

/// A visitor can stop the walk, as a device does at its input limit.
#[test]
fn a_visitor_can_stop_the_walk() {
    struct MaxTwo(usize);
    impl Visitor for MaxTwo {
        fn field(&mut self, scope: Scope, _f: Field, _v: Span) -> Result<(), ParseError> {
            if let Scope::Input(i) = scope {
                if i >= self.0 {
                    return Err(ParseError::Rejected);
                }
            }
            Ok(())
        }
    }
    let input = |n: u32| format!(r#"{{"sequence":{n},"redeemScript":null,{INPUT_REST}}}"#);
    let doc = format!(
        r#"[{{"global":{{"version":0,{GLOBAL_REST}}},"inputs":[{},{},{}],"outputs":[]}}]"#,
        input(1),
        input(2),
        input(3)
    );
    let doc = doc.as_bytes();
    assert_eq!(walk(doc, &mut MaxTwo(2)), Err(ParseError::Rejected));
    assert!(walk(doc, &mut MaxTwo(9)).is_ok());
}

// ── PSKB emit ────────────────────────────────────────────────────────────────

use kassigner_kaspa::pskb::{
    emit, emitted_len, write_partial_sig, EmitError, Splice, PARTIAL_SIG_MEMBER_LEN,
};

/// With no splices, the document comes out byte for byte.
#[test]
fn emit_with_no_splices_is_the_identity() {
    let bundle = upstream_bundle_string();
    let mut json = vec![0u8; bundle.len()];
    let n = decode_envelope(bundle.as_bytes(), &mut json).expect("decode");
    let doc = &json[..n];

    let mut out = vec![0u8; n];
    let m = emit(doc, &[], &mut out).expect("emit");
    assert_eq!(m, n);
    assert_eq!(&out[..m], doc, "an empty edit changed the document");
}

/// A bundle a device edits is one upstream still accepts.
#[test]
fn an_edited_bundle_is_still_valid_upstream() {
    use kaspa_wallet_pskt::bundle::Bundle;

    let bundle = upstream_bundle_string();
    let mut json = vec![0u8; bundle.len()];
    let n = decode_envelope(bundle.as_bytes(), &mut json).expect("decode");
    let doc = &json[..n];

    // An unknown member at the start of the first object.
    let obj = doc.iter().position(|&c| c == b'{').expect("an object") + 1;
    let addition = br#""kassignerTouched":true,"#;
    let splices = [Splice::insert_at(obj, addition)];

    let want = emitted_len(doc, &splices).expect("length");
    let mut out = vec![0u8; want];
    let m = emit(doc, &splices, &mut out).expect("emit");
    assert_eq!(m, want);

    // Re-envelope and hand it back to upstream.
    let mut env = vec![0u8; 4 + m * 2];
    let e = encode_envelope(&out[..m], &mut env).expect("encode");
    let text = core::str::from_utf8(&env[..e]).expect("ascii");
    Bundle::deserialize(text).expect("upstream rejected a bundle we edited");

    // And everything after the insertion is untouched.
    assert_eq!(&out[obj + addition.len()..m], &doc[obj..n]);
}

/// Splices must be ordered and disjoint; others are refused, not sorted.
#[test]
fn overlapping_or_unordered_splices_are_refused() {
    let doc = b"0123456789";
    let mut out = [0u8; 64];

    // Out of order.
    let s = [Splice::insert_at(5, b"x"), Splice::insert_at(2, b"y")];
    assert_eq!(
        emit(doc, &s, &mut out),
        Err(EmitError::UnorderedOrOverlapping { index: 1 })
    );

    // Overlapping replacements.
    let s = [
        Splice {
            at: 1,
            len: 4,
            insert: b"x",
        },
        Splice {
            at: 3,
            len: 2,
            insert: b"y",
        },
    ];
    assert_eq!(
        emit(doc, &s, &mut out),
        Err(EmitError::UnorderedOrOverlapping { index: 1 })
    );

    // Past the end.
    let s = [Splice {
        at: 8,
        len: 5,
        insert: b"",
    }];
    assert_eq!(
        emit(doc, &s, &mut out),
        Err(EmitError::OutOfBounds { index: 0 })
    );

    // Adjacent but not overlapping is fine.
    let s = [
        Splice {
            at: 1,
            len: 2,
            insert: b"AA",
        },
        Splice {
            at: 3,
            len: 2,
            insert: b"BB",
        },
    ];
    let k = emit(doc, &s, &mut out).expect("adjacent splices are legal");
    assert_eq!(&out[..k], b"0AABB56789");
}

/// Several splices apply in one pass, and the untouched bytes stay put.
#[test]
fn multiple_splices_apply_in_one_pass() {
    let doc = br#"{"a":1,"b":2,"c":3}"#;
    // Offsets computed, not counted.
    let b_value = doc.windows(5).position(|w| w == br#""b":2"#).unwrap() + 4;
    let s = [
        Splice::insert_at(1, br#""z":0,"#),
        Splice {
            at: b_value,
            len: 1,
            insert: b"9",
        },
    ];
    let want = emitted_len(doc, &s).unwrap();
    let mut out = vec![0u8; want];
    let n = emit(doc, &s, &mut out).unwrap();
    assert_eq!(
        core::str::from_utf8(&out[..n]).unwrap(),
        r#"{"z":0,"a":1,"b":9,"c":3}"#
    );
}

/// A partial signature member has upstream's shape: the 33-byte key, then
/// the externally tagged Schnorr signature, no sighash byte. `tests/pskb.rs`
/// checks upstream reads a whole signed bundle.
#[test]
fn partial_sig_member_has_the_expected_shape() {
    let pk = [0xABu8; 33];
    let sig = [0xCDu8; 64];
    let mut out = [0u8; PARTIAL_SIG_MEMBER_LEN];
    let n = write_partial_sig(&pk, &sig, &mut out).expect("write");
    let want = format!(
        "\"{}\":{{\"schnorr\":\"{}\"}}",
        "ab".repeat(33),
        "cd".repeat(64)
    );
    assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);
    assert_eq!(n, PARTIAL_SIG_MEMBER_LEN);
    assert_eq!(
        write_partial_sig(&pk, &sig, &mut [0u8; PARTIAL_SIG_MEMBER_LEN - 1]),
        Err(EmitError::BufferTooSmall)
    );
}

// ── Multisig ─────────────────────────────────────────────────────────────────

use kassigner_kaspa::multisig::{
    check_threshold, cosigner_index, redeem_script, redeem_script_len, sort_cosigners,
    MultisigError, MAX_KEYS,
};

/// A redeem script built here is byte-identical to upstream's.
#[test]
fn redeem_script_matches_upstream() {
    use kaspa_txscript::standard::multisig_redeem_script;

    for (m, n) in [
        (0usize, 1usize),
        (1, 1),
        (1, 2),
        (2, 3),
        (3, 5),
        (1, 16),
        (16, 16),
        (17, 17),
        (1, 20),
        (20, 20),
        (5, 21),
        (130, 130),
        (256, 280),
    ] {
        let keys: Vec<[u8; 32]> = (0..n).map(|i| [(i * 7 + 3) as u8; 32]).collect();

        let theirs = multisig_redeem_script(keys.iter(), m).expect("upstream builds it");
        let mut ours = vec![0u8; redeem_script_len(m, n)];
        let w = redeem_script(m, &keys, &mut ours).expect("we build it");

        assert_eq!(w, theirs.len(), "{m}-of-{n} length");
        assert_eq!(&ours[..w], &theirs[..], "{m}-of-{n} bytes");
    }
}

/// A script we built is recognised by our own parser as the group it is.
#[test]
fn a_built_script_round_trips_through_recognition() {
    use kassigner_kaspa::script::parse_multisig;

    for (m, n) in [(2usize, 3usize), (18, MAX_KEYS)] {
        let keys: Vec<[u8; 32]> = (0..n).map(|i| [(i + 1) as u8; 32]).collect();
        let mut script = vec![0u8; redeem_script_len(m, n)];
        let w = redeem_script(m, &keys, &mut script).unwrap();

        let parsed = parse_multisig(&script[..w]).expect("recognised");
        assert_eq!(usize::from(parsed.required), m);
        assert_eq!(usize::from(parsed.total), n);
        let got: Vec<&[u8]> = parsed.keys().collect();
        let want: Vec<&[u8]> = keys.iter().map(|k| &k[..]).collect();
        assert_eq!(got, want);
    }
}

/// Sorting is a byte comparison of the base58 strings, so `Z` sorts before
/// `t`; the sorted position is the cosigner index, and so the address.
#[test]
fn sorting_is_a_byte_comparison_over_strings() {
    let mut keys = ["tAAA", "ZAAA", "9AAA", "aAAA"];
    sort_cosigners(&mut keys);
    assert_eq!(keys, ["9AAA", "ZAAA", "aAAA", "tAAA"]);

    // Every permutation of one group yields one order.
    let base = ["kpubA", "kpubB", "kpubC"];
    for perm in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut k = [base[perm[0]], base[perm[1]], base[perm[2]]];
        sort_cosigners(&mut k);
        assert_eq!(k, base, "permutation {perm:?} produced a different order");
    }
}

/// The cosigner index is the position after sorting.
#[test]
fn the_cosigner_index_is_the_sorted_position() {
    let mut keys = ["kpubC", "kpubA", "kpubB"];
    sort_cosigners(&mut keys);

    assert_eq!(cosigner_index(&keys, "kpubA"), Ok(0));
    assert_eq!(cosigner_index(&keys, "kpubB"), Ok(1));
    assert_eq!(cosigner_index(&keys, "kpubC"), Ok(2));

    // A key not in the group: what a key exported from the wrong level gives.
    assert_eq!(
        cosigner_index(&keys, "kpubZ"),
        Err(MultisigError::NotAParticipant)
    );
}

/// Sorting refuses nothing, as upstream's `sort_unstable` refuses nothing: a
/// repeated key lands next to its twin, and an empty group is empty.
#[test]
fn sorting_refuses_nothing() {
    let mut keys = ["kpubA", "kpubB", "kpubA"];
    sort_cosigners(&mut keys);
    assert_eq!(keys, ["kpubA", "kpubA", "kpubB"]);

    let mut none: [&str; 0] = [];
    sort_cosigners(&mut none);
}

/// Building refuses what upstream's builder refuses, and nothing more.
#[test]
fn thresholds_follow_upstreams_builder() {
    assert_eq!(check_threshold(0, 3), Ok(()), "upstream builds 0-of-n");
    assert_eq!(check_threshold(17, 20), Ok(()));
    assert_eq!(
        check_threshold(21, 21),
        Ok(()),
        "the builder has no key limit"
    );
    assert_eq!(
        check_threshold(3, 2),
        Err(MultisigError::ThresholdAboveKeys { m: 3, n: 2 })
    );
    assert_eq!(check_threshold(1, 0), Err(MultisigError::NoKeys));

    let keys = [[0u8; 32]; 2];
    let mut out = [0u8; 128];
    assert_eq!(
        redeem_script(3, &keys, &mut out),
        Err(MultisigError::ThresholdAboveKeys { m: 3, n: 2 })
    );
    let mut tiny = [0u8; 4];
    assert_eq!(
        redeem_script(1, &keys, &mut tiny),
        Err(MultisigError::BufferTooSmall)
    );
}

// ── Derivation scheme ────────────────────────────────────────────────────────

use kassigner_kaspa::bip32_public::parse_path;
use kassigner_kaspa::derivation::{
    multisig_account, single_account, Path, CHANGE, MAX_BELOW_ACCOUNT, MULTISIG_ACCOUNT, RECEIVE,
    SINGLE_ACCOUNT,
};

/// The account paths are the text upstream's `build_derivate_path` writes,
/// `m/<purpose>'/111111'/<account>'` (`wallet/keys/src/derivation/gen1/hd.rs`),
/// read by our parser, which `tests/pskb.rs` checks against upstream's.
#[test]
fn the_account_paths_are_the_ones_upstream_writes() {
    let parsed = |text: &str| {
        let mut out = [ChildNumber(0); 8];
        let n = parse_path(text.as_bytes(), &mut out).expect("parses");
        out[..n].to_vec()
    };
    assert_eq!(SINGLE_ACCOUNT.to_vec(), parsed("m/44'/111111'/0'"));
    assert_eq!(MULTISIG_ACCOUNT.to_vec(), parsed("m/45'/111111'/0'"));
    assert_eq!(single_account(7).to_vec(), parsed("m/44'/111111'/7'"));
    assert_eq!(multisig_account(7).to_vec(), parsed("m/45'/111111'/7'"));
    assert_eq!((RECEIVE, CHANGE), (0, 1), "upstream's AddressType order");
}

/// What hangs below an account: two levels for a single-signature key, three
/// for multisig, none of them hardened.
#[test]
fn what_hangs_below_an_account() {
    let mut below = [ChildNumber(0); MAX_BELOW_ACCOUNT];
    let single = Path::Single { chain: 1, index: 7 };
    assert_eq!(
        single.children(&mut below).unwrap(),
        &[ChildNumber(1), ChildNumber(7)]
    );
    assert_eq!(single.account(), SINGLE_ACCOUNT);
    assert!(!single.is_multisig());

    let multi = Path::Multisig {
        cosigner: 2,
        chain: 0,
        index: 5,
    };
    assert_eq!(
        multi.children(&mut below).unwrap(),
        &[ChildNumber(2), ChildNumber(0), ChildNumber(5)]
    );
    assert_eq!(multi.account(), MULTISIG_ACCOUNT);
    assert!(multi.is_multisig());

    assert_eq!(Path::receive(3), Path::Single { chain: 0, index: 3 });
    assert_eq!(Path::change(3), Path::Single { chain: 1, index: 3 });

    // A hardened number below an account is not this scheme.
    assert_eq!(
        Path::receive(HARDENED_OFFSET).children(&mut below),
        Err(Bip32Error::InvalidChild)
    );
}

/// rusty-kaspa's five cosigner kpubs read and write back as the same text.
#[test]
fn a_kpub_is_written_as_it_reads() {
    use kassigner_kaspa::bip32_public::{ExtendedPublicKey, Prefix, TEXT_MAX};
    for text in [
        "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
        "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
        "kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy",
        "kpub2HuRXjAmhs3KwQ9WpHVaiHRjBP37TQUiUGFQBTwp7cdbArCo5s2MT6415nd3ZYaELvNbZ4qTJjCGTavExv514tWftaGQzCK8gQz6BQJNySp",
        "kpub2KCvcuKVgfy1h7PvCw4xFcdLAPoerVZBG4qTo8vRGH2Qe6p5AgLyRek5CEnuCDkduXHqgwtvaVfYYBS7gQBR1J4XowdvqvPXsHZGA5WyRJF",
    ] {
        let (prefix, key) = ExtendedPublicKey::from_text(text.as_bytes()).unwrap();
        assert_eq!(prefix, Prefix::Kpub);
        let mut out = [0u8; TEXT_MAX];
        let m = key.to_text(Prefix::Kpub, &mut out).unwrap();
        assert_eq!(core::str::from_utf8(&out[..m]).unwrap(), text);
    }
}

/// Text that is not a kpub is refused as upstream refuses it: a body a byte
/// short of 78 or past it, a changed character, text past `TEXT_MAX`.
#[test]
fn text_that_is_not_a_kpub_is_refused_as_upstream_refuses_it() {
    use kassigner_kaspa::base58::encode_check;
    use kassigner_kaspa::bip32_public::{ExtendedPublicKey, Prefix, TEXT_MAX};
    type Upstream = kaspa_bip32::ExtendedPublicKey<kaspa_bip32::secp256k1::PublicKey>;

    let good = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    assert!(
        good.parse::<Upstream>().is_ok(),
        "upstream reads the good one"
    );
    let (_, key) = ExtendedPublicKey::from_text(good.as_bytes()).unwrap();
    let mut body = [0u8; 79];
    key.serialize(Prefix::Kpub, &mut body).unwrap();

    let mut refused = Vec::new();
    for len in [77, 79] {
        let mut scratch = [0u8; 83];
        let mut out = [0u8; 128];
        let n = encode_check(&body[..len], &mut scratch, &mut out).unwrap();
        refused.push(String::from_utf8(out[..n].to_vec()).unwrap());
    }
    let mut changed = good.as_bytes().to_vec();
    changed[50] = if changed[50] == b'a' { b'b' } else { b'a' };
    refused.push(String::from_utf8(changed).unwrap());
    refused.push(format!("{good}{}", "1".repeat(TEXT_MAX)));

    for text in &refused {
        assert!(
            ExtendedPublicKey::from_text(text.as_bytes()).is_err(),
            "ours: {text}"
        );
        assert!(text.parse::<Upstream>().is_err(), "upstream: {text}");
    }
}

/// A kpub whose key is not a curve point is refused as upstream refuses it.
/// The x off the curve is the first from 1 upstream will not read.
#[test]
fn a_kpub_off_the_curve_is_refused_as_upstream_refuses_it() {
    use kaspa_bip32::secp256k1::PublicKey as UpKey;
    use kassigner_kaspa::base58::encode_check;
    use kassigner_kaspa::bip32_public::{ExtendedPublicKey, Prefix};
    type Upstream = kaspa_bip32::ExtendedPublicKey<UpKey>;

    let good = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    let (_, key) = ExtendedPublicKey::from_text(good.as_bytes()).unwrap();
    let text_of = |public_key: [u8; 33]| {
        // Field by field: `{ public_key, ..key }` here crashes esp195's
        // compiler (broken MIR).
        let mut changed = key;
        changed.public_key = public_key;
        let mut body = [0u8; 78];
        changed.serialize(Prefix::Kpub, &mut body).unwrap();
        let mut scratch = [0u8; 82];
        let mut out = [0u8; 128];
        let n = encode_check(&body, &mut scratch, &mut out).unwrap();
        (body, String::from_utf8(out[..n].to_vec()).unwrap())
    };
    let with_x = |tag: u8, x: [u8; 32]| {
        let mut k = [tag; 33];
        k[1..].copy_from_slice(&x);
        k
    };
    let off_curve = (1u8..=255)
        .map(|n| {
            let mut x = [0u8; 32];
            x[31] = n;
            with_x(2, x)
        })
        .find(|k| UpKey::from_slice(k).is_err())
        .expect("an x off the curve below 256");

    let mut wrong_tag = key.public_key;
    wrong_tag[0] = 5;
    let cases: [(&str, [u8; 33]); 4] = [
        ("an x with no y on the curve", off_curve),
        ("an x past the field prime", with_x(2, [0xff; 32])),
        ("a tag that is not 2 or 3", wrong_tag),
        ("all zeros", [0; 33]),
    ];
    for (what, public_key) in cases {
        let (body, text) = text_of(public_key);
        assert!(
            text.parse::<Upstream>().is_err(),
            "{what}: upstream reads it"
        );
        assert_eq!(
            ExtendedPublicKey::from_text(text.as_bytes()),
            Err(Bip32Error::InvalidPublicKey),
            "{what}"
        );
        assert_eq!(
            ExtendedPublicKey::deserialize(&body),
            Err(Bip32Error::InvalidPublicKey),
            "{what}"
        );
    }

    // The other tag on the same x is the other point: a key.
    let mut other = key.public_key;
    other[0] ^= 1;
    let (_, text) = text_of(other);
    assert!(text.parse::<Upstream>().is_ok());
    let (_, read) = ExtendedPublicKey::from_text(text.as_bytes()).unwrap();
    assert_eq!(read.public_key, other);
}
