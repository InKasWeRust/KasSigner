// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Known answers for Kaspa's rules, for a device to run at boot, beside
//! `kassigner_crypto::kat`. `tests/upstream.rs` proves agreement with
//! rusty-kaspa on a host toolchain; these run on the silicon about to sign.
//!
//! A boot check compares against constants, as the device has no node to
//! ask: the few values that came from outside this project. Each function
//! returns `(passed, total)`.

use crate::address::{decode, encode, Prefix, Version};
use crate::bip32_public::ExtendedPublicKey;
use crate::multisig::{address_keys, redeem_script, redeem_script_len, sort_cosigners};
use crate::script::redeem_hash;
use crate::sighash::{
    ecdsa_signature_hash, schnorr_signature_hash, Hash, SigHashType, SIG_HASH_ALL,
    SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE, SIG_HASH_SINGLE,
};
use crate::tx::{
    CovenantBinding, Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput,
    UtxoEntry,
};

/// The all-zero public key's mainnet address, `kaspa:qqqq…kx9awp4e` in every
/// implementation, encoded and decoded: the checksum and the alphabet are
/// where a wrong byte gives someone else's address. The round trip must
/// return the payload, so a decoder matching a broken encoder still fails.
pub fn address() -> (u32, u32) {
    const TOTAL: u32 = 3;
    const EXPECTED: &[u8] = b"kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
    let mut passed = 0;

    let payload = [0u8; 32];
    let mut out = [0u8; 128];
    let Ok(n) = encode(Prefix::Mainnet, Version::PubKey, &payload, &mut out) else {
        return (0, TOTAL);
    };
    if &out[..n] == EXPECTED {
        passed += 1;
    }

    let mut back = [0u8; 64];
    if let Ok((found, version, len)) = decode(&out[..n], &mut back) {
        if found == Prefix::Mainnet && version == Version::PubKey && len == 32 {
            passed += 1;
        }
        if back[..len] == payload[..] {
            passed += 1;
        }
    }
    (passed, TOTAL)
}

/// The 45' multisig vector [`multisig_45`] checks, shared with the tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupVector {
    /// The five extended public keys, in upstream's (unsorted) order.
    pub kpubs: [&'static str; 5],
    /// Signatures required.
    pub required: usize,
    /// The cosigner index every key is derived at.
    pub cosigner: u32,
    /// Receive.
    pub chain: u32,
    /// The address index.
    pub index: u32,
    /// The address the Go implementation gives.
    pub address: &'static str,
}

/// rusty-kaspa 2.1.0's Go `kaspawallet` import vector: see [`multisig_45`].
pub const MULTISIG_45: GroupVector = GroupVector {
    kpubs: [
        "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
        "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
        "kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy",
        "kpub2HuRXjAmhs3KwQ9WpHVaiHRjBP37TQUiUGFQBTwp7cdbArCo5s2MT6415nd3ZYaELvNbZ4qTJjCGTavExv514tWftaGQzCK8gQz6BQJNySp",
        "kpub2KCvcuKVgfy1h7PvCw4xFcdLAPoerVZBG4qTo8vRGH2Qe6p5AgLyRek5CEnuCDkduXHqgwtvaVfYYBS7gQBR1J4XowdvqvPXsHZGA5WyRJF",
    ],
    required: 2,
    cosigner: 1,
    chain: 0,
    index: 0,
    address: "kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998",
};

/// A 45' multisig address another implementation produced: rusty-kaspa's
/// test importing a Go `kaspawallet` multisig file
/// (`wallet/core/src/compat/gen1.rs`), two of five, cosigner index 1,
/// receive address 0.
///
/// Four rules must hold at once or the hash changes:
///
/// 1. Sort the **parent** key strings, not the children ([`sort_cosigners`]);
///    [`MULTISIG_45`] holds them unsorted.
/// 2. Use the **same** cosigner index for every key.
/// 3. Derive `/cosigner/chain/index`, three non-hardened levels.
/// 4. Write the threshold, each x-only key in sorted-parent order, the count
///    and `OP_CHECKMULTISIG`; hash and encode as pay-to-script-hash.
///
/// Five 111-byte strings of flash, so interoperability fails on the bench,
/// not at a user's address.
pub fn multisig_45() -> (u32, u32) {
    const TOTAL: u32 = 2;
    let v = MULTISIG_45;
    let mut kpubs = v.kpubs;
    let mut passed = 0;

    sort_cosigners(&mut kpubs);

    let parsed = kpubs.map(|t| ExtendedPublicKey::from_text(t.as_bytes()).map(|(_, k)| k));
    let [Ok(a), Ok(b), Ok(c), Ok(d), Ok(e)] = parsed else {
        return (passed, TOTAL);
    };
    let mut keys = [[0u8; 32]; 5];
    if address_keys(&[a, b, c, d, e], v.cosigner, v.chain, v.index, &mut keys) != Ok(5) {
        return (passed, TOTAL);
    }
    passed += 1;

    let mut script = [0u8; redeem_script_len(MULTISIG_45.required, 5)];
    let Ok(len) = redeem_script(v.required, &keys, &mut script) else {
        return (passed, TOTAL);
    };
    let hash = redeem_hash(&script[..len]);
    let mut out = [0u8; 128];
    if let Ok(n) = encode(Prefix::Mainnet, Version::ScriptHash, &hash, &mut out) {
        if &out[..n] == v.address.as_bytes() {
            passed += 1;
        }
    }
    (passed, TOTAL)
}

// ── Signature hashing ────────────────────────────────────────────────────────

/// One transaction shape and the hash type to sign it under: the recipe
/// `tests/upstream.rs` builds on both sides, here so a device builds the same
/// transactions and checks them against the answers those runs froze.
#[derive(Clone, Copy, Debug)]
pub struct SighashCase {
    pub version: u16,
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub covenants: bool,
    /// The raw sighash byte, built on both sides from this one value.
    pub hash_type: u8,
    /// Two fields for two conditions: only a native subnetwork with an
    /// empty payload leaves the payload unhashed.
    pub payload: bool,
    pub native_subnet: bool,
}

impl SighashCase {
    /// SIGHASH_ALL, native subnetwork, a payload present.
    pub const fn new(version: u16, n_inputs: usize, n_outputs: usize) -> Self {
        Self {
            version,
            n_inputs,
            n_outputs,
            covenants: false,
            hash_type: SIG_HASH_ALL.0,
            payload: true,
            native_subnet: true,
        }
    }

    pub const fn covenants(self) -> Self {
        Self {
            covenants: true,
            ..self
        }
    }

    pub const fn hash_type(self, t: SigHashType) -> Self {
        Self {
            hash_type: t.0,
            ..self
        }
    }
}

/// The largest shape the recipe builds.
pub const SIGHASH_MAX_INPUTS: usize = 4;
/// See [`SIGHASH_MAX_INPUTS`].
pub const SIGHASH_MAX_OUTPUTS: usize = 3;

/// The script every output pays to.
pub const SIGHASH_SPK: [u8; 34] = [0xAA; 34];
/// The script each input spends: its version and bytes. Each differs, the
/// last under version 1, as the hash commits only the signed input's script:
/// a hash taking another input's would then differ. Version 1 is only a
/// value to hash.
pub const SIGHASH_INPUT_SPKS: [(u16, &[u8]); SIGHASH_MAX_INPUTS] = [
    (0, &[0xA0; 34]),
    (0, &[0xA1; 35]),
    (0, &[0xA2; 23]),
    (1, &[0xA3; 40]),
];
/// The payload, when a case has one.
pub const SIGHASH_PAYLOAD: [u8; 3] = [0x11, 0x22, 0x33];
/// The subnetwork of a non-native case, the only shape where gas is not zero.
pub const SIGHASH_SUBNET: [u8; 20] = [0x42; 20];
/// Gas on a non-native subnetwork.
pub const SIGHASH_GAS: u64 = 0xDEAD_BEEF;
/// Lock time, every case.
pub const SIGHASH_LOCK_TIME: u64 = 0x0123_4567_89ab_cdef;
/// Covenant id, when a case binds one.
pub const SIGHASH_COVENANT_ID: [u8; 32] = [0x77; 32];
/// Signature-operation count, every input.
pub const SIGHASH_SIG_OPS: u8 = 1;

/// Input `i`'s previous transaction id.
pub const fn sighash_txid(i: usize) -> [u8; 32] {
    [i as u8; 32]
}
/// Input `i`'s sequence.
pub const fn sighash_sequence(i: usize) -> u64 {
    0x1000 + i as u64
}
/// Input `i`'s spent amount.
pub const fn sighash_amount(i: usize) -> u64 {
    100_000_000 + i as u64
}
/// Output `i`'s value.
pub const fn sighash_value(i: usize) -> u64 {
    50_000_000 + i as u64
}

/// This crate's Schnorr and ECDSA digests for one input of a case, for the
/// host test; `None` for an input the case does not have.
pub fn sighash_digests(case: SighashCase, input: usize) -> Option<(Hash, Hash)> {
    with_case(case, |tx, t| {
        Some((
            schnorr_signature_hash(tx, input, t)?,
            ecdsa_signature_hash(tx, input, t)?,
        ))
    })
}

/// The Schnorr digest alone, what the boot set compares: the unit signs no
/// ECDSA input.
pub fn sighash_schnorr(case: SighashCase, input: usize) -> Option<Hash> {
    with_case(case, |tx, t| schnorr_signature_hash(tx, input, t))
}

/// `digest` over a case's transaction and hash type, or `None` for a hash
/// type outside the six. Built on the stack: a few hundred bytes, as
/// `Transaction` borrows its slices.
fn with_case<R>(
    case: SighashCase,
    digest: impl FnOnce(&Transaction<'_>, SigHashType) -> Option<R>,
) -> Option<R> {
    let spk = ScriptPublicKey {
        version: 0,
        script: &SIGHASH_SPK,
    };
    let inputs: [TransactionInput; SIGHASH_MAX_INPUTS] =
        core::array::from_fn(|i| TransactionInput {
            previous_outpoint: Outpoint {
                transaction_id: sighash_txid(i),
                index: i as u32,
            },
            sequence: sighash_sequence(i),
            sig_op_count: SIGHASH_SIG_OPS,
            compute_budget: 0,
            signature_script: &[],
            utxo_entry: UtxoEntry {
                amount: sighash_amount(i),
                script_public_key: ScriptPublicKey {
                    version: SIGHASH_INPUT_SPKS[i].0,
                    script: SIGHASH_INPUT_SPKS[i].1,
                },
            },
        });
    let outputs: [TransactionOutput; SIGHASH_MAX_OUTPUTS] =
        core::array::from_fn(|i| TransactionOutput {
            value: sighash_value(i),
            script_public_key: spk,
            covenant: case.covenants.then_some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: SIGHASH_COVENANT_ID,
            }),
        });
    let tx = Transaction {
        version: case.version,
        inputs: &inputs[..case.n_inputs],
        outputs: &outputs[..case.n_outputs],
        lock_time: SIGHASH_LOCK_TIME,
        subnetwork_id: if case.native_subnet {
            [0u8; 20]
        } else {
            SIGHASH_SUBNET
        },
        gas: if case.native_subnet { 0 } else { SIGHASH_GAS },
        payload: if case.payload {
            &SIGHASH_PAYLOAD[..]
        } else {
            &[]
        },
    };
    // A case's byte is public: one outside the six fails the boot check.
    let t = SigHashType::from_u8(case.hash_type)?;
    digest(&tx, t)
}

/// The cases a device checks at boot, each with the input it signs: the six
/// hash types on both versions; SINGLE with no output facing the input,
/// where upstream signs a zero hash; both halves of the payload and
/// subnetwork gate; a covenant binding. All are conformance-test shapes.
pub const SIGHASH_BOOT: [(SighashCase, usize); 17] = [
    (SighashCase::new(0, 2, 2).hash_type(SIG_HASH_ALL), 1),
    (SighashCase::new(0, 2, 2).hash_type(SIG_HASH_NONE), 1),
    (SighashCase::new(0, 2, 2).hash_type(SIG_HASH_SINGLE), 1),
    (SighashCase::new(0, 2, 2).hash_type(any(SIG_HASH_ALL)), 1),
    (SighashCase::new(0, 2, 2).hash_type(any(SIG_HASH_NONE)), 1),
    (SighashCase::new(0, 2, 2).hash_type(any(SIG_HASH_SINGLE)), 1),
    (SighashCase::new(1, 2, 2).hash_type(SIG_HASH_ALL), 1),
    (SighashCase::new(1, 2, 2).hash_type(SIG_HASH_NONE), 1),
    (SighashCase::new(1, 2, 2).hash_type(SIG_HASH_SINGLE), 1),
    (SighashCase::new(1, 2, 2).hash_type(any(SIG_HASH_ALL)), 1),
    (SighashCase::new(1, 2, 2).hash_type(any(SIG_HASH_NONE)), 1),
    (SighashCase::new(1, 2, 2).hash_type(any(SIG_HASH_SINGLE)), 1),
    (SighashCase::new(0, 3, 1).hash_type(SIG_HASH_SINGLE), 2),
    (SighashCase::new(1, 3, 1).hash_type(SIG_HASH_SINGLE), 2),
    (no_payload(SighashCase::new(1, 2, 2), true), 0),
    (no_payload(SighashCase::new(1, 2, 2), false), 0),
    (SighashCase::new(1, 2, 2).covenants(), 1),
];

/// `t` with ANYONECANPAY set.
const fn any(t: SigHashType) -> SigHashType {
    SigHashType(t.0 | SIG_HASH_ANY_ONE_CAN_PAY.0)
}

/// A case with no payload, on a native subnetwork or not.
const fn no_payload(case: SighashCase, native: bool) -> SighashCase {
    SighashCase {
        payload: false,
        native_subnet: native,
        ..case
    }
}

// `SIGHASH_EXPECTED`, one per `SIGHASH_BOOT` entry, written by
// `tests/upstream.rs` from rusty-kaspa and rechecked on every host run.
include!("kat_sighash.rs");

/// The boot set's signature hashes against the frozen answers: the check
/// closest to funds. A digest one field off the node's still signs and
/// verifies against itself, then is refused, or accepted for something the
/// screen did not show.
pub fn sighash() -> (u32, u32) {
    let mut passed = 0;
    for (i, (case, input)) in SIGHASH_BOOT.iter().enumerate() {
        if sighash_schnorr(*case, *input) == Some(SIGHASH_EXPECTED[i]) {
            passed += 1;
        }
    }
    (passed, SIGHASH_BOOT.len() as u32)
}

/// Every known answer in this crate, as one total.
pub fn all() -> (u32, u32) {
    let mut passed = 0;
    let mut total = 0;
    for (p, t) in [address(), multisig_45(), sighash()] {
        passed += p;
        total += t;
    }
    (passed, total)
}
