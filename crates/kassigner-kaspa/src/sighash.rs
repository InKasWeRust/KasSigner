// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Signature hashing (upstream: `consensus/core/src/hashing/sighash.rs`,
//! `sighash_type.rs`; hashers from `crypto/hashes/src/hashers.rs`).
//!
//! Branches on `tx.version` where upstream does. Version 0 commits to the
//! sigop counts, as a digest over all inputs and a byte on the input signed;
//! version 1 and above drop both and commit to each output's covenant
//! binding. A signer can evaluate that gate: the version is in the payload.
//!
//! Every hash is Blake2b-256 keyed with a fixed ASCII string, but version 1's
//! transaction id: BLAKE3, keyed with the name padded with zeros to 32 bytes.
//! The key keeps a digest for one purpose from passing for another, so its
//! exact bytes are asserted against upstream in `tests/upstream.rs`.

use crate::constants::TX_VERSION_COVENANTS;
use crate::tx::{Outpoint, ScriptPublicKey, Transaction, TransactionOutput};

/// Length of every digest produced here.
pub const HASH_SIZE: usize = 32;

/// A 32-byte digest.
pub type Hash = [u8; HASH_SIZE];

/// Domain separation keys (upstream: `crypto/hashes/src/hashers.rs`).
const DOMAIN_TX_SIGNING: &[u8] = b"TransactionSigningHash";
/// rusty-kaspa's `PersonalMessageSigningHash`.
const DOMAIN_PERSONAL_MESSAGE: &[u8] = b"PersonalMessageSigningHash";
const DOMAIN_TX_SIGNING_ECDSA: &[u8] = b"TransactionSigningHashECDSA";

/// How much of a transaction a signature commits to. Its byte is the
/// crate's, as upstream keeps it: from outside, a type is a constant below or
/// what [`SigHashType::from_u8`] allows, read with [`SigHashType::to_u8`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigHashType(pub(crate) u8);

/// Commit to every input and every output. The only type KasSigner emits.
pub const SIG_HASH_ALL: SigHashType = SigHashType(0b0000_0001);
/// Commit to no outputs.
pub const SIG_HASH_NONE: SigHashType = SigHashType(0b0000_0010);
/// Commit to the one output at the same index as the input being signed.
pub const SIG_HASH_SINGLE: SigHashType = SigHashType(0b0000_0100);
/// Commit to only the input being signed.
pub const SIG_HASH_ANY_ONE_CAN_PAY: SigHashType = SigHashType(0b1000_0000);

/// The six types consensus allows, upstream's `ALLOWED_SIG_HASH_TYPES_VALUES`:
/// ALL, NONE and SINGLE, each alone or with ANYONECANPAY.
const ALLOWED: [u8; 6] = [
    SIG_HASH_ALL.0,
    SIG_HASH_NONE.0,
    SIG_HASH_SINGLE.0,
    SIG_HASH_ALL.0 | SIG_HASH_ANY_ONE_CAN_PAY.0,
    SIG_HASH_NONE.0 | SIG_HASH_ANY_ONE_CAN_PAY.0,
    SIG_HASH_SINGLE.0 | SIG_HASH_ANY_ONE_CAN_PAY.0,
];

impl SigHashType {
    #[inline]
    pub fn is_sighash_all(self) -> bool {
        self.0 & 0b0000_0111 == SIG_HASH_ALL.0
    }
    #[inline]
    pub fn is_sighash_none(self) -> bool {
        self.0 & 0b0000_0111 == SIG_HASH_NONE.0
    }
    #[inline]
    pub fn is_sighash_single(self) -> bool {
        self.0 & 0b0000_0111 == SIG_HASH_SINGLE.0
    }
    #[inline]
    pub fn is_sighash_anyone_can_pay(self) -> bool {
        self.0 & SIG_HASH_ANY_ONE_CAN_PAY.0 == SIG_HASH_ANY_ONE_CAN_PAY.0
    }
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// One of the six types consensus allows, or `None`, as upstream's
    /// `SigHashType::from_u8`.
    pub fn from_u8(value: u8) -> Option<Self> {
        ALLOWED.contains(&value).then_some(Self(value))
    }
}

/// A personal message's hash, what a message signature signs: keyed
/// BLAKE2b-256, as rusty-kaspa's `calc_personal_message_hash`. Its own key,
/// so no message hashes to a transaction's sighash.
pub fn personal_message_hash(message: &[u8]) -> Hash {
    let mut h = Hasher::new(DOMAIN_PERSONAL_MESSAGE);
    h.update(message);
    h.finalize()
}

type Blake2b256Keyed = blake2::Blake2bMac<blake2::digest::consts::U32>;

/// Keyed Blake2b-256, upstream's `Params::new().hash_length(32).key(domain)`
/// in another crate: the conformance test proves they agree. The key is a
/// domain separator, not a secret.
struct Hasher(Blake2b256Keyed);

impl Hasher {
    fn new(domain: &[u8]) -> Self {
        use blake2::digest::KeyInit;
        Self(
            <Blake2b256Keyed as KeyInit>::new_from_slice(domain)
                .expect("domain separator is within Blake2b's key length"),
        )
    }
    fn update(&mut self, data: &[u8]) -> &mut Self {
        use blake2::digest::Update;
        Update::update(&mut self.0, data);
        self
    }
    fn write_u8(&mut self, v: u8) -> &mut Self {
        self.update(&[v])
    }
    fn write_u16(&mut self, v: u16) -> &mut Self {
        self.update(&v.to_le_bytes())
    }
    fn write_u64(&mut self, v: u64) -> &mut Self {
        self.update(&v.to_le_bytes())
    }
    fn write_bool(&mut self, v: bool) -> &mut Self {
        self.write_u8(u8::from(v))
    }
    /// Length-prefixed bytes: a u64 length, then the bytes.
    fn write_var_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.write_u64(data.len() as u64).update(data)
    }
    fn finalize(self) -> Hash {
        use blake2::digest::FixedOutput;
        let mut out = [0u8; HASH_SIZE];
        out.copy_from_slice(&self.0.finalize_fixed());
        out
    }
}

/// rusty-kaspa's `TransactionID`.
const DOMAIN_TRANSACTION_ID: &[u8] = b"TransactionID";

/// A transaction's id, as upstream's `id` (`hashing/tx.rs`). Without
/// signature scripts or mass commitment, so signing does not change it.
///
/// Version 0 (`id_v0`): the other fields under Blake2b. Version 1 (`id_v1`):
/// BLAKE3 over the payload's digest and the rest's, which adds each output's
/// covenant binding. `None` above [`TX_VERSION_COVENANTS`], which consensus
/// refuses and upstream would hash as version 1.
pub fn transaction_id(tx: &Transaction) -> Option<Hash> {
    if tx.version > TX_VERSION_COVENANTS {
        return None;
    }
    if tx.version != 0 {
        return Some(transaction_id_v1(tx));
    }
    let mut h = Hasher::new(DOMAIN_TRANSACTION_ID);
    h.write_u16(tx.version).write_u64(tx.inputs.len() as u64);
    for input in tx.inputs {
        h.update(&input.previous_outpoint.transaction_id)
            .update(&input.previous_outpoint.index.to_le_bytes())
            .write_var_bytes(&[])
            .write_u64(input.sequence);
    }
    h.write_u64(tx.outputs.len() as u64);
    for output in tx.outputs {
        h.write_u64(output.value)
            .write_u16(output.script_public_key.version)
            .write_var_bytes(output.script_public_key.script);
    }
    h.write_u64(tx.lock_time)
        .update(&tx.subnetwork_id)
        .write_u64(tx.gas)
        .write_var_bytes(tx.payload);
    Some(h.finalize())
}

/// A BLAKE3 key as rusty-kaspa's `blake3_hasher!` makes one: the name, then
/// zeros to 32 bytes. Const only, so a name too long fails the build.
const fn blake3_key(domain: &[u8]) -> [u8; HASH_SIZE] {
    let mut key = [0u8; HASH_SIZE];
    let mut i = 0;
    while i < domain.len() {
        key[i] = domain[i];
        i += 1;
    }
    key
}

/// rusty-kaspa's `PayloadDigest`, `TransactionRest` and `TransactionV1Id`.
const KEY_PAYLOAD_DIGEST: [u8; HASH_SIZE] = blake3_key(b"PayloadDigest");
const KEY_TRANSACTION_REST: [u8; HASH_SIZE] = blake3_key(b"TransactionRest");
const KEY_TRANSACTION_V1_ID: [u8; HASH_SIZE] = blake3_key(b"TransactionV1Id");

/// Keyed BLAKE3, for version 1's transaction id. The key is a domain
/// separator, not a secret.
struct Blake3(blake3::Hasher);

impl Blake3 {
    fn new(key: &[u8; HASH_SIZE]) -> Self {
        Self(blake3::Hasher::new_keyed(key))
    }
    fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }
    fn write_u16(&mut self, v: u16) -> &mut Self {
        self.update(&v.to_le_bytes())
    }
    fn write_u64(&mut self, v: u64) -> &mut Self {
        self.update(&v.to_le_bytes())
    }
    fn write_bool(&mut self, v: bool) -> &mut Self {
        self.update(&[u8::from(v)])
    }
    /// Length-prefixed bytes: a u64 length, then the bytes.
    fn write_var_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.write_u64(data.len() as u64).update(data)
    }
    fn finalize(&self) -> Hash {
        *self.0.finalize().as_bytes()
    }
}

/// A version 1 transaction's id, `id_v1`: `TransactionV1Id` over the
/// payload's digest, then the rest's.
fn transaction_id_v1(tx: &Transaction) -> Hash {
    Blake3::new(&KEY_TRANSACTION_V1_ID)
        .update(&payload_digest(tx.payload))
        .update(&rest_digest(tx))
        .finalize()
}

/// `payload_digest`: the payload under `PayloadDigest`. Upstream's constant
/// for an empty payload, `ZERO_PAYLOAD_DIGEST`, is this hash of no bytes.
fn payload_digest(payload: &[u8]) -> Hash {
    Blake3::new(&KEY_PAYLOAD_DIGEST).update(payload).finalize()
}

/// `v1_rest_digest`: the transaction under `TransactionRest`, as upstream's
/// `write_transaction` writes it without payload, signature scripts or mass
/// commitment (the compute budget is one). An input is its outpoint, an
/// empty signature script and its sequence; an output its value, locking
/// script, and covenant binding if any. The payload is written empty.
fn rest_digest(tx: &Transaction) -> Hash {
    let mut h = Blake3::new(&KEY_TRANSACTION_REST);
    h.write_u16(tx.version).write_u64(tx.inputs.len() as u64);
    for input in tx.inputs {
        h.update(&input.previous_outpoint.transaction_id)
            .update(&input.previous_outpoint.index.to_le_bytes())
            .write_var_bytes(&[])
            .write_u64(input.sequence);
    }
    h.write_u64(tx.outputs.len() as u64);
    for output in tx.outputs {
        h.write_u64(output.value)
            .write_u16(output.script_public_key.version)
            .write_var_bytes(output.script_public_key.script)
            .write_bool(output.covenant.is_some());
        if let Some(binding) = output.covenant {
            h.write_u16(binding.authorizing_input)
                .update(&binding.covenant_id);
        }
    }
    h.write_u64(tx.lock_time)
        .update(&tx.subnetwork_id)
        .write_u64(tx.gas)
        .write_var_bytes(&[]);
    h.finalize()
}

/// rusty-kaspa's `CovenantID`.
const DOMAIN_COVENANT_ID: &[u8] = b"CovenantID";

/// A new covenant's id, KIP-20 (upstream: `covenant_id`): the outpoint its
/// authorizing input spends, the number of outputs it authorizes, then each
/// one's index, value and locking script. Bindings are left out, as they
/// name this id.
pub fn covenant_id<'b, 'o: 'b>(
    outpoint: &Outpoint,
    auth_outputs: impl Iterator<Item = (u32, &'b TransactionOutput<'o>)> + Clone,
) -> Hash {
    let mut h = Hasher::new(DOMAIN_COVENANT_ID);
    h.update(&outpoint.transaction_id)
        .update(&outpoint.index.to_le_bytes())
        .write_u64(auth_outputs.clone().count() as u64);
    for (index, output) in auth_outputs {
        h.update(&index.to_le_bytes())
            .write_u64(output.value)
            .write_u16(output.script_public_key.version)
            .write_var_bytes(output.script_public_key.script);
    }
    h.finalize()
}

fn previous_outputs_hash(tx: &Transaction, hash_type: SigHashType) -> Hash {
    if hash_type.is_sighash_anyone_can_pay() {
        return [0u8; HASH_SIZE];
    }
    let mut h = Hasher::new(DOMAIN_TX_SIGNING);
    for input in tx.inputs {
        h.update(&input.previous_outpoint.transaction_id)
            .update(&input.previous_outpoint.index.to_le_bytes());
    }
    h.finalize()
}

fn sequences_hash(tx: &Transaction, hash_type: SigHashType) -> Hash {
    if hash_type.is_sighash_single()
        || hash_type.is_sighash_anyone_can_pay()
        || hash_type.is_sighash_none()
    {
        return [0u8; HASH_SIZE];
    }
    let mut h = Hasher::new(DOMAIN_TX_SIGNING);
    for input in tx.inputs {
        h.write_u64(input.sequence);
    }
    h.finalize()
}

/// Only reached on transaction version 0.
fn sig_op_counts_hash(tx: &Transaction, hash_type: SigHashType) -> Hash {
    if hash_type.is_sighash_anyone_can_pay() {
        return [0u8; HASH_SIZE];
    }
    let mut h = Hasher::new(DOMAIN_TX_SIGNING);
    for input in tx.inputs {
        h.write_u8(input.sig_op_count);
    }
    h.finalize()
}

fn payload_hash(tx: &Transaction) -> Hash {
    // Both conditions, as upstream: a native transaction with a payload still
    // commits to it. Without the emptiness check, most covenant traffic would
    // leave its payload unsigned.
    if tx.subnetwork_id == crate::tx::SUBNETWORK_ID_NATIVE && tx.payload.is_empty() {
        return [0u8; HASH_SIZE];
    }
    let mut h = Hasher::new(DOMAIN_TX_SIGNING);
    h.write_var_bytes(tx.payload);
    h.finalize()
}

fn hash_script_public_key(h: &mut Hasher, spk: &ScriptPublicKey) {
    h.write_u16(spk.version).write_var_bytes(spk.script);
}

fn hash_output(h: &mut Hasher, output: &TransactionOutput, version: u16) {
    h.write_u64(output.value);
    hash_script_public_key(h, &output.script_public_key);
    // Covenant bindings exist from version 1.
    if version >= 1 {
        h.write_bool(output.covenant.is_some());
        if let Some(c) = &output.covenant {
            h.write_u16(c.authorizing_input).update(&c.covenant_id);
        }
    }
}

fn outputs_hash(tx: &Transaction, hash_type: SigHashType, input_index: usize) -> Hash {
    if hash_type.is_sighash_none() {
        return [0u8; HASH_SIZE];
    }
    let mut h = Hasher::new(DOMAIN_TX_SIGNING);
    if hash_type.is_sighash_single() {
        // Only the output facing this input, if there is one.
        if input_index >= tx.outputs.len() {
            return [0u8; HASH_SIZE];
        }
        hash_output(&mut h, &tx.outputs[input_index], tx.version);
        return h.finalize();
    }
    for output in tx.outputs {
        hash_output(&mut h, output, tx.version);
    }
    h.finalize()
}

/// The Schnorr signature hash for one input, as upstream's
/// `calc_schnorr_signature_hash`; `tests/upstream.rs` holds both sides of the
/// version gate to it. `None` for an input the transaction does not have,
/// where upstream panics.
pub fn schnorr_signature_hash(
    tx: &Transaction,
    input_index: usize,
    hash_type: SigHashType,
) -> Option<Hash> {
    let input = tx.inputs.get(input_index)?;
    let mut h = Hasher::new(DOMAIN_TX_SIGNING);

    h.write_u16(tx.version)
        .update(&previous_outputs_hash(tx, hash_type))
        .update(&sequences_hash(tx, hash_type));

    // Version 0: the sigop counts.
    if !tx.commits_to_covenants() {
        h.update(&sig_op_counts_hash(tx, hash_type));
    }

    h.update(&input.previous_outpoint.transaction_id)
        .update(&input.previous_outpoint.index.to_le_bytes());
    hash_script_public_key(&mut h, &input.utxo_entry.script_public_key);
    h.write_u64(input.utxo_entry.amount)
        .write_u64(input.sequence);

    // Version 0: this input's sigop count.
    if !tx.commits_to_covenants() {
        h.write_u8(input.sig_op_count);
    }

    h.update(&outputs_hash(tx, hash_type, input_index))
        .write_u64(tx.lock_time)
        .update(&tx.subnetwork_id)
        .write_u64(tx.gas)
        .update(&payload_hash(tx))
        .write_u8(hash_type.to_u8());

    Some(h.finalize())
}

/// The ECDSA signature hash, as upstream's `calc_ecdsa_signature_hash`;
/// `None` as [`schnorr_signature_hash`].
///
/// Not keyed Blake2b, as the name suggests: upstream declares
/// `TransactionSigningHashECDSA` with `sha256_hasher!`, which prefixes a
/// plain SHA-256 with `SHA256(domain)`:
///
/// ```text
/// sha256( sha256("TransactionSigningHashECDSA") || schnorr_hash )
/// ```
pub fn ecdsa_signature_hash(
    tx: &Transaction,
    input_index: usize,
    hash_type: SigHashType,
) -> Option<Hash> {
    use sha2::{Digest, Sha256};

    let inner = schnorr_signature_hash(tx, input_index, hash_type)?;
    let domain: [u8; HASH_SIZE] = Sha256::digest(DOMAIN_TX_SIGNING_ECDSA).into();
    let mut h = Sha256::new();
    h.update(domain);
    h.update(inner);
    Some(h.finalize().into())
}

#[cfg(test)]
mod personal_message {
    /// "Hello Kaspa!", rusty-kaspa's test message, hashed outside this
    /// crate.
    #[test]
    fn the_hash_is_rusty_kaspas() {
        let want: [u8; 32] = [
            0x2e, 0x55, 0xde, 0xda, 0x4a, 0x52, 0x24, 0x20, 0x8d, 0xbd, 0x4d, 0x93, 0xcf, 0xe5,
            0xaa, 0x22, 0xd9, 0x45, 0xea, 0xa6, 0x31, 0x72, 0xe3, 0x29, 0xc4, 0x9a, 0xfe, 0xd6,
            0x2f, 0x0e, 0x15, 0x10,
        ];
        assert_eq!(super::personal_message_hash(b"Hello Kaspa!"), want);
    }
}
