// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Writing a bundle of one transaction as upstream writes it.
//!
//! Upstream: `Bundle::serialize` (`wallet/pskt/src/bundle.rs`),
//! `serde_json::to_string` of a list of `Inner` (`pskt.rs`, `global.rs`,
//! `input.rs`, `output.rs`): fields in declaration order, `camelCase`, an
//! absent `Option` as `null`, bytes and hashes as lowercase hex.
//!
//! The bundle is what upstream's creator, constructor and updater leave:
//! the caller's values, neither side modifiable, and no extended keys,
//! `id`, partial signatures, `finalScriptSig`, output `redeemScript` or
//! proprietary fields. Signatures go in later by [`super::signature`]'s
//! splices. What upstream would not build is refused: a payload below
//! bundle version One (`PSKT<Constructor>::payload`), a covenant binding
//! below version Two or the covenant transaction version
//! (`PSKT<Constructor>::output`).
//!
//! `bip32Derivations` is a `BTreeMap` by compressed key, so a caller's
//! members must come in key byte order, each key once. Each value is the
//! caller's JSON: [`key_source`]'s `KeySource`, or `null`.

use crate::bip32_public::PUBLIC_KEY_SIZE;
use crate::constants::TX_VERSION_COVENANTS;
use crate::rpc::Sink;
use crate::tx::{CovenantBinding, EntryDetails, Outpoint, ScriptPublicKey, UtxoEntry};

/// A bundle's own version, upstream's `Version`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    /// The first: no payload, no covenant.
    Zero = 0,
    /// Carries a payload.
    One = 1,
    /// Carries covenant bindings.
    Two = 2,
}

/// The global map's fields a caller chooses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Global<'a> {
    pub version: Version,
    pub tx_version: u16,
    pub fallback_lock_time: Option<u64>,
    pub payload: Option<&'a [u8]>,
}

/// A `bip32Derivations` member: a compressed key and its JSON value,
/// upstream's `KeySource` ([`key_source`]) or `null`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member<'a> {
    pub public_key: &'a [u8; PUBLIC_KEY_SIZE],
    pub value: &'a [u8],
}

/// One input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input<'a> {
    pub previous_outpoint: Outpoint,
    /// The output it spends: value and script.
    pub utxo_entry: UtxoEntry<'a>,
    /// The rest of that output's entry.
    pub details: EntryDetails,
    /// `None` is absent, which upstream reads as final.
    pub sequence: Option<u64>,
    pub min_time: Option<u64>,
    pub sighash_type: u8,
    pub redeem_script: Option<&'a [u8]>,
    pub sig_op_count: Option<u8>,
    /// In key order.
    pub derivations: &'a [Member<'a>],
}

/// One output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output<'a> {
    pub amount: u64,
    pub script_public_key: ScriptPublicKey<'a>,
    pub covenant: Option<CovenantBinding>,
    /// In key order.
    pub derivations: &'a [Member<'a>],
}

/// Why a bundle was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The caller's buffer cannot hold it.
    BufferTooSmall,
    /// A payload below version One.
    PayloadNeedsVersionOne,
    /// Output `output` binds a covenant below version Two or the covenant
    /// transaction version.
    CovenantNeedsVersionTwo { output: usize },
    /// Input `input`'s derivations are not in key order, or name a key twice.
    InputKeyOrder { input: usize },
    /// Output `output`'s, likewise.
    OutputKeyOrder { output: usize },
}

impl From<crate::rpc::RpcError> for WriteError {
    fn from(_: crate::rpc::RpcError) -> Self {
        WriteError::BufferTooSmall
    }
}

/// Bytes [`key_source`] writes at most for a path of `levels` levels.
pub const fn key_source_max(levels: usize) -> usize {
    // `{"keyFingerprint":"` and eight hex, `","derivationPath":"m`, `"}`,
    // and per level a slash, ten digits and a hardened mark.
    19 + 8 + 21 + 2 + 12 * levels
}

/// Upstream's `KeySource` for `fingerprint` and `path` as serde writes it,
/// `{"keyFingerprint":"<hex>","derivationPath":"m/..."}`, into `out`: its
/// length. A level with its top bit set is hardened, written with `'`.
///
/// # Errors
///
/// `BufferTooSmall` under [`key_source_max`].
pub fn key_source(
    fingerprint: &[u8; 4],
    path: &[u32],
    out: &mut [u8],
) -> Result<usize, WriteError> {
    let mut s = Sink::writing(out);
    s.put(b"{\"keyFingerprint\":\"")?;
    s.hex_bare(fingerprint)?;
    s.put(b"\",\"derivationPath\":\"m")?;
    for &level in path {
        s.put(b"/")?;
        s.number(u64::from(level & 0x7fff_ffff))?;
        if level & 0x8000_0000 != 0 {
            s.put(b"'")?;
        }
    }
    s.put(b"\"}")?;
    Ok(s.len())
}

/// What upstream would refuse to build, before anything is written.
fn check(
    global: &Global<'_>,
    inputs: &[Input<'_>],
    outputs: &[Output<'_>],
) -> Result<(), WriteError> {
    if global.payload.is_some() && global.version < Version::One {
        return Err(WriteError::PayloadNeedsVersionOne);
    }
    for (k, o) in outputs.iter().enumerate() {
        if o.covenant.is_some()
            && (global.version < Version::Two || global.tx_version < TX_VERSION_COVENANTS)
        {
            return Err(WriteError::CovenantNeedsVersionTwo { output: k });
        }
        if !in_key_order(o.derivations) {
            return Err(WriteError::OutputKeyOrder { output: k });
        }
    }
    for (i, input) in inputs.iter().enumerate() {
        if !in_key_order(input.derivations) {
            return Err(WriteError::InputKeyOrder { input: i });
        }
    }
    Ok(())
}

fn in_key_order(members: &[Member<'_>]) -> bool {
    members
        .windows(2)
        .all(|w| w[0].public_key[..] < w[1].public_key[..])
}

fn optional_number(s: &mut Sink<'_>, v: Option<u64>) -> Result<(), WriteError> {
    match v {
        Some(v) => s.number(v)?,
        None => s.put(b"null")?,
    }
    Ok(())
}

fn optional_hex(s: &mut Sink<'_>, v: Option<&[u8]>) -> Result<(), WriteError> {
    match v {
        Some(v) => s.hex(v)?,
        None => s.put(b"null")?,
    }
    Ok(())
}

/// A script public key: one hex string, the version big-endian first.
fn script_public_key(s: &mut Sink<'_>, spk: &ScriptPublicKey<'_>) -> Result<(), WriteError> {
    s.put(b"\"")?;
    s.hex_bare(&spk.version.to_be_bytes())?;
    s.hex_bare(spk.script)?;
    s.put(b"\"")?;
    Ok(())
}

fn derivations(s: &mut Sink<'_>, members: &[Member<'_>]) -> Result<(), WriteError> {
    s.put(b"{")?;
    for (k, m) in members.iter().enumerate() {
        if k > 0 {
            s.put(b",")?;
        }
        s.hex(m.public_key)?;
        s.put(b":")?;
        s.put(m.value)?;
    }
    s.put(b"}")?;
    Ok(())
}

fn body(
    global: &Global<'_>,
    inputs: &[Input<'_>],
    outputs: &[Output<'_>],
    s: &mut Sink<'_>,
) -> Result<(), WriteError> {
    s.put(b"[{\"global\":{\"version\":")?;
    s.number(global.version as u64)?;
    s.put(b",\"txVersion\":")?;
    s.number(u64::from(global.tx_version))?;
    s.put(b",\"fallbackLockTime\":")?;
    optional_number(s, global.fallback_lock_time)?;
    s.put(b",\"inputsModifiable\":false,\"outputsModifiable\":false,\"inputCount\":")?;
    s.number(inputs.len() as u64)?;
    s.put(b",\"outputCount\":")?;
    s.number(outputs.len() as u64)?;
    s.put(b",\"xpubs\":{},\"id\":null,\"proprietaries\":{},\"payload\":")?;
    optional_hex(s, global.payload)?;
    s.put(b"},\"inputs\":[")?;
    for (i, input) in inputs.iter().enumerate() {
        if i > 0 {
            s.put(b",")?;
        }
        s.put(b"{\"utxoEntry\":{\"amount\":")?;
        s.number(input.utxo_entry.amount)?;
        s.put(b",\"scriptPublicKey\":")?;
        script_public_key(s, &input.utxo_entry.script_public_key)?;
        s.put(b",\"blockDaaScore\":")?;
        s.number(input.details.block_daa_score)?;
        s.put(b",\"isCoinbase\":")?;
        s.put(if input.details.is_coinbase {
            b"true"
        } else {
            b"false"
        })?;
        s.put(b",\"covenantId\":")?;
        optional_hex(s, input.details.covenant_id.as_ref().map(|c| &c[..]))?;
        s.put(b"},\"previousOutpoint\":{\"transactionId\":")?;
        s.hex(&input.previous_outpoint.transaction_id)?;
        s.put(b",\"index\":")?;
        s.number(u64::from(input.previous_outpoint.index))?;
        s.put(b"},\"sequence\":")?;
        optional_number(s, input.sequence)?;
        s.put(b",\"minTime\":")?;
        optional_number(s, input.min_time)?;
        s.put(b",\"partialSigs\":{},\"sighashType\":")?;
        s.number(u64::from(input.sighash_type))?;
        s.put(b",\"redeemScript\":")?;
        optional_hex(s, input.redeem_script)?;
        s.put(b",\"sigOpCount\":")?;
        optional_number(s, input.sig_op_count.map(u64::from))?;
        s.put(b",\"bip32Derivations\":")?;
        derivations(s, input.derivations)?;
        s.put(b",\"finalScriptSig\":null,\"proprietaries\":{}}")?;
    }
    s.put(b"],\"outputs\":[")?;
    for (k, output) in outputs.iter().enumerate() {
        if k > 0 {
            s.put(b",")?;
        }
        s.put(b"{\"amount\":")?;
        s.number(output.amount)?;
        s.put(b",\"scriptPublicKey\":")?;
        script_public_key(s, &output.script_public_key)?;
        s.put(b",\"redeemScript\":null,\"bip32Derivations\":")?;
        derivations(s, output.derivations)?;
        s.put(b",\"covenant\":")?;
        match &output.covenant {
            Some(c) => {
                s.put(b"{\"authorizingInput\":")?;
                s.number(u64::from(c.authorizing_input))?;
                s.put(b",\"covenantId\":")?;
                s.hex(&c.covenant_id)?;
                s.put(b"}")?;
            }
            None => s.put(b"null")?,
        }
        s.put(b",\"proprietaries\":{}}")?;
    }
    s.put(b"]}]")?;
    Ok(())
}

/// Bytes [`write()`] writes.
///
/// # Errors
///
/// What [`write()`] refuses besides the buffer.
pub fn written_len(
    global: &Global<'_>,
    inputs: &[Input<'_>],
    outputs: &[Output<'_>],
) -> Result<usize, WriteError> {
    check(global, inputs, outputs)?;
    let mut s = Sink::measure();
    body(global, inputs, outputs, &mut s)?;
    Ok(s.len())
}

/// The bundle document of one transaction as upstream serializes it, into
/// `out`: its length. [`encode_envelope`](super::encode_envelope) wraps it.
///
/// # Errors
///
/// `PayloadNeedsVersionOne`, `CovenantNeedsVersionTwo`, `InputKeyOrder` or
/// `OutputKeyOrder`, with nothing written; `BufferTooSmall` under
/// [`written_len`].
pub fn write(
    global: &Global<'_>,
    inputs: &[Input<'_>],
    outputs: &[Output<'_>],
    out: &mut [u8],
) -> Result<usize, WriteError> {
    check(global, inputs, outputs)?;
    let mut s = Sink::writing(out);
    body(global, inputs, outputs, &mut s)?;
    Ok(s.len())
}
