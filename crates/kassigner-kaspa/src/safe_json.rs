// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A transaction in rusty-kaspa's WASM SDK "safe" JSON, which wallets and
//! apps hand one another (upstream: `SerializableTransaction` in
//! `consensus/client/src/serializable/string.rs`, through `serde_json` in
//! `serializeToSafeJSON` and `deserializeFromSafeJSON`). Every 64-bit number
//! is a decimal string, so JavaScript keeps it whole; every input carries the
//! output it spends under `utxo`.
//!
//! Written as upstream writes it: the fields in declared order, the `utxo`'s
//! `address` `null` as unknown here, hex lowercase, a script public key one
//! hex string with its version big-endian first, the id computed
//! ([`transaction_id`]). Version 0 and version 1, whose inputs commit a
//! compute budget and no signature operations; both fields are written at
//! either version, as upstream writes them.
//!
//! Read as serde reads it: required fields required, an `Option` absent or
//! `null` none, `computeBudget` absent zero, `storageMass` or its alias
//! `mass` but not both, unknown members passed over, a key twice refused.
//! A decimal string reads as `u64::from_str` (a `+` allowed), an address as
//! upstream's `Address`. Stricter, never looser: a string with an escape
//! (no writer writes one), a script public key or address as an object, and
//! a hash or subnetwork id longer than its bytes (`faster_hex` drops the
//! tail) are refused.

use crate::address;
use crate::rpc::{RpcError, Sink};
use crate::sighash::{transaction_id, Hash};
use crate::tx::{
    CovenantBinding, EntryDetails, Outpoint, ScriptPublicKey, SubnetworkId, Transaction,
    TransactionInput, TransactionOutput, UtxoEntry,
};
use crate::wrpc::json::{self, At, Span};

/// Why a transaction was not written or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SafeJsonError {
    /// The caller's buffer cannot hold it.
    BufferTooSmall,
    /// Not one entry's details per input.
    Details,
    /// A version consensus does not know, which has no id.
    Version { version: u16 },
    /// The text is not a transaction as upstream reads one, from `at`.
    Malformed { at: usize },
    /// More inputs or outputs than the caller's arrays hold.
    TooMany,
}

impl From<RpcError> for SafeJsonError {
    fn from(_: RpcError) -> Self {
        SafeJsonError::BufferTooSmall
    }
}

fn malformed(at: At) -> SafeJsonError {
    SafeJsonError::Malformed { at }
}

// ── Writing ─────────────────────────────────────────────────────────────────

/// A `u64` as a decimal string.
fn text_number(s: &mut Sink<'_>, v: u64) -> Result<(), RpcError> {
    s.put(b"\"")?;
    s.number(v)?;
    s.put(b"\"")
}

/// A script public key: one hex string, the version big-endian first.
fn script_public_key(s: &mut Sink<'_>, spk: &ScriptPublicKey<'_>) -> Result<(), RpcError> {
    s.put(b"\"")?;
    s.hex_bare(&spk.version.to_be_bytes())?;
    s.hex_bare(spk.script)?;
    s.put(b"\"")
}

fn body(
    tx: &Transaction<'_>,
    details: &[EntryDetails],
    storage_mass: u64,
    id: &Hash,
    s: &mut Sink<'_>,
) -> Result<(), RpcError> {
    s.put(b"{\"id\":")?;
    s.hex(id)?;
    s.put(b",\"version\":")?;
    s.number(u64::from(tx.version))?;
    s.put(b",\"inputs\":[")?;
    for (i, (input, d)) in tx.inputs.iter().zip(details).enumerate() {
        if i > 0 {
            s.put(b",")?;
        }
        s.put(b"{\"transactionId\":")?;
        s.hex(&input.previous_outpoint.transaction_id)?;
        s.put(b",\"index\":")?;
        s.number(u64::from(input.previous_outpoint.index))?;
        s.put(b",\"sequence\":")?;
        text_number(s, input.sequence)?;
        s.put(b",\"sigOpCount\":")?;
        s.number(u64::from(input.sig_op_count))?;
        s.put(b",\"computeBudget\":")?;
        s.number(u64::from(input.compute_budget))?;
        s.put(b",\"signatureScript\":")?;
        s.hex(input.signature_script)?;
        s.put(b",\"utxo\":{\"address\":null,\"amount\":")?;
        text_number(s, input.utxo_entry.amount)?;
        s.put(b",\"scriptPublicKey\":")?;
        script_public_key(s, &input.utxo_entry.script_public_key)?;
        s.put(b",\"blockDaaScore\":")?;
        text_number(s, d.block_daa_score)?;
        s.put(b",\"isCoinbase\":")?;
        s.put(if d.is_coinbase { b"true" } else { b"false" })?;
        s.put(b",\"covenantId\":")?;
        match &d.covenant_id {
            Some(c) => s.hex(c)?,
            None => s.put(b"null")?,
        }
        s.put(b"}}")?;
    }
    s.put(b"],\"outputs\":[")?;
    for (k, output) in tx.outputs.iter().enumerate() {
        if k > 0 {
            s.put(b",")?;
        }
        s.put(b"{\"value\":")?;
        text_number(s, output.value)?;
        s.put(b",\"scriptPublicKey\":")?;
        script_public_key(s, &output.script_public_key)?;
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
        s.put(b"}")?;
    }
    s.put(b"],\"subnetworkId\":")?;
    s.hex(&tx.subnetwork_id)?;
    s.put(b",\"lockTime\":")?;
    text_number(s, tx.lock_time)?;
    s.put(b",\"gas\":")?;
    text_number(s, tx.gas)?;
    s.put(b",\"storageMass\":")?;
    text_number(s, storage_mass)?;
    s.put(b",\"payload\":")?;
    s.hex(tx.payload)?;
    s.put(b"}")
}

/// The id, for a transaction that can be written.
fn written_id(tx: &Transaction<'_>, details: &[EntryDetails]) -> Result<Hash, SafeJsonError> {
    if details.len() != tx.inputs.len() {
        return Err(SafeJsonError::Details);
    }
    transaction_id(tx).ok_or(SafeJsonError::Version {
        version: tx.version,
    })
}

/// Bytes [`write()`] writes.
///
/// # Errors
///
/// What [`write()`] refuses besides the buffer.
pub fn written_len(
    tx: &Transaction<'_>,
    details: &[EntryDetails],
    storage_mass: u64,
) -> Result<usize, SafeJsonError> {
    let id = written_id(tx, details)?;
    let mut s = Sink::measure();
    body(tx, details, storage_mass, &id, &mut s)?;
    Ok(s.len())
}

/// Write `tx` into `out` as `serializeToSafeJSON` does, its inputs' entries
/// completed by `details` (one per input), committing `storage_mass`; its
/// length. Signed or not, as its signature scripts are.
///
/// # Errors
///
/// `Details` for details not one per input, `Version` for a transaction
/// of a version above 1, `BufferTooSmall` under [`written_len`].
pub fn write(
    tx: &Transaction<'_>,
    details: &[EntryDetails],
    storage_mass: u64,
    out: &mut [u8],
) -> Result<usize, SafeJsonError> {
    let id = written_id(tx, details)?;
    let mut s = Sink::writing(out);
    body(tx, details, storage_mass, &id, &mut s)?;
    Ok(s.len())
}

// ── Reading ─────────────────────────────────────────────────────────────────

/// What the transaction carries besides its inputs and outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub version: u16,
    pub lock_time: u64,
    pub subnetwork_id: SubnetworkId,
    pub gas: u64,
    pub payload: &'a [u8],
}

/// What [`fill`] read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filled<'a> {
    /// Entries used in the caller's input array, and in its details.
    pub inputs: usize,
    /// Entries used in the caller's output array.
    pub outputs: usize,
    pub header: Header<'a>,
    /// The id as written, which upstream takes as it is.
    pub id: Hash,
    /// The storage mass, zero when absent or not a number, as upstream.
    pub storage_mass: u64,
}

/// `n` bytes off the front of `rest`.
fn take<'a>(rest: &mut &'a mut [u8], n: usize) -> Result<&'a mut [u8], SafeJsonError> {
    if rest.len() < n {
        return Err(SafeJsonError::TooMany);
    }
    let (head, tail) = core::mem::take(rest).split_at_mut(n);
    *rest = tail;
    Ok(head)
}

/// The hex string at `span`, any even length, decoded off the front of
/// `rest` as `hex::serde` reads bytes.
fn bytes<'a>(s: &[u8], span: Span, rest: &mut &'a mut [u8]) -> Result<&'a [u8], SafeJsonError> {
    let text = json::plain(s, span).map_err(malformed)?;
    if text.len() % 2 != 0 {
        return Err(malformed(span.0));
    }
    let out = take(rest, text.len() / 2)?;
    json::unhex(text, span.0 + 1, out).map_err(malformed)?;
    Ok(out)
}

/// The hex string at `span`, exactly `N` bytes.
fn fixed<const N: usize>(s: &[u8], span: Span) -> Result<[u8; N], SafeJsonError> {
    let text = json::plain(s, span).map_err(malformed)?;
    let mut out = [0u8; N];
    json::unhex(text, span.0 + 1, &mut out).map_err(malformed)?;
    Ok(out)
}

/// A script public key's hex string, its two version bytes then the
/// script, decoded off the front of `rest`.
fn script<'a>(
    s: &[u8],
    span: Span,
    rest: &mut &'a mut [u8],
) -> Result<ScriptPublicKey<'a>, SafeJsonError> {
    let all = bytes(s, span, rest)?;
    if all.len() < 2 {
        return Err(malformed(span.0));
    }
    Ok(ScriptPublicKey {
        version: u16::from_be_bytes([all[0], all[1]]),
        script: &all[2..],
    })
}

fn required(s: &[u8], obj: Span, key: &str) -> Result<Span, SafeJsonError> {
    json::required(s, obj, key).map_err(malformed)
}

fn optional(s: &[u8], obj: Span, key: &str) -> Result<Option<Span>, SafeJsonError> {
    json::optional(s, obj, key).map_err(malformed)
}

fn decimal(s: &[u8], obj: Span, key: &str) -> Result<u64, SafeJsonError> {
    json::decimal_text_at(s, required(s, obj, key)?).map_err(malformed)
}

/// An input's `utxo`: its value and script, and the rest of its entry.
fn utxo<'a>(
    s: &[u8],
    obj: Span,
    rest: &mut &'a mut [u8],
) -> Result<(UtxoEntry<'a>, EntryDetails), SafeJsonError> {
    if let Some(a) = optional(s, obj, "address")? {
        let text = json::plain(s, a).map_err(malformed)?;
        let mut payload = [0u8; 33];
        address::decode(text, &mut payload).map_err(|_| malformed(a.0))?;
    }
    let amount = decimal(s, obj, "amount")?;
    let script_public_key = script(s, required(s, obj, "scriptPublicKey")?, rest)?;
    let block_daa_score = decimal(s, obj, "blockDaaScore")?;
    let is_coinbase = json::bool_at(s, required(s, obj, "isCoinbase")?).map_err(malformed)?;
    let covenant_id = match optional(s, obj, "covenantId")? {
        Some(c) => Some(fixed::<32>(s, c)?),
        None => None,
    };
    Ok((
        UtxoEntry {
            amount,
            script_public_key,
        },
        EntryDetails {
            block_daa_score,
            is_coinbase,
            covenant_id,
        },
    ))
}

fn input<'a>(
    s: &[u8],
    obj: Span,
    rest: &mut &'a mut [u8],
) -> Result<(TransactionInput<'a>, EntryDetails), SafeJsonError> {
    let transaction_id = fixed::<32>(s, required(s, obj, "transactionId")?)?;
    let index = json::u32_at(s, required(s, obj, "index")?).map_err(malformed)?;
    let sequence = decimal(s, obj, "sequence")?;
    let ops = required(s, obj, "sigOpCount")?;
    let sig_op_count =
        u8::try_from(json::u64_at(s, ops).map_err(malformed)?).map_err(|_| malformed(ops.0))?;
    let compute_budget = match json::member(s, obj, "computeBudget").map_err(malformed)? {
        Some(b) => json::u16_at(s, b).map_err(malformed)?,
        None => 0,
    };
    let signature_script = bytes(s, required(s, obj, "signatureScript")?, rest)?;
    let (utxo_entry, details) = utxo(s, required(s, obj, "utxo")?, rest)?;
    Ok((
        TransactionInput {
            previous_outpoint: Outpoint {
                transaction_id,
                index,
            },
            sequence,
            sig_op_count,
            compute_budget,
            signature_script,
            utxo_entry,
        },
        details,
    ))
}

fn output<'a>(
    s: &[u8],
    obj: Span,
    rest: &mut &'a mut [u8],
) -> Result<TransactionOutput<'a>, SafeJsonError> {
    let value = decimal(s, obj, "value")?;
    let script_public_key = script(s, required(s, obj, "scriptPublicKey")?, rest)?;
    let covenant = match optional(s, obj, "covenant")? {
        Some(c) => {
            let authorizing_input =
                json::u16_at(s, required(s, c, "authorizingInput")?).map_err(malformed)?;
            let covenant_id = fixed::<32>(s, required(s, c, "covenantId")?)?;
            Some(CovenantBinding {
                authorizing_input,
                covenant_id,
            })
        }
        None => None,
    };
    Ok(TransactionOutput {
        value,
        script_public_key,
        covenant,
    })
}

/// The storage mass as `deserializeFromSafeJSON` takes it: a string under
/// `storageMass` or `mass`, zero when absent or not a number. Both names
/// are a field twice to serde. A string with an escape is refused, as every
/// other string here is: serde would undo it and read the number, and read
/// as it stands it would pass for "not a number", a zero upstream never
/// reads.
fn storage_mass(s: &[u8], top: Span) -> Result<u64, SafeJsonError> {
    let named = json::member(s, top, "storageMass").map_err(malformed)?;
    let alias = json::member(s, top, "mass").map_err(malformed)?;
    let span = match (named, alias) {
        (Some(_), Some(a)) => return Err(malformed(a.0)),
        (Some(v), None) | (None, Some(v)) => v,
        (None, None) => return Ok(0),
    };
    json::plain(s, span).map_err(malformed)?;
    Ok(json::decimal_text_at(s, span).unwrap_or(0))
}

/// Read `text` into `inputs`, `details`, `outputs`, and its hex decoded into
/// `bytes` (half of `text`'s length always suffices).
///
/// # Errors
///
/// `Malformed` where `text` is not a transaction upstream reads, or one this
/// refuses besides ([module notes](self)); `TooMany` for more inputs or
/// outputs than the arrays hold, or `bytes` short.
pub fn fill<'a>(
    text: &[u8],
    inputs: &mut [TransactionInput<'a>],
    details: &mut [EntryDetails],
    outputs: &mut [TransactionOutput<'a>],
    bytes: &'a mut [u8],
) -> Result<Filled<'a>, SafeJsonError> {
    let s = text;
    let top = json::document(s).map_err(malformed)?;
    let mut rest = bytes;
    let id = fixed::<32>(s, required(s, top, "id")?)?;
    let version = json::u16_at(s, required(s, top, "version")?).map_err(malformed)?;
    let mut ni = 0usize;
    for element in json::elements(s, required(s, top, "inputs")?).map_err(malformed)? {
        let (read, d) = input(s, element, &mut rest)?;
        *inputs.get_mut(ni).ok_or(SafeJsonError::TooMany)? = read;
        *details.get_mut(ni).ok_or(SafeJsonError::TooMany)? = d;
        ni += 1;
    }
    let mut no = 0usize;
    for element in json::elements(s, required(s, top, "outputs")?).map_err(malformed)? {
        *outputs.get_mut(no).ok_or(SafeJsonError::TooMany)? = output(s, element, &mut rest)?;
        no += 1;
    }
    let subnetwork_id = fixed::<20>(s, required(s, top, "subnetworkId")?)?;
    let lock_time = decimal(s, top, "lockTime")?;
    let gas = decimal(s, top, "gas")?;
    let storage_mass = storage_mass(s, top)?;
    let payload = self::bytes(s, required(s, top, "payload")?, &mut rest)?;
    Ok(Filled {
        inputs: ni,
        outputs: no,
        header: Header {
            version,
            lock_time,
            subnetwork_id,
            gas,
            payload,
        },
        id,
        storage_mass,
    })
}

/// The transaction over what [`fill`] read.
pub fn build<'a>(
    header: &Header<'a>,
    inputs: &'a [TransactionInput<'a>],
    outputs: &'a [TransactionOutput<'a>],
) -> Transaction<'a> {
    Transaction {
        version: header.version,
        inputs,
        outputs,
        lock_time: header.lock_time,
        subnetwork_id: header.subnetwork_id,
        gas: header.gas,
        payload: header.payload,
    }
}
