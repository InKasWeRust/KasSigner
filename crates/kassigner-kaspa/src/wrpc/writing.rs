// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A request written: its parameters by call, addresses and a transaction
//! in each encoding, and the frame around them.

use super::*;

// ── Writing ─────────────────────────────────────────────────────────────────

/// What a request asks, by call.
#[derive(Clone, Copy, Debug)]
pub enum Params<'a> {
    GetServerInfo,
    GetFeeEstimate,
    /// Addresses as text, `kaspa:…`, each decoded, checked and written as
    /// the node reads it.
    GetUtxosByAddresses {
        addresses: &'a [&'a [u8]],
    },
    /// A signed transaction, committing `storage_mass` ([`crate::rpc`]'s
    /// rule). `allow_orphan` lets the node hold it while an input's
    /// transaction is unknown.
    SubmitTransaction {
        transaction: &'a Transaction<'a>,
        storage_mass: u64,
        allow_orphan: bool,
    },
}

impl Params<'_> {
    /// The call these are the params of.
    pub fn call(&self) -> Call {
        match self {
            Params::GetServerInfo => Call::GetServerInfo,
            Params::GetFeeEstimate => Call::GetFeeEstimate,
            Params::GetUtxosByAddresses { .. } => Call::GetUtxosByAddresses,
            Params::SubmitTransaction { .. } => Call::SubmitTransaction,
        }
    }
}

fn put(s: &mut Sink<'_>, bytes: &[u8]) -> Result<(), WrpcError> {
    Ok(s.put(bytes)?)
}

fn length(n: usize) -> Result<[u8; 4], WrpcError> {
    Ok(u32::try_from(n)
        .map_err(|_| WrpcError::TooLong)?
        .to_le_bytes())
}

/// A `Vec<u8>`: its length, then its bytes.
fn vec(s: &mut Sink<'_>, bytes: &[u8]) -> Result<(), WrpcError> {
    put(s, &length(bytes.len())?)?;
    put(s, bytes)
}

/// A payload: a `u32` length, patched in once known, then what `f` writes.
fn payload<'o>(
    s: &mut Sink<'o>,
    f: impl FnOnce(&mut Sink<'o>) -> Result<(), WrpcError>,
) -> Result<(), WrpcError> {
    let at = s.len();
    put(s, &[0; 4])?;
    f(s)?;
    let n = length(s.len() - at - 4)?;
    s.patch(at, &n);
    Ok(())
}

/// `Option::None` written by `serialize!`: a payload holding the tag.
const NONE: [u8; 5] = [1, 0, 0, 0, 0];

/// Upstream's `Prefix` as borsh writes it: its declaration order.
const fn prefix_byte(p: Prefix) -> u8 {
    match p {
        Prefix::Mainnet => 0,
        Prefix::Testnet => 1,
        Prefix::Simnet => 2,
        Prefix::Devnet => 3,
    }
}

pub(super) const fn prefix_of_byte(b: u8) -> Option<Prefix> {
    match b {
        0 => Some(Prefix::Mainnet),
        1 => Some(Prefix::Testnet),
        2 => Some(Prefix::Simnet),
        3 => Some(Prefix::Devnet),
        _ => None,
    }
}

/// An address the caller gave, decoded.
fn decoded(index: usize, text: &[u8]) -> Result<Address, WrpcError> {
    let mut payload = [0u8; 33];
    let (prefix, version, n) =
        address::decode(text, &mut payload).map_err(|error| WrpcError::Address { index, error })?;
    debug_assert_eq!(n, version.payload_len());
    Ok(Address {
        prefix,
        version,
        payload,
    })
}

/// `RpcTransaction`'s serializer at struct version 1, its inputs and
/// outputs at version 2, the covenant hardfork's.
fn rpc_transaction(
    s: &mut Sink<'_>,
    tx: &Transaction<'_>,
    storage_mass: u64,
) -> Result<(), WrpcError> {
    put(s, &1u16.to_le_bytes())?;
    put(s, &tx.version.to_le_bytes())?;
    payload(s, |s| {
        put(s, &length(tx.inputs.len())?)?;
        for input in tx.inputs {
            payload(s, |s| {
                put(s, &[2])?;
                payload(s, |s| {
                    put(s, &[1])?;
                    put(s, &input.previous_outpoint.transaction_id)?;
                    put(s, &input.previous_outpoint.index.to_le_bytes())
                })?;
                vec(s, input.signature_script)?;
                put(s, &input.sequence.to_le_bytes())?;
                put(s, &[input.sig_op_count])?;
                put(s, &NONE)?;
                put(s, &input.compute_budget.to_le_bytes())
            })?;
        }
        Ok(())
    })?;
    payload(s, |s| {
        put(s, &length(tx.outputs.len())?)?;
        for output in tx.outputs {
            payload(s, |s| {
                put(s, &[2])?;
                put(s, &output.value.to_le_bytes())?;
                put(s, &output.script_public_key.version.to_le_bytes())?;
                vec(s, output.script_public_key.script)?;
                put(s, &NONE)?;
                match &output.covenant {
                    None => put(s, &NONE),
                    Some(c) => payload(s, |s| {
                        put(s, &[1])?;
                        payload(s, |s| {
                            put(s, &[1])?;
                            put(s, &c.authorizing_input.to_le_bytes())?;
                            put(s, &c.covenant_id)
                        })
                    }),
                }
            })?;
        }
        Ok(())
    })?;
    put(s, &tx.lock_time.to_le_bytes())?;
    put(s, &tx.subnetwork_id)?;
    put(s, &tx.gas.to_le_bytes())?;
    vec(s, tx.payload)?;
    put(s, &storage_mass.to_le_bytes())?;
    put(s, &NONE)
}

fn write_params(p: &Params<'_>, encoding: Encoding, s: &mut Sink<'_>) -> Result<(), WrpcError> {
    match (encoding, p) {
        (Encoding::Borsh, Params::GetServerInfo | Params::GetFeeEstimate) => {
            payload(s, |s| put(s, &1u16.to_le_bytes()))
        }
        (Encoding::Json, Params::GetServerInfo | Params::GetFeeEstimate) => put(s, b"{}"),
        (Encoding::Borsh, Params::GetUtxosByAddresses { addresses }) => payload(s, |s| {
            put(s, &1u16.to_le_bytes())?;
            put(s, &length(addresses.len())?)?;
            for (index, text) in addresses.iter().enumerate() {
                let a = decoded(index, text)?;
                put(s, &[prefix_byte(a.prefix), a.version as u8])?;
                vec(s, a.payload())?;
            }
            Ok(())
        }),
        (Encoding::Json, Params::GetUtxosByAddresses { addresses }) => {
            put(s, b"{\"addresses\":[")?;
            for (index, text) in addresses.iter().enumerate() {
                if index > 0 {
                    put(s, b",")?;
                }
                // Re-encoded, not as given: one spelling.
                let mut out = [0u8; MAX_ADDRESS_LEN];
                let n = decoded(index, text)?
                    .encode(&mut out)
                    .map_err(|error| WrpcError::Address { index, error })?;
                put(s, b"\"")?;
                put(s, &out[..n])?;
                put(s, b"\"")?;
            }
            put(s, b"]}")
        }
        (
            Encoding::Borsh,
            Params::SubmitTransaction {
                transaction,
                storage_mass,
                allow_orphan,
            },
        ) => payload(s, |s| {
            put(s, &1u16.to_le_bytes())?;
            payload(s, |s| rpc_transaction(s, transaction, *storage_mass))?;
            put(s, &[u8::from(*allow_orphan)])
        }),
        (
            Encoding::Json,
            Params::SubmitTransaction {
                transaction,
                storage_mass,
                allow_orphan,
            },
        ) => Ok(rpc::write(
            transaction,
            *storage_mass,
            *allow_orphan,
            Shape::Rpc,
            s,
        )?),
    }
}

/// A message's start: Borsh's header, JSON's `id` and `method`.
fn frame_start(id: u64, call: Call, encoding: Encoding, s: &mut Sink<'_>) -> Result<(), WrpcError> {
    match encoding {
        Encoding::Borsh => {
            put(s, &[1])?;
            put(s, &id.to_le_bytes())?;
            put(s, &[call.op()])
        }
        Encoding::Json => {
            put(s, b"{\"id\":")?;
            s.number(id)?;
            put(s, b",\"method\":\"")?;
            put(s, call.method().as_bytes())?;
            put(s, b"\",\"params\":")
        }
    }
}

fn frame_end(encoding: Encoding, s: &mut Sink<'_>) -> Result<(), WrpcError> {
    match encoding {
        Encoding::Borsh => Ok(()),
        Encoding::Json => put(s, b"}"),
    }
}

/// Bytes [`params`] writes.
///
/// # Errors
///
/// As [`params`], but for the buffer.
pub fn params_len(p: &Params<'_>, encoding: Encoding) -> Result<usize, WrpcError> {
    let mut s = Sink::measure();
    write_params(p, encoding, &mut s)?;
    Ok(s.len())
}

/// A request's params alone, into `out`: its length. [`frame`] wraps them
/// with an id later.
///
/// # Errors
///
/// `Address { index, error }` for an address that does not decode;
/// `BufferTooSmall` under [`params_len`].
pub fn params(p: &Params<'_>, encoding: Encoding, out: &mut [u8]) -> Result<usize, WrpcError> {
    let mut s = Sink::writing(out);
    write_params(p, encoding, &mut s)?;
    Ok(s.len())
}

/// Bytes [`frame`] writes around params of `params_len` bytes.
pub fn frame_len(id: u64, call: Call, encoding: Encoding, params_len: usize) -> usize {
    let mut s = Sink::measure();
    // Measuring has no buffer to run out of.
    let _ = frame_start(id, call, encoding, &mut s);
    let _ = frame_end(encoding, &mut s);
    s.len() + params_len
}

/// Request `id` of `call` around `params` from [`params`] in the same
/// encoding, into `out`: its length.
///
/// # Errors
///
/// `BufferTooSmall` under [`frame_len`].
pub fn frame(
    id: u64,
    call: Call,
    encoding: Encoding,
    params: &[u8],
    out: &mut [u8],
) -> Result<usize, WrpcError> {
    let mut s = Sink::writing(out);
    frame_start(id, call, encoding, &mut s)?;
    put(&mut s, params)?;
    frame_end(encoding, &mut s)?;
    Ok(s.len())
}

/// Bytes [`request`] writes.
///
/// # Errors
///
/// As [`request`], but for the buffer.
pub fn request_len(id: u64, p: &Params<'_>, encoding: Encoding) -> Result<usize, WrpcError> {
    let mut s = Sink::measure();
    frame_start(id, p.call(), encoding, &mut s)?;
    write_params(p, encoding, &mut s)?;
    frame_end(encoding, &mut s)?;
    Ok(s.len())
}

/// Request `id` for `p`, in `encoding`, into `out`: its length. The node's
/// answer carries `id`.
///
/// # Errors
///
/// `Address { index, error }` for an address that does not decode;
/// `BufferTooSmall` under [`request_len`].
pub fn request(
    id: u64,
    p: &Params<'_>,
    encoding: Encoding,
    out: &mut [u8],
) -> Result<usize, WrpcError> {
    let mut s = Sink::writing(out);
    frame_start(id, p.call(), encoding, &mut s)?;
    write_params(p, encoding, &mut s)?;
    frame_end(encoding, &mut s)?;
    Ok(s.len())
}
