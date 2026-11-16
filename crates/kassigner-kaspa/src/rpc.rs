// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! A signed transaction as a node's RPC takes it: `SubmitTransactionRequest`
//! and `RpcTransaction` (`rpc/core/src/model/`) as the wRPC JSON encoding
//! carries them ([`Shape::Rpc`]). Names are serde's `camelCase`; ids,
//! signature scripts, subnetwork id and payload are hex; a script public
//! key is one hex string, its version big-endian first.
//!
//! kaspa-rest-server's `POST /transactions` has its own model
//! (`SubmitTxModel`), which [`Shape::Rest`] writes: an output's value is
//! `amount`, its script public key `{"version":0,"scriptPublicKey":"<hex>"}`,
//! and undeclared fields, the mass among them, are dropped; the node sets
//! the mass at mempool entry.
//!
//! A node checks the committed storage mass against its own
//! (`check_mass_commitment`), so the request carries it as `mass`, the name
//! every node reads; `storageMass` is a newer alias, and a node refuses the
//! two disagreeing.
//!
//! The call itself is the app's, over wRPC, gRPC or REST; [`crate::wrpc`]
//! writes the whole wRPC message around these bytes.

use crate::tx::Transaction;

/// Why the request was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcError {
    /// The caller's buffer cannot hold the request.
    BufferTooSmall,
}

/// Which taker's JSON: the node's RPC, or the REST server's model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// `submitTransaction`'s params as serde writes them, mass committed.
    Rpc,
    /// kaspa-rest-server's `POST /transactions` body.
    Rest,
}

/// Where bytes go: into a buffer, or nowhere while measuring. Shared with
/// [`crate::wrpc`].
pub(crate) struct Sink<'o> {
    out: Option<&'o mut [u8]>,
    len: usize,
}

impl<'o> Sink<'o> {
    /// A sink that only counts.
    pub(crate) fn measure() -> Sink<'static> {
        Sink { out: None, len: 0 }
    }

    /// A sink writing into `out`.
    pub(crate) fn writing(out: &'o mut [u8]) -> Sink<'o> {
        Sink {
            out: Some(out),
            len: 0,
        }
    }

    /// Bytes put so far.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<(), RpcError> {
        let end = self.len + bytes.len();
        if let Some(out) = self.out.as_deref_mut() {
            out.get_mut(self.len..end)
                .ok_or(RpcError::BufferTooSmall)?
                .copy_from_slice(bytes);
        }
        self.len = end;
        Ok(())
    }

    /// Overwrite bytes already put at `at`, as a length once known.
    pub(crate) fn patch(&mut self, at: usize, bytes: &[u8]) {
        if let Some(slot) = self
            .out
            .as_deref_mut()
            .and_then(|out| out.get_mut(at..at + bytes.len()))
        {
            slot.copy_from_slice(bytes);
        }
    }

    pub(crate) fn hex(&mut self, bytes: &[u8]) -> Result<(), RpcError> {
        self.put(b"\"")?;
        self.hex_bare(bytes)?;
        self.put(b"\"")
    }

    pub(crate) fn hex_bare(&mut self, bytes: &[u8]) -> Result<(), RpcError> {
        for &b in bytes {
            self.put(&crate::hex::digits(b))?;
        }
        Ok(())
    }

    pub(crate) fn number(&mut self, v: u64) -> Result<(), RpcError> {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        let mut v = v;
        loop {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&digits[i..])
    }
}

/// The request in `shape` into `s`.
pub(crate) fn write(
    tx: &Transaction<'_>,
    storage_mass: u64,
    allow_orphan: bool,
    shape: Shape,
    s: &mut Sink<'_>,
) -> Result<(), RpcError> {
    s.put(b"{\"transaction\":{\"version\":")?;
    s.number(u64::from(tx.version))?;
    s.put(b",\"inputs\":[")?;
    for (i, input) in tx.inputs.iter().enumerate() {
        if i > 0 {
            s.put(b",")?;
        }
        s.put(b"{\"previousOutpoint\":{\"transactionId\":")?;
        s.hex(&input.previous_outpoint.transaction_id)?;
        s.put(b",\"index\":")?;
        s.number(u64::from(input.previous_outpoint.index))?;
        s.put(b"},\"signatureScript\":")?;
        s.hex(input.signature_script)?;
        s.put(b",\"sequence\":")?;
        s.number(input.sequence)?;
        s.put(b",\"sigOpCount\":")?;
        s.number(u64::from(input.sig_op_count))?;
        if tx.version >= 1 {
            s.put(b",\"computeBudget\":")?;
            s.number(u64::from(input.compute_budget))?;
        }
        s.put(b"}")?;
    }
    s.put(b"],\"outputs\":[")?;
    for (k, output) in tx.outputs.iter().enumerate() {
        if k > 0 {
            s.put(b",")?;
        }
        match shape {
            Shape::Rpc => {
                s.put(b"{\"value\":")?;
                s.number(output.value)?;
                s.put(b",\"scriptPublicKey\":\"")?;
                // One hex string: the version big-endian, the script.
                let version = output.script_public_key.version.to_be_bytes();
                s.hex_bare(&version)?;
                s.hex_bare(output.script_public_key.script)?;
                s.put(b"\"")?;
            }
            Shape::Rest => {
                s.put(b"{\"amount\":")?;
                s.number(output.value)?;
                s.put(b",\"scriptPublicKey\":{\"version\":")?;
                s.number(u64::from(output.script_public_key.version))?;
                s.put(b",\"scriptPublicKey\":")?;
                s.hex(output.script_public_key.script)?;
                s.put(b"}")?;
            }
        }
        if let Some(c) = &output.covenant {
            s.put(b",\"covenant\":{\"authorizingInput\":")?;
            s.number(u64::from(c.authorizing_input))?;
            s.put(b",\"covenantId\":")?;
            s.hex(&c.covenant_id)?;
            s.put(b"}")?;
        }
        s.put(b"}")?;
    }
    s.put(b"],\"lockTime\":")?;
    s.number(tx.lock_time)?;
    s.put(b",\"subnetworkId\":")?;
    s.hex(&tx.subnetwork_id)?;
    s.put(b",\"gas\":")?;
    s.number(tx.gas)?;
    s.put(b",\"payload\":")?;
    s.hex(tx.payload)?;
    if shape == Shape::Rpc {
        s.put(b",\"mass\":")?;
        s.number(storage_mass)?;
    }
    s.put(b"},\"allowOrphan\":")?;
    s.put(if allow_orphan { b"true" } else { b"false" })?;
    s.put(b"}")
}

/// Bytes [`submit_transaction`] writes for `tx` in `shape`.
pub fn submit_transaction_len(
    tx: &Transaction<'_>,
    storage_mass: u64,
    allow_orphan: bool,
    shape: Shape,
) -> usize {
    let mut s = Sink::measure();
    // Measuring has no buffer to run out of.
    let _ = write(tx, storage_mass, allow_orphan, shape, &mut s);
    s.len()
}

/// The `submitTransaction` request for signed `tx`, committing
/// `storage_mass`, as JSON in `shape` into `out`; its length.
///
/// # Errors
///
/// `BufferTooSmall` under [`submit_transaction_len`].
pub fn submit_transaction(
    tx: &Transaction<'_>,
    storage_mass: u64,
    allow_orphan: bool,
    shape: Shape,
    out: &mut [u8],
) -> Result<usize, RpcError> {
    let mut s = Sink::writing(out);
    write(tx, storage_mass, allow_orphan, shape, &mut s)?;
    Ok(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry};

    /// **The request is upstream's JSON, field for field**, and the REST
    /// server's model.
    #[test]
    fn the_request_is_upstreams_json() {
        let inputs = [TransactionInput {
            previous_outpoint: Outpoint {
                transaction_id: [0xAB; 32],
                index: 3,
            },
            sequence: 0,
            sig_op_count: 1,
            compute_budget: 0,
            signature_script: &[0x41, 0x01, 0x02],
            utxo_entry: UtxoEntry {
                amount: 0,
                script_public_key: ScriptPublicKey {
                    version: 0,
                    script: &[],
                },
            },
        }];
        let outputs = [TransactionOutput {
            value: 123_456_789,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &[0x20, 0xCD, 0xAC],
            },
            covenant: None,
        }];
        let tx = Transaction {
            version: 0,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 0,
            subnetwork_id: [0; 20],
            gas: 0,
            payload: &[],
        };
        let n = submit_transaction_len(&tx, 4_209, false, Shape::Rpc);
        let mut out = [0u8; 1024];
        assert_eq!(
            submit_transaction(&tx, 4_209, false, Shape::Rpc, &mut out),
            Ok(n)
        );
        let want = concat!(
            "{\"transaction\":{\"version\":0,\"inputs\":[{\"previousOutpoint\":{\"transactionId\":\"",
            "abababababababababababababababababababababababababababababababab",
            "\",\"index\":3},\"signatureScript\":\"410102\",\"sequence\":0,\"sigOpCount\":1}],",
            "\"outputs\":[{\"value\":123456789,\"scriptPublicKey\":\"000020cdac\"}],",
            "\"lockTime\":0,\"subnetworkId\":\"0000000000000000000000000000000000000000\",",
            "\"gas\":0,\"payload\":\"\",\"mass\":4209},\"allowOrphan\":false}"
        );
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);
        assert_eq!(
            submit_transaction(&tx, 4_209, false, Shape::Rpc, &mut [0u8; 16]),
            Err(RpcError::BufferTooSmall)
        );

        // The REST server's model: `amount`, the script public key an
        // object, no mass.
        let n = submit_transaction_len(&tx, 4_209, true, Shape::Rest);
        assert_eq!(
            submit_transaction(&tx, 4_209, true, Shape::Rest, &mut out),
            Ok(n)
        );
        let want = concat!(
            "{\"transaction\":{\"version\":0,\"inputs\":[{\"previousOutpoint\":{\"transactionId\":\"",
            "abababababababababababababababababababababababababababababababab",
            "\",\"index\":3},\"signatureScript\":\"410102\",\"sequence\":0,\"sigOpCount\":1}],",
            "\"outputs\":[{\"amount\":123456789,\"scriptPublicKey\":{\"version\":0,\"scriptPublicKey\":\"20cdac\"}}],",
            "\"lockTime\":0,\"subnetworkId\":\"0000000000000000000000000000000000000000\",",
            "\"gas\":0,\"payload\":\"\"},\"allowOrphan\":true}"
        );
        assert_eq!(core::str::from_utf8(&out[..n]).unwrap(), want);
    }
}
