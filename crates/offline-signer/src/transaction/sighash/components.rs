// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Transaction component hashes committed by the final sighash.

use crate::transaction::model::{Hash256, SigHashType, Transaction, TransactionOutput};

use super::blake2b::KaspaBlake2b;

/// Blake2b("TransactionOutpoints", serialization of all outpoints)
/// If ANYONECANPAY -> 0x0000...0000
pub(super) fn previous_outputs_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay() {
        return [0u8; 32];
    }

    let mut hasher = KaspaBlake2b::new();
    for input in tx.inputs() {
        hasher.update(&input.previous_outpoint.transaction_id);
        hasher.update(&input.previous_outpoint.index.to_le_bytes());
    }
    hasher.finalize()
}

// ─── sequencesHash ────────────────────────────────────────────────────

/// Blake2b("TransactionSequences", serialization of all sequences)
/// If ANYONECANPAY, SINGLE or NONE -> 0x0000...0000
pub(super) fn sequences_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay()
        || sighash_type.is_sighash_single()
        || sighash_type.is_sighash_none()
    {
        return [0u8; 32];
    }

    let mut hasher = KaspaBlake2b::new();
    for input in tx.inputs() {
        hasher.update(&input.sequence.to_le_bytes());
    }
    hasher.finalize()
}

// ─── sigOpCountsHash ──────────────────────────────────────────────────

/// Blake2b("TransactionSigOpCounts", serialization of all sigOpCounts)
/// If ANYONECANPAY -> 0x0000...0000
pub(super) fn sig_op_counts_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay() {
        return [0u8; 32];
    }

    let mut hasher = KaspaBlake2b::new();
    for input in tx.inputs() {
        hasher.update(&[input.sig_op_count]);
    }
    hasher.finalize()
}

// ─── outputsHash ──────────────────────────────────────────────────────

/// Blake2b("TransactionOutputs", serialization of outputs)
///
/// - NONE or (SINGLE with input_index >= num_outputs) -> 0x0000...0000
/// - SINGLE with input_index < num_outputs -> hash of output[input_index]
/// - Others -> hash of all outputs
pub(super) fn outputs_hash(
    tx: &Transaction,
    sighash_type: SigHashType,
    input_index: usize,
) -> Hash256 {
    if sighash_type.is_sighash_none() {
        return [0u8; 32];
    }

    if sighash_type.is_sighash_single() {
        if input_index >= tx.num_outputs {
            return [0u8; 32];
        }
        // Only the output with the same index
        let output = &tx.outputs[input_index];
        let mut hasher = KaspaBlake2b::new();
        hash_output(&mut hasher, output, tx.version);
        return hasher.finalize();
    }

    // SigHashAll: hash of all outputs
    let mut hasher = KaspaBlake2b::new();
    for output in tx.outputs() {
        hash_output(&mut hasher, output, tx.version);
    }
    hasher.finalize()
}

/// Serialize an output for hashing.
/// Matches Rusty Kaspa's `hash_output` which calls `hash_script_public_key`,
/// which uses `write_var_bytes` (u64 LE length prefix + raw bytes).
/// For tx version >= 1, also includes covenant binding data.
fn hash_output(hasher: &mut KaspaBlake2b, output: &TransactionOutput, tx_version: u16) {
    hasher.update(&output.value.to_le_bytes());
    // hash_script_public_key: version(u16 LE) + write_var_bytes(script)
    hasher.update(&output.script_public_key.version.to_le_bytes());
    hasher.update(&(output.script_public_key.script_len as u64).to_le_bytes());
    hasher.update(output.script_public_key.script_bytes());

    // Covenant binding (tx version >= 1)
    if tx_version >= 1 {
        if output.has_covenant {
            hasher.update(&[1u8]); // write_bool(true)
            hasher.update(&output.covenant_auth_input.to_le_bytes()); // write_u16
            hasher.update(&output.covenant_id); // update(Hash)
        } else {
            hasher.update(&[0u8]); // write_bool(false)
        }
    }
}

// ─── payloadHash ──────────────────────────────────────────────────────

/// If native with empty payload -> 0x0000...0000
/// Otherwise -> keyed Blake2b(write_var_bytes(payload))
pub(super) fn payload_hash(tx: &Transaction) -> Hash256 {
    if tx.is_native() && tx.payload_len == 0 {
        return [0u8; 32];
    }
    let mut hasher = KaspaBlake2b::new();
    // write_var_bytes: length prefix (u64 LE) + raw bytes
    hasher.update(&(tx.payload_len as u64).to_le_bytes());
    hasher.update(&tx.payload[..tx.payload_len]);
    hasher.finalize()
}
