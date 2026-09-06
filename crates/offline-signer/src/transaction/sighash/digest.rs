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

// Final Kaspa transaction signing digest assembly.

use crate::transaction::model::{Hash256, SigHashType, Transaction};

use super::blake2b::KaspaBlake2b;
use super::components::{
    outputs_hash, payload_hash, previous_outputs_hash, sequences_hash, sig_op_counts_hash,
};

/// Incremental keyed Blake2b-256 hasher for the final sighash digest.
struct SigHasher {
    hasher: KaspaBlake2b,
}

impl SigHasher {
    fn new() -> Self {
        Self {
            hasher: KaspaBlake2b::new(),
        }
    }

    fn update_u8(&mut self, val: u8) {
        self.hasher.update(&[val]);
    }

    fn update_u16_le(&mut self, val: u16) {
        self.hasher.update(&val.to_le_bytes());
    }

    fn update_u32_le(&mut self, val: u32) {
        self.hasher.update(&val.to_le_bytes());
    }

    fn update_u64_le(&mut self, val: u64) {
        self.hasher.update(&val.to_le_bytes());
    }

    fn update_hash(&mut self, hash: &Hash256) {
        self.hasher.update(hash);
    }

    fn update_bytes(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Hash256 {
        self.hasher.finalize()
    }
}

/// Compute the sighash for a specific transaction input.
///
/// This is the 32-byte message signed with Schnorr.
///
/// `tx`: the complete transaction
/// `input_index`: index of the input being signed
/// `sighash_type`: sighash type (normally SigHashAll)
///
/// Returns 32 bytes = keyed Blake2b of the sighash digest.
pub fn calculate_sighash(
    tx: &Transaction,
    input_index: usize,
    sighash_type: SigHashType,
) -> Hash256 {
    let input = &tx.inputs[input_index];

    let prev_outputs = previous_outputs_hash(tx, sighash_type);
    let sequences = sequences_hash(tx, sighash_type);
    let outputs = outputs_hash(tx, sighash_type, input_index);
    let payload = payload_hash(tx);

    // Build the final digest with "TransactionSigningHash" domain key
    let mut h = SigHasher::new();

    // 1. tx.Version (2 bytes LE)
    h.update_u16_le(tx.version);

    // 2. previousOutputsHash (32 bytes)
    h.update_hash(&prev_outputs);

    // 3. sequencesHash (32 bytes)
    h.update_hash(&sequences);

    // 4. sigOpCountsHash (32 bytes) — only for version 0
    if tx.version == 0 {
        let sig_op_counts = sig_op_counts_hash(tx, sighash_type);
        h.update_hash(&sig_op_counts);
    }

    // 5. txIn.PreviousOutpoint.TransactionID (32 bytes)
    h.update_hash(&input.previous_outpoint.transaction_id);

    // 6. txIn.PreviousOutpoint.Index (4 bytes LE)
    h.update_u32_le(input.previous_outpoint.index);

    // 7. txIn.PreviousOutput.ScriptPubKeyVersion (2 bytes LE)
    h.update_u16_le(input.utxo_entry.script_public_key.version);

    // 8. txIn.PreviousOutput.ScriptPubKey.length (8 bytes LE)
    h.update_u64_le(input.utxo_entry.script_public_key.script_len as u64);

    // 9. txIn.PreviousOutput.ScriptPubKey (variable)
    h.update_bytes(input.utxo_entry.script_public_key.script_bytes());

    // 10. txIn.PreviousOutput.Value (8 bytes LE)
    h.update_u64_le(input.utxo_entry.amount);

    // 11. txIn.Sequence (8 bytes LE)
    h.update_u64_le(input.sequence);

    // 12. txIn.SigOpCount (1 byte) — only for version 0
    if tx.version == 0 {
        h.update_u8(input.sig_op_count);
    }

    // 13. outputsHash (32 bytes)
    h.update_hash(&outputs);

    // 14. tx.Locktime (8 bytes LE)
    h.update_u64_le(tx.locktime);

    // 15. tx.SubnetworkID (20 bytes)
    h.update_bytes(&tx.subnetwork_id);

    // 16. tx.Gas (8 bytes LE)
    h.update_u64_le(tx.gas);

    // 17. payloadHash (32 bytes)
    h.update_hash(&payload);

    // 18. SigHash type (1 byte)
    h.update_u8(sighash_type.to_byte());

    let result = h.finalize();

    // The portable signer does not emit transaction-derived debug material.

    result
}
