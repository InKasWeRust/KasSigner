// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// KasSigner — Kaspa SigHash Calculation
// 100% Rust, no-std, no-alloc
//
// Implements sighash computation per the Kaspa specification:
//   https://kaspa-mdbook.aspectron.com/transactions/sighashes.html
//
// Similar a BIP-143 de Bitcoin pero usando Blake2b en vez de SHA256.
//
// The sighash is the 32-byte message signed with Schnorr.
//
// Flujo:
//   Transaction + input_index + sighash_type
//     → serialize fields per spec
//     → Blake2b(serialization)
//     → 32 bytes = sighash
//     → schnorr_sign(private_key, sighash)


use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

/// Blake2b con output de 32 bytes (256 bits)
type Blake2b256 = Blake2b<U32>;
use super::transaction::*;

/// Hash Blake2b-256 de un buffer
pub fn blake2b_hash(data: &[u8]) -> Hash256 {
    let mut hasher = Blake2b256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Hash Blake2b-256 incremental (usando un hasher)
struct SigHasher {
    hasher: Blake2b256,
}

impl SigHasher {
    fn new() -> Self {
        Self {
            hasher: Blake2b256::new(),
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
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// ─── previousOutputsHash ──────────────────────────────────────────────

/// Blake2b(serialization of all outpoints)
/// Si ANYONECANPAY → 0x0000...0000
fn previous_outputs_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay() {
        return [0u8; 32];
    }

    let mut hasher = Blake2b256::new();
    for input in tx.inputs() {
        hasher.update(&input.previous_outpoint.transaction_id);
        hasher.update(&input.previous_outpoint.index.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ─── sequencesHash ────────────────────────────────────────────────────

/// Blake2b(serialization of all sequences)
/// Si ANYONECANPAY, SINGLE o NONE → 0x0000...0000
fn sequences_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay()
        || sighash_type.is_sighash_single()
        || sighash_type.is_sighash_none()
    {
        return [0u8; 32];
    }

    let mut hasher = Blake2b256::new();
    for input in tx.inputs() {
        hasher.update(&input.sequence.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ─── sigOpCountsHash ──────────────────────────────────────────────────

/// Blake2b(serialization of all sigOpCounts)
/// Si ANYONECANPAY → 0x0000...0000
fn sig_op_counts_hash(tx: &Transaction, sighash_type: SigHashType) -> Hash256 {
    if sighash_type.is_anyone_can_pay() {
        return [0u8; 32];
    }

    let mut hasher = Blake2b256::new();
    for input in tx.inputs() {
        hasher.update(&[input.sig_op_count]);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ─── outputsHash ──────────────────────────────────────────────────────

/// Blake2b(serialization of outputs)
///
/// - NONE o (SINGLE con input_index >= num_outputs) → 0x0000...0000
/// - SINGLE with input_index < num_outputs → hash of output[input_index]
/// - Otros → hash de todos los outputs
fn outputs_hash(
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
        // Solo el output con el mismo index
        let output = &tx.outputs[input_index];
        let mut hasher = Blake2b256::new();
        hash_output(&mut hasher, output);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        return hash;
    }

    // SigHashAll: hash de todos los outputs
    let mut hasher = Blake2b256::new();
    for output in tx.outputs() {
        hash_output(&mut hasher, output);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Serialize an output for hashing
fn hash_output(hasher: &mut Blake2b256, output: &TransactionOutput) {
    hasher.update(&output.value.to_le_bytes());
    hasher.update(&output.script_public_key.version.to_le_bytes());
    hasher.update(output.script_public_key.script_bytes());
}

// ─── payloadHash ──────────────────────────────────────────────────────

/// Si native (subnetwork = 0x00...00) → 0x0000...0000
/// Sino → Blake2b(payload)
fn payload_hash(tx: &Transaction) -> Hash256 {
    if tx.is_native() {
        return [0u8; 32];
    }
    blake2b_hash(&tx.payload[..tx.payload_len])
}

// ═══════════════════════════════════════════════════════════════════════
// Public API: calculate_sighash
// ═══════════════════════════════════════════════════════════════════════

/// Compute the sighash for a specific transaction input.
///
/// This is the 32-byte message signed with Schnorr.
///
/// `tx`: the complete transaction
/// `input_index`: index of the input being signed
/// `sighash_type`: tipo de sighash (normalmente SigHashAll)
///
/// Retorna 32 bytes = Blake2b del sighash digest.
pub fn calculate_sighash(
    tx: &Transaction,
    input_index: usize,
    sighash_type: SigHashType,
) -> Hash256 {
    let input = &tx.inputs[input_index];

    let prev_outputs = previous_outputs_hash(tx, sighash_type);
    let sequences = sequences_hash(tx, sighash_type);
    let sig_op_counts = sig_op_counts_hash(tx, sighash_type);
    let outputs = outputs_hash(tx, sighash_type, input_index);
    let payload = payload_hash(tx);

    // Construir el digest final
    let mut h = SigHasher::new();

    // 1. tx.Version (2 bytes LE)
    h.update_u16_le(tx.version);

    // 2. previousOutputsHash (32 bytes)
    h.update_hash(&prev_outputs);

    // 3. sequencesHash (32 bytes)
    h.update_hash(&sequences);

    // 4. sigOpCountsHash (32 bytes)
    h.update_hash(&sig_op_counts);

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

    // 12. txIn.SigOpCount (1 byte)
    h.update_u8(input.sig_op_count);

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

    h.finalize()
}

// ═══════════════════════════════════════════════════════════════════════
// Full flow: sighash → Schnorr sign
// ═══════════════════════════════════════════════════════════════════════

/// Sign a Kaspa transaction input.
///
/// Compute the sighash and sign with Schnorr.
///
/// `tx`: complete transaction
/// `input_index`: input a firmar
/// `private_key`: 32-byte private key (from BIP32 derivation)
/// `sighash_type`: tipo (normalmente SigHashAll)
///
/// Retorna la firma Schnorr de 64 bytes.
pub fn sign_input(
    tx: &Transaction,
    input_index: usize,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) -> Result<super::schnorr::SchnorrSignature, super::schnorr::SchnorrError> {
    let sighash = calculate_sighash(tx, input_index, sighash_type);
    super::schnorr::schnorr_sign(private_key, &sighash)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: basic sighash computation for a single-input transaction.
pub fn test_sighash_basic() -> bool {
    // Create a simple transaction: 1 input, 1 output
    let mut tx = Transaction::new();
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    // Input: UTXO con 5 KAS (500_000_000 sompi)
    tx.inputs[0].previous_outpoint.transaction_id = [0xAA; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 500_000_000;
    // Script P2PK: OP_DATA_32 <pubkey_x> OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send 4.99 KAS
    tx.outputs[0].value = 499_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // Calcular sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // El sighash no debe ser todo ceros
    let all_zero = sighash.iter().all(|&b| b == 0);
    if all_zero {
        return false;
    }

    // Must be deterministic
    let sighash2 = calculate_sighash(&tx, 0, SigHashType::All);
    sighash == sighash2
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: different inputs produce different sighashes.
pub fn test_sighash_different_inputs() -> bool {
    // Transaction with 2 inputs — each must have a different sighash
    let mut tx = Transaction::new();
    tx.version = 0;
    tx.num_inputs = 2;
    tx.num_outputs = 1;

    // Input 0
    tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 100_000_000;
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xAA; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Input 1
    tx.inputs[1].previous_outpoint.transaction_id = [0x22; 32];
    tx.inputs[1].previous_outpoint.index = 1;
    tx.inputs[1].sequence = u64::MAX;
    tx.inputs[1].sig_op_count = 1;
    tx.inputs[1].utxo_entry.amount = 200_000_000;
    tx.inputs[1].utxo_entry.script_public_key.version = 0;
    tx.inputs[1].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[1].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[1].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[1].utxo_entry.script_public_key.script_len = 34;

    // Output
    tx.outputs[0].value = 290_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    let sighash0 = calculate_sighash(&tx, 0, SigHashType::All);
    let sighash1 = calculate_sighash(&tx, 1, SigHashType::All);

    // Must differ (each input has different outpoint, amount, script)
    sighash0 != sighash1
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: complete transaction signing pipeline.
pub fn test_sign_transaction_complete() -> bool {
    use super::bip39;
    use super::bip32;
    use super::schnorr;

    // 1. Generar wallet
    let entropy = [0u8; 16];
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // 2. Create transaction: 1 input (our UTXO), 1 output
    let mut tx = Transaction::new();
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    tx.inputs[0].previous_outpoint.transaction_id = [0x42; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = 0;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 1_000_000_000; // 10 KAS

    // Script del UTXO = P2PK con nuestra pubkey
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&pubkey_x);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send to another destination
    tx.outputs[0].value = 999_000_000; // 9.99 KAS (fee = 0.01 KAS)
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xFF; 32]); // destino
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // 3. Calcular sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // 4. Firmar con Schnorr
    let sig = match schnorr::schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 5. Verificar firma
    schnorr::schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: KAS amount formatting.
pub fn test_format_kas() -> bool {
    let mut buf = [0u8; 32];

    // 1.0 KAS = 100_000_000 sompi
    let len = Transaction::format_kas(100_000_000, &mut buf);
    if &buf[..len] != b"1.00" {
        return false;
    }

    // 10.5 KAS
    let len = Transaction::format_kas(1_050_000_000, &mut buf);
    if &buf[..len] != b"10.5" {
        return false;
    }

    // 0.001 KAS
    let len = Transaction::format_kas(100_000, &mut buf);
    if &buf[..len] != b"0.001" {
        return false;
    }

    true
}

/// Ejecuta todos los tests de sighash
#[cfg(any(test, feature = "verbose-boot"))]
/// Run all sighash test vectors.
pub fn run_sighash_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_sighash_basic() { passed += 1; }
    if test_sighash_different_inputs() { passed += 1; }
    if test_sign_transaction_complete() { passed += 1; }
    if test_format_kas() { passed += 1; }

    (passed, total)
}
