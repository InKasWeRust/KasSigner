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

// KasSigner — KSPT (KasSigner Packed Transaction) Parser
// 100% Rust, no-std, no-alloc
//
// Compact binary format for air-gapped communication (QR/camera).
//
// The companion app builds the transaction, serializes it in this
// format, and encodes it as QR. KasSigner reads it, shows the user
// the details (destination, amount, fee), signs each input, and returns
// the signatures as QR.
//
// ═══════════════════════════════════════════════════════════════════
// BINARY FORMAT: KasSigner KSPT v1
// ═══════════════════════════════════════════════════════════════════
//
// Header:
//   magic:    4 bytes  "KSPT" (0x4B 0x53 0x50 0x54)
//   version:  1 byte   (0x01)
//   flags:    1 byte   (reserved, 0x00)
//
// Global:
//   tx_version:    2 bytes LE
//   num_inputs:    1 byte  (1-8)
//   num_outputs:   1 byte  (1-4)
//   locktime:      8 bytes LE
//   subnetwork_id: 20 bytes
//   gas:           8 bytes LE
//   payload_len:   2 bytes LE (0-128)
//   payload:       [payload_len bytes]
//
// Per input (repeated num_inputs times):
//   prev_tx_id:    32 bytes
//   prev_index:    4 bytes LE
//   amount:        8 bytes LE (sompi of the UTXO being spent)
//   sequence:      8 bytes LE
//   sig_op_count:  1 byte
//   spk_version:   2 bytes LE
//   spk_len:       1 byte (1-64)
//   spk_script:    [spk_len bytes]
//
// Per output (repeated num_outputs times):
//   value:         8 bytes LE (sompi)
//   spk_version:   2 bytes LE
//   spk_len:       1 byte (1-64)
//   spk_script:    [spk_len bytes]
//
// Typical total: ~200-300 bytes for 1in/2out (fits in 1-2 QR codes)
//
// ═══════════════════════════════════════════════════════════════════
// SIGNED RESPONSE FORMAT
// ═══════════════════════════════════════════════════════════════════
//
// Header:
//   magic:    4 bytes  "KSSN" (0x4B 0x53 0x53 0x4E = KasSigner Signed)
//   version:  1 byte   (0x01)
//   num_sigs: 1 byte
//
// Per signature:
//   input_index: 1 byte
//   sighash_type: 1 byte
//   signature:    64 bytes (Schnorr)
//
// Typical total: 72 bytes for 1 input (fits easily in 1 QR)


use super::transaction::*;

/// Magic bytes for unsigned KSPT
const PSKT_MAGIC: [u8; 4] = [0x4B, 0x53, 0x50, 0x54]; // "KSPT"

/// Magic bytes for signed response
const SIGNED_MAGIC: [u8; 4] = [0x4B, 0x53, 0x53, 0x4E]; // "KSSN"

/// Current format version
const FORMAT_VERSION: u8 = 0x01;

/// KSPT v3: identical to v2 but redeem_len is u16 LE instead of u8.
const FORMAT_VERSION_V3: u8 = 0x03;

/// Maximum signatures in response
pub const MAX_SIGNATURES: usize = MAX_INPUTS;

/// KSPT parser errors
#[derive(Debug, Clone, Copy, PartialEq)]
/// Errors during KSPT parsing, signing, or serialization.
pub enum PsktError {
    /// Buffer too short
    BufferTooShort,
    /// Invalid magic bytes
    InvalidMagic,
    /// Unsupported version
    UnsupportedVersion,
    /// Too many inputs (> MAX_INPUTS)
    TooManyInputs,
    /// Too many outputs (> MAX_OUTPUTS)
    TooManyOutputs,
    /// Script too long (> MAX_SCRIPT_SIZE)
    ScriptTooLong,
    /// Payload too long (> MAX_PAYLOAD_SIZE)
    PayloadTooLong,
    /// Invalid SigHash type
    InvalidSigHashType,
    /// Output buffer too small
    OutputBufferTooSmall,
    /// No inputs present
    NoInputs,
    /// No outputs present
    NoOutputs,
}

// ─── Reader helper (cursor over slice, no-alloc) ─────────────────

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn peek_u8(&self) -> Option<u8> {
        if self.pos < self.data.len() { Some(self.data[self.pos]) } else { None }
    }

    fn read_u8(&mut self) -> Result<u8, PsktError> {
        if self.pos >= self.data.len() {
            return Err(PsktError::BufferTooShort);
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16_le(&mut self) -> Result<u16, PsktError> {
        if self.remaining() < 2 {
            return Err(PsktError::BufferTooShort);
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// SPK length, extended encoding: 1 byte, or 0xFF sentinel + u16 LE.
    /// Mirrors KasSee push_spk_len. Backward compatible with 1-byte lengths.
    fn read_spk_len(&mut self) -> Result<usize, PsktError> {
        let b = self.read_u8()?;
        if b == 0xFF {
            Ok(self.read_u16_le()? as usize)
        } else {
            Ok(b as usize)
        }
    }

    fn read_u32_le(&mut self) -> Result<u32, PsktError> {
        if self.remaining() < 4 {
            return Err(PsktError::BufferTooShort);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64_le(&mut self) -> Result<u64, PsktError> {
        if self.remaining() < 8 {
            return Err(PsktError::BufferTooShort);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], PsktError> {
        if self.remaining() < n {
            return Err(PsktError::BufferTooShort);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_hash256(&mut self) -> Result<Hash256, PsktError> {
        let bytes = self.read_bytes(32)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(bytes);
        Ok(hash)
    }
}

// ─── Writer helper (cursor over mutable buffer, no-alloc) ────────

struct ByteWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> ByteWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn written(&self) -> usize {
        self.pos
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<(), PsktError> {
        if self.remaining() < data.len() {
            return Err(PsktError::OutputBufferTooSmall);
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<(), PsktError> {
        self.write_bytes(&[val])
    }

    fn write_u16_le(&mut self, val: u16) -> Result<(), PsktError> {
        self.write_bytes(&val.to_le_bytes())
    }

    /// SPK length, extended encoding mirroring read_spk_len / KasSee push_spk_len.
    fn write_spk_len(&mut self, len: usize) -> Result<(), PsktError> {
        if len <= 254 {
            self.write_u8(len as u8)
        } else {
            self.write_u8(0xFF)?;
            self.write_u16_le(len as u16)
        }
    }

    fn write_u64_le(&mut self, val: u64) -> Result<(), PsktError> {
        self.write_bytes(&val.to_le_bytes())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Public API: Deserialization (QR -> Transaction)
// ═══════════════════════════════════════════════════════════════════

/// Parse a binary KSPT buffer and populate a Transaction.
///
/// The companion app generates this buffer, encodes it as QR(s),
/// KasSigner reads it with the camera and parses it here.
///
/// Returns Ok(()) on successful parse.
pub fn parse_pskt(data: &[u8], tx: &mut Transaction) -> Result<(), PsktError> {
    tx.clear();
    let mut r = ByteReader::new(data);

    // Header
    let magic = r.read_bytes(4)?;
    if magic != PSKT_MAGIC {
        return Err(PsktError::InvalidMagic);
    }

    let version = r.read_u8()?;
    if version != FORMAT_VERSION {
        return Err(PsktError::UnsupportedVersion);
    }

    let flags = r.read_u8()?; // bit 0x02 = has redeem scripts, bit 0x04 = has covenant bindings
    let has_redeem = (flags & 0x02) != 0;
    let has_covenant_data = (flags & 0x04) != 0;

    // Global
    tx.version = r.read_u16_le()?;
    let num_inputs = r.read_u8()? as usize;
    let num_outputs = r.read_u8()? as usize;

    if num_inputs == 0 {
        return Err(PsktError::NoInputs);
    }
    if num_inputs > MAX_INPUTS {
        return Err(PsktError::TooManyInputs);
    }
    if num_outputs == 0 {
        return Err(PsktError::NoOutputs);
    }
    if num_outputs > MAX_OUTPUTS {
        return Err(PsktError::TooManyOutputs);
    }

    tx.num_inputs = num_inputs;
    tx.num_outputs = num_outputs;
    tx.locktime = r.read_u64_le()?;

    let subnet_bytes = r.read_bytes(20)?;
    tx.subnetwork_id.copy_from_slice(subnet_bytes);

    tx.gas = r.read_u64_le()?;

    let payload_len = r.read_u16_le()? as usize;
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(PsktError::PayloadTooLong);
    }
    tx.payload_len = payload_len;
    if payload_len > 0 {
        let payload_bytes = r.read_bytes(payload_len)?;
        tx.payload[..payload_len].copy_from_slice(payload_bytes);
    }

    // Inputs
    for i in 0..num_inputs {
        tx.inputs[i].previous_outpoint.transaction_id = r.read_hash256()?;
        tx.inputs[i].previous_outpoint.index = r.read_u32_le()?;
        tx.inputs[i].utxo_entry.amount = r.read_u64_le()?;
        tx.inputs[i].sequence = r.read_u64_le()?;
        tx.inputs[i].sig_op_count = r.read_u8()?;

        let spk_version = r.read_u16_le()?;
        let spk_len = r.read_spk_len()?;
        if spk_len > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }

        tx.inputs[i].utxo_entry.script_public_key.version = spk_version;
        tx.inputs[i].utxo_entry.script_public_key.script_len = spk_len;
        let spk_bytes = r.read_bytes(spk_len)?;
        tx.inputs[i].utxo_entry.script_public_key.script[..spk_len]
            .copy_from_slice(spk_bytes);

        // Optional redeem script for P2SH inputs
        tx.inputs[i].redeem_script_len = 0;
        if has_redeem {
            let rs_len = r.read_u8()? as usize;
            if rs_len > 0 {
                if rs_len > MAX_REDEEM_SIZE {
                    return Err(PsktError::ScriptTooLong);
                }
                let rs_bytes = r.read_bytes(rs_len)?;
                tx.store_redeem(i, rs_bytes).map_err(|_| PsktError::ScriptTooLong)?;
            }
        }
    }

    // Outputs
    for i in 0..num_outputs {
        tx.outputs[i].value = r.read_u64_le()?;

        let spk_version = r.read_u16_le()?;
        let spk_len = r.read_spk_len()?;
        if spk_len > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }

        tx.outputs[i].script_public_key.version = spk_version;
        tx.outputs[i].script_public_key.script_len = spk_len;
        let spk_bytes = r.read_bytes(spk_len)?;
        tx.outputs[i].script_public_key.script[..spk_len]
            .copy_from_slice(spk_bytes);

        // Covenant binding (flag 0x04)
        if has_covenant_data {
            let has_cov = r.read_u8()?;
            if has_cov == 1 {
                tx.outputs[i].has_covenant = true;
                tx.outputs[i].covenant_auth_input = r.read_u16_le()?;
                let cov_id_bytes = r.read_bytes(32)?;
                tx.outputs[i].covenant_id.copy_from_slice(cov_id_bytes);
            } else {
                tx.outputs[i].has_covenant = false;
            }
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Public API: Serialization (Transaction -> bytes for QR)
// ═══════════════════════════════════════════════════════════════════

/// Serialize a Transaction to the KSPT binary format.
///
/// Useful for tests and for the companion app to generate the payload.
///
/// Returns the number of bytes written.
pub fn serialize_pskt(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    let mut w = ByteWriter::new(output);

    // Check if any output has covenant data
    let has_covenant_data = (0..tx.num_outputs).any(|i| tx.outputs[i].has_covenant);
    let flags: u8 = if has_covenant_data { 0x04 } else { 0x00 };

    // Header
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(FORMAT_VERSION)?;
    w.write_u8(flags)?;

    // Global
    w.write_u16_le(tx.version)?;
    w.write_u8(tx.num_inputs as u8)?;
    w.write_u8(tx.num_outputs as u8)?;
    w.write_u64_le(tx.locktime)?;
    w.write_bytes(&tx.subnetwork_id)?;
    w.write_u64_le(tx.gas)?;
    w.write_u16_le(tx.payload_len as u16)?;
    if tx.payload_len > 0 {
        w.write_bytes(&tx.payload[..tx.payload_len])?;
    }

    // Inputs
    for i in 0..tx.num_inputs {
        let input = &tx.inputs[i];
        w.write_bytes(&input.previous_outpoint.transaction_id)?;
        w.write_bytes(&input.previous_outpoint.index.to_le_bytes())?;
        w.write_u64_le(input.utxo_entry.amount)?;
        w.write_u64_le(input.sequence)?;
        w.write_u8(input.sig_op_count)?;
        w.write_u16_le(input.utxo_entry.script_public_key.version)?;
        w.write_spk_len(input.utxo_entry.script_public_key.script_len)?;
        w.write_bytes(input.utxo_entry.script_public_key.script_bytes())?;
    }

    // Outputs
    for i in 0..tx.num_outputs {
        let output_tx = &tx.outputs[i];
        w.write_u64_le(output_tx.value)?;
        w.write_u16_le(output_tx.script_public_key.version)?;
        w.write_spk_len(output_tx.script_public_key.script_len)?;
        w.write_bytes(output_tx.script_public_key.script_bytes())?;

        if has_covenant_data {
            if output_tx.has_covenant {
                w.write_u8(1)?;
                w.write_u16_le(output_tx.covenant_auth_input)?;
                w.write_bytes(&output_tx.covenant_id)?;
            } else {
                w.write_u8(0)?;
            }
        }
    }

    Ok(w.written())
}

/// Serialize a signed Transaction to KSPT binary format.
/// Same as serialize_kspt but with signatures appended per input.
/// flags byte = 0x01 to indicate signed KSPT.
pub fn serialize_signed_pskt(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    let mut w = ByteWriter::new(output);

    let has_covenant_data = (0..tx.num_outputs).any(|i| tx.outputs[i].has_covenant);
    let flags: u8 = 0x01 | if has_covenant_data { 0x04 } else { 0x00 }; // signed + optional covenant

    // Header
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(FORMAT_VERSION)?;
    w.write_u8(flags)?;

    // Global
    w.write_u16_le(tx.version)?;
    w.write_u8(tx.num_inputs as u8)?;
    w.write_u8(tx.num_outputs as u8)?;
    w.write_u64_le(tx.locktime)?;
    w.write_bytes(&tx.subnetwork_id)?;
    w.write_u64_le(tx.gas)?;
    w.write_u16_le(tx.payload_len as u16)?;
    if tx.payload_len > 0 {
        w.write_bytes(&tx.payload[..tx.payload_len])?;
    }

    // Inputs (with signatures)
    for i in 0..tx.num_inputs {
        let input = &tx.inputs[i];
        w.write_bytes(&input.previous_outpoint.transaction_id)?;
        w.write_bytes(&input.previous_outpoint.index.to_le_bytes())?;
        w.write_u64_le(input.utxo_entry.amount)?;
        w.write_u64_le(input.sequence)?;
        w.write_u8(input.sig_op_count)?;
        w.write_u16_le(input.utxo_entry.script_public_key.version)?;
        w.write_spk_len(input.utxo_entry.script_public_key.script_len)?;
        w.write_bytes(input.utxo_entry.script_public_key.script_bytes())?;
        // Signature (0 = unsigned, 64 = Schnorr)
        w.write_u8(input.sig_len)?;
        if input.sig_len > 0 {
            w.write_bytes(&input.signature[..input.sig_len as usize])?;
            w.write_u8(input.sighash_type)?;
        }
    }

    // Outputs
    for i in 0..tx.num_outputs {
        let output_tx = &tx.outputs[i];
        w.write_u64_le(output_tx.value)?;
        w.write_u16_le(output_tx.script_public_key.version)?;
        w.write_spk_len(output_tx.script_public_key.script_len)?;
        w.write_bytes(output_tx.script_public_key.script_bytes())?;

        if has_covenant_data {
            if output_tx.has_covenant {
                w.write_u8(1)?;
                w.write_u16_le(output_tx.covenant_auth_input)?;
                w.write_bytes(&output_tx.covenant_id)?;
            } else {
                w.write_u8(0)?;
            }
        }
    }

    Ok(w.written())
}

/// A Schnorr signature for a specific input
#[derive(Debug, Clone)]
/// A signed input: index + sighash type + 64-byte Schnorr signature.
pub struct InputSignature {
    pub input_index: u8,
    pub sighash_type: SigHashType,
    pub signature: [u8; 64],
}

/// Set of signatures to return to the companion app
#[derive(Debug)]
/// Collects signatures for all inputs and serializes the signed response.
pub struct SignedResponse {
    pub signatures: [InputSignature; MAX_SIGNATURES],
    pub num_signatures: usize,
}

impl SignedResponse {
    pub fn new() -> Self {
        Self {
            signatures: core::array::from_fn(|_| InputSignature {
                input_index: 0,
                sighash_type: SigHashType::All,
                signature: [0u8; 64],
            }),
            num_signatures: 0,
        }
    }

    /// Add a signature to the response
    pub fn add_signature(
        &mut self,
        input_index: u8,
        sighash_type: SigHashType,
        signature: &[u8; 64],
    ) -> Result<(), PsktError> {
        if self.num_signatures >= MAX_SIGNATURES {
            return Err(PsktError::TooManyInputs);
        }
        self.signatures[self.num_signatures] = InputSignature {
            input_index,
            sighash_type,
            signature: *signature,
        };
        self.num_signatures += 1;
        Ok(())
    }

    /// Serialize signatures to send via QR to the companion app
    pub fn serialize(&self, output: &mut [u8]) -> Result<usize, PsktError> {
        let mut w = ByteWriter::new(output);

        w.write_bytes(&SIGNED_MAGIC)?;
        w.write_u8(FORMAT_VERSION)?;
        w.write_u8(self.num_signatures as u8)?;

        for i in 0..self.num_signatures {
            let sig = &self.signatures[i];
            w.write_u8(sig.input_index)?;
            w.write_u8(sig.sighash_type.to_byte())?;
            w.write_bytes(&sig.signature)?;
        }

        Ok(w.written())
    }

    /// Parse a signed response (for tests/verification)
    pub fn parse(data: &[u8]) -> Result<Self, PsktError> {
        let mut r = ByteReader::new(data);

        let magic = r.read_bytes(4)?;
        if magic != SIGNED_MAGIC {
            return Err(PsktError::InvalidMagic);
        }

        let version = r.read_u8()?;
        if version != FORMAT_VERSION {
            return Err(PsktError::UnsupportedVersion);
        }

        let num_sigs = r.read_u8()? as usize;
        if num_sigs > MAX_SIGNATURES {
            return Err(PsktError::TooManyInputs);
        }

        let mut response = SignedResponse::new();
        response.num_signatures = num_sigs;

        for i in 0..num_sigs {
            response.signatures[i].input_index = r.read_u8()?;
            let sht = r.read_u8()?;
            response.signatures[i].sighash_type = SigHashType::from_byte(sht)
                .ok_or(PsktError::InvalidSigHashType)?;
            let sig_bytes = r.read_bytes(64)?;
            response.signatures[i].signature.copy_from_slice(sig_bytes);
        }

        Ok(response)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Full flow: parse → display → sign → serialize
// ═══════════════════════════════════════════════════════════════════

/// Sign all inputs of a parsed transaction.
///
/// Typical signing device flow:
/// 1. companion app -> QR -> parse KSPT -> Transaction
/// 2. show user: destination, amount, fee
/// 3. user confirms -> sign_transaction()
/// 4. serialize SignedResponse -> QR -> companion app
pub fn sign_transaction(
    tx: &Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) -> Result<SignedResponse, PsktError> {
    use super::sighash;

    let mut response = SignedResponse::new();

    for i in 0..tx.num_inputs {
        let sig = sighash::sign_input(tx, i, private_key, sighash_type)
            .map_err(|_| PsktError::NoInputs)?; // remap schnorr error

        response.add_signature(i as u8, sighash_type, &sig.bytes)?;
    }

    Ok(response)
}

/// Sign all inputs and store signatures directly in the Transaction.
/// Returns the number of inputs signed.
pub fn sign_transaction_in_place(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) -> Result<usize, PsktError> {
    use super::sighash;

    for i in 0..tx.num_inputs {
        let sig = sighash::sign_input(tx, i, private_key, sighash_type)
            .map_err(|_| PsktError::NoInputs)?;

        tx.inputs[i].signature = sig.bytes;
        tx.inputs[i].sig_len = 64;
        tx.inputs[i].sighash_type = sighash_type.to_byte();
    }

    Ok(tx.num_inputs)
}

/// Sign a multi-address transaction: each input may belong to a different
/// address index. Uses the BIP32 account key to derive the correct privkey
/// per input by matching the script pubkey.
///
/// Returns the number of inputs signed successfully.
/// Inputs whose pubkey doesn't match any of our addresses (0..=MAX_ADDR_INDEX)
/// are skipped (sig_len stays 0).
/// DKSAP stealth: the combined spending key for this transaction.
///
/// Returns (combined private scalar bytes, combined pubkey compressed).
/// The same pair serves every stealth input in the transaction, so it is
/// computed once by the caller rather than per input.
///
/// The stealth address is derived from the EVEN-Y form of the account
/// spend pubkey B. Both the sender (`pubkey_from_xonly`) and the device
/// scan (0x02 prefix) lift_x B as even-Y, so the address is
/// P = B_even + t*G. If the real account pubkey has odd Y the scalar must
/// be negated so that acct_scalar*G == B_even; otherwise (acct + tweak)*G
/// lands on the wrong x, the caller's match guard fails, the input is
/// never signed, and the stealth UTXO is permanently unspendable (~50% of
/// wallets).
///
/// Note that P itself has no parity guarantee: only its x is compared
/// against the script pubkey, so the returned compressed encoding may
/// begin 0x02 or 0x03 and callers must carry it whole.
#[inline(never)]
fn stealth_combined_key(
    account_key: &super::bip32::ExtendedPrivKey,
    tweak: &[u8; 32],
) -> Option<([u8; 32], [u8; 33])> {
    use k256::elliptic_curve::ScalarPrimitive;
    use k256::elliptic_curve::ops::Add;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    let acct_prim =
        ScalarPrimitive::<k256::Secp256k1>::from_slice(account_key.private_key_bytes()).ok()?;
    let acct_scalar = {
        let s = Scalar::from(acct_prim);
        let s_pt = (ProjectivePoint::GENERATOR * s).to_affine();
        let s_enc = s_pt.to_encoded_point(true);
        if s_enc.as_bytes()[0] == 0x03 { -s } else { s }
    };

    let tweak_prim = ScalarPrimitive::<k256::Secp256k1>::from_slice(tweak).ok()?;
    let combined_scalar = acct_scalar.add(&Scalar::from(tweak_prim));

    let combined_point = (ProjectivePoint::GENERATOR * combined_scalar).to_affine();
    let combined_encoded = combined_point.to_encoded_point(true);
    let enc = combined_encoded.as_bytes();
    if enc.len() != 33 {
        return None;
    }

    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&combined_scalar.to_bytes());
    let mut pk_c = [0u8; 33];
    pk_c.copy_from_slice(enc);
    Some((priv_bytes, pk_c))
}

pub fn sign_transaction_multi_addr(
    tx: &mut Transaction,
    account_key: &super::bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    mut ext: Option<crate::app::signing::ExtBanksMut<'_>>,
) -> Result<usize, PsktError> {
    use super::sighash;
    use super::bip32;


    // PHASE 1 — resolve (shallow stack). Resolve every input's
    // (index, chain) first, then run the sign loop below without any of
    // this on the frame.
    //   flags: 0 = not P2PK / skip, 1 = wallet key found, 2 = unmatched
    //   (stealth candidate); bit 1 of flags carries is_change when found.
    //
    // The 40-entry AddrPubkeyTable that used to be built here is gone.
    // It existed to replace an older per-input 2x100-derivation scan, but
    // `ext_scan_find` supersedes it on every axis: depth EXT_BANK_DEPTH
    // instead of 20, results PERSISTED into the banks instead of thrown
    // away with the table, and 1.4KB off this frame. It was also actively
    // wasteful from cold: the table derived receive 0..19 and change
    // 0..19, discarded them, and then the scan re-derived the same
    // indices from empty banks. Measured 40 derivations, ~4.7s of a
    // 13.3s 32-input cold sign.
    let mut resolved_idx = [0u16; crate::wallet::transaction::MAX_INPUTS];
    let mut resolved_flags = [0u8; crate::wallet::transaction::MAX_INPUTS];

    // DKSAP stealth: the combined key P = B_even + t*G is the SAME for
    // every stealth input in this transaction, so compute it once here
    // instead of per input inside the sign loop.
    //
    // Computing it before resolve also short-circuits the bank scan.
    // Stealth inputs are unmatched by construction: their pubkey is not
    // on either derivation chain, so `ext_scan_find` used to walk the
    // entire bank depth for each one before reporting nothing. At
    // EXT_BANK_DEPTH = 1000 that is ~78s from cold. Comparing against
    // the combined pubkey first costs one comparison and skips the walk
    // entirely.
    // (combined private scalar, combined pubkey compressed 33 bytes).
    let mut stealth: Option<([u8; 32], [u8; 33])> = if tx.has_stealth_tweak {
        stealth_combined_key(account_key, &tx.stealth_tweak)
    } else {
        None
    };

    {
        let mut deep_memo: Option<([u8; 32], (u16, bool))> = None;
        for i in 0..tx.num_inputs {
            let script = &tx.inputs[i].utxo_entry.script_public_key;
            if script.script_len != 34 || script.script[0] != 0x20 || script.script[33] != 0xAC {
                continue; // not a standard P2PK script we can sign
            }
            let mut target_pk = [0u8; 32];
            target_pk.copy_from_slice(&script.script[1..33]);
            // Stealth first: an input that matches the combined key is
            // ours but is on no derivation chain, so the banks can never
            // find it. Flag it now and skip the scan.
            if let Some((_, ref combined_pk)) = stealth {
                if combined_pk[1..33] == target_pk {
                    resolved_flags[i] = 2;
                    continue;
                }
            }
            // Memo next: consolidations repeat one source address, so
            // this hits without touching the banks at all.
            let mut found = match deep_memo {
                Some((pk, hit)) if pk == target_pk => Some(hit),
                _ => None,
            };
            if found.is_none() {
                // Extended banks. `ext_scan_find` searches the filled
                // region first and then KEEPS deriving into the banks,
                // storing every result, so this both replaces the old
                // idle-only lookup and the 2x100-derivation discard scan
                // that used to follow it. Cost is bounded by the bank
                // length (EXT_BANK_DEPTH), and it is paid at most once
                // per signing pass rather than once per unmatched input:
                // by the time the fronts reach capacity, every later
                // input resolves from RAM.
                if let Some((er, ern, ec, ecn)) = ext.as_mut() {
                    found = crate::app::signing::ext_scan_find(
                        account_key, &mut **er, &mut **ern, &mut **ec, &mut **ecn,
                        &target_pk);
                } else {
                    // No banks available (self-test path): fall back to
                    // the original discard scan.
                    found = bip32::find_address_index_for_pubkey(account_key, &target_pk);
                }
                if let Some(hit) = found { deep_memo = Some((target_pk, hit)); }
            }
            match found {
                Some((idx, is_change)) => {
                    resolved_idx[i] = idx;
                    resolved_flags[i] = 1 | ((is_change as u8) << 1);
                }
                None => { resolved_flags[i] = 2; }
            }
        }
    } // table dropped here — the sign loop below runs without it on stack

    // PHASE 2 — sign (deep stack, shallow locals). Key memo: consolidations
    // spend many UTXOs of ONE address; derive the key once, reuse for
    // repeats of the same pubkey.
    let mut key_memo: Option<([u8; 32], [u8; 32], [u8; 33])> = None; // (pubkey_tag, privkey, pubkey_c)

    // Compute the input-independent sighash parts ONCE. Per-input
    // recomputation walked the whole tx per signature (O(N^2) hashing for
    // N inputs) and nested an extra hasher frame in the deep sign chain.
    let sighash_reuse = sighash::SighashReuse::compute(tx, sighash_type);

    let mut signed_count = 0usize;

    // Chain parents for the per-input key derivation, built at most once
    // each and only when actually needed.
    //
    // `derive_address_key(account_key, idx)` costs three scalar
    // multiplies: the account key's pubkey to reach the chain key, the
    // chain key's pubkey to reach the address key, and the address key's
    // own pubkey. Only the last varies with `idx`. Through `ChainParent`
    // the first two are paid once per chain and the per-input cost drops
    // to one, so a 32-input consolidation across distinct addresses goes
    // from ~96 multiplies to ~34.
    //
    // Lazy so a transaction that only touches one chain never pays for
    // the other, and so a single-input send is no worse than before: two
    // multiplies to build, one to derive, which is the three it paid
    // already. Note that laziness saves MULTIPLIES, not stack: these two
    // slots exist for the whole frame either way. That is ~198 bytes on
    // the deep half of the signing pass, offset several times over by the
    // 1.4KB table removed from phase 1 above.
    let mut chain_recv: Option<bip32::ChainParent> = None;
    let mut chain_chg: Option<bip32::ChainParent> = None;

    for i in 0..tx.num_inputs {
        if resolved_flags[i] == 0 { continue; }
        let mut target_pk = [0u8; 32];
        {
            let script = &tx.inputs[i].utxo_entry.script_public_key;
            target_pk.copy_from_slice(&script.script[1..33]);
        }
        if resolved_flags[i] & 1 != 0 {
            let idx = resolved_idx[i];
            let is_change = resolved_flags[i] & 2 != 0;
            // Resolve the address key: reuse the memo when this input's
            // pubkey matches the last one (the consolidation common case),
            // otherwise derive once and memoize.
            // Reuse the memo when this input repeats the previous pubkey
            // (consolidation); else derive once and store the light form.
            let need_derive = match key_memo {
                Some((pk, _, _)) => pk != target_pk,
                None => true,
            };
            if need_derive {
                let slot = if is_change { &mut chain_chg } else { &mut chain_recv };
                if slot.is_none() {
                    *slot = bip32::ChainParent::new(
                        account_key,
                        if is_change { 1 } else { 0 },
                    ).ok();
                }
                let key_result = match slot {
                    Some(chain) => chain.derive(idx as u32),
                    // Chain derivation failed: fall back to the direct
                    // path so a single bad chain cannot silently drop
                    // every signature on that chain.
                    None => if is_change {
                        bip32::derive_change_key(account_key, idx)
                    } else {
                        bip32::derive_address_key(account_key, idx)
                    },
                };
                if let Ok(addr_key) = key_result {
                    if let Ok(pk_c) = addr_key.public_key_compressed() {
                        let mut pk32 = [0u8; 32];
                        pk32.copy_from_slice(addr_key.private_key_bytes());
                        key_memo = Some((target_pk, pk32, pk_c));
                    }
                }
            }
            if let Some((_, ref privkey_arr, pk_c)) = key_memo {
                let sig = sighash::sign_input_cached(tx, i, privkey_arr, sighash_type, &sighash_reuse)
                    .map_err(|_| PsktError::NoInputs)?;

                tx.inputs[i].signature = sig.bytes;
                tx.inputs[i].sig_len = 64;
                tx.inputs[i].sighash_type = sighash_type.to_byte();
                tx.inputs[i].sigs[0].signature = sig.bytes;
                tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                tx.inputs[i].sigs[0].pubkey_pos = 0;
                tx.inputs[i].sigs[0].present = true;
                tx.inputs[i].sigs[0].pubkey_compressed = pk_c;
                tx.inputs[i].sig_count = 1;
                signed_count += 1;
            }
        } else if resolved_flags[i] == 2 && tx.has_stealth_tweak {
            // Stealth spend: signing key = account_privkey + tweak
            // Combined key already computed once for the whole
            // transaction (see `stealth` above); resolve only flagged
            // this input because its pubkey matched it.
            if let Some((ref combined_privkey_src, ref combined_pk)) = stealth {
                if combined_pk[1..33] != target_pk { continue; }

                let mut combined_privkey = *combined_privkey_src;

                let sig = sighash::sign_input_cached(tx, i, &combined_privkey, sighash_type, &sighash_reuse)
                    .map_err(|_| PsktError::NoInputs)?;

                // Zeroize the working copy of the combined privkey.
                for b in combined_privkey.iter_mut() {
                    unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
                }

                tx.inputs[i].signature = sig.bytes;
                tx.inputs[i].sig_len = 64;
                tx.inputs[i].sighash_type = sighash_type.to_byte();
                tx.inputs[i].sigs[0].signature = sig.bytes;
                tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                tx.inputs[i].sigs[0].pubkey_pos = 0;
                tx.inputs[i].sigs[0].present = true;
                // Combined pubkey, compressed. Carried whole from the
                // hoisted computation: only its X was compared above, so
                // its Y parity is NOT guaranteed even and the real
                // prefix must be preserved.
                tx.inputs[i].sigs[0].pubkey_compressed = *combined_pk;
                tx.inputs[i].sig_count = 1;
                signed_count += 1;
            }
        }
    }

    if signed_count == 0 {
        return Err(PsktError::NoInputs);
    }

    // Volatile-zero the memoized private key before returning.
    if let Some((_, ref mut privkey_arr, _)) = key_memo {
        for b in privkey_arr.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
    }
    // Same for the hoisted stealth scalar: it now lives for the whole
    // function rather than one loop iteration, so it must be wiped here.
    if let Some((ref mut sk, _)) = stealth {
        for b in sk.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } }
    }
    Ok(signed_count)
}

// ═══════════════════════════════════════════════════════════════════
// Multisig Support
// ═══════════════════════════════════════════════════════════════════

/// Analyze a transaction input's script type.
/// For P2SH inputs with a redeem script, returns the redeem script's type.
pub fn analyze_input_script(tx: &Transaction, input_idx: usize) -> (ScriptType, Option<MultisigInfo>) {
    let script = &tx.inputs[input_idx].utxo_entry.script_public_key;
    let st = detect_script_type(&script.script, script.script_len);

    // P2SH: use the redeem script for pubkey analysis, but ONLY after
    // verifying it is the script this UTXO actually commits to.
    //
    // A P2SH scriptPublicKey is
    //     OP_BLAKE2B  OP_DATA_32  <32-byte hash>  OP_EQUAL
    // so the commitment is script[2..34]. The redeem script arrives in the
    // PSKT from the host, which is untrusted by definition on an air-gapped
    // signer. Without this check the device would parse and DISPLAY multisig
    // details, key positions and script types derived from a script the
    // attacker chose, while the UTXO is something else entirely.
    //
    // A forged script cannot steal funds: the sighash commits to
    // utxo_entry.script_public_key, which a node recomputes from its own UTXO
    // set, so the resulting sig_script fails the on-chain P2SH check. The
    // exposure is user deception, and on a device whose entire purpose is
    // showing the user what they are signing, that is enough.
    //
    // On mismatch the input is reported as Unknown rather than P2SH, so no
    // caller treats it as an analysed multisig input and the review screen
    // shows it as unrecognised.
    if st == ScriptType::P2SH && tx.inputs[input_idx].redeem_script_len > 0 {
        let rs = tx.redeem_bytes(input_idx);
        let rs_len = rs.len();

        if script.script_len != 35 {
            return (ScriptType::Unknown, None);
        }
        let commitment = &script.script[2..34];
        let actual = crate::wallet::sighash::blake2b_hash(rs);
        if actual[..] != commitment[..] {
            return (ScriptType::Unknown, None);
        }

        let rs_type = detect_script_type(rs, rs_len);
        let ms = if rs_type == ScriptType::Multisig {
            parse_multisig_script(rs, rs_len)
        } else {
            None
        };
        // Return P2SH as the script type so callers know it's wrapped
        return (ScriptType::P2SH, ms);
    }

    let ms = if st == ScriptType::Multisig {
        parse_multisig_script(&script.script, script.script_len)
    } else {
        None
    };
    (st, ms)
}

/// Sign a transaction supporting both P2PK and multisig inputs.
///
/// For each input:
///   - Detects script type (P2PK or multisig)
///   - P2PK: signs with the first matching key from any seed slot
///   - Multisig: signs with ALL matching keys across all seed slots
///   - Preserves existing signatures already in tx.sigs[] (from prior signers)
///
/// `seeds`: loaded seed slots, each (seed_64_bytes, is_loaded). Up to 8 entries.
/// Returns total number of new signatures added across all inputs.
pub fn sign_transaction_multisig(
    tx: &mut Transaction,
    seeds: &[([u8; 64], bool)],
    sighash_type: SigHashType,
    active_seed_idx: Option<usize>,
) -> Result<usize, PsktError> {
    use super::sighash;
    use super::bip32;

    let mut total_new_sigs = 0usize;
    let num_seeds = seeds.len().min(8);

    // Pre-derive account keys for loaded slots
    let mut acct_keys: [Option<bip32::ExtendedPrivKey>; 8] = [None, None, None, None, None, None, None, None];
    for s in 0..num_seeds {
        if seeds[s].1 {
            if let Ok(ak) = bip32::derive_account_key(&seeds[s].0) {
                acct_keys[s] = Some(ak);
            }
        }
    }

    // Pre-compute account-level x-only pubkey for each loaded seed ONCE
    // for the whole tx (rather than per-input). `acct_xonly_cache[s]`
    // is the seed's depth-3 x-only pubkey; if it matches a multisig
    // position elsewhere in the tx, we use it directly and skip
    // address-level derivation entirely.
    //
    // `acct_compressed_cache[s]` holds the parallel 33-byte compressed
    // form — needed by PSKT serialization (via InputSig.pubkey_compressed),
    // ignored by KSPT emission. We compute it here once rather than
    // re-deriving after signing.
    let mut acct_xonly_cache: [Option<[u8; 32]>; 8] =
        [None, None, None, None, None, None, None, None];
    let mut acct_compressed_cache: [Option<[u8; 33]>; 8] =
        [None, None, None, None, None, None, None, None];
    for s in 0..num_seeds {
        if let Some(ref acct) = acct_keys[s] {
            if let Ok(pk_c) = acct.public_key_compressed() {
                acct_compressed_cache[s] = Some(pk_c);
                // x-only is bytes 1..33 of compressed.
                let mut xonly = [0u8; 32];
                xonly.copy_from_slice(&pk_c[1..33]);
                acct_xonly_cache[s] = Some(xonly);
            }
        }
    }

    // Address-level pubkey tables, built lazily per seed. Only built
    // when a seed has no account-level match AND we hit an input that
    // requires an address-level search. Stored on the stack — each
    // table is ~1.3 KB (40 × 32-byte x-only pubkeys), max 8 tables =
    // ~10 KB worst case (fine for ESP32-S3's 512 KB SRAM).
    //
    // Using Option so we don't pay the build cost until needed, and
    // `built` tracks which slots have been populated.
    let mut addr_tables: [Option<bip32::AddrPubkeyTable>; 8] =
        [None, None, None, None, None, None, None, None];

    for i in 0..tx.num_inputs {
        let (script_type, ms_info) = analyze_input_script(tx, i);

        match script_type {
            ScriptType::P2PK => {
                // Already signed? skip
                if tx.inputs[i].sig_len > 0 { continue; }

                let script = &tx.inputs[i].utxo_entry.script_public_key;
                let mut target_pk = [0u8; 32];
                target_pk.copy_from_slice(&script.script[1..33]);

                for s in 0..num_seeds {
                    if let Some(ref acct) = acct_keys[s] {
                        if let Some((idx, is_chg)) = bip32::find_address_index_for_pubkey(acct, &target_pk) {
                            let key_result = if is_chg {
                                bip32::derive_change_key(acct, idx)
                            } else {
                                bip32::derive_address_key(acct, idx)
                            };
                            if let Ok(addr_key) = key_result {
                                let privkey = addr_key.private_key_bytes();
                                if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                    tx.inputs[i].signature = sig.bytes;
                                    tx.inputs[i].sig_len = 64;
                                    tx.inputs[i].sighash_type = sighash_type.to_byte();
                                    tx.inputs[i].sigs[0].signature = sig.bytes;
                                    tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                                    tx.inputs[i].sigs[0].pubkey_pos = 0;
                                    tx.inputs[i].sigs[0].present = true;
                                    // Stash compressed pubkey for PSKT
                                    // emission (ignored by KSPT).
                                    if let Ok(pk_c) = addr_key.public_key_compressed() {
                                        tx.inputs[i].sigs[0].pubkey_compressed = pk_c;
                                    }
                                    tx.inputs[i].sig_count = 1;
                                    total_new_sigs += 1;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            ScriptType::Multisig | ScriptType::P2SH => {
                if let Some(ref ms) = ms_info {
                    // Per-input: figure out which position each seed
                    // matches via the cached account-level pubkey. This
                    // is a few byte-comparisons, effectively free.
                    let mut seed_pos_match: [Option<u8>; 8] =
                        [None, None, None, None, None, None, None, None];
                    for s in 0..num_seeds {
                        if let Some(pk) = acct_xonly_cache[s] {
                            for p in 0..ms.n as usize {
                                if pk == ms.pubkeys[p] {
                                    seed_pos_match[s] = Some(p as u8);
                                    break;
                                }
                            }
                        }
                    }

                    for pos in 0..ms.n as usize {
                        // Already have a sig for this position? skip
                        let already = (0..tx.inputs[i].sig_count as usize)
                            .any(|s| tx.inputs[i].sigs[s].present && tx.inputs[i].sigs[s].pubkey_pos == pos as u8);
                        if already { continue; }

                        let target_pk = &ms.pubkeys[pos];

                        for s in 0..num_seeds {
                            if let Some(ref acct) = acct_keys[s] {
                                // Fast path: account-level match.
                                // Zero derivations.
                                if seed_pos_match[s] == Some(pos as u8) {
                                    let privkey = acct.private_key_bytes();
                                    if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                        let sc = tx.inputs[i].sig_count as usize;
                                        if sc < MAX_SIGS_PER_INPUT {
                                            tx.inputs[i].sigs[sc].signature = sig.bytes;
                                            tx.inputs[i].sigs[sc].sighash_type = sighash_type.to_byte();
                                            tx.inputs[i].sigs[sc].pubkey_pos = pos as u8;
                                            tx.inputs[i].sigs[sc].present = true;
                                            // Stash compressed pubkey for PSKT
                                            // emission (ignored by KSPT).
                                            if let Some(pk_c) = acct_compressed_cache[s] {
                                                tx.inputs[i].sigs[sc].pubkey_compressed = pk_c;
                                            }
                                            tx.inputs[i].sig_count += 1;
                                            total_new_sigs += 1;
                                        }
                                        break;
                                    }
                                }

                                // Address-level fallback using the cached
                                // pubkey table. Built ONCE per seed on
                                // first use — subsequent lookups are O(40)
                                // array scans with zero derivations.
                                //
                                // This is the "multisig built from
                                // per-address pubkeys" path. It used to
                                // run find_address_index_for_pubkey per
                                // (input, position, seed) which did up
                                // to 200 derivations each — that's the
                                // 45 s signing time we saw. The table
                                // caps derivations at 40 per seed for
                                // the entire tx regardless of input count.
                                if seed_pos_match[s].is_none() {
                                    // Lazy build
                                    if addr_tables[s].is_none() {
                                        addr_tables[s] =
                                            Some(bip32::AddrPubkeyTable::build(acct));
                                    }
                                    let tbl = match addr_tables[s].as_ref() {
                                        Some(t) => t,
                                        // Built immediately above by the
                                        // is_none() branch, so this is
                                        // unreachable today. Matched rather
                                        // than unwrapped because the invariant
                                        // is non-local: it holds only as long
                                        // as that branch stays directly above
                                        // this line, and a panic here is on
                                        // the signing path.
                                        None => continue,
                                    };
                                    if let Some((idx, is_chg)) = tbl.find_by_pubkey(target_pk) {
                                        let key_result = if is_chg {
                                            bip32::derive_change_key(acct, idx)
                                        } else {
                                            bip32::derive_address_key(acct, idx)
                                        };
                                        if let Ok(addr_key) = key_result {
                                            let privkey = addr_key.private_key_bytes();
                                            if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                                let sc = tx.inputs[i].sig_count as usize;
                                                if sc < MAX_SIGS_PER_INPUT {
                                                    tx.inputs[i].sigs[sc].signature = sig.bytes;
                                                    tx.inputs[i].sigs[sc].sighash_type = sighash_type.to_byte();
                                                    tx.inputs[i].sigs[sc].pubkey_pos = pos as u8;
                                                    tx.inputs[i].sigs[sc].present = true;
                                                    // Stash compressed pubkey for PSKT
                                                    // emission (ignored by KSPT).
                                                    if let Ok(pk_c) = addr_key.public_key_compressed() {
                                                        tx.inputs[i].sigs[sc].pubkey_compressed = pk_c;
                                                    }
                                                    tx.inputs[i].sig_count += 1;
                                                    total_new_sigs += 1;
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Sync legacy fields
                    if tx.inputs[i].sig_count > 0 && tx.inputs[i].sig_len == 0 {
                        tx.inputs[i].signature = tx.inputs[i].sigs[0].signature;
                        tx.inputs[i].sig_len = 64;
                        tx.inputs[i].sighash_type = tx.inputs[i].sigs[0].sighash_type;
                    }
                } else {
                    // P2SH without multisig info — check for covenant script.
                    // Scan the redeem script for 32-byte pubkey pushes (0x20 <32 bytes>).
                    // Supports: IF/ELSE covenants, state machines, and any script with
                    // embedded pubkeys followed by CHECKSIG/CHECKSIGVERIFY.
                    let rs = tx.redeem_bytes(i);
                    let rs_len = rs.len();

                    // Collect up to 4 candidate pubkeys from anywhere in the script
                    let mut candidates: [([u8; 32], bool); 8] = [([0u8; 32], false); 8];
                    let mut num_candidates = 0usize;

                    // Scan for OP_DATA_32 (0x20) followed by 32 bytes and then
                    // CHECKSIG (0xac) or CHECKSIGVERIFY (0xad) within a few bytes.
                    //
                    // IMPORTANT: this walk is opcode-aware. A naive byte scan
                    // breaks on any push whose DATA contains a 0x20 byte (e.g.
                    // an 8-byte salt, or a 4-byte amount). Such a 0x20 would be
                    // misread as OP_DATA_32, the scanner would jump +33, and a
                    // real pubkey push could be skipped entirely. By honoring
                    // each push's declared length we skip data bytes correctly
                    // and never confuse data for an opcode.
                    let mut off = 0usize;
                    while off < rs_len && num_candidates < 8 {
                        let op = rs[off];
                        if op == 0x20 && off + 33 <= rs_len {
                            // OP_DATA_32: candidate pubkey if followed by
                            // CHECKSIG/CHECKSIGVERIFY within 2 bytes.
                            let after = off + 33;
                            let has_checksig = (after < rs_len && (rs[after] == 0xac || rs[after] == 0xad))
                                || (after + 1 < rs_len && (rs[after + 1] == 0xac || rs[after + 1] == 0xad));
                            if has_checksig {
                                candidates[num_candidates].0.copy_from_slice(&rs[off + 1..off + 33]);
                                candidates[num_candidates].1 = true;
                                num_candidates += 1;
                            }
                            off += 33; // opcode + 32 data bytes
                        } else if (0x01..=0x4b).contains(&op) {
                            // Direct push of `op` bytes: skip opcode + data.
                            off += 1 + op as usize;
                        } else if op == 0x4c {
                            // OP_PUSHDATA1: 1-byte length follows.
                            if off + 1 < rs_len { off += 2 + rs[off + 1] as usize; } else { off += 1; }
                        } else if op == 0x4d {
                            // OP_PUSHDATA2: 2-byte LE length follows.
                            if off + 2 < rs_len {
                                let n = rs[off + 1] as usize | ((rs[off + 2] as usize) << 8);
                                off += 3 + n;
                            } else { off += 1; }
                        } else if op == 0x4e {
                            // OP_PUSHDATA4: 4-byte LE length follows.
                            if off + 4 < rs_len {
                                let n = rs[off + 1] as usize
                                    | ((rs[off + 2] as usize) << 8)
                                    | ((rs[off + 3] as usize) << 16)
                                    | ((rs[off + 4] as usize) << 24);
                                off += 5 + n;
                            } else { off += 1; }
                        } else {
                            // Non-push opcode: advance by one.
                            off += 1;
                        }
                    }

                    if num_candidates > 0 {

                    if tx.inputs[i].sig_count > 0 { /* skip */ }
                        else {
                            'cov_done: for c in 0..num_candidates {
                                if !candidates[c].1 { continue; }
                                let target_pk = candidates[c].0;
                                for s in 0..num_seeds {
                                    // For covenant inputs, only sign with the active seed.
                                    // This prevents the owner's seed from matching candidate 0
                                    // when the beneficiary intended to sign.
                                    if let Some(active) = active_seed_idx {
                                        if s != active { continue; }
                                    }
                                    if let Some(ref acct) = acct_keys[s] {
                                        // Check account-level xonly match first
                                        if let Some(pk) = acct_xonly_cache[s] {
                                            if pk == target_pk {
                                                let privkey = acct.private_key_bytes();
                                                if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                                    tx.inputs[i].sigs[0].signature = sig.bytes;
                                                    tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                                                    tx.inputs[i].sigs[0].pubkey_pos = c as u8;
                                                    tx.inputs[i].sigs[0].present = true;
                                                    if let Ok(pk_c) = acct.public_key_compressed() {
                                                        tx.inputs[i].sigs[0].pubkey_compressed = pk_c;
                                                    }
                                                    tx.inputs[i].sig_count = 1;
                                                    tx.inputs[i].signature = sig.bytes;
                                                    tx.inputs[i].sig_len = 64;
                                                    tx.inputs[i].sighash_type = sighash_type.to_byte();
                                                    total_new_sigs += 1;
                                                    break 'cov_done;
                                                }
                                            }
                                        }

                                        // Address-level fallback
                                        if addr_tables[s].is_none() {
                                            addr_tables[s] =
                                                Some(bip32::AddrPubkeyTable::build(acct));
                                        }
                                        let tbl = match addr_tables[s].as_ref() {
                                        Some(t) => t,
                                        // Built immediately above by the
                                        // is_none() branch, so this is
                                        // unreachable today. Matched rather
                                        // than unwrapped because the invariant
                                        // is non-local: it holds only as long
                                        // as that branch stays directly above
                                        // this line, and a panic here is on
                                        // the signing path.
                                        None => continue,
                                    };
                                        if let Some((idx, is_chg)) = tbl.find_by_pubkey(&target_pk) {
                                            let key_result = if is_chg {
                                                bip32::derive_change_key(acct, idx)
                                            } else {
                                                bip32::derive_address_key(acct, idx)
                                            };
                                            if let Ok(addr_key) = key_result {
                                                let privkey = addr_key.private_key_bytes();
                                                if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                                    tx.inputs[i].sigs[0].signature = sig.bytes;
                                                    tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                                                    tx.inputs[i].sigs[0].pubkey_pos = c as u8;
                                                    tx.inputs[i].sigs[0].present = true;
                                                    if let Ok(pk_c) = addr_key.public_key_compressed() {
                                                        tx.inputs[i].sigs[0].pubkey_compressed = pk_c;
                                                    }
                                                    tx.inputs[i].sig_count = 1;
                                                    tx.inputs[i].signature = sig.bytes;
                                                    tx.inputs[i].sig_len = 64;
                                                    tx.inputs[i].sighash_type = sighash_type.to_byte();
                                                    total_new_sigs += 1;
                                                    break 'cov_done;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Treasury script: starts with PUSH_32 <pubkey> CHECKSIGVERIFY (0x20 <32> 0xad)
                    // Single candidate — the owner pubkey at bytes 1..33
                    else if rs_len >= 35 && rs[0] == 0x20 && rs[33] == 0xad
                        && tx.inputs[i].sig_count == 0 {
                            let mut target_pk = [0u8; 32];
                            target_pk.copy_from_slice(&rs[1..33]);
                            'treas_done: for s in 0..num_seeds {
                                if let Some(active) = active_seed_idx {
                                    if s != active { continue; }
                                }
                                if let Some(ref acct) = acct_keys[s] {
                                    // Account-level xonly match
                                    if let Some(pk) = acct_xonly_cache[s] {
                                        if pk == target_pk {
                                            let privkey = acct.private_key_bytes();
                                            if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                                tx.inputs[i].sigs[0].signature = sig.bytes;
                                                tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                                                tx.inputs[i].sigs[0].pubkey_pos = 0;
                                                tx.inputs[i].sigs[0].present = true;
                                                if let Ok(pk_c) = acct.public_key_compressed() {
                                                    tx.inputs[i].sigs[0].pubkey_compressed = pk_c;
                                                }
                                                tx.inputs[i].sig_count = 1;
                                                tx.inputs[i].sighash_type = sighash_type.to_byte();
                                                total_new_sigs += 1;
                                                break 'treas_done;
                                            }
                                        }
                                    }
                                    // Address-level fallback (derived child keys)
                                    if addr_tables[s].is_none() {
                                        addr_tables[s] = Some(bip32::AddrPubkeyTable::build(acct));
                                    }
                                    let tbl = match addr_tables[s].as_ref() {
                                        Some(t) => t,
                                        // Built immediately above by the
                                        // is_none() branch, so this is
                                        // unreachable today. Matched rather
                                        // than unwrapped because the invariant
                                        // is non-local: it holds only as long
                                        // as that branch stays directly above
                                        // this line, and a panic here is on
                                        // the signing path.
                                        None => continue,
                                    };
                                    if let Some((idx, is_chg)) = tbl.find_by_pubkey(&target_pk) {
                                        let key_result = if is_chg {
                                            bip32::derive_change_key(acct, idx)
                                        } else {
                                            bip32::derive_address_key(acct, idx)
                                        };
                                        if let Ok(addr_key) = key_result {
                                            let privkey = addr_key.private_key_bytes();
                                            if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                                tx.inputs[i].sigs[0].signature = sig.bytes;
                                                tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                                                tx.inputs[i].sigs[0].pubkey_pos = 0;
                                                tx.inputs[i].sigs[0].present = true;
                                                if let Ok(pk_c) = addr_key.public_key_compressed() {
                                                    tx.inputs[i].sigs[0].pubkey_compressed = pk_c;
                                                }
                                                tx.inputs[i].sig_count = 1;
                                                tx.inputs[i].sighash_type = sighash_type.to_byte();
                                                total_new_sigs += 1;
                                                break 'treas_done;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                }
            }

            ScriptType::Unknown => {}
        }
    }

    Ok(total_new_sigs)
}

/// Check if a transaction has enough signatures on all inputs.
pub fn is_fully_signed(tx: &Transaction) -> bool {
    for i in 0..tx.num_inputs {
        let (script_type, ms_info) = analyze_input_script(tx, i);
        match script_type {
            ScriptType::P2PK => {
                if tx.inputs[i].sig_len == 0 { return false; }
            }
            ScriptType::Multisig | ScriptType::P2SH => {
                if let Some(ref ms) = ms_info {
                    if tx.inputs[i].sig_count < ms.m { return false; }
                } else {
                    // Covenant P2SH (any shape: IF/ELSE, treasury, or a
                    // salt-prefixed state machine). Every covenant spend path
                    // in this system is satisfied by exactly one signature, so
                    // a fixed-offset script-shape check is unnecessary and was
                    // fragile against a leading salt push. Require 1 sig.
                    if tx.inputs[i].sig_count == 0 { return false; }
                }
            }
            ScriptType::Unknown => { return false; }
        }
    }
    true
}

/// Count signatures present vs required.
/// Returns (present, required).
pub fn signature_status(tx: &Transaction) -> (u8, u8) {
    let mut present: u8 = 0;
    let mut required: u8 = 0;
    for i in 0..tx.num_inputs {
        let (script_type, ms_info) = analyze_input_script(tx, i);
        match script_type {
            ScriptType::P2PK => {
                required += 1;
                if tx.inputs[i].sig_len > 0 { present += 1; }
            }
            ScriptType::Multisig | ScriptType::P2SH => {
                if let Some(ref ms) = ms_info {
                    required += ms.m;
                    present += tx.inputs[i].sig_count.min(ms.m);
                } else {
                    // Covenant P2SH (IF/ELSE, treasury, or salt-prefixed state
                    // machine): exactly 1 signature required. See is_fully_signed
                    // for why we no longer pattern-match the script shape here.
                    required += 1;
                    if tx.inputs[i].sig_count > 0 { present += 1; }
                }
            }
            ScriptType::Unknown => { required += 1; }
        }
    }
    (present, required)
}

// ═══════════════════════════════════════════════════════════════════
// Serialization: Signed KSPT with multisig support
// ═══════════════════════════════════════════════════════════════════

/// Serialize a partially or fully signed KSPT with multisig support.
/// For each input, writes sig_count followed by each (pubkey_pos, sighash_type, 64-byte sig).
/// This format allows round-tripping partial signatures between signers.
pub fn serialize_signed_pskt_v2(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    let mut w = ByteWriter::new(output);

    // Header: "KSPT" + version 0x03 + flags
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(FORMAT_VERSION_V3)?; // v3: u16 LE redeem_len
    let fully = if is_fully_signed(tx) { 0x01u8 } else { 0x00u8 };
    w.write_u8(fully)?; // flags: 0x01 = fully signed, 0x00 = partial

    // Global
    w.write_u16_le(tx.version)?;
    w.write_u8(tx.num_inputs as u8)?;
    w.write_u8(tx.num_outputs as u8)?;
    w.write_u64_le(tx.locktime)?;
    w.write_bytes(&tx.subnetwork_id)?;
    w.write_u64_le(tx.gas)?;
    w.write_u16_le(tx.payload_len as u16)?;
    if tx.payload_len > 0 {
        w.write_bytes(&tx.payload[..tx.payload_len])?;
    }

    // Inputs with multi-signature support
    for i in 0..tx.num_inputs {
        let input = &tx.inputs[i];
        w.write_bytes(&input.previous_outpoint.transaction_id)?;
        w.write_bytes(&input.previous_outpoint.index.to_le_bytes())?;
        w.write_u64_le(input.utxo_entry.amount)?;
        w.write_u64_le(input.sequence)?;
        w.write_u8(input.sig_op_count)?;
        w.write_u16_le(input.utxo_entry.script_public_key.version)?;
        w.write_spk_len(input.utxo_entry.script_public_key.script_len)?;
        w.write_bytes(input.utxo_entry.script_public_key.script_bytes())?;

        // Signatures: count + per-sig (pubkey_pos, sighash_type, 64 bytes)
        w.write_u8(input.sig_count)?;
        for s in 0..input.sig_count as usize {
            if input.sigs[s].present {
                w.write_u8(input.sigs[s].pubkey_pos)?;
                w.write_u8(input.sigs[s].sighash_type)?;
                w.write_bytes(&input.sigs[s].signature)?;
            }
        }

        // Redeem script for P2SH round-trip (v3: u16 LE length)
        w.write_u16_le(input.redeem_script_len as u16)?;
        if input.redeem_script_len > 0 {
            w.write_bytes(tx.redeem_bytes(i))?;
        }
    }

    // Outputs
    for i in 0..tx.num_outputs {
        let out = &tx.outputs[i];
        w.write_u64_le(out.value)?;
        w.write_u16_le(out.script_public_key.version)?;
        w.write_spk_len(out.script_public_key.script_len)?;
        w.write_bytes(out.script_public_key.script_bytes())?;
    }

    Ok(w.written())
}

/// Parse a v2 signed KSPT (with multisig signatures) back into a Transaction.
/// Reads the sig_count + per-sig fields written by the v2 serializer.
pub fn parse_signed_pskt_v2(data: &[u8], tx: &mut Transaction) -> Result<(), PsktError> {
    // Clear stale state from previous scans -- the caller may reuse
    // the same Transaction struct across consecutive QR sessions.
    tx.clear();

    let mut r = ByteReader::new(data);

    let magic = r.read_bytes(4)?;
    if magic != PSKT_MAGIC {
        return Err(PsktError::InvalidMagic);
    }
    let version = r.read_u8()?;
    if version != 0x02 && version != FORMAT_VERSION_V3 {
        return Err(PsktError::UnsupportedVersion);
    }
    let _flags = r.read_u8()?; // 0x00=partial, 0x01=fully signed

    // Global
    tx.version = r.read_u16_le()?;
    let ni = r.read_u8()? as usize;
    let no = r.read_u8()? as usize;
    if ni == 0 || ni > MAX_INPUTS { return Err(PsktError::TooManyInputs); }
    if no == 0 || no > MAX_OUTPUTS { return Err(PsktError::TooManyOutputs); }
    tx.num_inputs = ni;
    tx.num_outputs = no;
    tx.locktime = r.read_u64_le()?;
    let sub = r.read_bytes(20)?;
    tx.subnetwork_id.copy_from_slice(sub);
    tx.gas = r.read_u64_le()?;
    let pl = r.read_u16_le()? as usize;
    if pl > MAX_PAYLOAD_SIZE { return Err(PsktError::PayloadTooLong); }
    tx.payload_len = pl;
    if pl > 0 {
        let pb = r.read_bytes(pl)?;
        tx.payload[..pl].copy_from_slice(pb);
    }

    // Inputs
    for i in 0..ni {
        let txid = r.read_bytes(32)?;
        tx.inputs[i].previous_outpoint.transaction_id.copy_from_slice(txid);
        tx.inputs[i].previous_outpoint.index = r.read_u32_le()?;
        tx.inputs[i].utxo_entry.amount = r.read_u64_le()?;
        tx.inputs[i].sequence = r.read_u64_le()?;
        tx.inputs[i].sig_op_count = r.read_u8()?;
        tx.inputs[i].utxo_entry.script_public_key.version = r.read_u16_le()?;
        let sl = r.read_spk_len()?;
        if sl > MAX_SCRIPT_SIZE { return Err(PsktError::ScriptTooLong); }
        tx.inputs[i].utxo_entry.script_public_key.script_len = sl;
        let sb = r.read_bytes(sl)?;
        tx.inputs[i].utxo_entry.script_public_key.script[..sl].copy_from_slice(sb);

        // Signatures
        let sig_count = r.read_u8()?;
        tx.inputs[i].sig_count = sig_count;
        for s in 0..sig_count as usize {
            if s >= MAX_SIGS_PER_INPUT { return Err(PsktError::TooManyInputs); }
            tx.inputs[i].sigs[s].pubkey_pos = r.read_u8()?;
            tx.inputs[i].sigs[s].sighash_type = r.read_u8()?;
            let sig_bytes = r.read_bytes(64)?;
            tx.inputs[i].sigs[s].signature.copy_from_slice(sig_bytes);
            tx.inputs[i].sigs[s].present = true;
        }
        // Sync legacy fields from first sig
        if sig_count > 0 {
            tx.inputs[i].signature = tx.inputs[i].sigs[0].signature;
            tx.inputs[i].sig_len = 64;
            tx.inputs[i].sighash_type = tx.inputs[i].sigs[0].sighash_type;
        }

        // Redeem script for P2SH round-trip (v3: u16 LE, v2: u8)
        let rs_len = if version == FORMAT_VERSION_V3 {
            r.read_u16_le()? as usize
        } else {
            r.read_u8()? as usize
        };
        if rs_len > 0 {
            if rs_len > MAX_REDEEM_SIZE { return Err(PsktError::ScriptTooLong); }
            let rs = r.read_bytes(rs_len)?;
            tx.store_redeem(i, rs).map_err(|_| PsktError::ScriptTooLong)?;
        }
    }

    // Outputs
    for i in 0..no {
        tx.outputs[i].value = r.read_u64_le()?;
        tx.outputs[i].script_public_key.version = r.read_u16_le()?;
        let sl = r.read_spk_len()?;
        if sl > MAX_SCRIPT_SIZE { return Err(PsktError::ScriptTooLong); }
        tx.outputs[i].script_public_key.script_len = sl;
        let sb = r.read_bytes(sl)?;
        tx.outputs[i].script_public_key.script[..sl].copy_from_slice(sb);
    }

    // Stealth tweak trailer: if remaining bytes start with 0x53 ('S') + 32 bytes,
    // read the stealth tweak. Backwards compatible with older KSPT v2 payloads.
    if r.remaining() >= 33 && r.peek_u8() == Some(0x53) {
        let _ = r.read_u8(); // consume marker
        let tweak = r.read_bytes(32)?;
        tx.stealth_tweak.copy_from_slice(tweak);
        tx.has_stealth_tweak = true;
    }

    // Covenant trailer: 0x43 ('C') + output_index(u8) + auth_input(u16 LE) + covenant_id(32)
    // May appear multiple times (one per covenanted output). Backwards compatible.
    while r.remaining() >= 36 && r.peek_u8() == Some(0x43) {
        let _ = r.read_u8(); // consume 'C' marker
        let out_idx = r.read_u8()? as usize;
        let auth_input = r.read_u16_le()?;
        let cov_id = r.read_bytes(32)?;
        if out_idx < tx.num_outputs {
            tx.outputs[out_idx].has_covenant = true;
            tx.outputs[out_idx].covenant_auth_input = auth_input;
            tx.outputs[out_idx].covenant_id.copy_from_slice(cov_id);
        }
    }

    Ok(())
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: KSPT serialize/parse round-trip.
pub fn test_serialize_parse_roundtrip() -> bool {
    // Create transaction, serialize, parse, verify equality
    let mut tx = Transaction::new();
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 2;

    // Input
    tx.inputs[0].previous_outpoint.transaction_id = [0xDE; 32];
    tx.inputs[0].previous_outpoint.index = 3;
    tx.inputs[0].utxo_entry.amount = 500_000_000; // 5 KAS
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xAA; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output 0: destination (4.5 KAS)
    tx.outputs[0].value = 450_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // Output 1: change (0.49 KAS, fee = 0.01 KAS)
    tx.outputs[1].value = 49_000_000;
    tx.outputs[1].script_public_key.version = 0;
    tx.outputs[1].script_public_key.script[0] = 0x20;
    tx.outputs[1].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[1].script_public_key.script[33] = 0xAC;
    tx.outputs[1].script_public_key.script_len = 34;

    // Serialize
    let mut buf = [0u8; 512];
    let size = match serialize_pskt(&tx, &mut buf) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Parsear
    let mut tx2 = Transaction::new();
    if parse_pskt(&buf[..size], &mut tx2).is_err() {
        return false;
    }

    // Verify fields
    tx2.version == tx.version
        && tx2.num_inputs == tx.num_inputs
        && tx2.num_outputs == tx.num_outputs
        && tx2.inputs[0].previous_outpoint.transaction_id == tx.inputs[0].previous_outpoint.transaction_id
        && tx2.inputs[0].previous_outpoint.index == tx.inputs[0].previous_outpoint.index
        && tx2.inputs[0].utxo_entry.amount == tx.inputs[0].utxo_entry.amount
        && tx2.outputs[0].value == tx.outputs[0].value
        && tx2.outputs[1].value == tx.outputs[1].value
        && tx2.fee() == tx.fee()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: invalid KSPT magic bytes are rejected.
pub fn test_invalid_magic() -> bool {
    let bad_data = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let mut tx = Transaction::new();
    matches!(parse_pskt(&bad_data, &mut tx), Err(PsktError::InvalidMagic))
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: complete KSPT parse → sign → serialize flow.
pub fn test_full_sign_flow() -> bool {
    use super::bip39;
    use super::bip32;
    use super::schnorr;
    use super::sighash;

    // 1. Generate wallet
    let entropy = [0x42u8; 16];
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

    // 2. Build transaction
    let mut tx = Transaction::new();
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 2;

    tx.inputs[0].previous_outpoint.transaction_id = [0x99; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].utxo_entry.amount = 1_000_000_000; // 10 KAS
    tx.inputs[0].sequence = 0;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&pubkey_x);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    tx.outputs[0].value = 500_000_000; // 5 KAS to destination
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xFF; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    tx.outputs[1].value = 499_000_000; // 4.99 KAS change
    tx.outputs[1].script_public_key.version = 0;
    tx.outputs[1].script_public_key.script[0] = 0x20;
    tx.outputs[1].script_public_key.script[1..33].copy_from_slice(&pubkey_x); // change to ourselves
    tx.outputs[1].script_public_key.script[33] = 0xAC;
    tx.outputs[1].script_public_key.script_len = 34;

    // 3. Serialize → parse (simulates QR roundtrip)
    let mut pskt_buf = [0u8; 512];
    let pskt_size = match serialize_pskt(&tx, &mut pskt_buf) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut parsed_tx = Transaction::new();
    if parse_pskt(&pskt_buf[..pskt_size], &mut parsed_tx).is_err() {
        return false;
    }

    // 4. Firmar
    let signed = match sign_transaction(&parsed_tx, key.private_key_bytes(), SigHashType::All) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if signed.num_signatures != 1 {
        return false;
    }

    // 5. Serialize response → parse (simulates QR round-trip)
    let mut resp_buf = [0u8; 256];
    let resp_size = match signed.serialize(&mut resp_buf) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let parsed_resp = match SignedResponse::parse(&resp_buf[..resp_size]) {
        Ok(r) => r,
        Err(_) => return false,
    };

    if parsed_resp.num_signatures != 1 {
        return false;
    }

    // 6. Verify signature with Schnorr
    let sighash_val = sighash::calculate_sighash(&parsed_tx, 0, SigHashType::All);
    let sig = super::schnorr::SchnorrSignature { bytes: parsed_resp.signatures[0].signature };
    schnorr::schnorr_verify(&pubkey_x, &sighash_val, &sig).is_ok()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: signed response has predictable size.
pub fn test_signed_response_size() -> bool {
    // Verify that the response size is predictable
    // 1 firma: 4 (magic) + 1 (ver) + 1 (num) + 1 (idx) + 1 (sht) + 64 (sig) = 72 bytes
    let mut resp = SignedResponse::new();
    let sig = [0xAB; 64];
    if resp.add_signature(0, SigHashType::All, &sig).is_err() { return false; }

    let mut buf = [0u8; 256];
    match resp.serialize(&mut buf) {
        Ok(size) => size == 72,
        Err(_) => false,
    }
}

/// Run all KSPT tests
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_pskt_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_serialize_parse_roundtrip() { passed += 1; }
    if test_invalid_magic() { passed += 1; }
    if test_full_sign_flow() { passed += 1; }
    if test_signed_response_size() { passed += 1; }

    (passed, total)
}
