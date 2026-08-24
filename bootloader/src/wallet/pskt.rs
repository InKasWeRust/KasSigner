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
// SIGNED RESPONSE FORMAT ("KSSN") — NOT THE WIRE FORMAT. TEST ONLY.
// ═══════════════════════════════════════════════════════════════════
//
// This device does not emit KSSN. What goes out after signing is KSPT, written
// by `serialize_signed_pskt` (PSKT_MAGIC, "KSPT"). Enumerated 2026-08-14:
// SIGNED_MAGIC is written only by `SignedResponse::serialize` and read only by
// `SignedResponse::parse`; `SignedResponse` is produced only by
// `sign_transaction`, whose only caller in the tree is `test_full_sign_flow`.
// The whole format is reachable from one test.
//
// Kept because that test is a useful end-to-end exercise of the signing path.
// Removing the format and rewriting the test against KSPT is tracked; it is not
// N-05, which was the log label in `app/signing.rs` that named this format
// while dumping a KSPT payload.
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

/// Magic bytes for the KSSN signed response.
///
/// TEST ONLY. Never emitted by this device; see the format block above. The
/// signed payload that actually leaves the device is KSPT, `PSKT_MAGIC`.
const SIGNED_MAGIC: [u8; 4] = [0x4B, 0x53, 0x53, 0x4E]; // "KSSN"

/// Current format version
const FORMAT_VERSION: u8 = 0x01;

/// KSPT v3: identical to v2 but redeem_len is u16 LE instead of u8.
const FORMAT_VERSION_V3: u8 = 0x03;
/// v4: v1 body plus a derivation-hint trailer.
///
/// A 45' multisig input cannot be signed without knowing WHICH
/// `(cosigner, chain, index)` produced its address: the redeem script proves the
/// key set but not our slot in it, and a 40-derivation table scan per input is
/// what the hint replaces. The compact QR transport had no way to carry that, so
/// a relayed KSPT lost it and the device refused to sign.
///
/// Emitted ONLY when at least one hint is present. A 44' transaction still goes
/// out as v1, which keeps the existing wallets working on firmware that has
/// never heard of v4 - and that firmware rejects v4 with `UnsupportedVersion`,
/// which tells the user to update rather than `TrailingData`, which would look
/// like a corrupt scan.
const FORMAT_VERSION_V4: u8 = 0x04;
/// Trailer markers. One per record type, matching the signed serializer's style
/// (`0x53` stealth tweak, `0x43` covenant binding) rather than one marker with a
/// kind byte.
///
/// `0x44` 'D' input hint, `0x45` 'E' output hint. Outputs need their own because
/// N-26 established that the output derivation map is what lets the device verify
/// CHANGE: without it a relayed transaction shows change as unverifiable, which
/// is the whole point of having carried it.
const TRAILER_MS45_IN: u8 = 0x44;
const TRAILER_MS45_OUT: u8 = 0x45;
/// `index(u8) + cosigner(u32 LE) + chain(u32 LE) + addr_index(u32 LE)`.
const MS45_HINT_BODY: usize = 1 + 4 + 4 + 4;
/// SIGNED KSPT carrying the same hint trailer.
///
/// A separate byte from the unsigned `0x04` for two reasons. The camera routes
/// `0x02`/`0x03` to the signed parser and everything else to the unsigned one, so
/// a signed payload marked `0x04` would be handed to the wrong parser. And the
/// signed parser deliberately REFUSES trailers it does not know, so appending
/// hints under `0x03` would make every existing signer reject the relay.
///
/// Without this the trailer died at the first signature: the device parsed v4,
/// signed, then re-serialized as v3 and dropped the hints, so the SECOND signer
/// received a transaction it could not resolve a slot in. Observed on hardware
/// 2026-08-17 - the first device signed 1/2 and the second failed.
const FORMAT_VERSION_SIGNED_V4: u8 = 0x05;

/// Maximum signatures in response
pub const MAX_SIGNATURES: usize = MAX_INPUTS;

/// Total supply in sompi: 29e9 KAS. Mirrors `MAX_SOMPI` in rusty-kaspa 2.0.1
/// (`consensus/core/src/constants.rs:39`), where
/// `check_transaction_output_value_ranges` refuses both a single value and a
/// running total above it. Any payload carrying more describes a transaction
/// no node would accept, so it is refused here rather than displayed.
pub const MAX_SOMPI: u64 = 29_000_000_000 * 100_000_000;

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
    /// Covenant binding record malformed: `has_cov` outside {0,1}, or an
    /// `authorizing_input` naming an input that does not exist.
    InvalidCovenantBinding,
    /// Bytes remained after a structurally complete payload.
    ///
    /// A correct KSPT has no tail: the header declares the input and
    /// output counts, every field declares its own length, and reading
    /// them all lands exactly on the final byte. Leftover bytes are not a
    /// payload, they are evidence that the buffer and the header disagree,
    /// which is what a mixed multi-frame assembly looks like when the
    /// fragments happen to line up.
    ///
    /// Deliberately strict: an unrecognised future trailer is refused
    /// rather than ignored. That costs forward compatibility if a trailer
    /// type is ever added, and the version byte is the place to handle
    /// that.
    TrailingData,
    /// An input amount or output value above `MAX_SOMPI`, or a total that is.
    ///
    /// Consensus rule, not an invented one: `check_transaction_output_value_ranges`
    /// in rusty-kaspa 2.0.1 refuses both a single value and a running total
    /// above `MAX_SOMPI`. A payload carrying more describes a transaction no
    /// node would accept.
    ///
    /// Checked at parse time because the device sums these values for the
    /// review screen and the release profile traps on overflow: two outputs
    /// near `u64::MAX` would panic before anything is signed. The array caps
    /// bound how MANY values there are, never how large, so this is what makes
    /// those sums provably safe rather than safe by assumption.
    ValueOutOfRange,
}

impl PsktError {
    /// Two short lines for `draw_tx_error_screen`, same contract as
    /// `PskError::screen_text`. Both parse paths rendered every failure as
    /// "Too many UTXOs" / "Consolidate first"; the KSPT path has its own
    /// error type, so it needs its own mapping.
    pub fn screen_text(&self) -> (&'static str, &'static str) {
        match self {
            PsktError::BufferTooShort      => ("Bundle too short", "Truncated in transit"),
            PsktError::InvalidMagic        => ("Not a KSPT bundle", "Wrong format scanned"),
            PsktError::UnsupportedVersion  => ("Unsupported version", "Update this firmware"),
            PsktError::TooManyInputs       => ("Too many UTXOs", "Consolidate first"),
            PsktError::TooManyOutputs      => ("Too many outputs", "Split the transaction"),
            PsktError::ScriptTooLong       => ("Script too long", "Not supported here"),
            PsktError::PayloadTooLong      => ("Payload too long", "Split the transaction"),
            PsktError::InvalidSigHashType  => ("Unsupported sighash", "This wallet signs ALL only"),
            PsktError::OutputBufferTooSmall => ("Result too large", "Split the transaction"),
            PsktError::NoInputs            => ("No inputs", "Nothing to sign"),
            PsktError::NoOutputs           => ("No outputs", "Nothing to send"),
            PsktError::InvalidCovenantBinding => ("Bad covenant binding", "Malformed or incomplete"),
            PsktError::ValueOutOfRange     => ("Amount out of range", "Above the total supply"),
            PsktError::TrailingData        => ("Extra data in bundle", "Rescan or resend"),
        }
    }
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

    /// Counterpart to `read_u32_le`, which already existed - the writer side did
    /// not, since nothing had needed a 32-bit field until the v4 hint trailer.
    fn write_u32_le(&mut self, val: u32) -> Result<(), PsktError> {
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
    // v1 and v4 share an identical BODY; v4 only adds a trailer, so one parser
    // reads both and older senders keep working unchanged.
    if version != FORMAT_VERSION && version != FORMAT_VERSION_V4 {
        return Err(PsktError::UnsupportedVersion);
    }
    let has_hint_trailer = version == FORMAT_VERSION_V4;

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
        // Consensus range check at parse time. The device sums these for the
        // review screen and the release profile traps on overflow, so an
        // unbounded value is a panic waiting on a hostile payload; the array
        // caps bound the count, never the magnitude.
        let amount = r.read_u64_le()?;
        if amount > MAX_SOMPI {
            return Err(PsktError::ValueOutOfRange);
        }
        tx.inputs[i].utxo_entry.amount = amount;
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
    // Running total across outputs, checked against MAX_SOMPI as each is
    // read. Mirrors the consensus rule, which rejects the total as well
    // as any single value.
    let mut out_total: u64 = 0;
    for i in 0..num_outputs {
        // Per-value and running-total range check, matching
        // `check_transaction_output_value_ranges` in rusty-kaspa.
        let value = r.read_u64_le()?;
        if value > MAX_SOMPI {
            return Err(PsktError::ValueOutOfRange);
        }
        out_total = match out_total.checked_add(value) {
            Some(t) if t <= MAX_SOMPI => t,
            _ => return Err(PsktError::ValueOutOfRange),
        };
        tx.outputs[i].value = value;

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
            match has_cov {
                0 => tx.outputs[i].has_covenant = false,
                1 => {
                    tx.outputs[i].has_covenant = true;
                    tx.outputs[i].covenant_auth_input = r.read_u16_le()?;
                    let cov_id_bytes = r.read_bytes(32)?;
                    tx.outputs[i].covenant_id.copy_from_slice(cov_id_bytes);
                }
                // Anything else means the sender and this parser disagree
                // about the record. Previously treated as "absent", which
                // silently dropped a binding the sender believed it sent.
                _ => return Err(PsktError::InvalidCovenantBinding),
            }
        }
    }

    // Every binding must name an input that exists. Same rule the node
    // applies (`crypto/txscript/src/covenants.rs`, `AuthInputOutOfBounds`).
    // Checked after the loop because `num_inputs` is known from the header
    // but the outputs are only complete here.
    for i in 0..num_outputs {
        let o = &tx.outputs[i];
        if o.has_covenant && (o.covenant_auth_input as usize) >= num_inputs {
            return Err(PsktError::InvalidCovenantBinding);
        }
    }

    // ── v4 hint trailer ──
    //
    // Read BEFORE the trailing-data check, which is what rejected v4 payloads on
    // firmware that predates it. Unknown markers are an error rather than a skip:
    // a hint the sender believed it sent and we silently dropped means the device
    // scans a 40-entry table or refuses to sign, and the user has no way to tell
    // why. Same reasoning as `InvalidCovenantBinding` above.
    if has_hint_trailer {
        while r.remaining() > 0 {
            let marker = r.read_u8()?;
            match marker {
                TRAILER_MS45_IN | TRAILER_MS45_OUT => {
                    if r.remaining() < MS45_HINT_BODY {
                        return Err(PsktError::TrailingData);
                    }
                    let idx = r.read_u8()? as usize;
                    let cosigner = r.read_u32_le()?;
                    let chain = r.read_u32_le()?;
                    let addr_index = r.read_u32_le()?;
                    let h = Ms45Hint {
                        present: true,
                        cosigner,
                        chain,
                        index: addr_index,
                    };
                    // A record naming a record that does not exist means the
                    // sender and this parser disagree about the transaction.
                    if marker == TRAILER_MS45_IN {
                        if idx >= num_inputs {
                            return Err(PsktError::TrailingData);
                        }
                        // A second hint for the same record is the same
                        // disagreement: one sender cannot mean both.
                        if tx.inputs[idx].ms45_hint.present {
                            return Err(PsktError::TrailingData);
                        }
                        tx.inputs[idx].ms45_hint = h;
                    } else {
                        if idx >= num_outputs {
                            return Err(PsktError::TrailingData);
                        }
                        if tx.outputs[idx].ms45_hint.present {
                            return Err(PsktError::TrailingData);
                        }
                        tx.outputs[idx].ms45_hint = h;
                    }
                }
                _ => return Err(PsktError::TrailingData),
            }
        }
    }

    // The header and the field lengths together account for every byte of
    // a well-formed KSPT, so anything left over means they disagree with
    // the buffer we were handed.
    if r.remaining() != 0 {
        return Err(PsktError::TrailingData);
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

    // Version by CONTENT: v4 only when there is a hint to carry.
    //
    // A 44' transaction has no hints and goes out as v1, so wallets on firmware
    // that predates v4 keep working. Bumping unconditionally would break every
    // one of them for a field they never use.
    let has_hints = (0..tx.num_inputs).any(|i| tx.inputs[i].ms45_hint.present)
        || (0..tx.num_outputs).any(|i| tx.outputs[i].ms45_hint.present);
    let ver = if has_hints { FORMAT_VERSION_V4 } else { FORMAT_VERSION };

    // Header
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(ver)?;
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

    // ── v4 hint trailer ──
    //
    // PER-RECORD, not per-transaction: a multi-address spend gives every input
    // its own `(cosigner, chain, index)`, so one header field could not describe
    // it. Only inputs and outputs that HAVE a hint get a record, so a mix of
    // hinted and unhinted inputs round-trips correctly.
    //
    // Outputs carry theirs because the output derivation map is what lets the
    // device verify CHANGE (N-26). A trailer with inputs only would sign fine and
    // show change as unverifiable, losing the check on the compact path that the
    // PSKB path has.
    if has_hints {
        for i in 0..tx.num_inputs {
            let h = &tx.inputs[i].ms45_hint;
            if h.present {
                w.write_u8(TRAILER_MS45_IN)?;
                w.write_u8(i as u8)?;
                w.write_u32_le(h.cosigner)?;
                w.write_u32_le(h.chain)?;
                w.write_u32_le(h.index)?;
            }
        }
        for i in 0..tx.num_outputs {
            let h = &tx.outputs[i].ms45_hint;
            if h.present {
                w.write_u8(TRAILER_MS45_OUT)?;
                w.write_u8(i as u8)?;
                w.write_u32_le(h.cosigner)?;
                w.write_u32_le(h.chain)?;
                w.write_u32_le(h.index)?;
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

// The `&mut **er` derefs at the `ext_scan_find` call below are written out
// rather than left to auto-deref. `ext` is `Option<(&mut Box<..>, ..)>`, and
// spelling the reborrow makes it visible that four independent mutable
// borrows are being handed to one call. Deliberate; clippy would rather they
// were implicit.
#[allow(clippy::explicit_auto_deref)]
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
    // And the 45' multisig account keys, m/45'/111111'/0'. A DIFFERENT subtree
    // from the 44' key above, so neither substitutes for the other: a 45' input
    // signed with a 44'-derived key produces a signature for a pubkey that is
    // not in the redeem script, which the network rejects.
    //
    // Derived here, once per seed for the whole transaction, for the same
    // reason the 44' keys are: three hardened HMAC-SHA512 steps each, and
    // paying that per input was the 45-second signing time this loop was
    // rewritten to avoid.
    let mut ms45_keys: [Option<bip32::ExtendedPrivKey>; 8] = [None, None, None, None, None, None, None, None];
    for s in 0..num_seeds {
        if seeds[s].1 {
            if let Ok(ak) = bip32::derive_account_key(&seeds[s].0) {
                acct_keys[s] = Some(ak);
            }
            if let Ok(mk) = bip32::derive_multisig_account_key(&seeds[s].0, 0) {
                ms45_keys[s] = Some(mk);
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

    // Hinted key cache, ACROSS inputs.
    //
    // The derivation was already hoisted out of the cosigner-position loop, but
    // it still ran once per INPUT. A multisig spend normally sweeps several
    // UTXOs from one address, so every input carries the same hint and the same
    // three-step path: vector M7 signed 6 inputs in 2321 ms, 387 ms each, where
    // all six shared one path and five derivations repeated work already done.
    //
    // NOT hoisted unconditionally, because inputs may legitimately differ: one
    // transaction can spend from two addresses, or from two cosigner families.
    // Keyed on the hint and recomputed when it changes, so it costs one
    // comparison per input and stays exact either way.
    let mut hint_cache_key: Option<(u32, u32, u32)> = None;
    let mut hint_cache: [Option<(bip32::ExtendedPrivKey, [u8; 32])>; 8] =
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

                    // Derive the hinted key ONCE per input, before the
                    // position loop.
                    //
                    // The hint carries ONE path for the whole input - the path
                    // of the address being spent - so every cosigner position
                    // compares against the same derived key. Deriving inside the
                    // loop walked the same three steps `n` times.
                    //
                    // Measured: 2-of-2 signed in 595 ms, 2-of-3 in 764 ms. The
                    // 169 ms delta is three derivations at ~47 ms, i.e. exactly
                    // one extra walk for the extra position. At N=5 it would be
                    // 15 derivations where 3 suffice.
                    //
                    // `None` covers both "no hint" and "hint did not derive",
                    // and the position loop treats them alike: no match, fall
                    // through to whatever the scheme allows.
                    // The x-only pubkey is computed here too, not in the
                    // position loop. `public_key_x_only()` is a scalar multiply
                    // - about the cost of a derivation - and the key is the same
                    // for every position, so calling it per position repeated
                    // the work n times for one answer. Same mistake as deriving
                    // in the loop, one level down.
                    if tx.inputs[i].ms45_hint.present {
                        let h = tx.inputs[i].ms45_hint;
                        let key = (h.cosigner, h.chain, h.index);
                        if hint_cache_key != Some(key) {
                            hint_cache = [None, None, None, None, None, None, None, None];
                            for s in 0..num_seeds {
                                if let Some(mk) = ms45_keys[s].as_ref() {
                                    if let Ok(k) = bip32::derive_child(mk, h.cosigner)
                                        .and_then(|k| bip32::derive_child(&k, h.chain))
                                        .and_then(|k| bip32::derive_child(&k, h.index))
                                    {
                                        if let Ok(pk) = k.public_key_x_only() {
                                            hint_cache[s] = Some((k, pk));
                                        }
                                    }
                                }
                            }
                            hint_cache_key = Some(key);
                        }
                    }
                    let hint_key = &hint_cache;

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
                                // 45' hint path, tried BEFORE the address table.
                                //
                                // The hint carries the derivation path of the
                                // ADDRESS BEING SPENT, so every cosigner of this
                                // input derives at the same
                                // /cosigner/chain/index and this device's own
                                // cosigner index is irrelevant here.
                                //
                                // UNTRUSTED INPUT. It arrives in the same PSKB an
                                // attacker could craft, so it says where to LOOK
                                // and never what to trust: the derived pubkey is
                                // compared against `target_pk`, which came out of
                                // this input's redeem script, which is what the
                                // P2SH address hashes to and what the user
                                // approved on the review screen. A crafted hint
                                // can only make us derive a key that then fails
                                // to match, costing three derivations.
                                //
                                // Three derivations, not a table build, and only
                                // when a hint is present.
                                if seed_pos_match[s].is_none() && tx.inputs[i].ms45_hint.present {
                                    if let Some((addr_key, pk)) = hint_key[s].as_ref() {
                                        {
                                            {
                                                if *pk == *target_pk {
                                                    let privkey = addr_key.private_key_bytes();
                                                    if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                                        let sc = tx.inputs[i].sig_count as usize;
                                                        if sc < MAX_SIGS_PER_INPUT {
                                                            tx.inputs[i].sigs[sc].signature = sig.bytes;
                                                            tx.inputs[i].sigs[sc].sighash_type = sighash_type.to_byte();
                                                            tx.inputs[i].sigs[sc].pubkey_pos = pos as u8;
                                                            tx.inputs[i].sigs[sc].present = true;
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

                                // Skip the 44' address table when a 45' hint
                                // was present and did not match.
                                //
                                // The table scans m/44'/111111'/0'/{0,1}/0..N.
                                // A 45' key lives at
                                // m/45'/111111'/0'/{cos}/{chain}/{idx} - a
                                // different subtree with an extra level - so it
                                // CANNOT appear in that table. Building it is 40
                                // derivations spent proving something already
                                // known.
                                //
                                // Measured before this guard, vector M1 (2-of-2,
                                // one input, hint present): `multisig sign` was
                                // 2476 ms. The hint itself is three derivations.
                                // The cost was the table being built for the
                                // cosigner position that is NOT ours, where the
                                // hint correctly fails to match and the old code
                                // fell straight through to the scan.
                                //
                                // Only skipped when a hint was actually present.
                                // A 44' multisig input carries no hint and still
                                // needs the table, which is how legacy wallets
                                // keep signing.
                                let hint_tried = tx.inputs[i].ms45_hint.present;
                                if seed_pos_match[s].is_none() && !hint_tried {
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

    // Header: "KSPT" + version + flags.
    //
    // 0x05 when there are hints to carry, 0x03 otherwise, so a 44' relay is
    // byte-identical to what it always was.
    let has_hints = (0..tx.num_inputs).any(|i| tx.inputs[i].ms45_hint.present)
        || (0..tx.num_outputs).any(|i| tx.outputs[i].ms45_hint.present);
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(if has_hints { FORMAT_VERSION_SIGNED_V4 } else { FORMAT_VERSION_V3 })?;
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

    // ─── Trailers ────────────────────────────────────────────────────────
    //
    // The parser reads both of these and this serializer wrote neither, so
    // anything signed here came back stripped of them.
    //
    // That matters because THIS is the covenant path. The caller selects v2
    // whenever any input is Multisig or P2SH, and every covenant is P2SH, so
    // every covenant signature was serialized by the one function that
    // discards the binding. `serialize_signed_pskt`, which does write it, is
    // the fallback for ordinary inputs that never have one.
    //
    // `covenant_id` is hashed into every output for `tx.version >= 1`, so a
    // second signer parsing this output computes a DIFFERENT SIGHASH and
    // produces an invalid signature. A stealth input loses
    // `has_stealth_tweak` and is not signed at all.
    //
    // Written in the order the parser reads them: stealth first, then the
    // covenant records. Both are optional and length-prefixed by their
    // marker, so a reader that does not know them stops at the end of the
    // outputs exactly as before. Backwards compatible in both directions.

    // Stealth tweak: 0x53 'S' + 32 bytes.
    if tx.has_stealth_tweak {
        w.write_u8(0x53)?;
        w.write_bytes(&tx.stealth_tweak)?;
    }

    // Covenant bindings: 0x43 'C' + out_idx(u8) + auth_input(u16 LE) + id(32),
    // one record per covenanted output.
    for i in 0..tx.num_outputs {
        let out = &tx.outputs[i];
        if out.has_covenant {
            w.write_u8(0x43)?;
            w.write_u8(i as u8)?;
            w.write_u16_le(out.covenant_auth_input)?;
            w.write_bytes(&out.covenant_id)?;
        }
    }

    // Hint records, so the NEXT signer gets what this one got.
    //
    // The hint is what lets a signer find its slot without a 40-derivation table
    // scan, and the output hint is what lets it verify change. Dropping them here
    // meant only the first signer had them.
    if has_hints {
        for i in 0..tx.num_inputs {
            let h = &tx.inputs[i].ms45_hint;
            if h.present {
                w.write_u8(TRAILER_MS45_IN)?;
                w.write_u8(i as u8)?;
                w.write_u32_le(h.cosigner)?;
                w.write_u32_le(h.chain)?;
                w.write_u32_le(h.index)?;
            }
        }
        for i in 0..tx.num_outputs {
            let h = &tx.outputs[i].ms45_hint;
            if h.present {
                w.write_u8(TRAILER_MS45_OUT)?;
                w.write_u8(i as u8)?;
                w.write_u32_le(h.cosigner)?;
                w.write_u32_le(h.chain)?;
                w.write_u32_le(h.index)?;
            }
        }
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
    if version != 0x02 && version != FORMAT_VERSION_V3
        && version != FORMAT_VERSION_SIGNED_V4
    {
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
        // Consensus range check at parse time. The device sums these for the
        // review screen and the release profile traps on overflow, so an
        // unbounded value is a panic waiting on a hostile payload; the array
        // caps bound the count, never the magnitude.
        let amount = r.read_u64_le()?;
        if amount > MAX_SOMPI {
            return Err(PsktError::ValueOutOfRange);
        }
        tx.inputs[i].utxo_entry.amount = amount;
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

        // Redeem script for P2SH round-trip. u16 LE on v3 AND on the signed v4,
        // u8 only on the original v2.
        //
        // `version == FORMAT_VERSION_V3` alone sent 0x05 down the u8 path while
        // the writer had emitted u16, so every field after the first redeem
        // script was misaligned and the parse died as BufferTooShort - a length
        // error, which is why it did not look like a version problem. The width
        // belongs to the BODY layout, and v4 inherits v3's body unchanged; only
        // the trailer differs.
        let rs_len = if version == FORMAT_VERSION_V3
            || version == FORMAT_VERSION_SIGNED_V4
        {
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
    let mut out_total: u64 = 0;
    for i in 0..no {
        // Per-value and running-total range check, matching
        // `check_transaction_output_value_ranges` in rusty-kaspa.
        let value = r.read_u64_le()?;
        if value > MAX_SOMPI {
            return Err(PsktError::ValueOutOfRange);
        }
        out_total = match out_total.checked_add(value) {
            Some(t) if t <= MAX_SOMPI => t,
            _ => return Err(PsktError::ValueOutOfRange),
        };
        tx.outputs[i].value = value;
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

    // Hint records: 0x44 input, 0x45 output. Same peek-and-consume shape as the
    // two loops above, and only present on 0x05.
    // `> MS45_HINT_BODY`, not `>= 1 + MS45_HINT_BODY`: same bound, and clippy's
    // int_plus_one rejects the second form.
    while r.remaining() > MS45_HINT_BODY
        && matches!(r.peek_u8(), Some(TRAILER_MS45_IN) | Some(TRAILER_MS45_OUT))
    {
        let marker = r.read_u8()?;
        let idx = r.read_u8()? as usize;
        let cosigner = r.read_u32_le()?;
        let chain = r.read_u32_le()?;
        let addr_index = r.read_u32_le()?;
        let h = Ms45Hint { present: true, cosigner, chain, index: addr_index };
        if marker == TRAILER_MS45_IN {
            if idx >= ni {
                return Err(PsktError::TrailingData);
            }
            // Same rule as the unsigned parser: a second hint for the same
            // record is a disagreement, one sender cannot mean both.
            if tx.inputs[idx].ms45_hint.present {
                return Err(PsktError::TrailingData);
            }
            tx.inputs[idx].ms45_hint = h;
        } else {
            if idx >= no {
                return Err(PsktError::TrailingData);
            }
            if tx.outputs[idx].ms45_hint.present {
                return Err(PsktError::TrailingData);
            }
            tx.outputs[idx].ms45_hint = h;
        }
    }

    // Both trailer loops above stop on the first byte that is not their
    // marker, so a trailer type this firmware does not know would be left
    // behind rather than skipped. Refuse instead of signing a bundle whose
    // tail we did not understand.
    if r.remaining() != 0 {
        return Err(PsktError::TrailingData);
    }

    Ok(())
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: KSPT serialize/parse round-trip.
pub fn test_serialize_parse_roundtrip() -> bool {
    // Create transaction, serialize, parse, verify equality
    // Heap, not stack. `Transaction` is 78,952 bytes and the frame that holds
    // it is reserved on entry, so a stack local here claimed the space for the
    // whole call whether or not it was still needed. Measured 2026-08-14 on
    // M5Stack: `verbose-boot` tripped the ProCpu stack guard inside
    // `self_test::test_sram`'s 2 KB buffer at test 1 of 5, SP 81,776 bytes
    // below the floor, 186,272 bytes of depth against 105,008 usable. These
    // tests never reached their own bodies in any build. See N-15.
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
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

    // Parsear. Second box: this frame held TWO 78,952-byte transactions,
    // 157,904 bytes in one frame against 105,008 usable.
    let mut tx2 = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
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
/// Test: a v4 hint trailer survives a serialize/parse round trip.
///
/// Covers what the v1 test cannot: that the version is bumped BY CONTENT, that
/// input and output records are both read back, and that an unhinted input in the
/// same transaction stays unhinted. The last one matters for a multi-address
/// spend, where a mix is normal and a parser that filled every input from the
/// first record would sign with the wrong path.
pub fn test_ms45_hint_roundtrip() -> bool {
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
    tx.version = 0;
    tx.num_inputs = 2;
    tx.num_outputs = 2;
    tx.inputs[0].utxo_entry.amount = 300_000_000;
    tx.inputs[1].utxo_entry.amount = 200_000_000;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 35;
    tx.inputs[1].utxo_entry.script_public_key.script_len = 35;
    tx.outputs[0].value = 100_000_000;
    tx.outputs[1].value = 399_400_000;
    tx.outputs[0].script_public_key.script_len = 34;
    tx.outputs[1].script_public_key.script_len = 35;

    // Input 0 hinted, input 1 NOT: the mix is the point.
    tx.inputs[0].ms45_hint = Ms45Hint { present: true, cosigner: 1, chain: 0, index: 7 };
    tx.inputs[1].ms45_hint = Ms45Hint::none();
    // Output 1 is change, on chain 1.
    tx.outputs[1].ms45_hint = Ms45Hint { present: true, cosigner: 1, chain: 1, index: 3 };

    let mut buf = [0u8; 1024];
    let size = match serialize_pskt(&tx, &mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    // Version chosen by content, not unconditionally.
    if buf[4] != FORMAT_VERSION_V4 {
        return false;
    }

    let mut tx2 = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
    if parse_pskt(&buf[..size], &mut tx2).is_err() {
        return false;
    }

    tx2.inputs[0].ms45_hint.present
        && tx2.inputs[0].ms45_hint.cosigner == 1
        && tx2.inputs[0].ms45_hint.chain == 0
        && tx2.inputs[0].ms45_hint.index == 7
        && !tx2.inputs[1].ms45_hint.present
        && !tx2.outputs[0].ms45_hint.present
        && tx2.outputs[1].ms45_hint.present
        && tx2.outputs[1].ms45_hint.cosigner == 1
        && tx2.outputs[1].ms45_hint.chain == 1
        && tx2.outputs[1].ms45_hint.index == 3
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: hints survive the SIGNED relay between signers.
///
/// This is the hop that failed on hardware. The first device parsed v4, signed,
/// then re-serialized through `serialize_signed_pskt_v2`, which wrote v3 and
/// dropped the trailer - so the second signer received a transaction with no
/// hints and could not resolve its slot. A round trip through the signed
/// serializer is what would have caught it here rather than on two devices.
pub fn test_ms45_hint_signed_roundtrip() -> bool {
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 2;
    tx.inputs[0].utxo_entry.amount = 300_000_000;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 35;
    tx.inputs[0].sig_op_count = 2;
    tx.outputs[0].value = 100_000_000;
    tx.outputs[0].script_public_key.script_len = 34;
    tx.outputs[1].value = 199_400_000;
    tx.outputs[1].script_public_key.script_len = 35;
    tx.inputs[0].ms45_hint = Ms45Hint { present: true, cosigner: 1, chain: 0, index: 0 };
    tx.outputs[1].ms45_hint = Ms45Hint { present: true, cosigner: 1, chain: 1, index: 3 };

    let mut buf = [0u8; 1024];
    let size = match serialize_signed_pskt_v2(&tx, &mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    // Version bumped BY CONTENT, and not to the unsigned 0x04, which the camera
    // would route to the wrong parser.
    if buf[4] != FORMAT_VERSION_SIGNED_V4 {
        return false;
    }

    let mut tx2 = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
    if parse_signed_pskt_v2(&buf[..size], &mut tx2).is_err() {
        return false;
    }
    tx2.inputs[0].ms45_hint.present
        && tx2.inputs[0].ms45_hint.cosigner == 1
        && tx2.inputs[0].ms45_hint.chain == 0
        && tx2.inputs[0].ms45_hint.index == 0
        && tx2.outputs[1].ms45_hint.present
        && tx2.outputs[1].ms45_hint.chain == 1
        && tx2.outputs[1].ms45_hint.index == 3
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: invalid KSPT magic bytes are rejected.
pub fn test_invalid_magic() -> bool {
    let bad_data = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    // Heap, not stack: see the note on the first boxed transaction in this file. N-15.
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
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
    // Heap, not stack: see the note on the first boxed transaction in this file. N-15.
    let mut tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
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

    // Second box in this frame, same reason as the roundtrip test above.
    let mut parsed_tx = match Transaction::new_boxed() {
        Some(t) => t,
        None => return false,
    };
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
