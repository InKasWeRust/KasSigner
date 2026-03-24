// KasSigner — PSKT (Partially Signed Kaspa Transaction) Parser
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
// BINARY FORMAT: KasSigner PSKT v1
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

/// Magic bytes for unsigned PSKT
const PSKT_MAGIC: [u8; 4] = [0x4B, 0x53, 0x50, 0x54]; // "KSPT"

/// Magic bytes for signed response
const SIGNED_MAGIC: [u8; 4] = [0x4B, 0x53, 0x53, 0x4E]; // "KSSN"

/// Current format version
const FORMAT_VERSION: u8 = 0x01;

/// Maximum signatures in response
pub const MAX_SIGNATURES: usize = MAX_INPUTS;

/// PSKT parser errors
#[derive(Debug, Clone, Copy, PartialEq)]
/// Errors during PSKT parsing, signing, or serialization.
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

// ─── Reader helper (cursor sobre slice, no-alloc) ─────────────────

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

// ─── Writer helper (cursor sobre buffer mutable, no-alloc) ────────

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

    fn write_u64_le(&mut self, val: u64) -> Result<(), PsktError> {
        self.write_bytes(&val.to_le_bytes())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Public API: Deserialization (QR -> Transaction)
// ═══════════════════════════════════════════════════════════════════

/// Parse a binary PSKT buffer and populate a Transaction.
///
/// The companion app generates this buffer, encodes it as QR(s),
/// KasSigner reads it with the camera and parses it here.
///
/// Returns Ok(()) on successful parse.
pub fn parse_pskt(data: &[u8], tx: &mut Transaction) -> Result<(), PsktError> {
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

    let _flags = r.read_u8()?; // Reserved

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
        let spk_len = r.read_u8()? as usize;
        if spk_len > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }

        tx.inputs[i].utxo_entry.script_public_key.version = spk_version;
        tx.inputs[i].utxo_entry.script_public_key.script_len = spk_len;
        let spk_bytes = r.read_bytes(spk_len)?;
        tx.inputs[i].utxo_entry.script_public_key.script[..spk_len]
            .copy_from_slice(spk_bytes);
    }

    // Outputs
    for i in 0..num_outputs {
        tx.outputs[i].value = r.read_u64_le()?;

        let spk_version = r.read_u16_le()?;
        let spk_len = r.read_u8()? as usize;
        if spk_len > MAX_SCRIPT_SIZE {
            return Err(PsktError::ScriptTooLong);
        }

        tx.outputs[i].script_public_key.version = spk_version;
        tx.outputs[i].script_public_key.script_len = spk_len;
        let spk_bytes = r.read_bytes(spk_len)?;
        tx.outputs[i].script_public_key.script[..spk_len]
            .copy_from_slice(spk_bytes);
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Public API: Serialization (Transaction -> bytes for QR)
// ═══════════════════════════════════════════════════════════════════

/// Serialize a Transaction to the PSKT binary format.
///
/// Useful for tests and for the companion app to generate the payload.
///
/// Returns the number of bytes written.
pub fn serialize_pskt(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    let mut w = ByteWriter::new(output);

    // Header
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(FORMAT_VERSION)?;
    w.write_u8(0x00)?; // flags

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
        w.write_u8(input.utxo_entry.script_public_key.script_len as u8)?;
        w.write_bytes(input.utxo_entry.script_public_key.script_bytes())?;
    }

    // Outputs
    for i in 0..tx.num_outputs {
        let output_tx = &tx.outputs[i];
        w.write_u64_le(output_tx.value)?;
        w.write_u16_le(output_tx.script_public_key.version)?;
        w.write_u8(output_tx.script_public_key.script_len as u8)?;
        w.write_bytes(output_tx.script_public_key.script_bytes())?;
    }

    Ok(w.written())
}

/// Serialize a signed Transaction to PSKT binary format.
/// Same as serialize_pskt but with signatures appended per input.
/// flags byte = 0x01 to indicate signed PSKT.
pub fn serialize_signed_pskt(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    let mut w = ByteWriter::new(output);

    // Header (flags = 0x01 for signed)
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(FORMAT_VERSION)?;
    w.write_u8(0x01)?; // flags: signed

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
        w.write_u8(input.utxo_entry.script_public_key.script_len as u8)?;
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
        w.write_u8(output_tx.script_public_key.script_len as u8)?;
        w.write_bytes(output_tx.script_public_key.script_bytes())?;
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
/// Typical hardware wallet flow:
/// 1. companion app -> QR -> parse_pskt() -> Transaction
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
pub fn sign_transaction_multi_addr(
    tx: &mut Transaction,
    seed: &[u8; 64],
    sighash_type: SigHashType,
) -> Result<usize, PsktError> {
    use super::sighash;
    use super::bip32;

    let account_key = bip32::derive_account_key(seed)
        .map_err(|_| PsktError::NoInputs)?;

    let mut signed_count = 0usize;

    for i in 0..tx.num_inputs {
        let script = &tx.inputs[i].utxo_entry.script_public_key;
        // P2PK Schnorr script: OP_DATA_32 (0x20) + 32-byte pubkey + OP_CHECKSIG (0xAC)
        if script.script_len != 34 || script.script[0] != 0x20 || script.script[33] != 0xAC {
            continue; // not a standard P2PK script we can sign
        }

        let mut target_pk = [0u8; 32];
        target_pk.copy_from_slice(&script.script[1..33]);

        // Find which address index this pubkey belongs to
        if let Some(idx) = bip32::find_address_index_for_pubkey(&account_key, &target_pk) {
            // Derive the privkey for this index
            if let Ok(addr_key) = bip32::derive_address_key(&account_key, idx) {
                let privkey = addr_key.private_key_bytes();
                let sig = sighash::sign_input(tx, i, privkey, sighash_type)
                    .map_err(|_| PsktError::NoInputs)?;

                tx.inputs[i].signature = sig.bytes;
                tx.inputs[i].sig_len = 64;
                tx.inputs[i].sighash_type = sighash_type.to_byte();
                signed_count += 1;
            }
        }
    }

    if signed_count == 0 {
        return Err(PsktError::NoInputs);
    }

    Ok(signed_count)
}

// ═══════════════════════════════════════════════════════════════════
// Multisig Support
// ═══════════════════════════════════════════════════════════════════

/// Analyze a transaction input's script type.
pub fn analyze_input_script(tx: &Transaction, input_idx: usize) -> (ScriptType, Option<MultisigInfo>) {
    let script = &tx.inputs[input_idx].utxo_entry.script_public_key;
    let st = detect_script_type(&script.script, script.script_len);
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
                        if let Some(idx) = bip32::find_address_index_for_pubkey(acct, &target_pk) {
                            if let Ok(addr_key) = bip32::derive_address_key(acct, idx) {
                                let privkey = addr_key.private_key_bytes();
                                if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                    tx.inputs[i].signature = sig.bytes;
                                    tx.inputs[i].sig_len = 64;
                                    tx.inputs[i].sighash_type = sighash_type.to_byte();
                                    tx.inputs[i].sigs[0].signature = sig.bytes;
                                    tx.inputs[i].sigs[0].sighash_type = sighash_type.to_byte();
                                    tx.inputs[i].sigs[0].pubkey_pos = 0;
                                    tx.inputs[i].sigs[0].present = true;
                                    tx.inputs[i].sig_count = 1;
                                    total_new_sigs += 1;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            ScriptType::Multisig => {
                if let Some(ref ms) = ms_info {
                    for pos in 0..ms.n as usize {
                        // Already have a sig for this position? skip
                        let already = (0..tx.inputs[i].sig_count as usize)
                            .any(|s| tx.inputs[i].sigs[s].present && tx.inputs[i].sigs[s].pubkey_pos == pos as u8);
                        if already { continue; }

                        let target_pk = &ms.pubkeys[pos];

                        for s in 0..num_seeds {
                            if let Some(ref acct) = acct_keys[s] {
                                if let Some(idx) = bip32::find_address_index_for_pubkey(acct, target_pk) {
                                    if let Ok(addr_key) = bip32::derive_address_key(acct, idx) {
                                        let privkey = addr_key.private_key_bytes();
                                        if let Ok(sig) = sighash::sign_input(tx, i, privkey, sighash_type) {
                                            let sc = tx.inputs[i].sig_count as usize;
                                            if sc < MAX_SIGS_PER_INPUT {
                                                tx.inputs[i].sigs[sc].signature = sig.bytes;
                                                tx.inputs[i].sigs[sc].sighash_type = sighash_type.to_byte();
                                                tx.inputs[i].sigs[sc].pubkey_pos = pos as u8;
                                                tx.inputs[i].sigs[sc].present = true;
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

                    // Sync legacy fields
                    if tx.inputs[i].sig_count > 0 && tx.inputs[i].sig_len == 0 {
                        tx.inputs[i].signature = tx.inputs[i].sigs[0].signature;
                        tx.inputs[i].sig_len = 64;
                        tx.inputs[i].sighash_type = tx.inputs[i].sigs[0].sighash_type;
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
            ScriptType::Multisig => {
                if let Some(ref ms) = ms_info {
                    if tx.inputs[i].sig_count < ms.m { return false; }
                } else {
                    return false;
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
            ScriptType::Multisig => {
                if let Some(ref ms) = ms_info {
                    required += ms.m;
                    present += tx.inputs[i].sig_count.min(ms.m);
                }
            }
            ScriptType::Unknown => { required += 1; }
        }
    }
    (present, required)
}

// ═══════════════════════════════════════════════════════════════════
// Serialization: Signed PSKT with multisig support
// ═══════════════════════════════════════════════════════════════════

/// Serialize a partially or fully signed PSKT with multisig support.
/// For each input, writes sig_count followed by each (pubkey_pos, sighash_type, 64-byte sig).
/// This format allows round-tripping partial signatures between signers.
pub fn serialize_signed_pskt_v2(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    let mut w = ByteWriter::new(output);

    // Header: "KSPT" + version 0x02 + flags
    w.write_bytes(&PSKT_MAGIC)?;
    w.write_u8(0x02)?; // v2 format with multisig
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
        w.write_u8(input.utxo_entry.script_public_key.script_len as u8)?;
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
    }

    // Outputs
    for i in 0..tx.num_outputs {
        let out = &tx.outputs[i];
        w.write_u64_le(out.value)?;
        w.write_u16_le(out.script_public_key.version)?;
        w.write_u8(out.script_public_key.script_len as u8)?;
        w.write_bytes(out.script_public_key.script_bytes())?;
    }

    Ok(w.written())
}

/// Parse a v2 signed PSKT (with multisig signatures) back into a Transaction.
/// Reads the sig_count + per-sig fields written by serialize_signed_pskt_v2.
pub fn parse_signed_pskt_v2(data: &[u8], tx: &mut Transaction) -> Result<(), PsktError> {
    let mut r = ByteReader::new(data);

    let magic = r.read_bytes(4)?;
    if magic != PSKT_MAGIC {
        return Err(PsktError::InvalidMagic);
    }
    let version = r.read_u8()?;
    if version != 0x02 {
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
        let sl = r.read_u8()? as usize;
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
    }

    // Outputs
    for i in 0..no {
        tx.outputs[i].value = r.read_u64_le()?;
        tx.outputs[i].script_public_key.version = r.read_u16_le()?;
        let sl = r.read_u8()? as usize;
        if sl > MAX_SCRIPT_SIZE { return Err(PsktError::ScriptTooLong); }
        tx.outputs[i].script_public_key.script_len = sl;
        let sb = r.read_bytes(sl)?;
        tx.outputs[i].script_public_key.script[..sl].copy_from_slice(sb);
    }

    Ok(())
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: PSKT serialize/parse round-trip.
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

    // Output 0: destino (4.5 KAS)
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

    // Serializar
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

    // Verificar campos
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
/// Test: invalid PSKT magic bytes are rejected.
pub fn test_invalid_magic() -> bool {
    let bad_data = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let mut tx = Transaction::new();
    matches!(parse_pskt(&bad_data, &mut tx), Err(PsktError::InvalidMagic))
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: complete PSKT parse → sign → serialize flow.
pub fn test_full_sign_flow() -> bool {
    use super::bip39;
    use super::bip32;
    use super::schnorr;
    use super::sighash;

    // 1. Generar wallet
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

    tx.outputs[0].value = 500_000_000; // 5 KAS al destino
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xFF; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    tx.outputs[1].value = 499_000_000; // 4.99 KAS change
    tx.outputs[1].script_public_key.version = 0;
    tx.outputs[1].script_public_key.script[0] = 0x20;
    tx.outputs[1].script_public_key.script[1..33].copy_from_slice(&pubkey_x); // change a nosotros
    tx.outputs[1].script_public_key.script[33] = 0xAC;
    tx.outputs[1].script_public_key.script_len = 34;

    // 3. Serializar → parsear (simula QR roundtrip)
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

    // 6. Verificar firma con Schnorr
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

/// Run all PSKT tests
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
