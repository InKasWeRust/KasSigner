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

// wallet/transaction.rs — Kaspa transaction structures, script parsing, multisig

// KasSigner — Kaspa Transaction Types
// 100% Rust, no-std, no-alloc
//
// Types representing Kaspa transactions as received by
// KasSigner from the companion app (via QR/PSKT).
//
// Note: we use fixed arrays and maximum limits because we have no allocator.
// A typical Kaspa transaction has 1-5 inputs and 1-2 outputs.
// We support up to MAX_INPUTS=8 and MAX_OUTPUTS=4 (enough for a hardware wallet).

#![allow(dead_code)]
/// Maximum supported inputs
pub const MAX_INPUTS: usize = 8;

/// Maximum supported outputs
pub const MAX_OUTPUTS: usize = 4;

/// Maximum script size (P2PK = 34 bytes, P2SH = 35 bytes)
pub const MAX_SCRIPT_SIZE: usize = 64;

/// Maximum payload size
pub const MAX_PAYLOAD_SIZE: usize = 128;

/// Hash de 32 bytes (Blake2b / transaction ID)
pub type Hash256 = [u8; 32];

/// Subnetwork ID (20 bytes)
pub type SubnetworkId = [u8; 20];

/// Native subnetwork (all zeros)
pub const SUBNETWORK_ID_NATIVE: SubnetworkId = [0u8; 20];

// ─── SigHash Types ────────────────────────────────────────────────────

/// Tipos de SigHash (Kaspa usa bitfield, diferente a Bitcoin)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
/// Kaspa sighash type — determines which parts of the transaction are signed.
pub enum SigHashType {
    All         = 0b0000_0001,
    None        = 0b0000_0010,
    Single      = 0b0000_0100,
    AnyOneCanPay = 0b1000_0000,
    // Combinaciones
    AllAnyOneCanPay    = 0b1000_0001,
    NoneAnyOneCanPay   = 0b1000_0010,
    SingleAnyOneCanPay = 0b1000_0100,
}

impl SigHashType {
    /// Parse a sighash type from its byte representation.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0b0000_0001 => Some(Self::All),
            0b0000_0010 => Some(Self::None),
            0b0000_0100 => Some(Self::Single),
            0b1000_0001 => Some(Self::AllAnyOneCanPay),
            0b1000_0010 => Some(Self::NoneAnyOneCanPay),
            0b1000_0100 => Some(Self::SingleAnyOneCanPay),
            _ => Option::None,
        }
    }

    /// Convert to the wire byte representation.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns true if this is an ANYONE_CAN_PAY variant.
    pub fn is_anyone_can_pay(self) -> bool {
        (self.to_byte() & 0b1000_0000) != 0
    }

    /// Returns true if this is a SIGHASH_NONE variant.
    pub fn is_sighash_none(self) -> bool {
        (self.to_byte() & 0b0000_0010) != 0
    }

    /// Returns true if this is a SIGHASH_SINGLE variant.
    pub fn is_sighash_single(self) -> bool {
        (self.to_byte() & 0b0000_0100) != 0
    }
}

// ─── Outpoint ─────────────────────────────────────────────────────────

/// Reference to a previous output (transaction ID + index)
#[derive(Debug, Clone)]
/// A transaction outpoint: previous tx ID + output index.
pub struct Outpoint {
    pub transaction_id: Hash256,
    pub index: u32,
}

// ─── Script Public Key ────────────────────────────────────────────────

/// ScriptPubKey with version (Kaspa versions its scripts)
#[derive(Debug, Clone)]
/// Script public key with version byte (Kaspa uses version 0).
pub struct ScriptPublicKey {
    pub version: u16,
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
}

impl ScriptPublicKey {
    pub fn new() -> Self {
        Self {
            version: 0,
            script: [0u8; MAX_SCRIPT_SIZE],
            script_len: 0,
        }
    }

        /// Get the raw script bytes.
pub fn script_bytes(&self) -> &[u8] {
        &self.script[..self.script_len]
    }
}

// ─── UTXO Entry (previous output being spent) ──────────────────

/// UTXO entry being spent (provided by companion app)
#[derive(Debug, Clone)]
/// Unspent transaction output entry (amount + script + metadata).
pub struct UtxoEntry {
    pub amount: u64,                  // sompi (1 KAS = 100_000_000 sompi)
    pub script_public_key: ScriptPublicKey,
}

// ─── Multisig Constants ──────────────────────────────────────────────

/// Maximum signatures per input (supports up to 5-of-5 multisig)
pub const MAX_SIGS_PER_INPUT: usize = 5;

/// Maximum public keys in a multisig script
pub const MAX_MULTISIG_KEYS: usize = 5;

// ─── Kaspa Script Opcodes (subset for multisig parsing) ─────────────

/// Kaspa script opcodes used in P2PK and multisig scripts.
pub const OP_DATA_32: u8 = 0x20; // push 32 bytes
pub const OP_1: u8 = 0x51;       // push value 1
pub const OP_2: u8 = 0x52;       // push value 2
pub const OP_3: u8 = 0x53;       // push value 3
pub const OP_4: u8 = 0x54;       // push value 4
pub const OP_5: u8 = 0x55;       // push value 5
pub const OP_CHECKSIG: u8 = 0xAC;
pub const OP_CHECKMULTISIG: u8 = 0xAE;

// ─── Multisig Script Info ────────────────────────────────────────────

/// Parsed multisig script: M-of-N with extracted pubkeys
#[derive(Debug, Clone)]
/// Detected M-of-N multisig parameters from a script.
pub struct MultisigInfo {
    pub m: u8,  // required signatures
    pub n: u8,  // total pubkeys
    pub pubkeys: [[u8; 32]; MAX_MULTISIG_KEYS],
}

impl MultisigInfo {
    pub fn new() -> Self {
        Self { m: 0, n: 0, pubkeys: [[0u8; 32]; MAX_MULTISIG_KEYS] }
    }
}

/// Script type detected from scriptPublicKey
#[derive(Debug, Clone, Copy, PartialEq)]
/// Detected script type (P2PK, multisig, or unknown).
pub enum ScriptType {
    /// Standard P2PK Schnorr: OP_DATA_32 <pubkey> OP_CHECKSIG
    P2PK,
    /// M-of-N multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
    Multisig,
    /// Unknown/unsupported script
    Unknown,
}

/// Parse a scriptPublicKey and detect its type
pub fn detect_script_type(script: &[u8], len: usize) -> ScriptType {
    if len == 34 && script[0] == OP_DATA_32 && script[33] == OP_CHECKSIG {
        return ScriptType::P2PK;
    }
    // Multisig: OP_m [OP_DATA_32 <32 bytes>]xN OP_n OP_CHECKMULTISIG
    if len >= 37 && script[len - 1] == OP_CHECKMULTISIG {
        let n_byte = script[len - 2];
        let m_byte = script[0];
        if m_byte >= OP_1 && m_byte <= OP_5 && n_byte >= OP_1 && n_byte <= OP_5 {
            let m = (m_byte - OP_1 + 1) as usize;
            let n = (n_byte - OP_1 + 1) as usize;
            if m <= n && n <= MAX_MULTISIG_KEYS {
                // Expected length: 1 (OP_m) + N*(1+32) (OP_DATA_32 + pubkey) + 1 (OP_n) + 1 (OP_CHECKMULTISIG)
                let expected_len = 1 + n * 33 + 1 + 1;
                if len == expected_len {
                    // Verify each pubkey push is OP_DATA_32
                    let mut valid = true;
                    for i in 0..n {
                        if script[1 + i * 33] != OP_DATA_32 {
                            valid = false;
                            break;
                        }
                    }
                    if valid {
                        return ScriptType::Multisig;
                    }
                }
            }
        }
    }
    ScriptType::Unknown
}

/// Parse a multisig scriptPublicKey, extracting M, N, and pubkeys.
/// Returns None if not a valid multisig script.
pub fn parse_multisig_script(script: &[u8], len: usize) -> Option<MultisigInfo> {
    if detect_script_type(script, len) != ScriptType::Multisig {
        return None;
    }
    let m = script[0] - OP_1 + 1;
    let n = script[len - 2] - OP_1 + 1;
    let mut info = MultisigInfo::new();
    info.m = m;
    info.n = n;
    for i in 0..n as usize {
        let start = 1 + i * 33 + 1; // skip OP_m + i*(OP_DATA_32+pubkey) + OP_DATA_32
        info.pubkeys[i].copy_from_slice(&script[start..start + 32]);
    }
    Some(info)
}

// ─── Transaction Input ────────────────────────────────────────────────

/// Single signature slot within an input
#[derive(Debug, Clone)]
/// Signature attached to a transaction input.
pub struct InputSig {
    pub signature: [u8; 64],
    pub sighash_type: u8,
    pub pubkey_pos: u8,  // position in multisig pubkey list (0-based), 0 for P2PK
    pub present: bool,
}

impl InputSig {
    pub const fn empty() -> Self {
        Self {
            signature: [0u8; 64],
            sighash_type: 0,
            pubkey_pos: 0,
            present: false,
        }
    }
}

/// Transaction input with support for multiple signatures (multisig)
#[derive(Debug, Clone)]
/// A transaction input: references a UTXO and provides a signature.
pub struct TransactionInput {
    pub previous_outpoint: Outpoint,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub utxo_entry: UtxoEntry,
    /// Signatures — up to MAX_SIGS_PER_INPUT for multisig
    pub sigs: [InputSig; MAX_SIGS_PER_INPUT],
    pub sig_count: u8,
    // Legacy single-sig aliases (first slot) for backward compat
    pub signature: [u8; 64],
    pub sig_len: u8,
    pub sighash_type: u8,
}

// ─── Transaction Output ───────────────────────────────────────────────

/// Transaction output
#[derive(Debug, Clone)]
/// A transaction output: amount + destination script.
pub struct TransactionOutput {
    pub value: u64,                    // sompi
    pub script_public_key: ScriptPublicKey,
}

// ─── Transaction ──────────────────────────────────────────────────────

/// Complete Kaspa transaction (for signing)
#[derive(Debug)]
/// A complete Kaspa transaction with inputs, outputs, and metadata.
pub struct Transaction {
    pub version: u16,
    pub inputs: [TransactionInput; MAX_INPUTS],
    pub num_inputs: usize,
    pub outputs: [TransactionOutput; MAX_OUTPUTS],
    pub num_outputs: usize,
    pub locktime: u64,
    pub subnetwork_id: SubnetworkId,
    pub gas: u64,
    pub payload: [u8; MAX_PAYLOAD_SIZE],
    pub payload_len: usize,
}

impl Transaction {
    /// Create an empty transaction
    pub fn new() -> Self {
        Self {
            version: 0,
            inputs: core::array::from_fn(|_| TransactionInput {
                previous_outpoint: Outpoint {
                    transaction_id: [0u8; 32],
                    index: 0,
                },
                sequence: 0,
                sig_op_count: 1,
                utxo_entry: UtxoEntry {
                    amount: 0,
                    script_public_key: ScriptPublicKey::new(),
                },
                sigs: [InputSig::empty(), InputSig::empty(), InputSig::empty(),
                       InputSig::empty(), InputSig::empty()],
                sig_count: 0,
                signature: [0u8; 64],
                sig_len: 0,
                sighash_type: 0,
            }),
            num_inputs: 0,
            outputs: core::array::from_fn(|_| TransactionOutput {
                value: 0,
                script_public_key: ScriptPublicKey::new(),
            }),
            num_outputs: 0,
            locktime: 0,
            subnetwork_id: SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: [0u8; MAX_PAYLOAD_SIZE],
            payload_len: 0,
        }
    }

    /// Get the transaction inputs slice.
    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs[..self.num_inputs]
    }

    /// Get the transaction outputs slice.
    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.outputs[..self.num_outputs]
    }

    /// Returns true if the transaction subnetwork is native (not a registry tx).
    pub fn is_native(&self) -> bool {
        self.subnetwork_id == SUBNETWORK_ID_NATIVE
    }

    /// Calculate total sompi across inputs
    pub fn total_input_value(&self) -> u64 {
        self.inputs().iter().map(|i| i.utxo_entry.amount).sum()
    }

    /// Calculate total sompi across outputs
    pub fn total_output_value(&self) -> u64 {
        self.outputs().iter().map(|o| o.value).sum()
    }

    /// Implicit fee = inputs - outputs
    pub fn fee(&self) -> u64 {
        self.total_input_value().saturating_sub(self.total_output_value())
    }

    /// Format a sompi value as KAS (no-alloc, returns in buffer)
    /// Example: 123_456_789 sompi -> "1.23456789"
    pub fn format_kas(sompi: u64, buf: &mut [u8]) -> usize {
        let kas = sompi / 100_000_000;
        let frac = sompi % 100_000_000;
        let mut pos = 0;

        // Integer part
        pos += Self::write_u64(kas, &mut buf[pos..]);

        // Decimal point
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }

        // Fractional part (8 digits with leading zeros)
        let mut frac_buf = [b'0'; 8];
        let mut f = frac;
        for i in (0..8).rev() {
            frac_buf[i] = b'0' + (f % 10) as u8;
            f /= 10;
        }

        // Write fraction (trim unnecessary trailing zeros)
        let mut last_nonzero = 0;
        for i in 0..8 {
            if frac_buf[i] != b'0' {
                last_nonzero = i;
            }
        }
        let frac_digits = if frac == 0 { 2 } else { last_nonzero + 1 };
        for i in 0..frac_digits {
            if pos < buf.len() {
                buf[pos] = frac_buf[i];
                pos += 1;
            }
        }

        pos
    }

    fn write_u64(mut val: u64, buf: &mut [u8]) -> usize {
        if val == 0 {
            if !buf.is_empty() {
                buf[0] = b'0';
            }
            return 1;
        }
        let mut digits = [0u8; 20];
        let mut count = 0;
        while val > 0 {
            digits[count] = b'0' + (val % 10) as u8;
            val /= 10;
            count += 1;
        }
        let written = count.min(buf.len());
        for i in 0..written {
            buf[i] = digits[count - 1 - i];
        }
        written
    }
}

// ═══════════════════════════════════════════════════════════════════
// Multisig Wallet Configuration (RAM-only, wiped on shutdown)
// ═══════════════════════════════════════════════════════════════════

/// Maximum multisig wallet configs stored simultaneously
pub const MAX_MULTISIG_WALLETS: usize = 2;

/// A multisig wallet configuration: M-of-N with pubkeys and derived script
#[derive(Clone)]
/// Runtime multisig configuration: M-of-N with collected pubkeys.
pub struct MultisigConfig {
    pub m: u8,
    pub n: u8,
    pub pubkeys: [[u8; 32]; MAX_MULTISIG_KEYS],
    /// The built scriptPublicKey (OP_m <pks> OP_n OP_CHECKMULTISIG)
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
    /// Whether this config has been fully set up
    pub active: bool,
}

impl MultisigConfig {
    pub const fn new() -> Self {
        Self {
            m: 0,
            n: 0,
            pubkeys: [[0u8; 32]; MAX_MULTISIG_KEYS],
            script: [0u8; MAX_SCRIPT_SIZE],
            script_len: 0,
            active: false,
        }
    }

    /// Build the multisig scriptPublicKey from the current M, N, pubkeys.
    /// Script format: OP_m OP_DATA_32 <pk0> OP_DATA_32 <pk1> ... OP_n OP_CHECKMULTISIG
    /// Returns script length, or 0 on error.
    pub fn build_script(&mut self) -> usize {
        if self.m == 0 || self.n == 0 || self.m > self.n || self.n as usize > MAX_MULTISIG_KEYS {
            return 0;
        }
        // Length: 1 (OP_m) + N*(1+32) + 1 (OP_n) + 1 (OP_CHECKMULTISIG)
        let len = 1 + (self.n as usize) * 33 + 1 + 1;
        if len > MAX_SCRIPT_SIZE { return 0; }

        let mut pos = 0;
        // OP_m (OP_1=0x51 for m=1, OP_2=0x52 for m=2, etc.)
        self.script[pos] = OP_1 + self.m - 1;
        pos += 1;
        // N pubkeys, each preceded by OP_DATA_32
        for i in 0..self.n as usize {
            self.script[pos] = OP_DATA_32;
            pos += 1;
            self.script[pos..pos + 32].copy_from_slice(&self.pubkeys[i]);
            pos += 32;
        }
        // OP_n
        self.script[pos] = OP_1 + self.n - 1;
        pos += 1;
        // OP_CHECKMULTISIG
        self.script[pos] = OP_CHECKMULTISIG;
        pos += 1;

        self.script_len = pos;
        pos
    }

    /// Get a human-readable label: "2-of-3" etc.
    pub fn label(&self, buf: &mut [u8]) -> usize {
        // Format: "M-of-N"
        let mut pos = 0;
        if pos < buf.len() { buf[pos] = b'0' + self.m; pos += 1; }
        for &c in b"-of-" { if pos < buf.len() { buf[pos] = c; pos += 1; } }
        if pos < buf.len() { buf[pos] = b'0' + self.n; pos += 1; }
        pos
    }
}

/// Storage for multisig wallet configurations
pub struct MultisigStore {
    pub configs: [MultisigConfig; MAX_MULTISIG_WALLETS],
}

impl MultisigStore {
    pub const fn new() -> Self {
        Self {
            configs: [MultisigConfig::new(), MultisigConfig::new()],
        }
    }

    /// Find the first free slot, or None if all full
    pub fn find_free(&self) -> Option<usize> {
        for i in 0..MAX_MULTISIG_WALLETS {
            if !self.configs[i].active { return Some(i); }
        }
        None
    }
}
