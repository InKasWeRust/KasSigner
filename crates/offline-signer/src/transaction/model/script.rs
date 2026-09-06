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

use super::constants::{
    MAX_MULTISIG_KEYS, MAX_SCRIPT_SIZE, OP_1, OP_5, OP_BLAKE2B, OP_CHECKMULTISIG, OP_CHECKSIG,
    OP_DATA_32, OP_EQUAL,
};

const MIN_MULTISIG_SCRIPT_LEN: usize = 1 + 33 + 1 + 1;

// ─── Script Public Key ────────────────────────────────────────────────

/// ScriptPubKey with version (Kaspa versions its scripts)
#[derive(Debug, Clone)]
/// Script public key with version byte (Kaspa uses version 0).
pub struct ScriptPublicKey {
    pub version: u16,
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
}

impl Default for ScriptPublicKey {
    fn default() -> Self {
        Self::new()
    }
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
    pub amount: u64, // sompi (1 KAS = 100_000_000 sompi)
    pub script_public_key: ScriptPublicKey,
    /// DAA score from the node. Not part of the sighash, but retained exactly
    /// so JSON round-trips never need a JavaScript `Number`.
    pub block_daa_score: u64,
}

// ─── Multisig Script Info ────────────────────────────────────────────

/// Parsed multisig script: M-of-N with extracted pubkeys
#[derive(Debug, Clone)]
/// Detected M-of-N multisig parameters from a script.
pub struct MultisigInfo {
    pub m: u8, // required signatures
    pub n: u8, // total pubkeys
    pub pubkeys: [[u8; 32]; MAX_MULTISIG_KEYS],
}

impl Default for MultisigInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigInfo {
    pub fn new() -> Self {
        Self {
            m: 0,
            n: 0,
            pubkeys: [[0u8; 32]; MAX_MULTISIG_KEYS],
        }
    }
}

/// Script type detected from scriptPublicKey
#[derive(Debug, Clone, Copy, PartialEq)]
/// Detected script type (P2PK, P2SH, multisig, or unknown).
pub enum ScriptType {
    /// Standard P2PK Schnorr: OP_DATA_32 <pubkey> OP_CHECKSIG
    P2PK,
    /// P2SH: OP_BLAKE2B OP_DATA_32 <script_hash> OP_EQUAL
    P2SH,
    /// M-of-N multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
    Multisig,
    /// Unknown/unsupported script
    Unknown,
}

/// Parse a scriptPublicKey and detect its type
pub fn detect_script_type(script: &[u8], len: usize) -> ScriptType {
    if is_p2pk_script(script, len) {
        return ScriptType::P2PK;
    }
    if is_p2sh_script(script, len) {
        return ScriptType::P2SH;
    }
    if is_multisig_script(script, len) {
        return ScriptType::Multisig;
    }
    ScriptType::Unknown
}

fn is_p2pk_script(script: &[u8], len: usize) -> bool {
    len == 34 && script.first() == Some(&OP_DATA_32) && script.get(33) == Some(&OP_CHECKSIG)
}

fn is_p2sh_script(script: &[u8], len: usize) -> bool {
    len == 35
        && script.first() == Some(&OP_BLAKE2B)
        && script.get(1) == Some(&OP_DATA_32)
        && script.get(34) == Some(&OP_EQUAL)
}

fn is_multisig_script(script: &[u8], len: usize) -> bool {
    let Some((_, n)) = multisig_thresholds(script, len) else {
        return false;
    };
    let expected_len = 1 + n * 33 + 1 + 1;
    len == expected_len && (0..n).all(|index| script.get(1 + index * 33) == Some(&OP_DATA_32))
}

fn multisig_thresholds(script: &[u8], len: usize) -> Option<(usize, usize)> {
    if len < MIN_MULTISIG_SCRIPT_LEN || script.get(len.checked_sub(1)?) != Some(&OP_CHECKMULTISIG) {
        return None;
    }
    let m_byte = *script.first()?;
    let n_byte = *script.get(len.checked_sub(2)?)?;
    if !(OP_1..=OP_5).contains(&m_byte) || !(OP_1..=OP_5).contains(&n_byte) {
        return None;
    }
    let m = usize::from(m_byte - OP_1 + 1);
    let n = usize::from(n_byte - OP_1 + 1);
    (m <= n && n <= MAX_MULTISIG_KEYS).then_some((m, n))
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
