// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// SPDX-License-Identifier: GPL-3.0-only

use crate::{derivation::xpub::KpubParts, transaction::sighash::blake2b_hash};

use super::{
    constants::{MAX_MULTISIG_KEYS, MAX_MULTISIG_WALLETS, MAX_SCRIPT_SIZE},
    input::Ms45Hint,
    multisig_validation::{contains_cosigner, slot_empty, valid_config},
};

mod derivation;

use derivation::{
    derive_children_at, derive_multisig_children, encode_redeem, push_byte, serialized_parts,
    sort_xonly_children, write_multisig_script,
};

/// Strict v1.0.6 45' multisig plus legacy 44' compatibility. New 45' wallets
/// derive `/cosigner/chain/index` beneath `m/45'/111111'/0'`; legacy descriptors
/// retain `/0/index` with per-address child-key sorting.
#[derive(Clone)]
pub struct MultisigConfig {
    pub m: u8,
    pub n: u8,
    pub cosigner_pubkeys: [[u8; 33]; MAX_MULTISIG_KEYS],
    pub cosigner_chain_codes: [[u8; 32]; MAX_MULTISIG_KEYS],
    pub addr_index: u32,
    pub v45: bool,
    /// Address family this device issues. In 45' it is this device's position
    /// in the sorted descriptor; ignored for legacy 44'.
    pub cosigner_index: u8,
    /// 0=external/receive, 1=change for 45'; ignored by legacy 44'.
    pub chain: u8,
    /// Metadata required to re-serialize each 45' participant byte-identically.
    pub cosigner_depth: [u8; MAX_MULTISIG_KEYS],
    pub cosigner_parent_fp: [[u8; 4]; MAX_MULTISIG_KEYS],
    pub cosigner_child_num: [[u8; 4]; MAX_MULTISIG_KEYS],
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
    pub active: bool,
}

impl Default for MultisigConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigConfig {
    pub const fn new() -> Self {
        Self {
            m: 0,
            n: 0,
            cosigner_pubkeys: [[0; 33]; MAX_MULTISIG_KEYS],
            cosigner_chain_codes: [[0; 32]; MAX_MULTISIG_KEYS],
            addr_index: 0,
            v45: false,
            cosigner_index: 0,
            chain: 0,
            cosigner_depth: [0; MAX_MULTISIG_KEYS],
            cosigner_parent_fp: [[0; 4]; MAX_MULTISIG_KEYS],
            cosigner_child_num: [[0; 4]; MAX_MULTISIG_KEYS],
            script: [0; MAX_SCRIPT_SIZE],
            script_len: 0,
            active: false,
        }
    }

    /// Return whether an in-range cosigner slot contains no participant data.
    #[must_use]
    pub fn slot_empty(&self, index: usize) -> bool {
        slot_empty(self, index)
    }

    /// Store one full cosigner entry. Keeping all five serialized kpub fields
    /// together prevents creation/import from accidentally changing parent
    /// ordering on descriptor export.
    pub fn set_cosigner(&mut self, index: usize, parts: &KpubParts) -> bool {
        if index >= MAX_MULTISIG_KEYS || contains_cosigner(self, parts, Some(index)) {
            return false;
        }
        self.cosigner_pubkeys[index] = parts.pubkey;
        self.cosigner_chain_codes[index] = parts.chain_code;
        self.cosigner_depth[index] = parts.depth;
        self.cosigner_parent_fp[index] = parts.parent_fp;
        self.cosigner_child_num[index] = parts.child_num;
        true
    }

    /// Build the redeem script for this config's current family/chain/index.
    /// 45' preserves canonical parent order; legacy 44' sorts derived children.
    pub fn build_script(&mut self) -> usize {
        if !valid_config(self.m, self.n) {
            return 0;
        }
        let Some(mut children) = derive_multisig_children(self) else {
            return 0;
        };
        if !self.v45 {
            sort_xonly_children(&mut children, self.n as usize);
        }
        write_multisig_script(self, &children)
    }

    /// Does this 45' descriptor reproduce the P2SH script hash at an untrusted
    /// derivation hint? The caller can therefore use hints as lookup indexes
    /// without trusting them as authorization.
    #[must_use]
    pub fn matches_at(&self, hint: &Ms45Hint, script_hash: &[u8; 32]) -> bool {
        if !self.v45
            || !hint.present
            || hint.chain > 1
            || hint.cosigner >= 0x8000_0000
            || hint.index >= 0x8000_0000
            || !valid_config(self.m, self.n)
        {
            return false;
        }
        let Some(children) = derive_children_at(self, hint.cosigner, hint.chain, hint.index) else {
            return false;
        };
        let mut redeem = [0u8; MAX_SCRIPT_SIZE];
        let Some(length) = encode_redeem(self.m, self.n, &children, &mut redeem) else {
            return false;
        };
        blake2b_hash(&redeem[..length]) == *script_hash
    }

    /// Sort 45' cosigner parents into the v1.0.6/rusty-kaspa canonical order.
    /// Legacy 44' configs are intentionally not reordered here.
    pub fn sort_cosigners(&mut self) {
        if !self.v45 {
            return;
        }
        let n = self.n as usize;
        for index in 1..n {
            let mut cursor = index;
            while cursor > 0 && self.serialized_entry(cursor - 1) > self.serialized_entry(cursor) {
                self.cosigner_pubkeys.swap(cursor - 1, cursor);
                self.cosigner_chain_codes.swap(cursor - 1, cursor);
                self.cosigner_depth.swap(cursor - 1, cursor);
                self.cosigner_parent_fp.swap(cursor - 1, cursor);
                self.cosigner_child_num.swap(cursor - 1, cursor);
                cursor -= 1;
            }
        }
    }

    #[must_use]
    pub fn same_wallet_as(&self, other: &Self) -> bool {
        (
            self.v45,
            self.m,
            self.n,
            &self.cosigner_pubkeys,
            &self.cosigner_chain_codes,
        ) == (
            other.v45,
            other.m,
            other.n,
            &other.cosigner_pubkeys,
            &other.cosigner_chain_codes,
        )
    }

    /// Resolve this device's own 45' family by matching its account kpub parts
    /// against the already-canonicalized descriptor.
    pub fn resolve_cosigner_index(&mut self, own: &KpubParts) -> bool {
        if !self.v45 {
            self.cosigner_index = 0;
            return true;
        }
        let own_entry = serialized_parts(own);
        for index in 0..self.n as usize {
            if self.serialized_entry(index) == own_entry {
                self.cosigner_index = index as u8;
                return true;
            }
        }
        false
    }

    /// Human-readable wallet label. 45' includes the address family and chain
    /// because neither can be inferred from a P2SH address.
    pub fn label(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0usize;
        push_byte(buf, &mut pos, b'0' + self.m);
        for byte in b"-of-" {
            push_byte(buf, &mut pos, *byte);
        }
        push_byte(buf, &mut pos, b'0' + self.n);
        if self.v45 {
            for byte in b" 45' S" {
                push_byte(buf, &mut pos, *byte);
            }
            push_byte(buf, &mut pos, b'0' + self.cosigner_index);
            for byte in b"/C" {
                push_byte(buf, &mut pos, *byte);
            }
            push_byte(buf, &mut pos, b'0' + self.chain);
        }
        pos.min(buf.len())
    }

    fn serialized_entry(&self, index: usize) -> [u8; 74] {
        // Version bytes are equal for every kpub, so omitting them preserves
        // exactly the same order while avoiding an unnecessary dependency.
        let mut out = [0u8; 74];
        out[0] = self.cosigner_depth[index];
        out[1..5].copy_from_slice(&self.cosigner_parent_fp[index]);
        out[5..9].copy_from_slice(&self.cosigner_child_num[index]);
        out[9..41].copy_from_slice(&self.cosigner_chain_codes[index]);
        out[41..74].copy_from_slice(&self.cosigner_pubkeys[index]);
        out
    }
}

/// Storage for multisig wallet configurations.
pub struct MultisigStore {
    pub configs: [MultisigConfig; MAX_MULTISIG_WALLETS],
}

impl Default for MultisigStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigStore {
    pub const fn new() -> Self {
        Self {
            configs: [MultisigConfig::new(), MultisigConfig::new()],
        }
    }

    #[must_use]
    pub fn find_free(&self) -> Option<usize> {
        self.configs.iter().position(|config| !config.active)
    }
}
