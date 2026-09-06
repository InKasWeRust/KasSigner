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

use super::{
    extended_private::ExtendedPrivKey,
    paths::{derive_address_key, derive_change_key},
};

/// Given an account key and a 32-byte x-only pubkey, find which address
/// index produced it. Scans 0..99 (covers typical wallet usage).
/// Returns None if no match. Used for multi-input signing.
/// Given an account key and a 32-byte x-only pubkey, find which address
/// index produced it. Scans both receive (chain 0) and change (chain 1)
/// paths, indices 0..99.
/// Returns Some((index, is_change)) or None if no match.
/// Used for multi-input signing.
/// Maximum address index scanned by `find_address_index_for_pubkey`
/// across each of the receive and change chains. Reduced from
/// 100 to 20 after diagnosing the 45 s signing time on 1-input multisig
/// txs. 100 per chain (200 derivations per call) × 3 multisig positions
/// × 1 input × 1 seed = ~700 HMAC-SHA512 + scalar-mult operations for
/// a single-input sign. At 20 per chain (40 per call) the same 700-op
/// ceiling drops to ~140 ops ≈ 7 s. Most wallets use indices 0-5 in
/// practice; 20 is a generous upper bound that still finishes fast.
///
/// If you need to sign against addresses beyond index 19, bump this
/// constant — but prefer the account-level kpub path in `multisig`
/// configs which avoids address-level search entirely (see
/// `sign_transaction_multisig` in pskt.rs for the seed_pos_match
/// fast path).
pub const ADDR_SCAN_DEPTH: u16 = 20;

/// Depth for on-the-fly key MATCHING during signing (P2PK funding +
/// per-address multisig). Decoupled from ADDR_SCAN_DEPTH on purpose:
/// matching derives one key per index on the fly with no table, so a
/// deeper bound costs nothing on a hit (the loop exits at the funding
/// index, normally <= 29) and only scans further on a genuine miss.
/// KasSee grows receive addresses in +10 steps and a used wallet can
/// sit past index 20, so the funding UTXO's index must be reachable
/// here or signing returns 0 sigs. The AddrPubkeyTable below stays at
/// ADDR_SCAN_DEPTH: it is a fixed [_; ADDR_SCAN_DEPTH*2] array held
/// [_; 8] deep on the signing stack in pskt.rs, so growing it would
/// blow the stack. Raise this further only if a wallet ever exceeds
/// 100 receive addresses (or consolidate it instead).
pub const SIGN_MATCH_DEPTH: u16 = 100;

/// Search m/44'/111111'/0'/0..1/0..SIGN_MATCH_DEPTH-1 for an x-only
/// pubkey matching target_pubkey. Returns Some((index, is_change))
/// or None if no match.
/// Used for per-address multisig signing and P2PK single-key signing
/// when the target pubkey's address index is unknown.
pub fn find_address_index_for_pubkey(
    account_key: &ExtendedPrivKey,
    target_pubkey: &[u8; 32],
) -> Option<(u16, bool)> {
    let mut no_checkpoint = || {};
    find_address_index_for_pubkey_with_checkpoint(account_key, target_pubkey, &mut no_checkpoint)
}

/// Watchdog-friendly variant of [`find_address_index_for_pubkey`]. Expensive
/// secp256k1 child/public-key derivations are split by caller-supplied liveness
/// checkpoints so constrained hardware can feed its watchdog while scanning.
pub fn find_address_index_for_pubkey_with_checkpoint(
    account_key: &ExtendedPrivKey,
    target_pubkey: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Option<(u16, bool)> {
    for idx in 0..SIGN_MATCH_DEPTH {
        checkpoint();
        if let Ok(key) = derive_address_key(account_key, u32::from(idx)) {
            checkpoint();
            if let Ok(pk) = key.public_key_x_only() {
                checkpoint();
                if pk == *target_pubkey {
                    return Some((idx, false));
                }
            }
        }
    }
    for idx in 0..SIGN_MATCH_DEPTH {
        checkpoint();
        if let Ok(key) = derive_change_key(account_key, u32::from(idx)) {
            checkpoint();
            if let Ok(pk) = key.public_key_x_only() {
                checkpoint();
                if pk == *target_pubkey {
                    return Some((idx, true));
                }
            }
        }
    }
    None
}

/// Pre-computed address pubkey table for cache-accelerated signing.
/// Stores x-only pubkeys for the first ADDR_SCAN_DEPTH indices of both
/// receive (chain=0) and change (chain=1) paths — 40 entries total.
///
/// Built ONCE per seed at the start of a multi-input signing pass, so
/// subsequent `find_by_pubkey` calls are O(40) array scans with zero
/// derivations. For a 3-position multisig across 11 inputs that's:
///   old: 11 × 3 × 200 = 6600 derivations  (~5 minutes)
///   new:  1 × 40 = 40 derivations          (~2 seconds)
///       + 11 × 3 × 40 lookups              (negligible)
///
/// The 40-slot table is ~1.3 KB. Signing contexts keep each lazily-built
/// table heap-backed so multi-seed signing does not reserve eight tables
/// on the constrained firmware stack.
pub struct AddrPubkeyTable {
    pub entries: [(bool, u16, [u8; 32]); (ADDR_SCAN_DEPTH as usize) * 2],
    pub filled: usize,
}

impl AddrPubkeyTable {
    /// Build the full receive + change pubkey table for an account key.
    /// Returns None if derivation fails anywhere (shouldn't happen for
    /// a valid account key).
    pub fn build(account_key: &ExtendedPrivKey) -> Self {
        let mut no_checkpoint = || {};
        Self::build_with_checkpoint(account_key, &mut no_checkpoint)
    }

    /// Watchdog-friendly table builder for embedded anti-klepto finalization.
    pub fn build_with_checkpoint(
        account_key: &ExtendedPrivKey,
        checkpoint: &mut (impl FnMut() + ?Sized),
    ) -> Self {
        let mut tbl = AddrPubkeyTable {
            entries: [(false, 0u16, [0u8; 32]); (ADDR_SCAN_DEPTH as usize) * 2],
            filled: 0,
        };
        for idx in 0..ADDR_SCAN_DEPTH {
            checkpoint();
            if let Ok(key) = derive_address_key(account_key, u32::from(idx)) {
                checkpoint();
                if let Ok(pk) = key.public_key_x_only() {
                    checkpoint();
                    tbl.entries[tbl.filled] = (false, idx, pk);
                    tbl.filled += 1;
                }
            }
        }
        for idx in 0..ADDR_SCAN_DEPTH {
            checkpoint();
            if let Ok(key) = derive_change_key(account_key, u32::from(idx)) {
                checkpoint();
                if let Ok(pk) = key.public_key_x_only() {
                    checkpoint();
                    tbl.entries[tbl.filled] = (true, idx, pk);
                    tbl.filled += 1;
                }
            }
        }
        tbl
    }

    /// Look up a target pubkey. O(n) linear scan over cached entries
    /// (n ≤ 40). Returns (idx, is_change) or None.
    pub fn find_by_pubkey(&self, target: &[u8; 32]) -> Option<(u16, bool)> {
        for e in &self.entries[..self.filled] {
            if &e.2 == target {
                return Some((e.1, e.0));
            }
        }
        None
    }
}
