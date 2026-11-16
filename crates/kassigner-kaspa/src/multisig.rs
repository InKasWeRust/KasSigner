// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Kaspa multisig: key ordering, cosigner index, redeem script (upstream:
//! `create_account_multisig` in `wallet/core/src/wallet/mod.rs`,
//! `multisig_redeem_script` in `crypto/txscript/src/standard/multisig.rs`).
//! Cited by name, as lines move between releases.
//!
//! Multisig is 45', with a cosigner level. There is no 44' multisig: BIP44
//! has no level to say which slot in the key set is yours.
//!
//! Upstream sorts the base58 key strings and finds the cosigner index by a
//! binary search in them, so the sorted position picks the path, the address
//! and what the redeem script commits to. Consensus does not check the order;
//! it is the wallet's rule, and a cosigner keeping a typed order would derive
//! the wrong key and a different address. The sort compares the encodings'
//! bytes, not decoded keys, so `Z` sorts before `t`.
//!
//! An address derives every key at the same cosigner index, chain and index,
//! and the redeem script takes them in the group's order, not sorted again:
//! [`address_keys`] (upstream: `WalletDerivationManager::derive_public_key`,
//! `create_multisig_address`).
//!
//! As upstream, the sort refuses nothing (an empty group, a repeated key),
//! and the builder only an empty key set and a threshold above the count: a
//! threshold of zero and a count past the engine's limit are built. Group
//! policy is decided above this crate.

/// Most keys a multisig check accepts (upstream: `MAX_PUB_KEYS_PER_MUTLTISIG`,
/// `crypto/txscript/src/lib.rs`).
pub const MAX_KEYS: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultisigError {
    /// No keys. Upstream: `Error::EmptyKeys`.
    NoKeys,
    /// The threshold exceeds the number of keys. Upstream:
    /// `Error::ErrTooManyRequiredSigs`.
    ThresholdAboveKeys { m: usize, n: usize },
    /// The caller's buffer is too small.
    BufferTooSmall,
    /// The caller's own key is not in the group.
    NotAParticipant,
    /// Deriving a cosigner key failed: a hardened number, or no valid key.
    Derivation(Bip32Error),
}

use crate::bip32_public::{Bip32Error, ChildNumber, ExtendedPublicKey};

/// Sort key strings into cosigner order in place: index `i` is then cosigner
/// `i`. Bytes compared, as upstream's `sort_unstable`; an insertion sort, as
/// there is no allocator.
pub fn sort_cosigners(keys: &mut [&str]) {
    for i in 1..keys.len() {
        let mut j = i;
        while j > 0 && keys[j - 1] > keys[j] {
            keys.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// Cosigner index of `mine` within an already-sorted group.
///
/// # Errors
///
/// `NotAParticipant` if the key is not in the group: the key exported is not
/// the one the group was built with, and retrying will not help.
pub fn cosigner_index(sorted: &[&str], mine: &str) -> Result<usize, MultisigError> {
    sorted
        .iter()
        .position(|k| *k == mine)
        .ok_or(MultisigError::NotAParticipant)
}

/// The x-only keys of one address of a group, into `out`: each of
/// `cosigners`, in cosigner order, derived at `cosigner/chain/index`, not
/// sorted after, as [`redeem_script`] takes them. Returns how many.
///
/// # Errors
///
/// `BufferTooSmall` when `out` is short, `Derivation` when a step fails (a
/// hardened number among them).
pub fn address_keys(
    cosigners: &[ExtendedPublicKey],
    cosigner: u32,
    chain: u32,
    index: u32,
    out: &mut [[u8; 32]],
) -> Result<usize, MultisigError> {
    let out = out
        .get_mut(..cosigners.len())
        .ok_or(MultisigError::BufferTooSmall)?;
    for (slot, parent) in out.iter_mut().zip(cosigners) {
        let child = parent
            .derive_child(ChildNumber(cosigner))
            .and_then(|k| k.derive_child(ChildNumber(chain)))
            .and_then(|k| k.derive_child(ChildNumber(index)))
            .map_err(MultisigError::Derivation)?;
        // The compressed key's x coordinate: drop the parity byte.
        slot.copy_from_slice(&child.public_key[1..33]);
    }
    Ok(cosigners.len())
}

/// Check a threshold against a key count as upstream's builder does.
///
/// # Errors
///
/// `NoKeys` for no keys, `ThresholdAboveKeys` when `m` exceeds `n`.
pub const fn check_threshold(m: usize, n: usize) -> Result<(), MultisigError> {
    if n == 0 {
        return Err(MultisigError::NoKeys);
    }
    if m > n {
        return Err(MultisigError::ThresholdAboveKeys { m, n });
    }
    Ok(())
}

/// Bytes of the minimal little-endian script number for `v` (upstream:
/// `serialize_i64`).
const fn number_bytes(v: usize) -> usize {
    let mut n = 0usize;
    let mut rest = v;
    let mut top = 0usize;
    while rest != 0 {
        top = rest & 0xff;
        rest >>= 8;
        n += 1;
    }
    // A set top bit would read as a sign, so a zero byte follows it.
    if top & 0x80 != 0 {
        n += 1;
    }
    n
}

/// Bytes of `v` as `ScriptBuilder::add_i64` writes it: one opcode for 0 to
/// 16, else a push of its script number.
const fn number_len(v: usize) -> usize {
    if v <= 16 {
        1
    } else {
        1 + number_bytes(v)
    }
}

/// Write `v` as `add_i64` does. `out` must hold [`number_len`] of it.
fn write_number(v: usize, out: &mut [u8]) -> usize {
    if v == 0 {
        out[0] = 0x00; // OP_0
        return 1;
    }
    if v <= 16 {
        out[0] = 0x50 + v as u8; // OP_1 through OP_16
        return 1;
    }
    let n = number_bytes(v);
    out[0] = n as u8; // OP_DATA_n: a script number is never 76 bytes
    let mut rest = v;
    for b in out[1..=n].iter_mut() {
        *b = (rest & 0xff) as u8;
        rest >>= 8;
    }
    1 + n
}

/// Bytes a redeem script for `n` Schnorr keys and threshold `m` occupies.
pub const fn redeem_script_len(m: usize, n: usize) -> usize {
    // The threshold, n pushes of (1 + 32), the key count, OP_CHECKMULTISIG.
    number_len(m) + n * 33 + number_len(n) + 1
}

/// Build a multisig redeem script over x-only keys, already in cosigner
/// order: the sort is over the base58 strings, gone by now. Sort with
/// [`sort_cosigners`], derive, then build.
///
/// # Errors
///
/// What [`check_threshold`] refuses, or `BufferTooSmall`.
pub fn redeem_script(m: usize, keys: &[[u8; 32]], out: &mut [u8]) -> Result<usize, MultisigError> {
    let n = keys.len();
    check_threshold(m, n)?;
    let total = redeem_script_len(m, n);
    let out = out.get_mut(..total).ok_or(MultisigError::BufferTooSmall)?;
    let mut w = write_number(m, out);
    for k in keys {
        out[w] = 0x20; // OP_DATA_32
        out[w + 1..w + 33].copy_from_slice(k);
        w += 33;
    }
    w += write_number(n, &mut out[w..]);
    out[w] = 0xae; // OP_CHECKMULTISIG
    Ok(w + 1)
}
