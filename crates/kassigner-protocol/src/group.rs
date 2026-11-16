// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A multisig group as a KasSigner holds one: the threshold and the
//! cosigners' account keys, `m/45'/111111'/0'`, in cosigner order, enough to
//! show its addresses, write its descriptor and find the unit's position.
//! Public keys only.
//!
//! The rules are rusty-kaspa's (`create_account_multisig` and
//! `import_multisig_with_mnemonic`, `wallet/core/src/wallet/mod.rs`): keys
//! sorted as text under one prefix
//! ([`kassigner_kaspa::multisig::sort_cosigners`]); a key's cosigner index is
//! its place in that order ([`Group::position`]); an address derives every
//! key at one cosigner index, chain and index
//! ([`kassigner_kaspa::multisig::address_keys`]) into upstream's redeem
//! script. Only kpubs are taken, so the text sorts as upstream's; an `xpub`
//! or a `ktub` is refused ([`GroupError::NotAKpub`]), not converted.
//!
//! Stricter than upstream, never contrary: at most `N` keys, a device's
//! limit, and no key twice, by its public key whatever its text says, as its
//! holder could not tell which position is its own. [`repeated_key`] applies
//! that to a redeem script made elsewhere, where upstream's engine, never
//! comparing keys, counts the key twice toward M. A key's depth is not
//! checked, as upstream does not.
//!
//! Whether the unit's own key is in the group is the holder's to ask
//! ([`Group::position`]).

use kassigner_kaspa::address::{self, Prefix as Network, Version};
use kassigner_kaspa::bip32_public::{ExtendedPublicKey, Prefix};
use kassigner_kaspa::multisig::{
    address_keys, check_threshold, redeem_script, redeem_script_len, sort_cosigners, MultisigError,
    MAX_KEYS,
};
use kassigner_kaspa::script::{multisig_shape, redeem_hash};

use crate::descriptor::{self, DescriptorError, KPUB_STR_LEN};

/// The longest redeem script a group writes: [`MAX_KEYS`] keys.
pub const MAX_REDEEM: usize = redeem_script_len(MAX_KEYS, MAX_KEYS);

/// Why a group was not made, or an address or descriptor not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupError {
    /// The descriptor's text does not read, as [`descriptor::parse`] says.
    Descriptor(DescriptorError),
    /// The key at `index`, in cosigner order, is not a mainnet kpub: bad
    /// text or checksum, a key off the curve, or another prefix.
    NotAKpub { index: usize },
    /// The key at `index`, in cosigner order, has the public key of an
    /// earlier one.
    RepeatedKey { index: usize },
    /// More keys than the holder holds, or than the engine checks.
    TooManyKeys { found: usize, limit: usize },
    /// A threshold of zero: such a script is spent with no signature.
    NoThreshold,
    /// What the multisig rules refuse: no keys, a threshold above them, a
    /// derivation that fails, a buffer too small.
    Multisig(MultisigError),
    /// The caller's buffer is too small.
    BufferTooSmall,
}

impl From<DescriptorError> for GroupError {
    fn from(e: DescriptorError) -> Self {
        GroupError::Descriptor(e)
    }
}

impl From<MultisigError> for GroupError {
    fn from(e: MultisigError) -> Self {
        GroupError::Multisig(e)
    }
}

/// A multisig group of at most `N` keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group<const N: usize> {
    required: usize,
    total: usize,
    /// In cosigner order; past `total`, copies of the first, never read.
    keys: [ExtendedPublicKey; N],
}

impl<const N: usize> Group<N> {
    /// A group from a descriptor's text, `multi_hd45(M,<kpub>,...)`.
    ///
    /// # Errors
    ///
    /// `Descriptor` for text [`descriptor::parse`] refuses, more than `N`
    /// entries among it; `NotAKpub` and `RepeatedKey` for its keys.
    pub fn from_descriptor(text: &str) -> Result<Self, GroupError> {
        let mut entries = [""; N];
        let d = descriptor::parse(text, &mut entries)?;
        Self::from_sorted(d.m, &entries[..d.n])
    }

    /// A group from its threshold and its keys, in any order, as a unit
    /// collects them one at a time.
    ///
    /// # Errors
    ///
    /// `TooManyKeys` past `N` or the engine's [`MAX_KEYS`]; `NoThreshold`;
    /// `Multisig` for no keys or a threshold above them; `RepeatedKey`.
    pub fn new(required: usize, keys: &[ExtendedPublicKey]) -> Result<Self, GroupError> {
        let limit = N.min(MAX_KEYS);
        if keys.len() > limit {
            return Err(GroupError::TooManyKeys {
                found: keys.len(),
                limit,
            });
        }
        let mut texts = [[0u8; KPUB_STR_LEN]; N];
        for (text, key) in texts.iter_mut().zip(keys) {
            let n = key
                .to_text(Prefix::Kpub, text)
                .map_err(|_| GroupError::BufferTooSmall)?;
            if n != KPUB_STR_LEN {
                return Err(GroupError::BufferTooSmall);
            }
        }
        let mut sorted = [""; N];
        for (s, text) in sorted.iter_mut().zip(&texts[..keys.len()]) {
            *s = core::str::from_utf8(text).map_err(|_| GroupError::BufferTooSmall)?;
        }
        let sorted = &mut sorted[..keys.len()];
        sort_cosigners(sorted);
        Self::from_sorted(required, sorted)
    }

    /// The keys' texts already in cosigner order, decoded and checked.
    fn from_sorted(required: usize, texts: &[&str]) -> Result<Self, GroupError> {
        if required == 0 {
            return Err(GroupError::NoThreshold);
        }
        check_threshold(required, texts.len())?;
        let mut keys = [first_key(texts)?; N];
        for (index, (slot, text)) in keys.iter_mut().zip(texts).enumerate() {
            *slot = kpub(text).ok_or(GroupError::NotAKpub { index })?;
        }
        // Two texts of one key can differ in its parent or child number and
        // need not sort side by side, so every pair is compared.
        for i in 1..texts.len() {
            if keys[..i].iter().any(|k| k.public_key == keys[i].public_key) {
                return Err(GroupError::RepeatedKey { index: i });
            }
        }
        Ok(Self {
            required,
            total: texts.len(),
            keys,
        })
    }

    /// Signatures the group needs.
    pub const fn required(&self) -> usize {
        self.required
    }

    /// Keys in the group.
    pub const fn total(&self) -> usize {
        self.total
    }

    /// The keys, in cosigner order.
    pub fn keys(&self) -> &[ExtendedPublicKey] {
        &self.keys[..self.total]
    }

    /// The cosigner index upstream gives `account`, found by the whole
    /// extended key as upstream finds its text; `None` if not in the group.
    pub fn position(&self, account: &ExtendedPublicKey) -> Option<usize> {
        self.keys().iter().position(|k| k == account)
    }

    /// The redeem script of the address at `cosigner`, `chain`, `index`, into
    /// `out`; returns its length. `cosigner` is the branch: whose index every
    /// key is derived at.
    ///
    /// # Errors
    ///
    /// `Multisig` for a derivation that fails, a hardened number among
    /// them, or an `out` too small.
    pub fn redeem(
        &self,
        cosigner: u32,
        chain: u32,
        index: u32,
        out: &mut [u8],
    ) -> Result<usize, GroupError> {
        let mut xs = [[0u8; 32]; MAX_KEYS];
        let n = address_keys(self.keys(), cosigner, chain, index, &mut xs)?;
        Ok(redeem_script(self.required, &xs[..n], out)?)
    }

    /// The address at `cosigner`, `chain`, `index`, on `network`, as text
    /// into `out`; returns its length.
    ///
    /// # Errors
    ///
    /// As [`Group::redeem`]; `BufferTooSmall` for an `out` too small for the
    /// address.
    pub fn address(
        &self,
        network: Network,
        cosigner: u32,
        chain: u32,
        index: u32,
        out: &mut [u8],
    ) -> Result<usize, GroupError> {
        let mut script = [0u8; MAX_REDEEM];
        let n = self.redeem(cosigner, chain, index, &mut script)?;
        script_address(network, &script[..n], out)
    }

    /// [`Group::address`] for a holder that derives only the last step:
    /// `keys` already derived to one cosigner, chain and index, the first
    /// [`Group::total`] used, x-only, in cosigner order, as
    /// [`kassigner_kaspa::multisig::address_keys`] writes them.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall` for an `out` too small for the address.
    pub fn address_of_keys(
        &self,
        network: Network,
        keys: &[[u8; 32]; N],
        out: &mut [u8],
    ) -> Result<usize, GroupError> {
        let mut script = [0u8; MAX_REDEEM];
        let n = redeem_script(self.required, &keys[..self.total], &mut script)?;
        script_address(network, &script[..n], out)
    }

    /// The group's descriptor, `multi_hd45(M,<kpub>,...)`, keys in cosigner
    /// order, into `out`; returns its length. [`descriptor::max_len`] of the
    /// key count is always enough.
    ///
    /// # Errors
    ///
    /// `Descriptor` for an `out` too small.
    pub fn write_descriptor(&self, out: &mut [u8]) -> Result<usize, GroupError> {
        let mut texts = [[0u8; KPUB_STR_LEN]; N];
        let mut entries = [""; N];
        for ((text, entry), key) in texts.iter_mut().zip(entries.iter_mut()).zip(self.keys()) {
            key.to_text(Prefix::Kpub, text)
                .map_err(|_| GroupError::BufferTooSmall)?;
            *entry = core::str::from_utf8(text).map_err(|_| GroupError::BufferTooSmall)?;
        }
        Ok(descriptor::write(
            self.required,
            &entries[..self.total],
            out,
        )?)
    }
}

/// The place in a multisig redeem script of the first key that repeats an
/// earlier one; `None` if all differ or the script is not a multisig.
///
/// [`GroupError::RepeatedKey`]'s rule for a script made elsewhere, which a
/// unit refuses to sign: its M of N counts the key twice, and a bundle,
/// keeping one signature a public key, cannot carry both. Every pair is
/// compared, since such a script need not be in order.
pub fn repeated_key(redeem: &[u8]) -> Option<usize> {
    let ms = multisig_shape(redeem)?;
    let found = ms
        .keys()
        .enumerate()
        .skip(1)
        .find(|&(i, key)| ms.keys().take(i).any(|earlier| earlier == key));
    found.map(|(i, _)| i)
}

/// A kpub's key: `None` for text that is not one, or one with another
/// prefix.
fn kpub(text: &str) -> Option<ExtendedPublicKey> {
    match ExtendedPublicKey::from_text(text.as_bytes()) {
        Ok((Prefix::Kpub, key)) => Some(key),
        _ => None,
    }
}

/// The first text's key, to fill a group's array with before the rest.
fn first_key(texts: &[&str]) -> Result<ExtendedPublicKey, GroupError> {
    let first = texts.first().ok_or(MultisigError::NoKeys)?;
    kpub(first).ok_or(GroupError::NotAKpub { index: 0 })
}

/// A redeem script's pay-to-script-hash address on `network`, as text into
/// `out`; returns its length. Every address a group writes is made here.
fn script_address(network: Network, script: &[u8], out: &mut [u8]) -> Result<usize, GroupError> {
    address::encode(network, Version::ScriptHash, &redeem_hash(script), out)
        .map_err(|_| GroupError::BufferTooSmall)
}
