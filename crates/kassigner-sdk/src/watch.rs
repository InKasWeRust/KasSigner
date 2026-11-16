// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What an app watches, derived as a unit derives it:
//!
//! - An [`Account`], a `44'` kpub: receive and change chains of
//!   pay-to-public-key addresses.
//! - A [`Group`], a `45'` multisig: the same chains under each cosigner index,
//!   paying to its redeem script's hash.
//! - A [`Kcc3Address`], a `22'` address held as text. Under KCC-3 a leaked kpub
//!   exposes every key, so a unit exports none, and the address is spent whole.
//!
//! A unit knows its first [`RECEIVE_DEPTH`] receive and [`CHANGE_DEPTH`] change
//! keys and searches up to [`SEARCH_DEPTH`] for an input with no derivation; an
//! app watching past those first keys writes the derivation in each request.
//!
//! Mainnet only: a unit shows every address as `kaspa:`, so one from another
//! network is [`WatchError::NotMainnet`]. Nothing is cached.

use kassigner_kaspa::address::{self, AddressError, Version, MAX_ADDRESS_LEN};
use kassigner_kaspa::bip32_public::{Bip32Error, ChildNumber, ExtendedPublicKey};
use kassigner_kaspa::script::{
    address_payload, pay_to_pubkey, pay_to_script_hash, redeem_hash, PAY_TO_PUBKEY_LEN,
    PAY_TO_SCRIPT_HASH_LEN,
};
use kassigner_kaspa::tx::ScriptPublicKey;
use kassigner_protocol::check::MAX_MULTISIG_KEYS;
use kassigner_protocol::group::{self, GroupError};

use crate::Network;

pub use kassigner_kaspa::derivation::{CHANGE, RECEIVE};
pub use kassigner_protocol::check::{CHANGE_DEPTH, RECEIVE_DEPTH, SEARCH_BATCH, SEARCH_DEPTH};

/// A multisig group of at most [`MAX_MULTISIG_KEYS`] keys, the most a unit
/// signs.
pub type Group = group::Group<MAX_MULTISIG_KEYS>;

/// The longest redeem script of a [`Group`].
pub const MAX_REDEEM: usize = group::MAX_REDEEM;

/// Why something could not be watched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchError {
    /// A child could not be derived: a hardened index, or one BIP32 skips.
    Derivation(Bip32Error),
    /// The group refused: a hardened cosigner, chain or index, or one BIP32
    /// skips. Any other cosigner index is valid, as upstream allows.
    Group(GroupError),
    /// Text that is not an address.
    NotAnAddress(AddressError),
    /// An address off mainnet, the one network a unit signs for: the network it
    /// names.
    NotMainnet(Network),
    /// An address of the wrong kind (a key's for a `22'` address, an ECDSA
    /// key's for a payment), or a script that pays no address.
    NotScriptHash,
    /// The caller's buffer cannot hold the result.
    BufferTooSmall,
}

impl From<Bip32Error> for WatchError {
    fn from(e: Bip32Error) -> Self {
        WatchError::Derivation(e)
    }
}

impl From<GroupError> for WatchError {
    fn from(e: GroupError) -> Self {
        WatchError::Group(e)
    }
}

/// `Ok` for mainnet.
///
/// # Errors
///
/// `NotMainnet` for any other.
pub(crate) const fn mainnet(network: Network) -> Result<(), WatchError> {
    match network {
        Network::Mainnet => Ok(()),
        other => Err(WatchError::NotMainnet(other)),
    }
}

/// The mainnet address a version-0 locking script pays, as text into `out`: its
/// length. The inverse of [`crate::request::script_of_address`].
///
/// # Errors
///
/// `NotScriptHash` for a script that is not a key's or a script hash's, such as
/// a covenant's; `BufferTooSmall` for a short `out` ([`MAX_ADDRESS_LEN`] always
/// fits).
pub fn address_of_script(script: &[u8], out: &mut [u8]) -> Result<usize, WatchError> {
    let spk = ScriptPublicKey { version: 0, script };
    let (version, payload) = address_payload(&spk).ok_or(WatchError::NotScriptHash)?;
    address::encode(Network::Mainnet, version, payload, out).map_err(|_| WatchError::BufferTooSmall)
}

// ── A 44' account ───────────────────────────────────────────────────────────

/// A `44'` account, `m/44'/111111'/0'`, watched through the kpub a unit
/// exports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    key: ExtendedPublicKey,
}

impl Account {
    /// The account of `key`, a kpub a unit exported.
    pub const fn new(key: ExtendedPublicKey) -> Self {
        Account { key }
    }

    /// The kpub.
    pub const fn key(&self) -> &ExtendedPublicKey {
        &self.key
    }

    /// The x-only key at `chain`/`index`, which a pay-to-public-key script
    /// holds.
    ///
    /// # Errors
    ///
    /// `Derivation` for a hardened chain or index, or one BIP32 skips.
    pub fn public_key(&self, chain: u32, index: u32) -> Result<[u8; 32], WatchError> {
        let child = self
            .key
            .derive_child(ChildNumber(chain))?
            .derive_child(ChildNumber(index))?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&child.public_key[1..]);
        Ok(x)
    }

    /// The locking script of `chain`/`index`, to match a UTXO against.
    ///
    /// # Errors
    ///
    /// As [`Account::public_key`].
    pub fn script(&self, chain: u32, index: u32) -> Result<[u8; PAY_TO_PUBKEY_LEN], WatchError> {
        Ok(pay_to_pubkey(&self.public_key(chain, index)?))
    }

    /// The mainnet address of `chain`/`index`, as text into `out`: its length.
    ///
    /// # Errors
    ///
    /// As [`Account::public_key`]; `BufferTooSmall` for a short `out`
    /// ([`MAX_ADDRESS_LEN`] always fits).
    pub fn address(&self, chain: u32, index: u32, out: &mut [u8]) -> Result<usize, WatchError> {
        let key = self.public_key(chain, index)?;
        address::encode(Network::Mainnet, Version::PubKey, &key, out)
            .map_err(|_| WatchError::BufferTooSmall)
    }
}

// ── A 45' group ─────────────────────────────────────────────────────────────

/// The locking script of a group's `cosigner`/`chain`/`index`: its redeem
/// script's hash.
///
/// # Errors
///
/// `Group` for a hardened level, or a child BIP32 skips.
pub fn group_script(
    group: &Group,
    cosigner: u32,
    chain: u32,
    index: u32,
) -> Result<[u8; PAY_TO_SCRIPT_HASH_LEN], WatchError> {
    let mut redeem = [0u8; MAX_REDEEM];
    let n = group.redeem(cosigner, chain, index, &mut redeem)?;
    Ok(pay_to_script_hash(&redeem_hash(&redeem[..n])))
}

/// The mainnet address of a group's `cosigner`/`chain`/`index`, as text into
/// `out`: its length.
///
/// # Errors
///
/// As [`group_script`]; `BufferTooSmall` for a short `out` ([`MAX_ADDRESS_LEN`]
/// always fits).
pub fn group_address(
    group: &Group,
    cosigner: u32,
    chain: u32,
    index: u32,
    out: &mut [u8],
) -> Result<usize, WatchError> {
    group
        .address(Network::Mainnet, cosigner, chain, index, out)
        .map_err(|e| match e {
            GroupError::BufferTooSmall => WatchError::BufferTooSmall,
            other => WatchError::Group(other),
        })
}

// ── A 22' address ───────────────────────────────────────────────────────────

/// A `22'` address a unit made: its text and script hash, all an app knows of a
/// `22'` account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc3Address {
    text: [u8; MAX_ADDRESS_LEN],
    len: usize,
    hash: [u8; 32],
}

impl Kcc3Address {
    /// `text`, trimmed, as a `22'` address. Any mainnet script-hash address
    /// reads: the text cannot tell what is behind the hash.
    ///
    /// # Errors
    ///
    /// `NotAnAddress`; `NotMainnet`; `NotScriptHash` for a key's address.
    pub fn read(text: &[u8]) -> Result<Self, WatchError> {
        let text = text.trim_ascii();
        let mut payload = [0u8; 33];
        let (network, version, n) =
            address::decode(text, &mut payload).map_err(WatchError::NotAnAddress)?;
        mainnet(network)?;
        if version != Version::ScriptHash || n != 32 || text.len() > MAX_ADDRESS_LEN {
            return Err(WatchError::NotScriptHash);
        }
        let mut held = [0u8; MAX_ADDRESS_LEN];
        held[..text.len()].copy_from_slice(text);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&payload[..32]);
        Ok(Kcc3Address {
            text: held,
            len: text.len(),
            hash,
        })
    }

    /// The address as text.
    pub fn text(&self) -> &[u8] {
        &self.text[..self.len]
    }

    /// The script hash the address carries.
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The locking script an output paying it carries.
    pub const fn script(&self) -> [u8; PAY_TO_SCRIPT_HASH_LEN] {
        pay_to_script_hash(&self.hash)
    }
}
