// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Covenant cards: made, backed up, and found in an account.
//!
//! One card so far, Time-Locked Savings: UTXOs locked until a chosen minute,
//! then claimed by the owner or recovered by the recovery wallet, if any. The
//! card is its program (`kassigner_protocol::card::savings`).
//!
//! 1. Make it, [`savings`], from the owner's `kaspa:q` address, the recovery
//!    wallet's if any (`44'` receive addresses, for a unit to sign), and a UTC
//!    minute; send UTXOs to its [`address()`].
//! 2. Back it up as one line, [`backup`], which rebuilds it ([`read_backup`]);
//!    the address alone does not.
//! 3. Spend it as [`Source::Card`] coins with a lock time at or past that
//!    minute; [`signer`] finds the account's key.
//!
//! [`Source::Card`]: crate::request::Source::Card

use kassigner_kaspa::address::{self, AddressError, Version};
use kassigner_kaspa::bip340::PUBLIC_KEY_SIZE;

use crate::watch::{self, Account, WatchError, RECEIVE};
use crate::Network;

pub use kassigner_protocol::card::backup::{BackupError, MAX_LEN as BACKUP_MAX_LEN};
pub use kassigner_protocol::card::savings::{
    CardError, Entry, Savings, UnlockAt, PROGRAM_LEN, SIGNATURE_SCRIPT_LEN, SIG_LEN, SIG_OP_COUNT,
};

/// Why an address was not taken as a card's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Text that is not an address.
    NotAnAddress(AddressError),
    /// An address off mainnet, the one network of a card.
    NotMainnet(Network),
    /// Not a Schnorr key's address (`kaspa:q…`): a script's or an ECDSA key's.
    NotAKey,
}

/// Why a card was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MakeError {
    /// The owner's address, as [`KeyError`] says.
    Owner(KeyError),
    /// The recovery wallet's address, as [`KeyError`] says.
    Recovery(KeyError),
    /// A day or time that does not exist, or a minute before the first a card
    /// can unlock at.
    Date,
    /// A key that is no BIP340 public key, which could never sign.
    Card(CardError),
}

/// The key a mainnet Schnorr address carries.
fn key_of(text: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], KeyError> {
    let mut payload = [0u8; 33];
    let (network, version, n) =
        address::decode(text.trim_ascii(), &mut payload).map_err(KeyError::NotAnAddress)?;
    if network != Network::Mainnet {
        return Err(KeyError::NotMainnet(network));
    }
    match (version, n) {
        (Version::PubKey, PUBLIC_KEY_SIZE) => {
            let mut key = [0u8; PUBLIC_KEY_SIZE];
            key.copy_from_slice(&payload[..PUBLIC_KEY_SIZE]);
            Ok(key)
        }
        _ => Err(KeyError::NotAKey),
    }
}

/// A Time-Locked Savings card: `owner`, the `kaspa:q` address of the key that
/// claims it; `recovery`, that of the key that may recover it instead, or
/// `None` (the owner's own counts as none); unlocking at `hour`:`minute` UTC on
/// `day`/`month`/`year`.
///
/// # Errors
///
/// `Owner` or `Recovery` as [`KeyError`]; `Date`; `Card`.
pub fn savings(
    owner: &[u8],
    recovery: Option<&[u8]>,
    day: u8,
    month: u8,
    year: u32,
    hour: u8,
    minute: u8,
) -> Result<Savings, MakeError> {
    let owner = key_of(owner).map_err(MakeError::Owner)?;
    let recovery = recovery
        .map(key_of)
        .transpose()
        .map_err(MakeError::Recovery)?;
    let unlock = UnlockAt::from_date_time(year, month, day, hour, minute).ok_or(MakeError::Date)?;
    Savings::new(owner, recovery, unlock).map_err(MakeError::Card)
}

/// `card`'s address, `kaspa:p…`, as text into `out`: its length.
///
/// # Errors
///
/// `BufferTooSmall` for a short `out`
/// ([`kassigner_kaspa::address::MAX_ADDRESS_LEN`] always fits).
pub fn address(card: &Savings, out: &mut [u8]) -> Result<usize, WatchError> {
    card.address(out).map_err(|_| WatchError::BufferTooSmall)
}

/// `card`'s backup line into `out`: its length.
///
/// # Errors
///
/// `BufferTooSmall` for a short `out`; [`BACKUP_MAX_LEN`] always fits.
pub fn backup(card: &Savings, out: &mut [u8]) -> Result<usize, BackupError> {
    kassigner_protocol::card::backup::write(card, out)
}

/// The card whose backup is `line`, exactly as [`backup`] writes it, whitespace
/// at its ends aside.
///
/// # Errors
///
/// The first [`BackupError`] found.
pub fn read_backup(line: &[u8]) -> Result<Savings, BackupError> {
    kassigner_protocol::card::backup::read(line)
}

/// Which of `account`'s first `depth` receive keys is `card`'s, and its entry:
/// [`Entry::Claim`] for the owner's (first if both), [`Entry::Recover`] for the
/// recovery wallet's. `None` for neither: the unit searches.
///
/// # Errors
///
/// As [`Account::public_key`].
pub fn signer(
    account: &Account,
    card: &Savings,
    depth: u32,
) -> Result<Option<(u32, Entry)>, WatchError> {
    let mut recovery = None;
    for index in 0..depth {
        let key = account.public_key(RECEIVE, index)?;
        if key == *card.owner() {
            return Ok(Some((index, Entry::Claim)));
        }
        if recovery.is_none() && card.recovery() == Some(&key) {
            recovery = Some((index, Entry::Recover));
        }
    }
    Ok(recovery)
}

/// Whether `account`'s receive key `index` is one of `card`'s.
///
/// # Errors
///
/// As [`Account::public_key`].
pub(crate) fn holds(account: &Account, card: &Savings, index: u32) -> Result<bool, WatchError> {
    let key = account.public_key(RECEIVE, index)?;
    Ok(key == *card.owner() || card.recovery() == Some(&key))
}

// A card's program fits where a request holds a redeem script.
const _: () = assert!(PROGRAM_LEN <= watch::MAX_REDEEM);
