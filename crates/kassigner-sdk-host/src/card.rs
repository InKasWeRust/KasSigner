// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A covenant card, Time-Locked Savings: [`kassigner_sdk::card`] over owned
//! values.
//!
//! A card's UTXOs are spent with
//! [`crate::request::RequestBuilder::spend_card`] under a lock time on or
//! after [`Card::unlock_ms`].

use kassigner_kaspa::address::{self, Prefix, Version, MAX_ADDRESS_LEN};
use kassigner_sdk::card::{self, Entry, Savings, BACKUP_MAX_LEN};

use crate::watch::Account;
use crate::Fault;

/// A Time-Locked Savings card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Card {
    inner: Savings,
}

/// Which of an account's receive keys is a card's, and which entry it
/// spends by ([`Card::signer`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardSigner {
    /// The receive index.
    pub index: u32,
    /// Whether the key is the recovery wallet's rather than the owner's.
    pub recovers: bool,
}

/// A key as its mainnet Schnorr address.
fn key_address(key: &[u8; 32]) -> Result<String, Fault> {
    let mut text = [0u8; MAX_ADDRESS_LEN];
    let n = address::encode(Prefix::Mainnet, Version::PubKey, key, &mut text).map_err(Fault::of)?;
    Ok(crate::watch::text(&text[..n]))
}

impl Card {
    /// The card whose owner's key is at `owner`, a `kaspa:q` address, and
    /// recovery wallet's key at `recovery`, if any, unlocking on
    /// `day`/`month`/`year` at `hour`:`minute` UTC, a 24-hour clock.
    ///
    /// # Errors
    ///
    /// The SDK's `MakeError`: `Owner(..)` or `Recovery(..)` for an address
    /// that is not a mainnet Schnorr key's; `Date` for a day or time of day
    /// that is not one, or a minute before the first a card can unlock at;
    /// `Card(..)` for a key that is not a valid BIP340 public key.
    pub fn savings(
        owner: &str,
        recovery: Option<&str>,
        day: u32,
        month: u32,
        year: u32,
        hour: u32,
        minute: u32,
    ) -> Result<Card, Fault> {
        let (Ok(day), Ok(month), Ok(hour), Ok(minute)) = (
            u8::try_from(day),
            u8::try_from(month),
            u8::try_from(hour),
            u8::try_from(minute),
        ) else {
            return Err(Fault::of(card::MakeError::Date));
        };
        let inner = card::savings(
            owner.as_bytes(),
            recovery.map(str::as_bytes),
            day,
            month,
            year,
            hour,
            minute,
        )
        .map_err(Fault::of)?;
        Ok(Card { inner })
    }

    /// The card `line` is the backup of.
    ///
    /// # Errors
    ///
    /// The SDK's `BackupError` for the first thing wrong.
    pub fn from_backup(line: &str) -> Result<Card, Fault> {
        let inner = card::read_backup(line.as_bytes()).map_err(Fault::of)?;
        Ok(Card { inner })
    }

    /// The SDK's card.
    pub const fn inner(&self) -> &Savings {
        &self.inner
    }

    /// Its address, `kaspa:p…`, where UTXOs are sent to be locked.
    pub fn address(&self) -> Result<String, Fault> {
        let mut text = [0u8; MAX_ADDRESS_LEN];
        let n = card::address(&self.inner, &mut text).map_err(Fault::of)?;
        Ok(crate::watch::text(&text[..n]))
    }

    /// Its locking script, to match UTXOs against.
    pub fn script(&self) -> Vec<u8> {
        self.inner.locking_script().to_vec()
    }

    /// Its backup line, `savings_v1(...)`, to show as a QR code and keep.
    pub fn backup(&self) -> Result<String, Fault> {
        let mut line = [0u8; BACKUP_MAX_LEN];
        let n = card::backup(&self.inner, &mut line).map_err(Fault::of)?;
        Ok(crate::watch::text(&line[..n]))
    }

    /// The owner's key, as its `kaspa:q` address.
    pub fn owner(&self) -> Result<String, Fault> {
        key_address(self.inner.owner())
    }

    /// The recovery wallet's key, as its `kaspa:q` address, if any.
    pub fn recovery(&self) -> Result<Option<String>, Fault> {
        self.inner.recovery().map(key_address).transpose()
    }

    /// When it unlocks, in Unix milliseconds: the least lock time a spend
    /// is built under ([`crate::request::RequestBuilder::lock_until`]).
    pub fn unlock_ms(&self) -> u64 {
        self.inner.unlock().ms()
    }

    /// The day it unlocks on, 1 to 31.
    pub fn unlock_day(&self) -> u32 {
        u32::from(self.inner.unlock().date().2)
    }

    /// The month it unlocks in, 1 to 12.
    pub fn unlock_month(&self) -> u32 {
        u32::from(self.inner.unlock().date().1)
    }

    /// The year it unlocks in.
    pub fn unlock_year(&self) -> u32 {
        self.inner.unlock().date().0
    }

    /// The hour it unlocks at, UTC, 0 to 23.
    pub fn unlock_hour(&self) -> u32 {
        u32::from(self.inner.unlock().time().0)
    }

    /// The minute of that hour, 0 to 59.
    pub fn unlock_minute(&self) -> u32 {
        u32::from(self.inner.unlock().time().1)
    }

    /// Which of `account`'s first `depth` receive keys is this card's, the
    /// owner's if the account holds both; none for neither.
    ///
    /// # Errors
    ///
    /// `Derivation(..)` for an index BIP32 says to skip.
    pub fn signer(&self, account: &Account, depth: u32) -> Result<Option<CardSigner>, Fault> {
        let found = card::signer(account.inner(), &self.inner, depth).map_err(Fault::of)?;
        Ok(found.map(|(index, entry)| CardSigner {
            index,
            recovers: entry == Entry::Recover,
        }))
    }
}
