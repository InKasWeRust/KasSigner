// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A covenant card: [`kassigner_sdk_host::card`] over the C ABI.

use kassigner_sdk_host::card as host;

use crate::watch::Account;
use crate::Fault;

/// A Time-Locked Savings card: UTXOs locked until its unlock time, then
/// spendable by its owner or, if it has one, its recovery wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Object)]
pub struct Card {
    inner: host::Card,
}

/// Which of an account's receive keys is a card's, and whether it
/// recovers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CardSigner {
    /// The receive index.
    pub index: u32,
    /// Whether it is the recovery wallet's key; otherwise the owner's.
    pub recovers: bool,
}

#[uniffi::export]
impl Card {
    /// The card of `owner`, the `kaspa:q` address of the key that claims
    /// it, and `recovery`, that of the key that may recover it, if any;
    /// unlocking on `day`/`month`/`year` at `hour`:`minute` UTC (24-hour).
    ///
    /// # Errors
    ///
    /// `Owner(..)` or `Recovery(..)` for an address that is not a mainnet
    /// Schnorr key's; `Date` for a date or time that does not exist or is
    /// before the first a card can unlock at; `Card(..)` for a key that is
    /// not a BIP340 public key.
    #[uniffi::constructor]
    pub fn savings(
        owner: String,
        recovery: Option<String>,
        day: u32,
        month: u32,
        year: u32,
        hour: u32,
        minute: u32,
    ) -> Result<Card, Fault> {
        Ok(Card {
            inner: host::Card::savings(
                &owner,
                recovery.as_deref(),
                day,
                month,
                year,
                hour,
                minute,
            )?,
        })
    }

    /// The card `line` is the backup of.
    ///
    /// # Errors
    ///
    /// The first thing wrong with the line.
    #[uniffi::constructor]
    pub fn from_backup(line: String) -> Result<Card, Fault> {
        Ok(Card {
            inner: host::Card::from_backup(&line)?,
        })
    }

    /// Its address, `kaspa:p…`, where UTXOs are sent to be locked.
    pub fn address(&self) -> Result<String, Fault> {
        Ok(self.inner.address()?)
    }

    /// Its locking script, to match UTXOs against.
    pub fn script(&self) -> Vec<u8> {
        self.inner.script()
    }

    /// Its backup line, `savings_v1(...)`, to keep and show as a QR code.
    pub fn backup(&self) -> Result<String, Fault> {
        Ok(self.inner.backup()?)
    }

    /// The owner's key, as its `kaspa:q` address.
    pub fn owner(&self) -> Result<String, Fault> {
        Ok(self.inner.owner()?)
    }

    /// The recovery wallet's key, as its `kaspa:q` address, or none.
    pub fn recovery(&self) -> Result<Option<String>, Fault> {
        Ok(self.inner.recovery()?)
    }

    /// The moment it unlocks, Unix time in milliseconds: the least lock
    /// time a claim or recovery is built under (`lock_until`).
    pub fn unlock_ms(&self) -> u64 {
        self.inner.unlock_ms()
    }

    /// The day it unlocks on, 1 to 31.
    pub fn unlock_day(&self) -> u32 {
        self.inner.unlock_day()
    }

    /// The month it unlocks in, 1 to 12.
    pub fn unlock_month(&self) -> u32 {
        self.inner.unlock_month()
    }

    /// The year it unlocks in.
    pub fn unlock_year(&self) -> u32 {
        self.inner.unlock_year()
    }

    /// The hour it unlocks at, UTC, 0 to 23.
    pub fn unlock_hour(&self) -> u32 {
        self.inner.unlock_hour()
    }

    /// The minute of that hour, 0 to 59.
    pub fn unlock_minute(&self) -> u32 {
        self.inner.unlock_minute()
    }

    /// Which of `account`'s first `depth` receive keys is this card's, the
    /// owner's if the account holds both; none if it holds neither, for the
    /// unit to search.
    ///
    /// # Errors
    ///
    /// An index BIP32 says to skip.
    pub fn signer(&self, account: &Account, depth: u32) -> Result<Option<CardSigner>, Fault> {
        Ok(self
            .inner
            .signer(account.inner(), depth)?
            .map(|s| CardSigner {
                index: s.index,
                recovers: s.recovers,
            }))
    }
}

impl Card {
    /// The host crate's card.
    pub const fn inner(&self) -> &host::Card {
        &self.inner
    }
}
