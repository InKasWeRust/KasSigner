// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A covenant card (cov++): [`kassigner_sdk_host::card`] for JavaScript.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::card as host;

use crate::watch::Account;
use crate::Fault;

/// A Time-Locked Savings card: UTXOs locked until its unlock time, then
/// claimed by its owner or recovered by its recovery wallet, if it has one.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Card {
    inner: host::Card,
}

#[wasm_bindgen]
impl Card {
    /// The card of `owner`, the claiming key's `kaspa:q` address, and
    /// `recovery`, the recovery key's, or none, unlocking on
    /// `day`/`month`/`year` at `hour`:`minute` UTC (24-hour clock).
    pub fn savings(
        owner: &str,
        recovery: Option<String>,
        day: u32,
        month: u32,
        year: u32,
        hour: u32,
        minute: u32,
    ) -> Result<Card, Fault> {
        Ok(Card {
            inner: host::Card::savings(owner, recovery.as_deref(), day, month, year, hour, minute)?,
        })
    }

    /// The card `line` is the backup of.
    #[wasm_bindgen(js_name = fromBackup)]
    pub fn from_backup(line: &str) -> Result<Card, Fault> {
        Ok(Card {
            inner: host::Card::from_backup(line)?,
        })
    }

    /// Its own address, `kaspa:p…`, where UTXOs are sent to be locked.
    pub fn address(&self) -> Result<String, Fault> {
        Ok(self.inner.address()?)
    }

    /// Its locking script, to match UTXOs against.
    pub fn script(&self) -> Vec<u8> {
        self.inner.script()
    }

    /// Its backup line, `savings_v1(...)`, to show as a QR code and keep.
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

    /// Its unlock time, Unix milliseconds: the least lock time a claim or
    /// recovery is built under (`lockUntil`).
    #[wasm_bindgen(getter, js_name = unlockMs)]
    pub fn unlock_ms(&self) -> u64 {
        self.inner.unlock_ms()
    }

    /// The day it unlocks on, 1 to 31.
    #[wasm_bindgen(getter, js_name = unlockDay)]
    pub fn unlock_day(&self) -> u32 {
        self.inner.unlock_day()
    }

    /// The month it unlocks in, 1 to 12.
    #[wasm_bindgen(getter, js_name = unlockMonth)]
    pub fn unlock_month(&self) -> u32 {
        self.inner.unlock_month()
    }

    /// The year it unlocks in.
    #[wasm_bindgen(getter, js_name = unlockYear)]
    pub fn unlock_year(&self) -> u32 {
        self.inner.unlock_year()
    }

    /// The hour it unlocks at, UTC, 0 to 23.
    #[wasm_bindgen(getter, js_name = unlockHour)]
    pub fn unlock_hour(&self) -> u32 {
        self.inner.unlock_hour()
    }

    /// The minute of that hour, 0 to 59.
    #[wasm_bindgen(getter, js_name = unlockMinute)]
    pub fn unlock_minute(&self) -> u32 {
        self.inner.unlock_minute()
    }

    /// Which of `account`'s first `depth` receive keys is this card's, the
    /// owner's if the account holds both, and whether it recovers; none if
    /// it holds neither, leaving the search to the unit.
    pub fn signer(&self, account: &Account, depth: u32) -> Result<Option<CardSigner>, Fault> {
        Ok(self
            .inner
            .signer(account.inner(), depth)?
            .map(|inner| CardSigner { inner }))
    }
}

impl Card {
    /// The host crate's card.
    pub const fn inner(&self) -> &host::Card {
        &self.inner
    }
}

/// Which of an account's receive keys is a card's, and which entry it
/// spends by.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardSigner {
    inner: host::CardSigner,
}

#[wasm_bindgen]
impl CardSigner {
    /// The receive index.
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.inner.index
    }

    /// Whether the key is the recovery wallet's; otherwise the owner's.
    #[wasm_bindgen(getter)]
    pub fn recovers(&self) -> bool {
        self.inner.recovers
    }
}
