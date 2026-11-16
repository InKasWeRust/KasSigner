// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Time-Locked Savings, card version 1: `sil/time_locked_savings.sil`.
//!
//! Coins sent to the card wait until a UTC minute the owner chose: until
//! then nobody, the owner included, can move them; then the owner or the
//! recovery wallet, either alone, can. With no recovery wallet the recovery
//! slot holds the owner's key.
//!
//! # The program
//!
//! Three values, all state, pushed in this order between the halves:
//!
//! | Field      | Type       | Push                          |
//! |------------|------------|-------------------------------|
//! | `owner`    | `pubkey`   | `OP_DATA_32` and the key      |
//! | `recovery` | `pubkey`   | `OP_DATA_32` and the key      |
//! | `unlockAt` | `temporal` | `OP_DATA_8` and the time, LE  |
//!
//! `unlockAt` is in milliseconds, so the lock time is a timestamp, never a
//! DAA score: the program refuses a value under [`LOCK_TIME_THRESHOLD`].
//! This card also requires a whole minute, an [`UnlockAt`].
//!
//! # A spend
//!
//! The input carries the signature, the entry's tag and the program
//! ([`Savings::signature_script`]). The lock time is a timestamp at or past
//! the card's time, and the sequence is not [`MAX_TX_IN_SEQUENCE_NUM`],
//! which turns the lock time check off and which the program refuses.
//! Consensus takes the transaction once the median time is past its lock
//! time (rusty-kaspa's `check_tx_is_finalized`). Under transaction version
//! 0 the input commits [`SIG_OP_COUNT`] signature operations. Any sighash
//! type is accepted.
//!
//! [`MAX_TX_IN_SEQUENCE_NUM`]: kassigner_kaspa::constants::MAX_TX_IN_SEQUENCE_NUM

use kassigner_kaspa::address::{self, AddressError, Prefix, Version};
use kassigner_kaspa::bip340::{is_public_key, PUBLIC_KEY_SIZE};
use kassigner_kaspa::constants::LOCK_TIME_THRESHOLD;
use kassigner_kaspa::kcc::abi::{Field, Type, DISPATCH_TAG_LEN};
use kassigner_kaspa::kcc::hash::HASH_LEN;
use kassigner_kaspa::kcc::push::explicit_len;
use kassigner_kaspa::kcc::state::{state_value, Parts, Span};
use kassigner_kaspa::kcc::value::{Segment, Value};
use kassigner_kaspa::script::{pay_to_script_hash, redeem_hash, PAY_TO_SCRIPT_HASH_LEN};

/// The template before the state: `OP_TOALTSTACK`, setting the tag aside.
pub const PREFIX: [u8; 1] = [0x6b];

/// The template after the state: the entries, `claim` then `recover`, and
/// `OP_RETURN` for any other tag.
pub const SUFFIX: [u8; 82] = [
    0x6c, 0x76, 0x04, 0xdd, 0x9a, 0xb0, 0x92, 0x87, 0x63, 0x75, 0x53, 0x79, //
    0x82, 0x01, 0x41, 0x9d, 0x75, 0x76, 0x76, 0x05, 0x00, 0x88, 0x52, 0x6a, //
    0x74, 0xa2, 0x69, 0xb0, 0x53, 0x79, 0x53, 0x79, 0xac, 0x69, 0x75, 0x75, //
    0x75, 0x75, 0x51, 0x67, 0x76, 0x04, 0x92, 0x6f, 0xea, 0x0e, 0x87, 0x63, //
    0x75, 0x53, 0x79, 0x82, 0x01, 0x41, 0x9d, 0x75, 0x76, 0x76, 0x05, 0x00, //
    0x88, 0x52, 0x6a, 0x74, 0xa2, 0x69, 0xb0, 0x53, 0x79, 0x52, 0x79, 0xac, //
    0x69, 0x75, 0x75, 0x75, 0x75, 0x51, 0x67, 0x6a, 0x68, 0x68,
];

/// KCC-1's `TemplateHash(PREFIX, SUFFIX)`, the card's name to a reader. The
/// unit knows the card by its program; the tests check this against the
/// compiled `.sil`.
pub const TEMPLATE_HASH: [u8; HASH_LEN] = [
    0xdf, 0x62, 0xf9, 0x1e, 0x77, 0xa7, 0xc1, 0xc6, 0x6c, 0xcd, 0x16, 0x5a, //
    0x4c, 0x77, 0x75, 0xc7, 0x2a, 0x2f, 0x6e, 0x6b, 0x3c, 0xd2, 0x2d, 0x64, //
    0xb9, 0xc7, 0x21, 0x1f, 0x8a, 0x44, 0x77, 0x82,
];

/// The state's layout, in declaration order.
pub const STATE: [Field<'static>; 3] = [
    Field {
        name: "owner",
        ty: Type::Pubkey,
    },
    Field {
        name: "recovery",
        ty: Type::Pubkey,
    },
    Field {
        name: "unlockAt",
        ty: Type::Temporal,
    },
];

/// Bytes the state takes: two keys and a time, each `PushExplicit`.
pub const STATE_LEN: usize = 2 * explicit_len(PUBLIC_KEY_SIZE) + explicit_len(TIME_LEN);

/// Bytes a card's program takes.
pub const PROGRAM_LEN: usize = PREFIX.len() + STATE_LEN + SUFFIX.len();

/// Bytes of a signature as the program takes it: 64, and the sighash type.
pub const SIG_LEN: usize = 65;

/// Bytes of a spend's signature script: signature, tag, program, pushed.
pub const SIGNATURE_SCRIPT_LEN: usize =
    1 + SIG_LEN + 1 + DISPATCH_TAG_LEN + PROGRAM_PUSH_HEAD.len() + PROGRAM_LEN;

/// Signature operations a spend runs, committed under transaction version 0.
pub const SIG_OP_COUNT: u8 = 1;

/// Milliseconds in a minute.
pub const MS_PER_MINUTE: u64 = 60_000;

/// Minutes in a day.
pub const MINUTES_PER_DAY: u32 = 1_440;

/// The first whole minute at or past [`LOCK_TIME_THRESHOLD`]: minute
/// 8,333,334 of the Unix epoch, 5 November 1985, 00:54 UTC.
pub const FIRST_MINUTE: u32 = LOCK_TIME_THRESHOLD.div_ceil(MS_PER_MINUTE) as u32;

/// Bytes of the time in the state.
const TIME_LEN: usize = 8;
/// Days from 1 March of year 0 to the Unix epoch.
const DAYS_TO_1970: u64 = 719_468;

/// Days in `month` of `year`, Gregorian.
const fn days_in_month(year: u32, month: u8) -> u8 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
/// `OP_DATA_32`.
const OP_DATA_32: u8 = 0x20;
/// `OP_DATA_8`.
const OP_DATA_8: u8 = 0x08;
/// `OP_DATA_65`.
const OP_DATA_65: u8 = 0x41;
/// `OP_DATA_4`.
const OP_DATA_4: u8 = 0x04;
/// A program's `PushMinimal`: `OP_PUSHDATA1` and its length, 76 to 255.
const PROGRAM_PUSH_HEAD: [u8; 2] = [0x4c, PROGRAM_LEN as u8];
const _: () = assert!(PROGRAM_LEN > 75 && PROGRAM_LEN <= 255);

/// The two entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// `claim(sig ownerSig)`: the owner, from its time on.
    Claim,
    /// `recover(sig recoverySig)`: the recovery wallet, from its time on.
    Recover,
}

impl Entry {
    /// The entry's dispatch tag, KCC-1's, as the compiler wrote it.
    #[must_use]
    pub const fn tag(self) -> [u8; DISPATCH_TAG_LEN] {
        match self {
            Entry::Claim => [0xdd, 0x9a, 0xb0, 0x92],
            Entry::Recover => [0x92, 0x6f, 0xea, 0x0e],
        }
    }

    /// The entry a tag names, if either.
    #[must_use]
    pub fn from_tag(tag: [u8; DISPATCH_TAG_LEN]) -> Option<Self> {
        [Entry::Claim, Entry::Recover]
            .into_iter()
            .find(|e| e.tag() == tag)
    }
}

/// When a card unlocks, in whole minutes since the Unix epoch: the median
/// time a lock is held to trails the clock by minutes anyway, and a card
/// whose backup line is lost can be found from its keys by trying minutes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnlockAt(u32);

impl UnlockAt {
    /// The minute `minutes` after the Unix epoch, if it is [`FIRST_MINUTE`]
    /// or later.
    #[must_use]
    pub const fn new(minutes: u32) -> Option<Self> {
        if minutes >= FIRST_MINUTE {
            Some(Self(minutes))
        } else {
            None
        }
    }

    /// The minute `ms` is the start of, if it is a whole minute and
    /// [`FIRST_MINUTE`] or later.
    #[must_use]
    pub const fn from_ms(ms: u64) -> Option<Self> {
        if !ms.is_multiple_of(MS_PER_MINUTE) || ms / MS_PER_MINUTE > u32::MAX as u64 {
            return None;
        }
        Self::new((ms / MS_PER_MINUTE) as u32)
    }

    /// `hour`:`minute` UTC on `day`/`month`/`year`, Gregorian, if valid and
    /// [`FIRST_MINUTE`] or later.
    #[must_use]
    pub const fn from_date_time(
        year: u32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
    ) -> Option<Self> {
        if year < 1970 || month < 1 || month > 12 || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        if hour > 23 || minute > 59 {
            return None;
        }
        // The `days_from_civil` algorithm, unsigned: the year is no earlier
        // than the epoch's, so no term goes negative.
        let y = year as u64 - if month <= 2 { 1 } else { 0 };
        let m = month as u64;
        let era = y / 400;
        let yoe = y % 400;
        let doy = (153 * if m > 2 { m - 3 } else { m + 9 } + 2) / 5 + day as u64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe;
        if days < DAYS_TO_1970 {
            return None;
        }
        let minutes =
            (days - DAYS_TO_1970) * MINUTES_PER_DAY as u64 + hour as u64 * 60 + minute as u64;
        if minutes > u32::MAX as u64 {
            return None;
        }
        Self::new(minutes as u32)
    }

    /// Its date: the year, the month from 1 and the day from 1.
    #[must_use]
    pub const fn date(self) -> (u32, u8, u8) {
        // The `civil_from_days` algorithm, unsigned.
        let z = (self.0 / MINUTES_PER_DAY) as u64 + DAYS_TO_1970;
        let era = z / 146_097;
        let doe = z % 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
        (year as u32, month as u8, day as u8)
    }

    /// Its time of day: the hour, 0 to 23, and the minute, 0 to 59.
    #[must_use]
    pub const fn time(self) -> (u8, u8) {
        let of_day = self.0 % MINUTES_PER_DAY;
        ((of_day / 60) as u8, (of_day % 60) as u8)
    }

    /// Minutes since the Unix epoch.
    #[must_use]
    pub const fn minutes(self) -> u32 {
        self.0
    }

    /// In milliseconds: the card's `unlockAt`, the least lock time a spend
    /// can carry.
    #[must_use]
    pub const fn ms(self) -> u64 {
        self.0 as u64 * MS_PER_MINUTE
    }
}

/// Why a card was not made, or a program not read as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardError {
    /// Thirty-two bytes that are not a BIP340 public key.
    NotAKey,
    /// Another program: another length, or another template.
    NotThisCard,
    /// This template around a state it never writes: a field off its
    /// layout, or a time not a whole minute from [`FIRST_MINUTE`] on.
    BadState,
}

/// A Time-Locked Savings card: owner, recovery wallet, unlock time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Savings {
    owner: [u8; PUBLIC_KEY_SIZE],
    recovery: Option<[u8; PUBLIC_KEY_SIZE]>,
    unlock: UnlockAt,
}

impl Savings {
    /// The card of `owner`, with recovery wallet `recovery` or none,
    /// unlocking at `unlock`. A recovery key equal to the owner's counts as
    /// none: the program is the same.
    ///
    /// # Errors
    ///
    /// [`CardError::NotAKey`] for a key that is not a BIP340 public key.
    pub fn new(
        owner: [u8; PUBLIC_KEY_SIZE],
        recovery: Option<[u8; PUBLIC_KEY_SIZE]>,
        unlock: UnlockAt,
    ) -> Result<Self, CardError> {
        let keys_ok = is_public_key(&owner) && recovery.as_ref().is_none_or(is_public_key);
        if !keys_ok {
            return Err(CardError::NotAKey);
        }
        Ok(Self {
            owner,
            recovery: recovery.filter(|r| *r != owner),
            unlock,
        })
    }

    /// The owner's key.
    #[must_use]
    pub const fn owner(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.owner
    }

    /// The recovery wallet's key, or `None` for no recovery wallet.
    #[must_use]
    pub const fn recovery(&self) -> Option<&[u8; PUBLIC_KEY_SIZE]> {
        self.recovery.as_ref()
    }

    /// The time it unlocks.
    #[must_use]
    pub const fn unlock(&self) -> UnlockAt {
        self.unlock
    }

    /// The key in the recovery slot: the recovery wallet's, or the owner's.
    const fn recovery_slot(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        match &self.recovery {
            Some(r) => r,
            None => &self.owner,
        }
    }

    /// The card's program: the template's prefix, the state, the suffix.
    #[must_use]
    pub fn program(&self) -> [u8; PROGRAM_LEN] {
        let mut p = [0u8; PROGRAM_LEN];
        let (prefix, rest) = p.split_at_mut(PREFIX.len());
        prefix.copy_from_slice(&PREFIX);
        let (state, suffix) = rest.split_at_mut(STATE_LEN);
        suffix.copy_from_slice(&SUFFIX);
        // `PushExplicit` of 32 or 8 bytes is the direct push; the time is
        // under 2^63, so its `int` is its little-endian bytes.
        let (owner, rest) = state.split_at_mut(explicit_len(PUBLIC_KEY_SIZE));
        let (recovery, time) = rest.split_at_mut(explicit_len(PUBLIC_KEY_SIZE));
        owner[0] = OP_DATA_32;
        owner[1..].copy_from_slice(&self.owner);
        recovery[0] = OP_DATA_32;
        recovery[1..].copy_from_slice(self.recovery_slot());
        time[0] = OP_DATA_8;
        time[1..].copy_from_slice(&self.unlock.ms().to_le_bytes());
        p
    }

    /// The card's locking script: pay-to-script-hash of its program.
    #[must_use]
    pub fn locking_script(&self) -> [u8; PAY_TO_SCRIPT_HASH_LEN] {
        pay_to_script_hash(&redeem_hash(&self.program()))
    }

    /// The card's address, mainnet only, `kaspa:p…`, into `out`: bytes
    /// written.
    ///
    /// # Errors
    ///
    /// [`AddressError::BufferTooSmall`] for an `out` too short;
    /// [`address::MAX_ADDRESS_LEN`] always fits.
    pub fn address(&self, out: &mut [u8]) -> Result<usize, AddressError> {
        address::encode(
            Prefix::Mainnet,
            Version::ScriptHash,
            &redeem_hash(&self.program()),
            out,
        )
    }

    /// The card whose program is `program`.
    ///
    /// # Errors
    ///
    /// [`CardError::NotThisCard`] for another program,
    /// [`CardError::BadState`] for a state this card never writes,
    /// [`CardError::NotAKey`] for a key in it that is none.
    pub fn from_program(program: &[u8]) -> Result<Self, CardError> {
        if program.len() != PROGRAM_LEN {
            return Err(CardError::NotThisCard);
        }
        let span = Span {
            start: PREFIX.len(),
            len: STATE_LEN,
        };
        let parts = Parts::of(program, span).map_err(|_| CardError::NotThisCard)?;
        if parts.prefix != PREFIX || parts.suffix != SUFFIX {
            return Err(CardError::NotThisCard);
        }
        let read = |name| state_value(&STATE, parts.state, &[Segment::Field(name)]);
        let key = |name| match read(name) {
            Ok(Value::Bytes(b)) => b.try_into().map_err(|_| CardError::BadState),
            _ => Err(CardError::BadState),
        };
        let owner = key("owner")?;
        let recovery = key("recovery")?;
        let unlock = match read("unlockAt") {
            Ok(Value::Int(ms)) => u64::try_from(ms).ok().and_then(UnlockAt::from_ms),
            _ => None,
        }
        .ok_or(CardError::BadState)?;
        Self::new(owner, Some(recovery), unlock)
    }

    /// The signature script of a spend through `entry` signed `sig`, laid
    /// out as KCC-1's envelope: signature, tag, program, each pushed.
    #[must_use]
    pub fn signature_script(
        &self,
        entry: Entry,
        sig: &[u8; SIG_LEN],
    ) -> [u8; SIGNATURE_SCRIPT_LEN] {
        let mut s = [0u8; SIGNATURE_SCRIPT_LEN];
        let (head, rest) = s.split_at_mut(1 + SIG_LEN);
        head[0] = OP_DATA_65;
        head[1..].copy_from_slice(sig);
        let (tag, rest) = rest.split_at_mut(1 + DISPATCH_TAG_LEN);
        tag[0] = OP_DATA_4;
        tag[1..].copy_from_slice(&entry.tag());
        let (push, program) = rest.split_at_mut(PROGRAM_PUSH_HEAD.len());
        push.copy_from_slice(&PROGRAM_PUSH_HEAD);
        program.copy_from_slice(&self.program());
        s
    }
}
