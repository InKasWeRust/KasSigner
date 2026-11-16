// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A card's backup: one line of text that rebuilds the card.
//!
//! A card's address is a hash of its program, and neither SilverScript nor
//! any KCC keeps the program's values: this line does, for kassigner.org to
//! show as a QR code, a unit to save, or a hand to copy. It moves no coins
//! but tells whose card it is, when it opens and what it holds: keep it
//! private, like a watch-only key.
//!
//! ```text
//! savings_v1(<owner>,<recovery>,<DD/MM/YYYY HH:MM>,<card>)
//! ```
//!
//! - `owner`: the owner's key as its mainnet Schnorr address, `kaspa:q…`.
//! - `recovery`: the recovery wallet's key the same way, or `none`.
//! - The unlock time, UTC, day first, on a 24-hour clock.
//! - `card`: the card's own address, `kaspa:p…`.
//!
//! With a recovery wallet the line is 232 characters, two more than a
//! version 9 code holds, so a unit shows it in frames; without, 169.
//! Addresses carry a checksum, so a character copied wrong is caught in its
//! field, and the card rebuilt from the first three fields must have the
//! fourth's address.
//!
//! A line is read only if it is what [`write()`] makes of that card
//! (lowercase, two-digit day, month, hour and minute, one space before the
//! hour, `none` for no recovery wallet), give or take whitespace at its
//! ends: two backups of one card are the same text.
//! `savings_v1` names the card and its version; a reader refuses a name it
//! does not know. Mainnet only, as the cards are.

use super::savings::{Savings, UnlockAt};
use kassigner_kaspa::address::{self, AddressError, Prefix, Version};
use kassigner_kaspa::bip340::PUBLIC_KEY_SIZE;
use kassigner_kaspa::script::redeem_hash;

/// How a Time-Locked Savings v1 backup begins.
pub const SAVINGS_V1: &str = "savings_v1(";

/// Written for a card with no recovery wallet.
pub const NONE: &str = "none";

/// Characters of a mainnet address with a 32-byte payload: `kaspa:`, the
/// version and payload in five-bit groups, the checksum.
pub const ADDRESS_LEN: usize = "kaspa:".len() + (8 * (1 + 32usize)).div_ceil(5) + 8;

/// Most digits a year takes: the last unlock minute is in year 10,136.
const YEAR_MAX_DIGITS: usize = 5;

/// Longest time: `DD/MM/`, the year, and ` HH:MM`.
const DATE_MAX_LEN: usize = 6 + YEAR_MAX_DIGITS + 6;

/// Longest backup line: name, three addresses, time, commas, parenthesis.
pub const MAX_LEN: usize = SAVINGS_V1.len() + 3 * ADDRESS_LEN + DATE_MAX_LEN + 3 + 1;

/// Why a line is not a card's backup, or was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupError {
    /// Not a backup of a card this reader knows: no name, or another.
    NotABackup,
    /// The name, but not four fields in parentheses ending the line.
    Malformed,
    /// A key field that is not a mainnet Schnorr address of a valid key, or
    /// `none` for the owner.
    BadKey,
    /// A time not `DD/MM/YYYY HH:MM`, not a real date and time, or before
    /// the first minute a card can unlock.
    BadDate,
    /// A card field that is not a mainnet script-hash address.
    BadAddress,
    /// The address is not the card the other fields make.
    NotTheCard,
    /// The card, but not its line: the owner's key as the recovery wallet's,
    /// where [`write()`] puts `none`. Uppercase or another date form fails
    /// earlier.
    NotCanonical,
    /// The caller's buffer cannot hold the line; [`MAX_LEN`] always can.
    BufferTooSmall,
}

/// `card`'s backup line into `out`: bytes written.
///
/// # Errors
///
/// [`BackupError::BufferTooSmall`] for an `out` shorter than the line.
pub fn write(card: &Savings, out: &mut [u8]) -> Result<usize, BackupError> {
    let mut w = Writer { out, at: 0 };
    w.put(SAVINGS_V1.as_bytes())?;
    w.key(card.owner())?;
    w.put(b",")?;
    match card.recovery() {
        Some(key) => w.key(key)?,
        None => w.put(NONE.as_bytes())?,
    }
    w.put(b",")?;
    let (year, month, day) = card.unlock().date();
    let (hour, minute) = card.unlock().time();
    w.two(day)?;
    w.put(b"/")?;
    w.two(month)?;
    w.put(b"/")?;
    w.year(year)?;
    w.put(b" ")?;
    w.two(hour)?;
    w.put(b":")?;
    w.two(minute)?;
    w.put(b",")?;
    w.address(Version::ScriptHash, &redeem_hash(&card.program()))?;
    w.put(b")")?;
    Ok(w.at)
}

/// The card `line` is the backup of.
///
/// # Errors
///
/// The first [`BackupError`] found: each field's form left to right, then
/// the keys' validity, then [`BackupError::NotTheCard`], then
/// [`BackupError::NotCanonical`].
pub fn read(line: &[u8]) -> Result<Savings, BackupError> {
    let line = line.trim_ascii();
    let inner = line
        .strip_prefix(SAVINGS_V1.as_bytes())
        .ok_or(BackupError::NotABackup)?
        .strip_suffix(b")")
        .ok_or(BackupError::Malformed)?;
    if inner.iter().any(|&b| b == b'(' || b == b')') {
        return Err(BackupError::Malformed);
    }
    let mut fields = inner.split(|&b| b == b',');
    let (Some(owner), Some(recovery), Some(date), Some(card), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(BackupError::Malformed);
    };

    let owner = key(owner)?;
    let recovery = if recovery == NONE.as_bytes() {
        None
    } else {
        Some(key(recovery)?)
    };
    let unlock = read_date(date).ok_or(BackupError::BadDate)?;
    let hash = card_hash(card)?;

    let rebuilt = Savings::new(owner, recovery, unlock).map_err(|_| BackupError::BadKey)?;
    if redeem_hash(&rebuilt.program()) != hash {
        return Err(BackupError::NotTheCard);
    }
    let mut again = [0u8; MAX_LEN];
    let n = write(&rebuilt, &mut again)?;
    if again[..n] != *line {
        return Err(BackupError::NotCanonical);
    }
    Ok(rebuilt)
}

/// The key a mainnet Schnorr address carries.
fn key(field: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], BackupError> {
    match decode(field) {
        Ok((Version::PubKey, payload)) => Ok(payload),
        _ => Err(BackupError::BadKey),
    }
}

/// The program hash a mainnet script-hash address carries.
fn card_hash(field: &[u8]) -> Result<[u8; 32], BackupError> {
    match decode(field) {
        Ok((Version::ScriptHash, payload)) => Ok(payload),
        _ => Err(BackupError::BadAddress),
    }
}

/// A mainnet address with a 32-byte payload: its version and payload.
fn decode(field: &[u8]) -> Result<(Version, [u8; 32]), AddressError> {
    let mut payload = [0u8; 33];
    match address::decode(field, &mut payload)? {
        (Prefix::Mainnet, version, 32) => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&payload[..32]);
            Ok((version, out))
        }
        _ => Err(AddressError::BadPayloadLength),
    }
}

/// `DD/MM/YYYY HH:MM`: two digits, two digits, the year with no leading
/// zero; one space; two digits, a colon, two digits.
fn read_date(field: &[u8]) -> Option<UnlockAt> {
    let mut halves = field.split(|&b| b == b' ');
    let (Some(field), Some(clock), None) = (halves.next(), halves.next(), halves.next()) else {
        return None;
    };
    let mut hm = clock.split(|&b| b == b':');
    let (Some(hour), Some(minute), None) = (hm.next(), hm.next(), hm.next()) else {
        return None;
    };
    if hour.len() != 2 || minute.len() != 2 {
        return None;
    }
    let hour = u8::try_from(number(hour)?).ok()?;
    let minute = u8::try_from(number(minute)?).ok()?;
    let mut parts = field.split(|&b| b == b'/');
    let (Some(day), Some(month), Some(year), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if day.len() != 2 || month.len() != 2 || year.len() > YEAR_MAX_DIGITS {
        return None;
    }
    if year.first() == Some(&b'0') {
        return None;
    }
    let day = u8::try_from(number(day)?).ok()?;
    let month = u8::try_from(number(month)?).ok()?;
    UnlockAt::from_date_time(number(year)?, month, day, hour, minute)
}

/// Decimal digits, at least one, as a number that fits a `u32`.
fn number(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u32, |n, &d| {
        if !d.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add(u32::from(d - b'0'))
    })
}

/// Bytes into a buffer, failing when it is full.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), BackupError> {
        let end = self.at + bytes.len();
        self.out
            .get_mut(self.at..end)
            .ok_or(BackupError::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn address(&mut self, version: Version, payload: &[u8]) -> Result<(), BackupError> {
        let mut text = [0u8; ADDRESS_LEN];
        let n = address::encode(Prefix::Mainnet, version, payload, &mut text)
            .map_err(|_| BackupError::BufferTooSmall)?;
        self.put(&text[..n])
    }

    fn key(&mut self, key: &[u8; PUBLIC_KEY_SIZE]) -> Result<(), BackupError> {
        self.address(Version::PubKey, key)
    }

    fn two(&mut self, n: u8) -> Result<(), BackupError> {
        self.put(&[b'0' + n / 10, b'0' + n % 10])
    }

    fn year(&mut self, year: u32) -> Result<(), BackupError> {
        let mut digits = [0u8; 10];
        let mut i = digits.len();
        let mut y = year;
        loop {
            i -= 1;
            digits[i] = b'0' + (y % 10) as u8;
            y /= 10;
            if y == 0 {
                break;
            }
        }
        self.put(&digits[i..])
    }
}
