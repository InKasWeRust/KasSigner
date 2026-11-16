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

//! What a container password has to be before a card is written.
//!
//! The container's derivation ([`crate::container`]) raises the cost per
//! guess (a hundred thousand hashes, or sixteen megabytes and four passes),
//! not the number of guesses: a six-character password falls under any
//! derivation. Refusing weak ones is the other half of protecting a lost
//! card.
//!
//! Device policy at level 2, like [`crate::slot::Passphrase`]'s character
//! set: enforced where the secret is sealed, so no caller skips it. It
//! covers every sealed file but a stego backup ([`crate::container::policy`]):
//! sealing with a key takes a [`crate::container::SealingKey`], which only a
//! derivation that applied the policy makes.
//!
//! Length, classes and distinct characters only: dictionary checks (zxcvbn
//! and its kind) need tables and a heap this crate lacks, so four common
//! words with a digit and a capital pass.
//!
//! Only when sealing: cards from v1.0.7 with passwords this would refuse
//! must keep opening.

/// Fewest bytes a password may have.
pub const MIN_LEN: usize = 12;

/// Fewest character classes (lower, upper, digit, other) a password must
/// draw from.
pub const MIN_CLASSES: u8 = 3;

/// Fewest distinct bytes a password must hold.
pub const MIN_DISTINCT: usize = 6;

/// Why a password was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weakness {
    /// Fewer than [`MIN_LEN`] bytes.
    TooShort { have: usize, min: usize },
    /// Fewer than [`MIN_CLASSES`] of lower, upper, digit, other.
    TooFewClasses { have: u8, min: u8 },
    /// Fewer than [`MIN_DISTINCT`] distinct bytes: `aaaaaaaaaaaA1` passes
    /// the two checks above with three distinct bytes.
    TooFewDistinct { have: usize, min: usize },
}

/// How strong an accepted password is, for the meter a board shows before
/// the card is written.
///
/// From the bits of a password drawn uniformly from its classes, which
/// overstates one made of words, so the thresholds sit high: the shortest
/// accepted is always `Fair`, and `Strong` starts at sixteen characters
/// over all four classes, sixteen or seventeen over three.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// Accepted, and under eighty estimated bits.
    Fair,
    /// Eighty to a hundred estimated bits.
    Good,
    /// A hundred bits and above.
    Strong,
}

/// Check a password against the policy and rate it.
///
/// # Errors
///
/// The first [`Weakness`] found, in the order length, classes, distinct
/// bytes, so a board can tell the person the one thing to fix.
pub fn check(password: &[u8]) -> Result<Strength, Weakness> {
    if password.len() < MIN_LEN {
        return Err(Weakness::TooShort {
            have: password.len(),
            min: MIN_LEN,
        });
    }
    let classes = classes(password);
    if classes.count() < MIN_CLASSES {
        return Err(Weakness::TooFewClasses {
            have: classes.count(),
            min: MIN_CLASSES,
        });
    }
    let distinct = distinct(password);
    if distinct < MIN_DISTINCT {
        return Err(Weakness::TooFewDistinct {
            have: distinct,
            min: MIN_DISTINCT,
        });
    }
    Ok(rate(password.len(), classes))
}

/// The estimated bits of a password of `len` bytes drawn from `classes`,
/// times ten, in integers: `len * log2(pool) * 10`. The pool is the bytes in
/// the classes used: 26, 26, 10 and 33 (printable ASCII outside the other
/// three). `log2` comes from a table, to a tenth of a bit.
const fn bits_x10(len: usize, classes: Classes) -> usize {
    let pool = classes.pool();
    // Every reachable pool size.
    let log2_x10 = match pool {
        10 => 33,
        26 => 47,
        33 => 50,
        36 => 52,
        43 => 54,
        52 => 57,
        59 => 59,
        62 => 60,
        69 => 61,
        85 => 64,
        95 => 66,
        _ => 0,
    };
    len * log2_x10
}

const fn rate(len: usize, classes: Classes) -> Strength {
    let bits = bits_x10(len, classes) / 10;
    if bits >= 100 {
        Strength::Strong
    } else if bits >= 80 {
        Strength::Good
    } else {
        Strength::Fair
    }
}

/// Which of the four classes a password draws from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Classes {
    lower: bool,
    upper: bool,
    digit: bool,
    other: bool,
}

impl Classes {
    const fn count(self) -> u8 {
        self.lower as u8 + self.upper as u8 + self.digit as u8 + self.other as u8
    }

    /// Bytes an attacker has to try per position, given the classes seen.
    const fn pool(self) -> usize {
        (if self.lower { 26 } else { 0 })
            + (if self.upper { 26 } else { 0 })
            + (if self.digit { 10 } else { 0 })
            + (if self.other { 33 } else { 0 })
    }
}

fn classes(password: &[u8]) -> Classes {
    let mut c = Classes {
        lower: false,
        upper: false,
        digit: false,
        other: false,
    };
    for &b in password {
        match b {
            b'a'..=b'z' => c.lower = true,
            b'A'..=b'Z' => c.upper = true,
            b'0'..=b'9' => c.digit = true,
            _ => c.other = true,
        }
    }
    c
}

/// Distinct byte values, counted with a 256-bit set on the stack.
fn distinct(password: &[u8]) -> usize {
    let mut seen = [0u64; 4];
    for &b in password {
        seen[usize::from(b >> 6)] |= 1u64 << (b & 63);
    }
    seen.iter().map(|w| w.count_ones() as usize).sum()
}
