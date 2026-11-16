// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The multisig descriptor: one line naming a multisig group's keys and how
//! many signatures it needs, which a participant hands the others so every
//! device derives the same addresses.
//!
//! ```text
//! multi_hd45(M,<kpub>,<kpub>,...,<kpub>)
//! ```
//!
//! Kaspa multisig is 45', with a cosigner level, sorted. There is no 44'
//! multisig: BIP44 has no cosigner level to say which slot is yours.
//! `multi_hd(` and `multi(` are not Kaspa multisig and are refused.
//!
//! The entries come back sorted, the written order discarded. The sort is
//! rusty-kaspa's wallet rule, not consensus: upstream takes the cosigner
//! index, so the derivation path and the address, from the sorted base58
//! strings. It lives in `kassigner_kaspa::multisig`, checked against
//! upstream, and is not restated here.
//!
//! At most [`MAX_KEYS`] keys: the script engine refuses a multisig check
//! over more, so a larger group has an address whose coins nobody can move.
//! Upstream's builder, and `kassigner_kaspa`'s, build one anyway, so a group
//! is refused here, read or written. A device's smaller limit is the
//! caller's, by the slice it passes.
//!
//! An optional `#` header line is skipped unread: among the entries it would
//! change the sort and so every address.
//!
//! No base58, key validation or derivation here: [`crate::group`] does
//! those, reading a descriptor through this. A caller must still confirm
//! its own key is among the entries ([`crate::group::Group::position`]), or
//! a participant with the wrong key derives silently until a signature
//! fails to verify.

use kassigner_kaspa::multisig::{sort_cosigners, MAX_KEYS};

/// The only prefix Kaspa multisig uses.
pub const PREFIX: &str = "multi_hd45(";

/// A serialized kpub is always this many base58 characters: 78 bytes with
/// fixed version bytes, plus a four-byte checksum. The sort depends on it:
/// at equal lengths, sorting the text sorts the encoded bytes.
pub const KPUB_STR_LEN: usize = 111;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorError {
    /// Not a `multi_hd45(` descriptor: `multi_hd(` and `multi(` among them.
    BadScheme,
    /// Missing the closing parenthesis.
    Unterminated,
    /// The threshold is absent, not a number, written with a leading zero,
    /// or outside 1 to [`MAX_KEYS`].
    BadThreshold,
    /// More entries than the caller allows, or than the engine's
    /// [`MAX_KEYS`].
    TooManyKeys { found: usize, limit: usize },
    /// No entries at all.
    NoKeys,
    /// The threshold exceeds the number of keys.
    ThresholdAboveKeys { m: usize, n: usize },
    /// An entry is not `KPUB_STR_LEN` characters.
    BadEntryLength { index: usize, len: usize },
    /// Two entries are equal. This format's rule, not Kaspa's: a key at two
    /// cosigner indices leaves its holder unable to tell which is its own.
    DuplicateKey { index: usize },
    /// The caller's output slice is too small.
    BufferTooSmall,
}

/// A parsed descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Signatures required.
    pub m: usize,
    /// Keys present.
    pub n: usize,
}

/// Strip a byte-order mark, then an optional `#` header line, unread;
/// returns what follows.
///
/// Some editors start a UTF-8 file with the mark, `U+FEFF`, which
/// `trim_start` does not remove. Only at the very start: anywhere else it
/// is text.
pub fn strip_header(text: &str) -> &str {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let t = text.trim_start();
    if let Some(rest) = t.strip_prefix('#') {
        match rest.find('\n') {
            Some(i) => rest[i + 1..].trim_start(),
            None => "",
        }
    } else {
        t
    }
}

/// Parse a descriptor, writing its entries into `out` in sorted order.
///
/// `out` bounds the key count, passed in like every bound in this crate; a
/// descriptor with more entries is refused, not truncated. The engine's
/// [`MAX_KEYS`] bounds it too.
///
/// Index `i` in `out` is cosigner index `i`: upstream derives from the
/// sorted position, not the written one.
///
/// # Errors
///
/// The first fault found. No key is validated: an entry is checked for
/// length and uniqueness only.
pub fn parse<'a>(text: &'a str, out: &mut [&'a str]) -> Result<Descriptor, DescriptorError> {
    let line = strip_header(text).trim_end();

    let body = line
        .strip_prefix(PREFIX)
        .ok_or(DescriptorError::BadScheme)?
        .strip_suffix(')')
        .ok_or(DescriptorError::Unterminated)?;

    let (m_str, rest) = body.split_once(',').ok_or(DescriptorError::BadThreshold)?;
    let m = threshold(m_str).ok_or(DescriptorError::BadThreshold)?;

    let limit = out.len().min(MAX_KEYS);
    let mut n = 0usize;
    for entry in rest.split(',') {
        if !entry.is_ascii() || entry.len() != KPUB_STR_LEN {
            return Err(DescriptorError::BadEntryLength {
                index: n,
                len: entry.chars().count(),
            });
        }
        if n >= limit {
            return Err(DescriptorError::TooManyKeys {
                found: n + 1,
                limit,
            });
        }
        out[n] = entry;
        n += 1;
    }
    if n == 0 {
        return Err(DescriptorError::NoKeys);
    }
    if m > n {
        return Err(DescriptorError::ThresholdAboveKeys { m, n });
    }

    // Ordering is Kaspa's rule, handed down.
    sort_cosigners(&mut out[..n]);
    // A repeated key is this format's to refuse. Sorted, a twin is adjacent.
    for i in 1..n {
        if out[i - 1] == out[i] {
            return Err(DescriptorError::DuplicateKey { index: i });
        }
    }

    Ok(Descriptor { m, n })
}

/// A threshold as written: 1 to [`MAX_KEYS`] in decimal, no leading zero.
fn threshold(text: &str) -> Option<usize> {
    let digits = text.as_bytes();
    if digits.is_empty() || digits.len() > 2 || digits[0] == b'0' {
        return None;
    }
    let mut m = 0usize;
    for &d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        m = m * 10 + usize::from(d - b'0');
    }
    (1..=MAX_KEYS).contains(&m).then_some(m)
}

/// Digits a threshold of at most `n` takes.
const fn threshold_digits(n: usize) -> usize {
    if n >= 10 {
        2
    } else {
        1
    }
}

/// Longest descriptor a group of `n` keys can produce, prefix and all.
pub const fn max_len(n: usize) -> usize {
    // prefix + "M," + n entries + (n-1) commas + ")"; the threshold is at
    // most `n`, so its digits are at most `n`'s.
    PREFIX.len() + threshold_digits(n) + 1 + n * KPUB_STR_LEN + n.saturating_sub(1) + 1
}

/// Write a descriptor into `out`, returning bytes written. Entries are
/// written in the order given: sorting here would hide a caller that thought
/// its order meant something, and parsing sorts anyway. A repeated entry is
/// not checked; `parse` refuses it.
///
/// # Errors
///
/// `BufferTooSmall` if `out` is shorter than [`max_len`] of the key count;
/// otherwise what `parse` returns for a threshold, key count or entry that
/// cannot be written.
pub fn write(m: usize, keys: &[&str], out: &mut [u8]) -> Result<usize, DescriptorError> {
    if keys.is_empty() {
        return Err(DescriptorError::NoKeys);
    }
    if keys.len() > MAX_KEYS {
        return Err(DescriptorError::TooManyKeys {
            found: keys.len(),
            limit: MAX_KEYS,
        });
    }
    if !(1..=MAX_KEYS).contains(&m) {
        return Err(DescriptorError::BadThreshold);
    }
    if m > keys.len() {
        return Err(DescriptorError::ThresholdAboveKeys { m, n: keys.len() });
    }
    for (i, k) in keys.iter().enumerate() {
        if !k.is_ascii() || k.len() != KPUB_STR_LEN {
            return Err(DescriptorError::BadEntryLength {
                index: i,
                len: k.chars().count(),
            });
        }
    }

    let total = max_len(keys.len());
    if out.len() < total {
        return Err(DescriptorError::BufferTooSmall);
    }

    let mut w = 0usize;
    let p = PREFIX.as_bytes();
    out[w..w + p.len()].copy_from_slice(p);
    w += p.len();
    if m >= 10 {
        out[w] = b'0' + (m / 10) as u8;
        w += 1;
    }
    out[w] = b'0' + (m % 10) as u8;
    w += 1;
    out[w] = b',';
    w += 1;
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out[w] = b',';
            w += 1;
        }
        out[w..w + k.len()].copy_from_slice(k.as_bytes());
        w += k.len();
    }
    out[w] = b')';
    w += 1;
    Ok(w)
}
