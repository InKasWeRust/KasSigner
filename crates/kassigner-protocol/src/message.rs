// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A signed message as it travels: the text exactly as signed, the address
//! that signed it and the signature. A signature alone proves nothing, so a
//! unit's Sign Message writes all three, and whoever reads them back checks
//! rather than signs.
//!
//! The layout is ours, with no key material, so it lives here, where a
//! companion reads it as the firmware does. rusty-kaspa has no file for
//! this; its CLI prints the signature. Plain text with markers:
//!
//! ```text
//! -----BEGIN KASPA SIGNED MESSAGE-----
//! <the text, exactly as signed>
//! -----BEGIN SIGNATURE-----
//! <address>
//! <signature, 128 hex>
//! -----END KASPA SIGNED MESSAGE-----
//! ```
//!
//! Every line break of the markers is `\n`. The text is everything between
//! the first marker's line and the last signature marker, so a text holding
//! the marker itself reads back as written.

use core::ops::Range;

/// Printable ASCII: the alphabet of a unit's keyboard, its fonts and a
/// passphrase.
pub const fn printable(c: u8) -> bool {
    matches!(c, 0x20..=0x7E)
}

/// Whether `bytes` are a message a unit's Sign Message takes: printable
/// ASCII and line breaks, not empty. Nothing a screen cannot show, so what
/// is shown is what is signed.
///
/// A line break is `\n` or `\r\n`; a carriage return anywhere else is
/// refused. A unit also refuses a seed as a message, which only it can
/// tell: it holds the word list.
pub fn is_text(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.iter().enumerate().all(|(i, &c)| {
            printable(c) || c == b'\n' || (c == b'\r' && bytes.get(i + 1) == Some(&b'\n'))
        })
}

/// Whether `bytes` are a message a unit signs: [`is_text`], with no space
/// ending a line or the text and no line break ending the text, which would
/// be signed but show as nothing. Reading seed words off a text, or checking
/// someone else's signature, keeps [`is_text`].
pub fn is_signable(bytes: &[u8]) -> bool {
    is_text(bytes)
        && bytes.last() != Some(&b'\n')
        && bytes.split(|&c| c == b'\n').all(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            line.last() != Some(&b' ')
        })
}

/// The first line.
const BEGIN: &[u8] = b"-----BEGIN KASPA SIGNED MESSAGE-----\n";
/// Between the text and the address.
const SIGNATURE: &[u8] = b"\n-----BEGIN SIGNATURE-----\n";
/// The last line, its line break optional when read.
const END: &[u8] = b"\n-----END KASPA SIGNED MESSAGE-----";

/// Hex characters a signature takes.
pub const SIGNATURE_HEX: usize = 128;

/// Decode `text`, hex in either case, into `out`, which it must fill
/// exactly; false if it does not. Reads a record's signature, or a typed key.
pub fn read_hex(text: &[u8], out: &mut [u8]) -> bool {
    if text.len() != out.len() * 2 {
        return false;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    for (o, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(hi), Some(lo)) => *o = (hi << 4) | lo,
            _ => return false,
        }
    }
    true
}

/// What the markers add to the text, the address and the signature.
pub const OVERHEAD: usize = BEGIN.len() + SIGNATURE.len() + 1 + END.len() + 1;

/// Where a record's parts are in its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parts {
    pub text: Range<usize>,
    pub address: Range<usize>,
    pub signature: Range<usize>,
}

/// Write `text`, `address` and `signature` as a record into `out`, returning
/// its length, or `None` if it does not fit.
pub fn write(text: &[u8], address: &[u8], signature: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut n = 0;
    for part in [
        BEGIN, text, SIGNATURE, address, b"\n", signature, END, b"\n",
    ] {
        out.get_mut(n..n + part.len())?.copy_from_slice(part);
        n += part.len();
    }
    Some(n)
}

/// A record's parts, when `bytes` are one: the markers where they belong, a
/// one-line address, and a signature of 128 hex characters.
pub fn read(bytes: &[u8]) -> Option<Parts> {
    let body = bytes.strip_prefix(BEGIN)?;
    let body = body.strip_suffix(b"\n").unwrap_or(body);
    let body = body.strip_suffix(END)?;
    let at = body
        .windows(SIGNATURE.len())
        .rposition(|w| w == SIGNATURE)?;
    let tail = &body[at + SIGNATURE.len()..];
    let line = tail.iter().position(|&c| c == b'\n')?;
    let (address, signature) = (&tail[..line], &tail[line + 1..]);
    if address.is_empty()
        || signature.len() != SIGNATURE_HEX
        || !signature.iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    let start = BEGIN.len();
    let tail_at = start + at + SIGNATURE.len();
    Some(Parts {
        text: start..start + at,
        address: tail_at..tail_at + line,
        signature: tail_at + line + 1..tail_at + line + 1 + SIGNATURE_HEX,
    })
}

#[cfg(test)]
mod tests {
    use super::{is_signable, is_text, read, write, OVERHEAD, SIGNATURE_HEX};

    /// A text a unit signs shows all it holds: a space ending a line or the
    /// text, or a line break ending it, is refused, though still [`is_text`].
    #[test]
    fn a_signed_text_shows_all_it_holds() {
        for text in [
            &b"Hello Kaspa!"[..],
            b"two\nlines",
            b"two\r\nlines",
            b"a blank\n\nline between",
            b" indented",
            b"two  spaces inside",
            b"x",
        ] {
            assert!(is_signable(text), "{:?}", core::str::from_utf8(text));
        }
        for text in [
            &b"ends "[..],
            b" ",
            b"a line ends \nhere",
            b"a line ends \r\nhere",
            b"   \nonly spaces",
            b"ends\n",
            b"ends\r\n",
            b"\n",
            b"two\n\n",
        ] {
            assert!(is_text(text), "{:?}", core::str::from_utf8(text));
            assert!(!is_signable(text), "{:?}", core::str::from_utf8(text));
        }
        assert!(!is_signable(b""));
        assert!(!is_signable(b"tab\there"));
    }

    const ADDRESS: &[u8] = b"kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs";

    /// A record reads back as written, a text holding the marker included; a
    /// missing final line break is taken; anything else is not a record.
    #[test]
    fn a_record_reads_back_as_written() {
        let signature = [b'a'; SIGNATURE_HEX];
        for text in [
            &b"Hello Kaspa!"[..],
            b"two\nlines",
            b"holds\n-----BEGIN SIGNATURE-----\nitself",
        ] {
            let mut out = [0u8; 512];
            let n = write(text, ADDRESS, &signature, &mut out).unwrap();
            assert_eq!(n, text.len() + ADDRESS.len() + SIGNATURE_HEX + OVERHEAD);
            let parts = read(&out[..n]).unwrap();
            assert_eq!(&out[parts.text.clone()], text);
            assert_eq!(&out[parts.address.clone()], ADDRESS);
            assert_eq!(&out[parts.signature.clone()], &signature[..]);
            assert_eq!(read(&out[..n - 1]), Some(parts), "no final line break");
            assert!(read(&out[1..n]).is_none());
            assert!(read(&out[..n - 2]).is_none());
        }
        let mut short = [0u8; 64];
        assert!(write(b"x", ADDRESS, &signature, &mut short).is_none());
        let mut out = [0u8; 512];
        let n = write(b"x", ADDRESS, &[b'g'; SIGNATURE_HEX], &mut out).unwrap();
        assert!(read(&out[..n]).is_none(), "not hex");
        assert!(read(b"Hello Kaspa!").is_none());
    }
}
