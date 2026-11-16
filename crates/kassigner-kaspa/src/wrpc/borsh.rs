// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Borsh as a node writes it, read in place.
//!
//! The borsh crate's 1.x rules: integers little-endian, a `bool` one byte,
//! 0 or 1, an `Option` a 0 or 1 tag then the value, a `Vec<u8>` or `String`
//! a `u32` length then the bytes, a `String` UTF-8, an `f64` never NaN.
//! Over it, workflow-serializer's: a `serialize!` struct is a payload, a
//! `u32` length then the struct, which a reader may stop short of; so a
//! node appends fields an older reader skips.
//!
//! An error is the offset in the message where it goes wrong.

use super::json::At;

/// A reader over `s[i..end]`.
#[derive(Clone, Debug)]
pub(super) struct Reader<'a> {
    s: &'a [u8],
    i: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    /// Over `s[start..end]`; an `end` past the message is the message's.
    pub(super) fn new(s: &'a [u8], start: usize, end: usize) -> Self {
        Reader {
            s,
            i: start,
            end: end.min(s.len()),
        }
    }

    /// The message it reads.
    pub(super) fn message(&self) -> &'a [u8] {
        self.s
    }

    /// Where the next read starts.
    pub(super) fn at(&self) -> usize {
        self.i
    }

    /// Where this reader stops.
    pub(super) fn end(&self) -> usize {
        self.end
    }

    pub(super) fn bytes(&mut self, n: usize) -> Result<&'a [u8], At> {
        let end = self
            .i
            .checked_add(n)
            .filter(|&e| e <= self.end)
            .ok_or(self.i)?;
        let b = self.s.get(self.i..end).ok_or(self.i)?;
        self.i = end;
        Ok(b)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], At> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }

    pub(super) fn u8(&mut self) -> Result<u8, At> {
        Ok(self.array::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, At> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, At> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, At> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// An `f64`; NaN is refused, as borsh refuses it.
    pub(super) fn f64(&mut self) -> Result<f64, At> {
        let at = self.i;
        let v = f64::from_le_bytes(self.array()?);
        if v.is_nan() {
            Err(at)
        } else {
            Ok(v)
        }
    }

    pub(super) fn bool(&mut self) -> Result<bool, At> {
        let at = self.i;
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(at),
        }
    }

    /// An `Option`'s tag: whether a value follows.
    pub(super) fn some(&mut self) -> Result<bool, At> {
        self.bool()
    }

    /// A `u32` length and as many bytes: a `Vec<u8>`.
    pub(super) fn vec(&mut self) -> Result<&'a [u8], At> {
        let n = self.u32()?;
        self.bytes(usize::try_from(n).map_err(|_| self.i)?)
    }

    /// A `String`: a `Vec<u8>` that is UTF-8.
    pub(super) fn string(&mut self) -> Result<&'a str, At> {
        let at = self.i + 4;
        let b = self.vec()?;
        core::str::from_utf8(b).map_err(|e| at + e.valid_up_to())
    }

    /// A payload: a reader over the struct it holds; this one moves past.
    pub(super) fn payload(&mut self) -> Result<Reader<'a>, At> {
        let n = self.u32()?;
        let start = self.i;
        self.bytes(usize::try_from(n).map_err(|_| self.i)?)?;
        Ok(Reader {
            s: self.s,
            i: start,
            end: self.i,
        })
    }

    /// Everything read: borsh's `try_from_slice` refuses bytes left over.
    pub(super) fn done(&self) -> Result<(), At> {
        if self.i == self.end {
            Ok(())
        } else {
            Err(self.i)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Borsh's rules, every read bounded: a length past the end is refused
    /// where it is, and a payload's reader stops at its end.
    #[test]
    fn borshs_rules_and_every_read_bounded() {
        let s = [
            1, 0x34, 0x12, 2, 0, 0, 0, b'h', b'i', 5, 0, 0, 0, 7, 9, 9, 9, 9, 2,
        ];
        let mut r = Reader::new(&s, 0, s.len());
        assert_eq!(r.bool(), Ok(true));
        assert_eq!(r.u16(), Ok(0x1234));
        assert_eq!(r.string(), Ok("hi"));
        let mut p = r.payload().unwrap();
        assert_eq!((p.at(), p.end()), (13, 18));
        assert_eq!(p.u8(), Ok(7));
        assert_eq!(p.u64(), Err(14));
        assert_eq!(r.at(), 18);
        assert_eq!(r.bool(), Err(18));
        assert_eq!(r.done(), Ok(()));

        let long = [9, 0, 0, 0, 1];
        assert_eq!(Reader::new(&long, 0, 5).vec(), Err(4));
        let huge = [0xff, 0xff, 0xff, 0xff];
        assert_eq!(Reader::new(&huge, 0, 4).payload().map(|_| ()), Err(4));
        let nan = f64::NAN.to_le_bytes();
        assert_eq!(Reader::new(&nan, 0, 8).f64(), Err(0));
        let bad = [2, 0, 0, 0, 0xc3, 0x28];
        assert_eq!(Reader::new(&bad, 0, 6).string(), Err(4));
        assert_eq!(Reader::new(&s, 0, 99).end(), s.len());
    }
}
