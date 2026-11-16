// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The EXIF block: a TIFF file inside an APP1 segment (EXIF 2.32 §4.5,
//! TIFF 6.0 §2).
//!
//! After `Exif\0\0`: the byte order (`II` little, `MM` big endian), 42,
//! and the first directory's offset; every offset counts from that header.
//! A directory is a count, twelve-byte entries in tag order, and the next
//! directory's offset or zero. An entry is a tag, a type, a count, and four
//! bytes holding the value if it fits, else its offset.
//!
//! [`Tiff`] reads either order; [`Writer`] writes the one it is given. Every
//! offset is checked, with checked sums (`usize` is 32 bits on a unit),
//! before it is followed: a damaged block gives `None`, never a panic.

use crate::segment::{APP1, EXIF_HEADER};
use crate::Error;

/// Tags this project reads or writes. The numbers are the specification's.
pub mod tag {
    pub const IMAGE_DESCRIPTION: u16 = 0x010E;
    pub const MAKE: u16 = 0x010F;
    pub const MODEL: u16 = 0x0110;
    pub const ORIENTATION: u16 = 0x0112;
    pub const X_RESOLUTION: u16 = 0x011A;
    pub const Y_RESOLUTION: u16 = 0x011B;
    pub const RESOLUTION_UNIT: u16 = 0x0128;
    pub const SOFTWARE: u16 = 0x0131;
    pub const DATE_TIME: u16 = 0x0132;
    /// Offset of the Exif sub-directory.
    pub const EXIF_IFD: u16 = 0x8769;
    pub const EXIF_VERSION: u16 = 0x9000;
    pub const USER_COMMENT: u16 = 0x9286;
    pub const FLASHPIX_VERSION: u16 = 0xA000;
    pub const COLOR_SPACE: u16 = 0xA001;
    pub const PIXEL_X_DIMENSION: u16 = 0xA002;
    pub const PIXEL_Y_DIMENSION: u16 = 0xA003;
}

/// Field types (TIFF 6.0, section 2, "Types").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    Byte = 1,
    Ascii = 2,
    Short = 3,
    Long = 4,
    Rational = 5,
    Undefined = 7,
    SLong = 9,
    SRational = 10,
}

impl Kind {
    /// Bytes of one value.
    pub const fn size(self) -> usize {
        match self {
            Kind::Byte | Kind::Ascii | Kind::Undefined => 1,
            Kind::Short => 2,
            Kind::Long | Kind::SLong => 4,
            Kind::Rational | Kind::SRational => 8,
        }
    }

    const fn from_u16(v: u16) -> Option<Kind> {
        Some(match v {
            1 => Kind::Byte,
            2 => Kind::Ascii,
            3 => Kind::Short,
            4 => Kind::Long,
            5 => Kind::Rational,
            7 => Kind::Undefined,
            9 => Kind::SLong,
            10 => Kind::SRational,
            _ => return None,
        })
    }
}

/// Bytes of the character-set field that opens a `UserComment` value.
pub const USER_COMMENT_CHARSET: usize = 8;

/// One directory entry, as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub tag: u16,
    /// The type as written; [`Entry::kind`] is `None` for an unknown one.
    pub kind: u16,
    pub count: u32,
    /// Where the entry sits in the block.
    pub at: usize,
    /// The entry's twelve bytes, to copy it forward unchanged.
    pub raw: [u8; 12],
}

impl Entry {
    pub const fn kind(&self) -> Option<Kind> {
        Kind::from_u16(self.kind)
    }

    /// Bytes the value takes, or `None` for an unknown type or a count that
    /// overflows.
    pub fn value_len(&self) -> Option<usize> {
        let size = self.kind()?.size();
        usize::try_from(self.count).ok()?.checked_mul(size)
    }
}

/// A TIFF block, borrowed, in either byte order.
#[derive(Clone, Copy)]
pub struct Tiff<'a> {
    bytes: &'a [u8],
    pub little_endian: bool,
}

impl<'a> Tiff<'a> {
    /// The block inside a whole APP1 segment, `0xFF 0xE1` and its length
    /// first.
    pub fn of_app1(segment: &'a [u8]) -> Option<Self> {
        if segment.len() < 10 || segment[0] != 0xFF || segment[1] != APP1 {
            return None;
        }
        if segment[4..10] != EXIF_HEADER {
            return None;
        }
        Self::new(&segment[10..])
    }

    /// A block from its header on.
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let little_endian = match (bytes[0], bytes[1]) {
            (0x49, 0x49) => true,
            (0x4D, 0x4D) => false,
            _ => return None,
        };
        let t = Tiff {
            bytes,
            little_endian,
        };
        if t.u16_at(2)? != 42 {
            return None;
        }
        Some(t)
    }

    /// The whole block.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn u16_at(&self, at: usize) -> Option<u16> {
        let b = self.bytes.get(at..at.checked_add(2)?)?;
        Some(if self.little_endian {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    }

    pub fn u32_at(&self, at: usize) -> Option<u32> {
        let b = self.bytes.get(at..at.checked_add(4)?)?;
        Some(if self.little_endian {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    /// Offset of the first directory.
    pub fn ifd0(&self) -> Option<usize> {
        let off = usize::try_from(self.u32_at(4)?).ok()?;
        (off.checked_add(2)? <= self.bytes.len()).then_some(off)
    }

    /// Entries in the directory at `ifd`. Plain sums here and in
    /// [`Tiff::entry`] and [`Tiff::next_ifd`]: `ifd` is inside the block and
    /// a count fits in 16 bits.
    pub fn entry_count(&self, ifd: usize) -> Option<usize> {
        let n = usize::from(self.u16_at(ifd)?);
        (ifd + 2 + n * 12 + 4 <= self.bytes.len()).then_some(n)
    }

    /// Entry `i` of the directory at `ifd`.
    pub fn entry(&self, ifd: usize, i: usize) -> Option<Entry> {
        if i >= self.entry_count(ifd)? {
            return None;
        }
        let at = ifd + 2 + i * 12;
        let mut raw = [0u8; 12];
        raw.copy_from_slice(self.bytes.get(at..at + 12)?);
        Some(Entry {
            tag: self.u16_at(at)?,
            kind: self.u16_at(at + 2)?,
            count: self.u32_at(at + 4)?,
            at,
            raw,
        })
    }

    /// The directory's entries, in order.
    pub fn entries(&self, ifd: usize) -> impl Iterator<Item = Entry> + '_ {
        let n = self.entry_count(ifd).unwrap_or(0);
        (0..n).filter_map(move |i| self.entry(ifd, i))
    }

    /// Offset of the directory after the one at `ifd`, 0 for none.
    pub fn next_ifd(&self, ifd: usize) -> Option<u32> {
        let n = self.entry_count(ifd)?;
        self.u32_at(ifd + 2 + n * 12)
    }

    /// The first entry with `tag` in the directory at `ifd`.
    pub fn find(&self, ifd: usize, tag: u16) -> Option<Entry> {
        self.entries(ifd).find(|e| e.tag == tag)
    }

    /// An entry's value bytes: inline when four bytes or fewer, else at its
    /// offset. `e` may come from elsewhere (its fields are public), so its
    /// place is a checked sum.
    pub fn value(&self, e: &Entry) -> Option<&'a [u8]> {
        let len = e.value_len()?;
        let field = e.at.checked_add(8)?;
        if len <= 4 {
            // Inline: the entry's last four bytes.
            return self.bytes.get(field..field.checked_add(len)?);
        }
        let off = usize::try_from(self.u32_at(field)?).ok()?;
        self.bytes.get(off..off.checked_add(len)?)
    }

    /// The four-byte field as a number: an offset, or an inline LONG or
    /// SHORT value.
    pub fn field_u32(&self, e: &Entry) -> Option<u32> {
        let field = e.at.checked_add(8)?;
        match e.kind()? {
            Kind::Short if e.count == 1 => self.u16_at(field).map(u32::from),
            _ => self.u32_at(field),
        }
    }

    /// The `UserComment` of the first directory, after its character-set
    /// field.
    pub fn user_comment(&self) -> Option<&'a [u8]> {
        let e = self.find(self.ifd0()?, tag::USER_COMMENT)?;
        let v = self.value(&e)?;
        v.get(USER_COMMENT_CHARSET..)
    }

    /// An ASCII entry of the first directory, its terminating NUL dropped.
    pub fn ascii(&self, t: u16) -> Option<&'a [u8]> {
        let e = self.find(self.ifd0()?, t)?;
        if e.kind()? != Kind::Ascii {
            return None;
        }
        let v = self.value(&e)?;
        Some(v.strip_suffix(&[0]).unwrap_or(v))
    }
}

/// What an entry's four-byte field holds.
#[derive(Clone, Copy, Debug)]
pub enum Field {
    /// A value of four bytes or fewer, padded with zeros on the right.
    Inline([u8; 4]),
    /// An offset into the block.
    Offset(u32),
}

/// Builds an APP1 segment holding a TIFF block in the caller's buffer. The
/// caller writes directories ([`Writer::ifd`], [`Writer::entry`]), data
/// ([`Writer::put`]) and the first directory's offset
/// ([`Writer::set_ifd0`]); offsets are block-relative, as
/// [`Writer::offset`] gives them.
pub struct Writer<'o> {
    out: &'o mut [u8],
    pos: usize,
    little_endian: bool,
}

/// Bytes before the TIFF header in the segment: marker, length, `Exif\0\0`.
const TIFF_START: usize = 10;

impl<'o> Writer<'o> {
    /// Start a segment, with the TIFF header and its first-directory offset
    /// left at zero.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall`.
    pub fn new(out: &'o mut [u8], little_endian: bool) -> Result<Self, Error> {
        if out.len() < TIFF_START + 8 {
            return Err(Error::BufferTooSmall);
        }
        out[0] = 0xFF;
        out[1] = APP1;
        out[2..4].copy_from_slice(&[0, 0]);
        out[4..10].copy_from_slice(&EXIF_HEADER);
        let mut w = Writer {
            out,
            pos: TIFF_START,
            little_endian,
        };
        w.put(if little_endian { b"II" } else { b"MM" })?;
        w.u16(42)?;
        w.u32(0)?;
        Ok(w)
    }

    /// The current position, block-relative.
    pub const fn offset(&self) -> usize {
        self.pos - TIFF_START
    }

    pub fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .pos
            .checked_add(bytes.len())
            .ok_or(Error::BufferTooSmall)?;
        if end > self.out.len() {
            return Err(Error::BufferTooSmall);
        }
        self.out[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub fn u16(&mut self, v: u16) -> Result<(), Error> {
        let b = if self.little_endian {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.put(&b)
    }

    pub fn u32(&mut self, v: u32) -> Result<(), Error> {
        let b = if self.little_endian {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.put(&b)
    }

    /// A zero byte if the position is odd: TIFF wants word-aligned offsets.
    pub fn align(&mut self) -> Result<(), Error> {
        if self.offset() % 2 == 1 {
            self.put(&[0])?;
        }
        Ok(())
    }

    /// Open a directory of `count` entries. The entries follow, then
    /// [`Writer::next_ifd`].
    pub fn ifd(&mut self, count: u16) -> Result<(), Error> {
        self.u16(count)
    }

    /// One entry.
    pub fn entry(&mut self, tag: u16, kind: Kind, count: u32, field: Field) -> Result<(), Error> {
        self.u16(tag)?;
        self.u16(kind as u16)?;
        self.u32(count)?;
        match field {
            Field::Inline(b) => self.put(&b),
            Field::Offset(o) => self.u32(o),
        }
    }

    /// An entry whose single SHORT value sits inline.
    pub fn short(&mut self, tag: u16, v: u16) -> Result<(), Error> {
        let b = if self.little_endian {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.entry(tag, Kind::Short, 1, Field::Inline([b[0], b[1], 0, 0]))
    }

    /// An entry whose single LONG value sits inline.
    pub fn long(&mut self, tag: u16, v: u32) -> Result<(), Error> {
        let b = if self.little_endian {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        };
        self.entry(tag, Kind::Long, 1, Field::Inline(b))
    }

    /// An entry copied as is, offsets included.
    pub fn raw_entry(&mut self, e: &Entry) -> Result<(), Error> {
        self.put(&e.raw)
    }

    /// Close a directory with the offset of the next one, 0 for none.
    pub fn next_ifd(&mut self, offset: u32) -> Result<(), Error> {
        self.u32(offset)
    }

    /// Point the header at the first directory.
    pub fn set_ifd0(&mut self, offset: u32) {
        let b = if self.little_endian {
            offset.to_le_bytes()
        } else {
            offset.to_be_bytes()
        };
        self.out[TIFF_START + 4..TIFF_START + 8].copy_from_slice(&b);
    }

    /// Fill in the segment's length and return the bytes written.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall` for a segment past what a length field can say.
    pub fn finish(self) -> Result<usize, Error> {
        let len = self.pos - 2;
        let len = u16::try_from(len).map_err(|_| Error::BufferTooSmall)?;
        self.out[2..4].copy_from_slice(&len.to_be_bytes());
        Ok(self.pos)
    }
}
