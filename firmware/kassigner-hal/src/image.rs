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

//! The running image, hashed as its file is.
//!
//! The verification screen shows the SHA-256 of the image in flash up to the
//! end of the image proper: the unsigned `.bin` the build writes, so it
//! matches `sha256sum` of that file and of a Docker rebuild from source.
//!
//! The signed `.bin` adds `0xFF` padding to the next 4 KB and the Secure
//! Boot signature sector, neither hashed: each signing gives a new
//! signature, which no rebuild could reproduce. Secure Boot checks the
//! owner's signature, under the key whose digest is burned in the unit,
//! before this code runs; a release is vouched for by its signed
//! `SHA256SUMS`. The hash is computed at every boot and held in RAM: the
//! unit keeps no state, and the hash is no secret.
//!
//! The image ends as the ESP-IDF image format says: a 24-byte header whose
//! second byte counts the segments and whose last byte flags an appended
//! SHA-256; each segment, an 8-byte header (load address, length) and its
//! bytes; zeros up to one byte short of a 16-byte boundary and a checksum
//! byte; then, if flagged, the 32-byte digest.
//!
//! That digest, which espflash always appends, is the SHA-256 of everything
//! before it; the hash compares the two, so a misread or incomplete image
//! gives [`Error::Mismatch`], never a number.
//!
//! A board implements [`Image`] over its own flash, with the unsafe that
//! takes; the arithmetic here is the same on every board and host-tested.

use core::fmt;
use sha2::{Digest, Sha256};

/// The first byte of an image.
pub const MAGIC: u8 = 0xE9;

/// Bytes in the image header.
const HEADER: u32 = 24;

/// Bytes in a segment's header: its load address and its length.
const SEGMENT_HEADER: u32 = 8;

/// The most segments an image may have (ESP-IDF's `ESP_IMAGE_MAX_SEGMENTS`).
pub const MAX_SEGMENTS: u8 = 16;

/// Where in the header the appended-digest flag sits.
const HASH_APPENDED: usize = 23;

/// Bytes of the appended digest.
const DIGEST: u32 = 32;

/// Bytes read at a time while hashing.
pub const CHUNK: usize = 4096;

/// A read from flash that did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadFailed;

/// The running image's bytes, as a board reads them from its flash.
pub trait Image {
    /// Fill `buf` with the image's bytes from `offset`, counted from the
    /// image's first byte.
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadFailed>;

    /// Bytes readable from the image's first byte, to the end of the flash;
    /// an image claiming to run past it is refused.
    fn limit(&self) -> u32;
}

/// Why no hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The board could not find the image running, or a way to read it.
    NotFound,
    /// The board could not read its flash.
    Read,
    /// The first byte is not an image's.
    NotAnImage,
    /// More segments than an image may have.
    Segments,
    /// The image would run past the end of the flash.
    TooLong,
    /// The image's own appended digest does not match its bytes as read.
    Mismatch,
}

impl From<ReadFailed> for Error {
    fn from(_: ReadFailed) -> Self {
        Error::Read
    }
}

/// The image, measured and hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hashed {
    /// The unsigned `.bin`'s size.
    pub len: u32,
    /// The unsigned `.bin`'s SHA-256.
    pub sha256: [u8; 32],
}

impl fmt::Display for Hashed {
    /// `912000 bytes, sha256 67d4a50b...`, all 64 digits as `sha256sum`
    /// writes them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes, sha256 ", self.len)?;
        self.sha256.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Where the image ends and whether its digest is appended, from its header
/// and its segments' headers.
pub fn extent<I: Image + ?Sized>(image: &mut I) -> Result<(u32, bool), Error> {
    let mut header = [0u8; HEADER as usize];
    image.read(0, &mut header)?;
    if header[0] != MAGIC {
        return Err(Error::NotAnImage);
    }
    let segments = header[1];
    if segments > MAX_SEGMENTS {
        return Err(Error::Segments);
    }
    let appended = header[HASH_APPENDED] == 1;
    let limit = image.limit();

    let mut at = HEADER;
    for _ in 0..segments {
        let mut seg = [0u8; SEGMENT_HEADER as usize];
        if at.checked_add(SEGMENT_HEADER).is_none_or(|end| end > limit) {
            return Err(Error::TooLong);
        }
        image.read(at, &mut seg)?;
        let len = u32::from_le_bytes([seg[4], seg[5], seg[6], seg[7]]);
        at = at
            .checked_add(SEGMENT_HEADER)
            .and_then(|a| a.checked_add(len))
            .ok_or(Error::TooLong)?;
    }
    // Zeros, then the checksum byte as the last of a 16-byte block: the end
    // is the image so far plus one byte, rounded up to 16.
    let mut end = at
        .checked_add(1 + 15)
        .map(|a| a & !15)
        .ok_or(Error::TooLong)?;
    if appended {
        end = end.checked_add(DIGEST).ok_or(Error::TooLong)?;
    }
    if end > limit {
        return Err(Error::TooLong);
    }
    Ok((end, appended))
}

/// The image's length and SHA-256, its appended digest checked on the way.
pub fn hash<I: Image + ?Sized>(image: &mut I) -> Result<Hashed, Error> {
    let (len, appended) = extent(image)?;
    let body = if appended { len - DIGEST } else { len };

    let mut hasher = Sha256::new();
    let mut buf = [0u8; CHUNK];
    let mut at = 0;
    while at < body {
        let n = (body - at).min(CHUNK as u32);
        let part = &mut buf[..n as usize];
        image.read(at, part)?;
        hasher.update(&*part);
        at += n;
    }
    if appended {
        let mut digest = [0u8; DIGEST as usize];
        image.read(body, &mut digest)?;
        if hasher.clone().finalize()[..] != digest[..] {
            return Err(Error::Mismatch);
        }
        hasher.update(digest);
    }
    Ok(Hashed {
        len,
        sha256: hasher.finalize().into(),
    })
}
