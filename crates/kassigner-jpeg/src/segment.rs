// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Marker segments (T.81 §B.1): start-of-image, segments (`0xFF`, a marker
//! and a big-endian length counting itself), start-of-scan, entropy-coded
//! data, end-of-image. This module walks up to start-of-scan; the rest is
//! [`crate::scan`]'s.

use crate::Error;

/// Start of image.
pub const SOI: u8 = 0xD8;
/// End of image.
pub const EOI: u8 = 0xD9;
/// Start of scan: the last segment before the entropy-coded data.
pub const SOS: u8 = 0xDA;
/// Define restart interval.
pub const DRI: u8 = 0xDD;
/// Define Huffman tables.
pub const DHT: u8 = 0xC4;
/// Application segment 0: JFIF.
pub const APP0: u8 = 0xE0;
/// Application segment 1: EXIF, and also XMP.
pub const APP1: u8 = 0xE1;

/// What an APP1 segment's payload begins with when it carries EXIF.
pub const EXIF_HEADER: [u8; 6] = *b"Exif\0\0";

/// One segment of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// The marker byte after `0xFF`.
    pub marker: u8,
    /// Offset of the `0xFF` that introduces it.
    pub start: usize,
    /// One past its last byte.
    pub end: usize,
}

impl Segment {
    /// The bytes after the length field; empty for a segment that is not
    /// `file`'s (its fields are public).
    pub fn payload<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        let from = self.start.saturating_add(4).min(self.end);
        file.get(from..self.end).unwrap_or(&[])
    }
}

/// Whether a frame-header marker: SOF0 to SOF15, which share their range
/// with DHT (`0xC4`), JPG (`0xC8`) and DAC (`0xCC`).
pub const fn is_frame_header(marker: u8) -> bool {
    matches!(marker, 0xC0..=0xCF) && marker != DHT && marker != 0xC8 && marker != 0xCC
}

/// Whether a marker stands alone, with no length field after it.
const fn standalone(marker: u8) -> bool {
    matches!(marker, 0x01 | 0xD0..=0xD9)
}

/// Whether `file` begins with a start-of-image marker.
pub fn is_jpeg(file: &[u8]) -> bool {
    file.len() >= 2 && file[0] == 0xFF && file[1] == SOI
}

/// The segments after start-of-image up to and including start-of-scan.
/// Fill bytes and standalone markers are skipped. Stops at start-of-scan,
/// end-of-image or anything that does not parse; check the last marker to
/// tell which.
pub fn segments(file: &[u8]) -> Segments<'_> {
    Segments {
        file,
        pos: if is_jpeg(file) { 2 } else { file.len() },
        done: false,
    }
}

/// See [`segments`].
pub struct Segments<'a> {
    file: &'a [u8],
    pos: usize,
    done: bool,
}

impl Iterator for Segments<'_> {
    type Item = Segment;

    fn next(&mut self) -> Option<Segment> {
        if self.done {
            return None;
        }
        loop {
            let f = self.file;
            if self.pos + 4 > f.len() {
                self.done = true;
                return None;
            }
            if f[self.pos] != 0xFF {
                // A damaged header: stop.
                self.done = true;
                return None;
            }
            let marker = f[self.pos + 1];
            if marker == 0xFF {
                // A fill byte before a marker, allowed by B.1.1.2.
                self.pos += 1;
                continue;
            }
            if marker == EOI {
                self.done = true;
                return None;
            }
            if standalone(marker) {
                self.pos += 2;
                continue;
            }
            let len = usize::from(u16::from_be_bytes([f[self.pos + 2], f[self.pos + 3]]));
            if len < 2 {
                self.done = true;
                return None;
            }
            let end = match self.pos.checked_add(2).and_then(|v| v.checked_add(len)) {
                Some(e) if e <= f.len() => e,
                _ => {
                    self.done = true;
                    return None;
                }
            };
            let seg = Segment {
                marker,
                start: self.pos,
                end,
            };
            self.pos = end;
            if marker == SOS {
                self.done = true;
            }
            return Some(seg);
        }
    }
}

/// The image's width and height, from its frame header.
pub fn dimensions(file: &[u8]) -> Option<(u16, u16)> {
    let sof = segments(file).find(|s| is_frame_header(s.marker))?;
    let p = sof.payload(file);
    if p.len() < 5 {
        return None;
    }
    let height = u16::from_be_bytes([p[1], p[2]]);
    let width = u16::from_be_bytes([p[3], p[4]]);
    if width == 0 || height == 0 {
        return None;
    }
    Some((width, height))
}

/// Whether a segment is an APP1 carrying EXIF, rather than XMP or another
/// APP1 use.
pub fn is_exif(file: &[u8], seg: &Segment) -> bool {
    seg.marker == APP1 && seg.payload(file).starts_with(&EXIF_HEADER)
}

/// The first EXIF APP1 segment, whole: from its `0xFF` to its end.
pub fn exif_app1(file: &[u8]) -> Option<Segment> {
    segments(file).find(|s| is_exif(file, s))
}

/// Offset of the start-of-scan marker, or `None` for a file with none in
/// its header.
pub fn scan_start(file: &[u8]) -> Option<usize> {
    segments(file).find(|s| s.marker == SOS).map(|s| s.start)
}

/// Write `file` to `out` with `app1` (a whole segment) as its only EXIF
/// segment, after any leading APP0s, and return the length. Everything else
/// is copied as is.
///
/// # Errors
///
/// `NotJpeg`; `Malformed` for a header with no start-of-scan;
/// `BufferTooSmall`.
pub fn replace_exif(file: &[u8], app1: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if !is_jpeg(file) {
        return Err(Error::NotJpeg);
    }
    let sos = scan_start(file).ok_or(Error::Malformed)?;
    let mut w = Cursor { out, pos: 0 };
    w.put(&file[..2])?;
    let mut placed = false;
    for seg in segments(file) {
        if seg.marker == SOS {
            break;
        }
        if !placed && seg.marker != APP0 {
            w.put(app1)?;
            placed = true;
        }
        if is_exif(file, &seg) {
            continue;
        }
        w.put(&file[seg.start..seg.end])?;
    }
    if !placed {
        w.put(app1)?;
    }
    w.put(&file[sos..])?;
    Ok(w.pos)
}

struct Cursor<'o> {
    out: &'o mut [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
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
}
