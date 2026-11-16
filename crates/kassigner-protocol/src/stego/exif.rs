// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The Descriptor carrier: the payload in `UserComment`, the descriptor in
//! `ImageDescription`, inside the photo's EXIF block.
//!
//! No camera writes a block of two entries, and the entry count was the
//! most telling feature over 1.3 million images in "Digital Image
//! Authentication from JPEG Headers". So the block is, by preference:
//!
//! 1. **The photo's own,** its TIFF block copied whole so every offset
//!    holds, with a new first directory appended: the photo's entries and
//!    our two, in tag order. The old directory stays, unreferenced.
//! 2. **A software-export block,** for a photo with none. It names a
//!    program rather than a camera, which would not match a messaging app's
//!    quantization tables; program and date come from the caller's random
//!    bytes.
//! 3. **Two entries,** when the frame's size cannot be read: findable, but
//!    a backup that opens beats none.
//!
//! Each is read back before use; one that fails drops to the next.

use kassigner_jpeg::exif::{tag, Field, Kind, Tiff, Writer, USER_COMMENT_CHARSET};
use kassigner_jpeg::segment;
use kassigner_jpeg::Error as JpegError;

/// Program names for the software-export block: ordinary re-encoders with
/// no header signature of their own.
pub const SOFTWARE: [&str; 8] = [
    "GIMP 2.10.38",
    "ImageMagick 7.1.1-39",
    "Paint.NET 5.1.2",
    "IrfanView 4.70",
    "XnView MP 1.8.3",
    "darktable 4.8.1",
    "digiKam 8.4.0",
    "Photos 1.0",
];

/// Random bytes the template draws its program name and date from.
pub const RANDOM: usize = 8;

/// Room past the host block that [`build`] asks of `out`: enough for a new
/// directory of 140 host entries and our two, with our data at its longest.
/// A larger directory needs a larger `out` or drops to the next builder.
pub const APP1_EXTRA: usize = 2048;

/// Bytes the software-export or minimal block takes at most.
pub const APP1_TEMPLATE_MAX: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExifError {
    /// None of the three builders produced a block that read back.
    Build,
    /// The output cannot hold the block.
    BufferTooSmall,
    Jpeg(JpegError),
}

impl From<JpegError> for ExifError {
    fn from(e: JpegError) -> Self {
        ExifError::Jpeg(e)
    }
}

/// The two tags this carrier owns.
const OURS: [u16; 2] = [tag::IMAGE_DESCRIPTION, tag::USER_COMMENT];

/// The payload in a photo's `UserComment`, after its character-set field.
pub fn read_payload(file: &[u8]) -> Option<&[u8]> {
    let seg = segment::exif_app1(file)?;
    let t = Tiff::of_app1(&file[seg.start..seg.end])?;
    let p = t.user_comment()?;
    (!p.is_empty()).then_some(p)
}

/// The caption in a photo's `ImageDescription`.
pub fn read_descriptor(file: &[u8]) -> Option<&[u8]> {
    let seg = segment::exif_app1(file)?;
    let t = Tiff::of_app1(&file[seg.start..seg.end])?;
    t.ascii(tag::IMAGE_DESCRIPTION)
}

/// Build the block for `file` into `out`: the photo's own carried forward,
/// else the software-export one (named and dated from `random`), else the
/// minimal one, each read back first. Returns the block's length.
///
/// # Errors
///
/// `Build` when nothing reads back; `BufferTooSmall` for an `out` shorter
/// than the host block plus [`APP1_EXTRA`], or than [`APP1_TEMPLATE_MAX`].
pub fn build(
    file: &[u8],
    descriptor: &[u8],
    payload: &[u8],
    random: &[u8; RANDOM],
    out: &mut [u8],
) -> Result<usize, ExifError> {
    if let Some(seg) = segment::exif_app1(file) {
        let host = &file[seg.start..seg.end];
        if out.len() < host.len() + APP1_EXTRA {
            return Err(ExifError::BufferTooSmall);
        }
        if let Ok(n) = carry_forward(host, descriptor, payload, out) {
            if reads_back(&out[..n], descriptor, payload) {
                return Ok(n);
            }
        }
    }
    if out.len() < APP1_TEMPLATE_MAX {
        return Err(ExifError::BufferTooSmall);
    }
    if let Some((w, h)) = segment::dimensions(file) {
        if let Ok(n) = template(descriptor, payload, w, h, random, out) {
            if reads_back(&out[..n], descriptor, payload) {
                return Ok(n);
            }
        }
    }
    if let Ok(n) = minimal(descriptor, payload, out) {
        if reads_back(&out[..n], descriptor, payload) {
            return Ok(n);
        }
    }
    Err(ExifError::Build)
}

/// Whether a built block gives back exactly what went in.
fn reads_back(app1: &[u8], descriptor: &[u8], payload: &[u8]) -> bool {
    let Some(t) = Tiff::of_app1(app1) else {
        return false;
    };
    t.ascii(tag::IMAGE_DESCRIPTION) == Some(descriptor) && t.user_comment() == Some(payload)
}

/// Put `app1` after the leading APP0s of the JPEG in `buf[..len]`, every
/// old EXIF block taken out, and return the new length. In place, since for
/// Both `buf` already holds the re-encoded photo. `buf` holds at least
/// `len + app1.len()`.
pub fn place(buf: &mut [u8], len: usize, app1: &[u8]) -> Result<usize, ExifError> {
    if len > buf.len() || buf.len() - len < app1.len() {
        return Err(ExifError::BufferTooSmall);
    }
    if !segment::is_jpeg(&buf[..len]) {
        return Err(ExifError::Jpeg(JpegError::NotJpeg));
    }
    // Take out every EXIF block, last first, so earlier offsets hold.
    let mut len = len;
    loop {
        let last = segment::segments(&buf[..len])
            .filter(|s| segment::is_exif(&buf[..len], s))
            .last();
        let Some(seg) = last else { break };
        buf.copy_within(seg.end..len, seg.start);
        len -= seg.end - seg.start;
    }
    // Where ours goes: after the leading APP0s.
    let at = segment::segments(&buf[..len])
        .find(|s| s.marker != segment::APP0)
        .map_or(len, |s| s.start);
    if segment::scan_start(&buf[..len]).is_none() {
        return Err(ExifError::Jpeg(JpegError::Malformed));
    }
    buf.copy_within(at..len, at + app1.len());
    buf[at..at + app1.len()].copy_from_slice(app1);
    Ok(len + app1.len())
}

/// Builder 1: the host's block carried forward with our two entries.
fn carry_forward(
    host: &[u8],
    descriptor: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, ExifError> {
    let t = Tiff::of_app1(host).ok_or(ExifError::Build)?;
    let block = t.bytes();
    let ifd0 = t.ifd0().ok_or(ExifError::Build)?;
    let n = t.entry_count(ifd0).ok_or(ExifError::Build)?;
    if n > 200 {
        return Err(ExifError::Build);
    }
    let kept = t.entries(ifd0).filter(|e| !OURS.contains(&e.tag)).count();
    let total = u16::try_from(kept + 2).map_err(|_| ExifError::Build)?;

    let mut w = Writer::new(out, t.little_endian)?;
    // The host block after its header, where it sat: its offsets hold.
    w.put(&block[8..])?;
    w.align()?;
    let new_ifd0 = w.offset();
    let desc_store = descriptor.len() + 1;
    let uc_store = USER_COMMENT_CHARSET + payload.len();
    let data = new_ifd0 + 2 + usize::from(total) * 12 + 4;
    let desc_at = data;
    let uc_at = data + desc_store;

    w.ifd(total)?;
    let mut wrote_desc = false;
    let mut wrote_uc = false;
    let mut hosts = t
        .entries(ifd0)
        .filter(|e| !OURS.contains(&e.tag))
        .peekable();
    for _ in 0..total {
        let host_tag = hosts.peek().map_or(u16::MAX, |e| e.tag);
        let desc_tag = if wrote_desc {
            u16::MAX
        } else {
            tag::IMAGE_DESCRIPTION
        };
        let uc_tag = if wrote_uc {
            u16::MAX
        } else {
            tag::USER_COMMENT
        };
        if desc_tag <= host_tag && desc_tag <= uc_tag {
            write_description(&mut w, descriptor, desc_at)?;
            wrote_desc = true;
        } else if uc_tag <= host_tag {
            w.entry(
                tag::USER_COMMENT,
                Kind::Undefined,
                uc_store as u32,
                Field::Offset(uc_at as u32),
            )?;
            wrote_uc = true;
        } else if let Some(e) = hosts.next() {
            w.raw_entry(&e)?;
        }
    }
    // The next-directory pointer as the host had it: the thumbnail survives.
    w.next_ifd(t.next_ifd(ifd0).unwrap_or(0))?;
    debug_assert_eq!(w.offset(), desc_at);
    write_description_data(&mut w, descriptor)?;
    w.put(&[0u8; USER_COMMENT_CHARSET])?;
    w.put(payload)?;
    w.set_ifd0(new_ifd0 as u32);
    Ok(w.finish()?)
}

/// `ImageDescription`'s entry: inline when text and NUL fit four bytes, else
/// at `at`, whose slot is reserved either way so later offsets hold.
fn write_description(w: &mut Writer<'_>, descriptor: &[u8], at: usize) -> Result<(), ExifError> {
    let store = descriptor.len() + 1;
    if store <= 4 {
        let mut inline = [0u8; 4];
        inline[..descriptor.len()].copy_from_slice(descriptor);
        w.entry(
            tag::IMAGE_DESCRIPTION,
            Kind::Ascii,
            store as u32,
            Field::Inline(inline),
        )?;
    } else {
        w.entry(
            tag::IMAGE_DESCRIPTION,
            Kind::Ascii,
            store as u32,
            Field::Offset(at as u32),
        )?;
    }
    Ok(())
}

/// `ImageDescription`'s data slot: text and NUL, or as many zeros if inline.
fn write_description_data(w: &mut Writer<'_>, descriptor: &[u8]) -> Result<(), ExifError> {
    let store = descriptor.len() + 1;
    if store <= 4 {
        w.put(&[0u8; 4][..store])?;
    } else {
        w.put(descriptor)?;
        w.put(&[0])?;
    }
    Ok(())
}

/// A plausible `YYYY:MM:DD HH:MM:SS` from random bytes: a unit has no
/// clock, and no two photos should share it.
pub fn date_time(random: &[u8; RANDOM]) -> [u8; 19] {
    let year = 2019 + u32::from(random[0] % 7);
    let month = 1 + u32::from(random[1] % 12);
    let day = 1 + u32::from(random[2] % 28);
    let hour = 6 + u32::from(random[3] % 17);
    let minute = u32::from(random[4] % 60);
    let second = u32::from(random[5] % 60);
    let mut out = *b"0000:00:00 00:00:00";
    let two = |o: &mut [u8], v: u32| {
        o[0] = b'0' + ((v / 10) % 10) as u8;
        o[1] = b'0' + (v % 10) as u8;
    };
    two(&mut out[0..2], year / 100);
    two(&mut out[2..4], year % 100);
    two(&mut out[5..7], month);
    two(&mut out[8..10], day);
    two(&mut out[11..13], hour);
    two(&mut out[14..16], minute);
    two(&mut out[17..19], second);
    out
}

/// Builder 2: a software-export block, little-endian.
fn template(
    descriptor: &[u8],
    payload: &[u8],
    width: u16,
    height: u16,
    random: &[u8; RANDOM],
    out: &mut [u8],
) -> Result<usize, ExifError> {
    let software = SOFTWARE[usize::from(random[6]) % SOFTWARE.len()].as_bytes();
    let date = date_time(random);
    let desc_store = descriptor.len() + 1;
    let sw_store = software.len() + 1;
    let uc_store = USER_COMMENT_CHARSET + payload.len();

    let mut w = Writer::new(out, true)?;
    let ifd0 = w.offset();
    const N0: u16 = 9;
    const N1: u16 = 5;
    let data = ifd0 + 2 + usize::from(N0) * 12 + 4;
    let desc_at = data;
    let xres_at = desc_at + desc_store;
    let yres_at = xres_at + 8;
    let sw_at = yres_at + 8;
    let date_at = sw_at + sw_store;
    let uc_at = date_at + 20;
    let mut exif_at = uc_at + uc_store;
    if exif_at % 2 == 1 {
        exif_at += 1;
    }

    w.ifd(N0)?;
    write_description(&mut w, descriptor, desc_at)?;
    w.short(tag::ORIENTATION, 1)?;
    w.entry(
        tag::X_RESOLUTION,
        Kind::Rational,
        1,
        Field::Offset(xres_at as u32),
    )?;
    w.entry(
        tag::Y_RESOLUTION,
        Kind::Rational,
        1,
        Field::Offset(yres_at as u32),
    )?;
    w.short(tag::RESOLUTION_UNIT, 2)?;
    w.entry(
        tag::SOFTWARE,
        Kind::Ascii,
        sw_store as u32,
        Field::Offset(sw_at as u32),
    )?;
    w.entry(
        tag::DATE_TIME,
        Kind::Ascii,
        20,
        Field::Offset(date_at as u32),
    )?;
    w.long(tag::EXIF_IFD, exif_at as u32)?;
    w.entry(
        tag::USER_COMMENT,
        Kind::Undefined,
        uc_store as u32,
        Field::Offset(uc_at as u32),
    )?;
    w.next_ifd(0)?;

    write_description_data(&mut w, descriptor)?;
    for _ in 0..2 {
        w.u32(72)?;
        w.u32(1)?;
    }
    w.put(software)?;
    w.put(&[0])?;
    w.put(&date)?;
    w.put(&[0])?;
    w.put(&[0u8; USER_COMMENT_CHARSET])?;
    w.put(payload)?;
    w.align()?;
    debug_assert_eq!(w.offset(), exif_at);

    w.ifd(N1)?;
    w.entry(
        tag::EXIF_VERSION,
        Kind::Undefined,
        4,
        Field::Inline(*b"0232"),
    )?;
    w.entry(
        tag::FLASHPIX_VERSION,
        Kind::Undefined,
        4,
        Field::Inline(*b"0100"),
    )?;
    w.short(tag::COLOR_SPACE, 1)?;
    w.long(tag::PIXEL_X_DIMENSION, u32::from(width))?;
    w.long(tag::PIXEL_Y_DIMENSION, u32::from(height))?;
    w.next_ifd(0)?;
    w.set_ifd0(ifd0 as u32);
    Ok(w.finish()?)
}

/// Builder 3: our two entries and nothing else.
fn minimal(descriptor: &[u8], payload: &[u8], out: &mut [u8]) -> Result<usize, ExifError> {
    let desc_store = descriptor.len() + 1;
    let uc_store = USER_COMMENT_CHARSET + payload.len();
    let mut w = Writer::new(out, true)?;
    let ifd0 = w.offset();
    let data = ifd0 + 2 + 2 * 12 + 4;
    w.ifd(2)?;
    write_description(&mut w, descriptor, data)?;
    w.entry(
        tag::USER_COMMENT,
        Kind::Undefined,
        uc_store as u32,
        Field::Offset((data + desc_store) as u32),
    )?;
    w.next_ifd(0)?;
    write_description_data(&mut w, descriptor)?;
    w.put(&[0u8; USER_COMMENT_CHARSET])?;
    w.put(payload)?;
    w.set_ifd0(ifd0 as u32);
    Ok(w.finish()?)
}
