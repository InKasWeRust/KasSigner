// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The carriers, and an export and an extraction over them.
//!
//! A backup subtly wrong would show only the day the seed is needed, so
//! [`export`] reads its output back, both carriers, before it returns.
//! [`extract`] always reads both, since nobody is asked which was used and
//! a stale payload in one must not hide a good one in the other; which
//! opens is level 2's to find out.

use super::blob;
use super::exif::{self, ExifError, RANDOM};
use super::picture::{self, PictureError, Tables, Window};
use super::walk::KEY_SIZE;
use super::PAYLOAD_MAX;
use kassigner_jpeg::Error as JpegError;

/// Where the payload goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// The EXIF block: survives a re-save, lost when metadata is stripped.
    Descriptor,
    /// The coefficients: survives metadata stripping, lost on a re-save.
    Picture,
    /// Both at once: lost only when both happen.
    Both,
}

impl Carrier {
    pub const ALL: [Carrier; 3] = [Carrier::Descriptor, Carrier::Picture, Carrier::Both];

    /// The card's name.
    pub const fn label(self) -> &'static str {
        match self {
            Carrier::Descriptor => "Descriptor",
            Carrier::Picture => "Picture",
            Carrier::Both => "Both",
        }
    }

    /// Where it hides the backup.
    pub const fn description(self) -> &'static str {
        match self {
            Carrier::Descriptor => "In the photo's metadata",
            Carrier::Picture => "In the photo itself",
            Carrier::Both => "In the metadata and the photo",
        }
    }

    const fn metadata(self) -> bool {
        matches!(self, Carrier::Descriptor | Carrier::Both)
    }

    const fn coefficients(self) -> bool {
        matches!(self, Carrier::Picture | Carrier::Both)
    }
}

/// Why an export or an extraction was refused, by name, for the screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StegoError {
    /// Not a JPEG file.
    NotJpeg,
    /// A progressive or otherwise non-baseline JPEG, which Picture cannot use.
    Progressive,
    /// Too few usable coefficients for the payload.
    TooSmall,
    /// A frame larger than this device walks.
    TooLarge,
    /// A damaged header, or a scan cut short.
    Damaged,
    /// No EXIF block could be built that read back.
    Exif,
    /// The result did not read back as written.
    Verify,
    /// A payload, descriptor or buffer outside its bounds.
    Bounds,
}

impl From<JpegError> for StegoError {
    fn from(e: JpegError) -> Self {
        match e {
            JpegError::NotJpeg => StegoError::NotJpeg,
            JpegError::NotBaseline => StegoError::Progressive,
            JpegError::TooLarge => StegoError::TooLarge,
            JpegError::Malformed | JpegError::Truncated => StegoError::Damaged,
            JpegError::BufferTooSmall => StegoError::Bounds,
            // Optimized tables lacking a changed value's code: this photo
            // cannot carry it.
            JpegError::Unencodable => StegoError::TooSmall,
        }
    }
}

impl From<PictureError> for StegoError {
    fn from(e: PictureError) -> Self {
        match e {
            PictureError::Jpeg(j) => j.into(),
            PictureError::NoCapacity => StegoError::TooSmall,
            PictureError::Window | PictureError::BufferTooSmall => StegoError::Bounds,
            PictureError::NoPayload => StegoError::Verify,
        }
    }
}

impl From<ExifError> for StegoError {
    fn from(e: ExifError) -> Self {
        match e {
            ExifError::Build => StegoError::Exif,
            ExifError::BufferTooSmall => StegoError::Bounds,
            ExifError::Jpeg(j) => j.into(),
        }
    }
}

/// What goes into a photo.
pub struct Export<'a> {
    /// The caption, printable ASCII, at most
    /// [`super::DESCRIPTOR_WRITE_MAX`]; written by Descriptor and Both.
    pub descriptor: &'a [u8],
    /// The payload, [`blob`]'s v3 form, at most [`PAYLOAD_MAX`].
    pub payload: &'a [u8],
    /// The walk key level 2 derived from the descriptor.
    pub key: &'a [u8; KEY_SIZE],
    /// Random bytes for the software-export block.
    pub random: &'a [u8; RANDOM],
}

/// Room `out` needs past the photo and its EXIF block: the new block's
/// growth and the re-encoded scan's.
pub const OUT_EXTRA: usize = exif::APP1_EXTRA + 4096;

/// Write `file` to `out` with the export in it by `carrier`, read it back,
/// and return the length. `app1` is EXIF scratch, the photo's own block
/// plus [`exif::APP1_EXTRA`]; `tables` is filled here. `out` holds
/// `file.len()`, the photo's EXIF block and [`OUT_EXTRA`].
///
/// # Errors
///
/// By name, as the screen says them.
pub fn export(
    file: &[u8],
    carrier: Carrier,
    export: &Export<'_>,
    window: &mut Window<'_>,
    tables: &mut Tables,
    app1: &mut [u8],
    out: &mut [u8],
) -> Result<usize, StegoError> {
    if !super::descriptor_ok(export.descriptor)
        || export.payload.is_empty()
        || export.payload.len() > PAYLOAD_MAX
    {
        return Err(StegoError::Bounds);
    }
    if !kassigner_jpeg::segment::is_jpeg(file) {
        return Err(StegoError::NotJpeg);
    }

    // The picture first: its rewrite copies the head, where the metadata
    // then goes in place.
    let mut len = if carrier.coefficients() {
        picture::embed(file, export.payload, export.key, window, tables, out)?
    } else {
        if out.len() < file.len() {
            return Err(StegoError::Bounds);
        }
        out[..file.len()].copy_from_slice(file);
        file.len()
    };

    if carrier.metadata() {
        let n = exif::build(file, export.descriptor, export.payload, export.random, app1)?;
        len = exif::place(out, len, &app1[..n])?;
    }

    // Read back, both carriers, from what will be written.
    let written = &out[..len];
    if carrier.metadata()
        && (exif::read_payload(written) != Some(export.payload)
            || exif::read_descriptor(written) != Some(export.descriptor))
    {
        return Err(StegoError::Verify);
    }
    if carrier.coefficients() {
        let mut back = [0u8; PAYLOAD_MAX];
        let n = picture::extract(written, export.key, window, tables, &mut back)
            .map_err(|_| StegoError::Verify)?;
        if back[..n] != *export.payload {
            return Err(StegoError::Verify);
        }
    }
    Ok(len)
}

/// Each carrier's payload length in the caller's buffers, or `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extracted {
    /// Bytes of the Picture carrier's payload in `picture_out`.
    pub picture: Option<usize>,
    /// Bytes of the Descriptor carrier's payload in `descriptor_out`.
    pub descriptor: Option<usize>,
}

impl Extracted {
    pub const fn any(&self) -> bool {
        self.picture.is_some() || self.descriptor.is_some()
    }
}

/// Read both carriers of `file` under `key`, the picture's payload into
/// `picture_out` and the metadata's into `descriptor_out`, each of a known
/// [`blob::shape`] or absent. A picture not baseline or damaged just has no
/// Picture payload; its metadata may still carry one.
///
/// # Errors
///
/// `NotJpeg`; `Bounds` for an output shorter than [`PAYLOAD_MAX`].
pub fn extract(
    file: &[u8],
    key: &[u8; KEY_SIZE],
    window: &mut Window<'_>,
    tables: &mut Tables,
    picture_out: &mut [u8],
    descriptor_out: &mut [u8],
) -> Result<Extracted, StegoError> {
    if !kassigner_jpeg::segment::is_jpeg(file) {
        return Err(StegoError::NotJpeg);
    }
    if picture_out.len() < PAYLOAD_MAX || descriptor_out.len() < PAYLOAD_MAX {
        return Err(StegoError::Bounds);
    }
    let picture = picture::extract(file, key, window, tables, &mut picture_out[..PAYLOAD_MAX])
        .ok()
        .filter(|&n| blob::shape(&picture_out[..n]).is_ok());
    let descriptor = exif::read_payload(file)
        .filter(|p| p.len() <= PAYLOAD_MAX && blob::shape(p).is_ok())
        .map(|p| {
            descriptor_out[..p.len()].copy_from_slice(p);
            p.len()
        });
    Ok(Extracted {
        picture,
        descriptor,
    })
}
