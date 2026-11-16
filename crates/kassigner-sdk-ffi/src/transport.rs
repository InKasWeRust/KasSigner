// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QR codes to and from a unit: [`kassigner_sdk_host::transport`] over
//! the C ABI.

use std::sync::Mutex;

use kassigner_sdk_host::transport as host;

use crate::{lock, Fault, Profile};

/// A payload as the QR codes a unit reads: one bare code, or frames.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Object)]
pub struct Codes {
    inner: host::Codes,
}

/// The codes showing `payload`, marked `format` (`kspt` for a request,
/// `pskb` for a bundle, `opaque` for a text), to a unit of `profile`.
///
/// # Errors
///
/// `Empty`, `TooManyFrames`, or an unknown format name.
#[uniffi::export]
pub fn codes(payload: Vec<u8>, format: String, profile: &Profile) -> Result<Codes, Fault> {
    Ok(Codes::over(host::codes(
        &payload,
        &format,
        profile.inner(),
    )?))
}

#[uniffi::export]
impl Codes {
    /// How many codes: one for a bare code.
    pub fn frames(&self) -> u32 {
        self.inner.frames()
    }

    /// The largest QR version among them.
    pub fn version(&self) -> u8 {
        self.inner.version()
    }

    /// Whether the one code is the bare payload, with no header.
    pub fn bare(&self) -> bool {
        self.inner.bare()
    }

    /// Milliseconds each code stays on screen: 600 up to version 7, 850 at
    /// versions 8 and 9.
    pub fn period_ms(&self) -> u32 {
        self.inner.period_ms()
    }

    /// The bytes of code `index`: the frame, or the bare payload.
    pub fn bytes(&self, index: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.bytes(index)?)
    }

    /// Code `index` as its module matrix, from the unit's own encoder.
    pub fn matrix(&self, index: u32) -> Result<Matrix, Fault> {
        Ok(self.inner.matrix(index)?.into())
    }

    /// Code `index` as SVG, `module` pixels a module, with a quiet zone of
    /// four.
    pub fn svg(&self, index: u32, module: u32) -> Result<String, Fault> {
        Ok(self.inner.svg(index, module)?)
    }
}

impl Codes {
    pub(crate) const fn over(inner: host::Codes) -> Codes {
        Codes { inner }
    }
}

/// A code's modules.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Matrix {
    /// Modules a side.
    pub size: u8,
    /// `size * size` modules, row by row, `1` for dark.
    pub modules: Vec<u8>,
}

impl From<host::Matrix> for Matrix {
    fn from(m: host::Matrix) -> Self {
        Matrix {
            size: m.size,
            modules: m.modules,
        }
    }
}

/// What taking a code did.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Taken {
    /// `whole`: the reply is in, [`Reader::collect`] gives it; `partial`:
    /// `have` of `need` frames are in; `nothing`: a frame already held or of
    /// a dropped set; `notAReply`: neither a frame nor a bare reply.
    pub status: String,
    /// Frames in, when `partial`.
    pub have: u32,
    /// Frames expected, when `partial`.
    pub need: u32,
    /// The reply's length, when `whole`.
    pub length: u32,
    /// Whether the reply is whole.
    pub whole: bool,
}

impl From<host::Taken> for Taken {
    fn from(t: host::Taken) -> Self {
        Taken {
            status: t.status.to_string(),
            have: t.have,
            need: t.need,
            length: t.length,
            whole: t.whole(),
        }
    }
}

/// Reads a reply off a unit's screen, one decoded code at a time.
#[derive(uniffi::Object)]
pub struct Reader {
    inner: Mutex<host::Reader>,
}

#[uniffi::export]
impl Reader {
    /// A reader for a unit of `profile` showing `slot` payload bytes a
    /// frame: 225 on every shipping unit.
    #[uniffi::constructor]
    pub fn new(profile: &Profile, slot: u32) -> Reader {
        Reader {
            inner: Mutex::new(host::Reader::new(profile.inner(), slot)),
        }
    }

    /// Forget everything taken so far.
    pub fn reset(&self) {
        lock(&self.inner).reset();
    }

    /// Take one decoded code.
    ///
    /// # Errors
    ///
    /// `Frame(...)` for a frame the unit would refuse: an unknown format,
    /// more frames than the profile allows, a mixed set, a wrong digest.
    /// After either of the last two the reader resets, as the unit does.
    pub fn take(&self, code: Vec<u8>) -> Result<Taken, Fault> {
        Ok(lock(&self.inner).take(&code)?.into())
    }

    /// The format the codes taken announce, or none yet.
    pub fn format(&self) -> Option<String> {
        lock(&self.inner).format()
    }

    /// Which of the first 64 frames are in, bit `i` for frame `i`. Zero
    /// after a bare reply, a reset, or a set dropped for another.
    pub fn received(&self) -> u64 {
        lock(&self.inner).received()
    }

    /// The whole reply, once a take said `whole`.
    ///
    /// # Errors
    ///
    /// Before the reply is whole.
    pub fn collect(&self) -> Result<Vec<u8>, Fault> {
        Ok(lock(&self.inner).collect()?)
    }
}

/// The first readable QR code in a grayscale image, `width` by `height`,
/// one byte a pixel, by the unit's own decoder; none if no code reads.
/// `denom`, the adaptive threshold's window divisor, is 8 for a code
/// filling much of the image, 3 for a small one: try one, then the other.
///
/// # Errors
///
/// A side over 1024, or fewer pixels than the sides say.
#[uniffi::export]
pub fn decode_qr(
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    denom: u32,
) -> Result<Option<Vec<u8>>, Fault> {
    Ok(host::decode_qr(&pixels, width, height, denom)?)
}
