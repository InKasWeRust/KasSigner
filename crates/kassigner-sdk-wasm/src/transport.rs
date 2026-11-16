// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Across the gap: [`kassigner_sdk_host::transport`] for JavaScript.
//!
//! Out, [`Codes`]: a payload as the codes a unit reads (bytes, matrix or
//! SVG), shown in turn every `Codes.periodMs`. In, a [`Reader`]: decoded
//! codes until the reply is whole; [`decode_qr`] decodes a camera frame as
//! the unit does.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::transport as host;

use crate::{Fault, Profile};

/// A payload as the codes a unit reads: one bare code when it fits one,
/// the unit's frames past that.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Codes {
    inner: host::Codes,
}

/// How `payload`, marked `format` (`kspt` for a request, `pskb` for a
/// bundle, `opaque` for a text), is shown to a unit of `profile`.
///
/// Throws `Empty`, `TooManyFrames`; `no format named "..."` for an
/// unknown `format`.
#[wasm_bindgen]
pub fn codes(payload: &[u8], format: &str, profile: &Profile) -> Result<Codes, Fault> {
    Ok(Codes::over(host::codes(payload, format, profile.inner())?))
}

#[wasm_bindgen]
impl Codes {
    /// How many codes: one for a bare code.
    #[wasm_bindgen(getter)]
    pub fn frames(&self) -> u32 {
        self.inner.frames()
    }

    /// The largest code version any of them takes.
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u8 {
        self.inner.version()
    }

    /// How long each code stays on screen, in milliseconds: 600 up to
    /// version 7, 850 above.
    #[wasm_bindgen(getter, js_name = periodMs)]
    pub fn period_ms(&self) -> u32 {
        self.inner.period_ms()
    }

    /// Whether the one code is the bare payload, with no frame header.
    #[wasm_bindgen(getter)]
    pub fn bare(&self) -> bool {
        self.inner.bare()
    }

    /// The bytes of code `index`: the frame, or the bare payload.
    pub fn bytes(&self, index: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.bytes(index)?)
    }

    /// Code `index` as its module matrix, from the unit's own encoder.
    pub fn matrix(&self, index: u32) -> Result<Matrix, Fault> {
        Ok(Matrix {
            inner: self.inner.matrix(index)?,
        })
    }

    /// Code `index` as an SVG document: `module` pixels a module, a quiet
    /// zone of four modules, dark on light.
    pub fn svg(&self, index: u32, module: u32) -> Result<String, Fault> {
        Ok(self.inner.svg(index, module)?)
    }
}

impl Codes {
    pub(crate) const fn over(inner: host::Codes) -> Codes {
        Codes { inner }
    }
}

/// A code's modules: `size` a side, dark modules `1`, row by row.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    inner: host::Matrix,
}

#[wasm_bindgen]
impl Matrix {
    /// Modules a side.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> u8 {
        self.inner.size
    }

    /// The modules, `size * size` of them, row by row, `1` for dark.
    #[wasm_bindgen(getter)]
    pub fn modules(&self) -> Vec<u8> {
        self.inner.modules.clone()
    }

    /// Whether the module at column `x`, row `y` is dark; light outside.
    pub fn dark(&self, x: u8, y: u8) -> bool {
        self.inner.dark(x, y)
    }

    /// The matrix as an SVG document, drawn as [`Codes::svg`] draws it.
    pub fn svg(&self, module: u32) -> String {
        self.inner.svg(module)
    }
}

/// What a code the reader took did.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taken {
    inner: host::Taken,
}

#[wasm_bindgen]
impl Taken {
    /// `whole` (the reply is in, [`Reader::collect`] gives it), `partial`
    /// (`have` of `need` frames in), `nothing` (a frame already held, or of
    /// a dropped transmission) or `notAReply` (something else was in view).
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.inner.status.to_string()
    }

    /// Frames in, when `partial`.
    #[wasm_bindgen(getter)]
    pub fn have(&self) -> u32 {
        self.inner.have
    }

    /// Frames expected, when `partial`.
    #[wasm_bindgen(getter)]
    pub fn need(&self) -> u32 {
        self.inner.need
    }

    /// The reply's length, when `whole`.
    #[wasm_bindgen(getter)]
    pub fn length(&self) -> u32 {
        self.inner.length
    }

    /// Whether the reply is whole.
    #[wasm_bindgen(getter)]
    pub fn whole(&self) -> bool {
        self.inner.whole()
    }
}

/// Reads a reply off a unit's screen, one decoded code at a time.
#[wasm_bindgen]
pub struct Reader {
    inner: host::Reader,
}

#[wasm_bindgen]
impl Reader {
    /// A reader for a unit of `profile` whose screen shows `slot` bytes a
    /// frame past the header: 225 on every unit (`display_bytes_per_frame`).
    #[wasm_bindgen(constructor)]
    pub fn new(profile: &Profile, slot: u32) -> Reader {
        Reader {
            inner: host::Reader::new(profile.inner(), slot),
        }
    }

    /// Forget everything taken so far.
    pub fn reset(&mut self) {
        self.inner.reset();
    }

    /// Take one decoded code, as the camera gave it.
    ///
    /// Throws `Frame(...)` for a frame the unit's reassembler refuses: an
    /// unknown format, too many frames, a mixed set, a wrong digest. After
    /// either of the last two the reader resets, as the unit does.
    pub fn take(&mut self, code: &[u8]) -> Result<Taken, Fault> {
        Ok(Taken {
            inner: self.inner.take(code)?,
        })
    }

    /// The name of the format the codes taken announce, or none yet.
    pub fn format(&mut self) -> Option<String> {
        self.inner.format()
    }

    /// Which frames are in, as a `BigInt`: bit `i` for frame `i`, over the
    /// first 64. Zero after a bare reply, a reset, or a set dropped for
    /// another.
    pub fn received(&mut self) -> u64 {
        self.inner.received()
    }

    /// The whole reply, once a take said `whole`.
    ///
    /// Throws before the reply is whole.
    pub fn collect(&mut self) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.collect()?)
    }
}

/// Decode the first readable QR code in a grayscale frame, `width` by
/// `height`, a byte a pixel, with the unit's own decoder; `undefined` when
/// none reads. `denom` is the adaptive threshold's window divisor: the
/// units use 8 for dense codes and 3 to rescue versions 1 and 2; try one,
/// then the other.
///
/// Throws for a side of zero or over 1024, or fewer pixels than the sides
/// say.
#[wasm_bindgen(js_name = decodeQr)]
pub fn decode_qr(
    pixels: &[u8],
    width: u32,
    height: u32,
    denom: u32,
) -> Result<Option<Vec<u8>>, Fault> {
    Ok(host::decode_qr(pixels, width, height, denom)?)
}
