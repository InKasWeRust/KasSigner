// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Across the gap: [`kassigner_sdk::transport`] over owned values.
//!
//! [`Codes`] plans a payload into the codes a unit reads; a [`Reader`]
//! takes back what a unit shows, one decoded code at a time; [`decode_qr`]
//! decodes a camera frame with the unit's own decoder.

use kassigner_protocol::frame::Format;
use kassigner_qr::{Decoder, QrMatrix, Scratch, MAX_PAYLOAD_SIZE};
use kassigner_sdk::transport::{self, Progress, ReaderBuffers, State, CODE_MAX, FRAME_BUF};

use crate::{Fault, Profile};

/// A format by its name: `kspt`, `pskb`, `kpub`, `descriptor`,
/// `container` or `opaque`.
pub fn format(name: &str) -> Result<Format, Fault> {
    Ok(match name.trim() {
        "kspt" => Format::Kspt,
        "pskb" => Format::Pskb,
        "kpub" => Format::Kpub,
        "descriptor" => Format::Descriptor,
        "container" => Format::Container,
        "opaque" => Format::Opaque,
        other => return Err(Fault(format!("no format named {other:?}"))),
    })
}

/// A format's name.
pub fn format_name(f: Format) -> &'static str {
    match f {
        Format::Kspt => "kspt",
        Format::Pskb => "pskb",
        Format::Kpub => "kpub",
        Format::Descriptor => "descriptor",
        Format::Container => "container",
        Format::Opaque => "opaque",
    }
}

/// A payload as the codes a unit reads: one bare code when it fits one,
/// the unit's frames past that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Codes {
    plan: transport::Codes,
    format: Format,
    payload: Vec<u8>,
}

/// How `payload`, marked `format_name` (`kspt` for a request, `pskb` for a
/// bundle, `opaque` for a text), is shown to a unit of `profile`.
///
/// # Errors
///
/// `Empty`; `TooManyFrames { frames, limit }`; `no format named ..` for an
/// unknown name.
pub fn codes(payload: &[u8], format_name: &str, profile: &Profile) -> Result<Codes, Fault> {
    let plan = transport::Codes::plan(payload.len(), profile.inner()).map_err(Fault::of)?;
    Ok(Codes::over(plan, format(format_name)?, payload.to_vec()))
}

impl Codes {
    /// How many codes: one for a bare code.
    pub fn frames(&self) -> u32 {
        self.plan.frames as u32
    }

    /// The largest code version any of them takes.
    pub fn version(&self) -> u8 {
        self.plan.version
    }

    /// Whether the one code is the bare payload, with no frame header.
    pub fn bare(&self) -> bool {
        self.plan.bare
    }

    /// Milliseconds each code stays on screen: 600 up to version 7, 850
    /// past it.
    pub fn period_ms(&self) -> u32 {
        self.plan.period_ms()
    }

    /// The bytes of code `index`: the frame, or the bare payload.
    pub fn bytes(&self, index: u32) -> Result<Vec<u8>, Fault> {
        let mut out = [0u8; FRAME_BUF];
        let n = self
            .plan
            .bytes(self.format, &self.payload, index as usize, &mut out)
            .map_err(Fault::of)?;
        Ok(out[..n].to_vec())
    }

    /// Code `index` as its module matrix, from the unit's own encoder.
    pub fn matrix(&self, index: u32) -> Result<Matrix, Fault> {
        let qr = self
            .plan
            .code(self.format, &self.payload, index as usize)
            .map_err(Fault::of)?;
        Ok(Matrix::of(&qr))
    }

    /// Code `index` as an SVG document, as [`Matrix::svg`] draws it.
    pub fn svg(&self, index: u32, module: u32) -> Result<String, Fault> {
        Ok(self.matrix(index)?.svg(module))
    }
}

impl Codes {
    /// Codes over a plan the SDK made for `payload`.
    pub fn over(plan: transport::Codes, format: Format, payload: Vec<u8>) -> Codes {
        Codes {
            plan,
            format,
            payload,
        }
    }
}

/// A code's modules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    /// Modules a side.
    pub size: u8,
    /// The modules, `size * size` of them, row by row, `1` for dark.
    pub modules: Vec<u8>,
}

impl Matrix {
    /// Whether the module at column `x`, row `y` is dark; light outside.
    pub fn dark(&self, x: u8, y: u8) -> bool {
        x < self.size
            && y < self.size
            && self.modules[usize::from(y) * usize::from(self.size) + usize::from(x)] == 1
    }

    /// The matrix as an SVG document, `module` pixels a module with a
    /// quiet zone of four modules, dark on light.
    pub fn svg(&self, module: u32) -> String {
        const QUIET: u32 = 4;
        let side = (u32::from(self.size) + 2 * QUIET) * module;
        let mut s = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{side}\" height=\"{side}\" \
             viewBox=\"0 0 {side} {side}\" shape-rendering=\"crispEdges\">\
             <rect width=\"{side}\" height=\"{side}\" fill=\"#fff\"/><path fill=\"#000\" d=\""
        );
        for y in 0..self.size {
            for x in 0..self.size {
                if self.dark(x, y) {
                    let px = (u32::from(x) + QUIET) * module;
                    let py = (u32::from(y) + QUIET) * module;
                    s.push_str(&format!("M{px} {py}h{module}v{module}h-{module}z"));
                }
            }
        }
        s.push_str("\"/></svg>");
        s
    }
}

impl Matrix {
    /// The modules of `qr`, copied out.
    pub fn of(qr: &QrMatrix) -> Matrix {
        let size = qr.size;
        let mut modules = Vec::with_capacity(usize::from(size) * usize::from(size));
        for y in 0..size {
            for x in 0..size {
                modules.push(u8::from(qr.get(x, y)));
            }
        }
        Matrix { size, modules }
    }
}

/// What a code the reader took did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taken {
    /// `whole`: the reply is in ([`Reader::collect`]); `partial`: `have` of
    /// `need` frames in; `nothing`: a frame already held or of a dropped
    /// transmission; `notAReply`: neither a frame nor a bare reply.
    pub status: &'static str,
    /// Frames in, when `partial`.
    pub have: u32,
    /// Frames expected, when `partial`.
    pub need: u32,
    /// The reply's length, when `whole`.
    pub length: u32,
}

impl Taken {
    /// Whether the reply is whole.
    pub fn whole(&self) -> bool {
        self.status == "whole"
    }
}

/// Reads a reply off a unit's screen, one decoded code at a time: the
/// SDK's reader, resumed over buffers sized by the profile for each call.
pub struct Reader {
    max_frames: usize,
    payload: Vec<u8>,
    seen: Vec<bool>,
    sizes: Vec<u8>,
    bare: Vec<u8>,
    state: State,
}

impl Reader {
    /// A reader for a unit of `profile` whose screen shows `slot` bytes a
    /// frame past the header: 225 on every unit (`display_bytes_per_frame`).
    pub fn new(profile: &Profile, slot: u32) -> Reader {
        let p = profile.inner();
        let mut payload = vec![0u8; p.max_reassembled];
        let mut seen = vec![false; p.max_frames];
        let mut sizes = vec![0u8; p.max_frames];
        let mut bare = vec![0u8; CODE_MAX];
        let state = transport::Reader::new(
            ReaderBuffers {
                payload: &mut payload,
                seen: &mut seen,
                sizes: &mut sizes,
                bare: &mut bare,
            },
            slot as usize,
        )
        .suspend();
        Reader {
            max_frames: p.max_frames,
            payload,
            seen,
            sizes,
            bare,
            state,
        }
    }

    /// Forget everything taken so far.
    pub fn reset(&mut self) {
        self.with(|r| r.reset());
    }

    /// Take one decoded code, as the camera gave it.
    ///
    /// # Errors
    ///
    /// `Frame(..)` for a frame the unit's reassembler refuses: a bad header,
    /// an unknown format, more frames than the profile allows, a mixed set
    /// or a wrong digest; after either of the last two it starts over.
    /// `BufferTooSmall` for a bare reply longer than one code holds.
    pub fn take(&mut self, code: &[u8]) -> Result<Taken, Fault> {
        let max_frames = self.max_frames;
        let got = self.with(|r| r.take(code, max_frames)).map_err(Fault::of)?;
        Ok(match got {
            Progress::Whole(n) => Taken {
                status: "whole",
                have: 0,
                need: 0,
                length: n as u32,
            },
            Progress::Partial { have, need } => Taken {
                status: "partial",
                have: have as u32,
                need: need as u32,
                length: 0,
            },
            Progress::Nothing => Taken {
                status: "nothing",
                have: 0,
                need: 0,
                length: 0,
            },
            Progress::NotAReply => Taken {
                status: "notAReply",
                have: 0,
                need: 0,
                length: 0,
            },
        })
    }

    /// The name of the format the codes taken so far say is coming.
    pub fn format(&mut self) -> Option<String> {
        self.with(|r| r.format())
            .map(|f| format_name(f).to_string())
    }

    /// Which of the first 64 frames are in, bit `i` for frame `i`: zero
    /// after a bare reply, a reset, or a set dropped for another.
    pub fn received(&mut self) -> u64 {
        self.with(|r| r.received())
    }

    /// The whole reply, once a take said `whole`.
    ///
    /// # Errors
    ///
    /// `Frame(..)` before the reply is whole.
    pub fn collect(&mut self) -> Result<Vec<u8>, Fault> {
        let mut out = vec![0u8; self.payload.len().max(self.bare.len())];
        let n = self.with(|r| r.collect(&mut out)).map_err(Fault::of)?;
        out.truncate(n);
        Ok(out)
    }
}

impl Reader {
    /// `f` over the SDK's reader, resumed on the buffers and suspended after.
    fn with<T>(&mut self, f: impl FnOnce(&mut transport::Reader<'_>) -> T) -> T {
        let mut r = transport::Reader::resume(
            ReaderBuffers {
                payload: &mut self.payload,
                seen: &mut self.seen,
                sizes: &mut self.sizes,
                bare: &mut self.bare,
            },
            self.state,
        );
        let t = f(&mut r);
        self.state = r.suspend();
        t
    }
}

impl Drop for Reader {
    /// Clears the buffers, which a suspended SDK reader leaves to their
    /// holder.
    fn drop(&mut self) {
        self.payload.fill(0);
        self.sizes.fill(0);
        self.bare.fill(0);
    }
}

/// Decode the first readable QR code in a grayscale frame, a byte a pixel,
/// with the unit's own decoder; none when no code reads. `denom` is the
/// threshold window's divisor: the units use 8 for dense codes and 3 for
/// versions 1 and 2, switching between them after misses.
///
/// # Errors
///
/// `BadFrame` for a side of zero or over 1024, or fewer pixels than the
/// sides say.
pub fn decode_qr(
    pixels: &[u8],
    width: u32,
    height: u32,
    denom: u32,
) -> Result<Option<Vec<u8>>, Fault> {
    let mut scratch = Box::new(Scratch::new());
    let mut decoder = Decoder::new(&mut scratch);
    let mut gray = pixels.to_vec();
    let mut out = vec![0u8; MAX_PAYLOAD_SIZE];
    match decoder.decode(
        width as usize,
        height as usize,
        denom as usize,
        &mut gray,
        &mut out,
    ) {
        Ok(d) => {
            out.truncate(d.len);
            Ok(Some(out))
        }
        Err(kassigner_qr::DecodeError::NotFound | kassigner_qr::DecodeError::Unreadable) => {
            Ok(None)
        }
        Err(e) => Err(Fault::of(e)),
    }
}
