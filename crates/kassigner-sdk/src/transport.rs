// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Codes across the gap: a request shown to a unit, a reply read off one.
//!
//! A request that fits one code up to version 6 goes as that bare code; past
//! that, in the unit's frames ([`kassigner_protocol::frame`]), whose headers
//! carry the payload's digest so two transmissions never mix. [`Codes::plan`]
//! takes the smallest version from 6 to 9 that needs at most five frames, else
//! version 9. A payload one denser code would hold still goes as version-6
//! frames, which a unit reads off a phone in poor light sooner. Codes come from
//! the unit's own encoder ([`QrMatrix`]): several platforms' QR libraries
//! encode binary wrongly.
//!
//! A [`Reader`] takes a unit's codes in any order, through the unit's own
//! [`Reassembler`]; a frame of another transmission starts it over, as on a
//! unit.

use kassigner_protocol::frame::{
    self, Format, FrameError, Reassembler, FIRST_HEADER_LEN, HEADER_LEN,
};
use kassigner_protocol::kspt;
use kassigner_protocol::profile::Profile;
use kassigner_qr::{byte_capacity, encode, QrError, QrMatrix, MAX_VERSION};

/// Milliseconds a code up to version 7 stays on the screen for a unit's camera:
/// what the P4 needs at version 7.
pub const PERIOD_UP_TO_V7_MS: u32 = 600;

/// The same at versions 8 and 9: on the M5, version 9 at 850 reads about as
/// fast as version 7 at 400.
pub const PERIOD_V8_V9_MS: u32 = 850;

/// The smallest version of a frame's code, below which the header costs too
/// much; the largest of a bare code.
pub const MIN_VERSION: u8 = 6;

/// Most frames a request is shown in, while a version up to 9 allows.
pub const PREFERRED_FRAMES: usize = 5;

/// How a payload is shown: one bare code, or frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Codes {
    /// Codes in all; one for a bare code.
    pub frames: usize,
    /// The largest code version among them.
    pub version: u8,
    /// Most payload bytes a frame carries past its five-byte header (frame 0
    /// three fewer); the whole payload for a bare code.
    pub bytes_per_frame: usize,
    /// Whether the one code is the payload itself, with no header.
    pub bare: bool,
}

/// Why a payload could not be shown or read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// An empty payload.
    Empty,
    /// More frames than the profile reassembles, or than 255.
    TooManyFrames { frames: usize, limit: usize },
    /// A frame index past the plan.
    NoSuchFrame { index: usize, frames: usize },
    /// The caller's buffer cannot hold the code's bytes.
    BufferTooSmall,
    /// The encoder refused: past version 9, which a plan never asks for.
    Qr(QrError),
    /// A frame refused, as [`FrameError`] says.
    Frame(FrameError),
    /// What is held of the reply is longer than the caller's buffer.
    TooLong { needed: usize },
}

impl From<QrError> for TransportError {
    fn from(e: QrError) -> Self {
        TransportError::Qr(e)
    }
}

impl From<FrameError> for TransportError {
    fn from(e: FrameError) -> Self {
        TransportError::Frame(e)
    }
}

/// Payload bytes a version-`v` frame carries past its header.
const fn payload_per_frame(v: u8) -> usize {
    match byte_capacity(v) {
        Some(c) => c - HEADER_LEN,
        None => 0,
    }
}

impl Codes {
    /// How `len` bytes are shown to a unit of `profile`.
    ///
    /// # Errors
    ///
    /// `Empty`; `TooManyFrames` past the profile's `max_frames` or 255.
    pub fn plan(len: usize, profile: &Profile) -> Result<Codes, TransportError> {
        if len == 0 {
            return Err(TransportError::Empty);
        }
        if let Some(version) = kassigner_qr::select_version(len).filter(|&v| v <= MIN_VERSION) {
            return Ok(Codes {
                frames: 1,
                version,
                bytes_per_frame: len,
                bare: true,
            });
        }
        let mut version = MAX_VERSION;
        let mut frames = frame::frames_needed(len, payload_per_frame(MAX_VERSION));
        for v in MIN_VERSION..=MAX_VERSION {
            let n = frame::frames_needed(len, payload_per_frame(v));
            if n <= PREFERRED_FRAMES {
                version = v;
                frames = n;
                break;
            }
        }
        if frames > profile.max_frames || frames > usize::from(u8::MAX) {
            return Err(TransportError::TooManyFrames {
                frames,
                limit: profile.max_frames,
            });
        }
        Ok(Codes {
            frames,
            version,
            bytes_per_frame: payload_per_frame(version),
            bare: false,
        })
    }

    /// Milliseconds each code stays on the screen, by version:
    /// [`PERIOD_UP_TO_V7_MS`] or [`PERIOD_V8_V9_MS`].
    pub const fn period_ms(&self) -> u32 {
        if self.version <= 7 {
            PERIOD_UP_TO_V7_MS
        } else {
            PERIOD_V8_V9_MS
        }
    }

    /// Code `index` of `payload` under this plan into `out`, the frame or the
    /// bare payload: its length.
    ///
    /// # Errors
    ///
    /// `NoSuchFrame`; `BufferTooSmall` for a short `out` ([`FRAME_BUF`] always
    /// fits); `Frame` for a `payload` shorter than planned.
    pub fn bytes(
        &self,
        format: Format,
        payload: &[u8],
        index: usize,
        out: &mut [u8],
    ) -> Result<usize, TransportError> {
        if index >= self.frames {
            return Err(TransportError::NoSuchFrame {
                index,
                frames: self.frames,
            });
        }
        if self.bare {
            let out = out
                .get_mut(..payload.len())
                .ok_or(TransportError::BufferTooSmall)?;
            out.copy_from_slice(payload);
            return Ok(payload.len());
        }
        frame::write_split(format, payload, index as u8, self.frames as u8, out).map_err(
            |e| match e {
                FrameError::TooLarge => TransportError::BufferTooSmall,
                other => TransportError::Frame(other),
            },
        )
    }

    /// Code `index` of `payload` under this plan, as the matrix to draw.
    ///
    /// # Errors
    ///
    /// As [`Codes::bytes`]; `Qr`, which a plan from [`Codes::plan`] never
    /// causes.
    pub fn code(
        &self,
        format: Format,
        payload: &[u8],
        index: usize,
    ) -> Result<QrMatrix, TransportError> {
        let mut buf = [0u8; CODE_MAX];
        let n = self.bytes(format, payload, index, &mut buf)?;
        Ok(encode(&buf[..n])?)
    }
}

/// The most bytes one code carries: a version-9 code's.
pub const CODE_MAX: usize = match byte_capacity(MAX_VERSION) {
    Some(c) => c,
    None => 0,
};

/// The plan for a KSPT request, its codes made with [`Format::Kspt`].
///
/// # Errors
///
/// As [`Codes::plan`].
pub fn request_codes(kspt: &[u8], profile: &Profile) -> Result<Codes, TransportError> {
    Codes::plan(kspt.len(), profile)
}

/// What a code taken by the reader did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The reply is whole: its length, for [`Reader::collect`].
    Whole(usize),
    /// A frame taken; `have` of `need` are in.
    Partial { have: usize, need: usize },
    /// A frame already held: nothing new.
    Nothing,
    /// Not a frame or a bare reply: something else in view.
    NotAReply,
}

/// Reads a reply off a unit's screen, a decoded code at a time.
pub struct Reader<'a> {
    reassembler: Reassembler<'a>,
    /// A bare reply as it came: [`CODE_MAX`] bytes.
    bare: &'a mut [u8],
    bare_len: Option<usize>,
}

/// What a [`Reader`] knows beside its buffers, between [`Reader::suspend`] and
/// [`Reader::resume`] over the same buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    frames: frame::State,
    bare_len: Option<usize>,
}

/// The buffers a [`Reader`] works in, the caller's.
pub struct ReaderBuffers<'a> {
    /// The payload as reassembled: the profile's `max_reassembled`.
    pub payload: &'a mut [u8],
    /// One slot per frame the profile allows.
    pub seen: &'a mut [bool],
    /// One slot per frame the profile allows.
    pub sizes: &'a mut [u8],
    /// A bare reply: [`CODE_MAX`].
    pub bare: &'a mut [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `buffers`; `slot` is the most a frame carries past its
    /// header, a unit's 225 (`display_bytes_per_frame`).
    pub fn new(buffers: ReaderBuffers<'a>, slot: usize) -> Self {
        Reader {
            reassembler: Reassembler::new(buffers.payload, buffers.seen, buffers.sizes, slot),
            bare: buffers.bare,
            bare_len: None,
        }
    }

    /// End the reader, its buffers uncleared, and return its [`State`] for
    /// [`Reader::resume`]: for a binding that cannot keep a borrow between
    /// codes and clears the buffers itself when done.
    pub fn suspend(self) -> State {
        State {
            frames: self.reassembler.suspend(),
            bare_len: self.bare_len,
        }
    }

    /// A reader over `buffers` as [`Reader::suspend`] left them, from `state`.
    /// A state that does not fit them, which would make [`Reader::collect`]
    /// panic, starts over.
    pub fn resume(buffers: ReaderBuffers<'a>, state: State) -> Self {
        let mut reader = Reader {
            reassembler: Reassembler::resume(
                buffers.payload,
                buffers.seen,
                buffers.sizes,
                state.frames,
            ),
            bare: buffers.bare,
            bare_len: state.bare_len,
        };
        if reader.bare_len.is_some_and(|n| n > reader.bare.len()) {
            reader.reset();
        }
        reader
    }

    /// Forget everything taken so far.
    pub fn reset(&mut self) {
        self.reassembler.reset();
        self.bare_len = None;
    }

    /// Take one decoded code as the camera gave it; `max_frames` is the
    /// profile's.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall` for a bare reply longer than `bare`; `Frame` for a
    /// frame the reassembler refuses (an unknown format, too many frames, a
    /// held frame with other bytes, a set whose digest is wrong). The last two
    /// reset the reader, as on a unit.
    pub fn take(&mut self, code: &[u8], max_frames: usize) -> Result<Progress, TransportError> {
        if code.starts_with(&kspt::MAGIC) || code.starts_with(kassigner_kaspa::pskb::MAGIC) {
            // A bare reply: whole in one code, held as it came.
            let held = self
                .bare
                .get_mut(..code.len())
                .ok_or(TransportError::BufferTooSmall)?;
            held.copy_from_slice(code);
            self.reassembler.reset();
            self.bare_len = Some(code.len());
            return Ok(Progress::Whole(code.len()));
        }
        let f = match frame::parse(code, max_frames) {
            Ok(f) => f,
            Err(FrameError::NotAFrame) => return Ok(Progress::NotAReply),
            Err(e) => return Err(TransportError::Frame(e)),
        };
        let mut before = self.reassembler.progress().0;
        match self.reassembler.push(&f) {
            Ok(()) => {}
            // Another transmission, named: the screen moved on, and what it
            // shows now is read, as on a unit. Counted from none, so a set of
            // one replaced by one is progress.
            Err(FrameError::StreamChanged) if f.named.is_some() => {
                self.reassembler.reset();
                before = 0;
                self.reassembler.push(&f)?;
            }
            Err(FrameError::StreamChanged) => return Ok(Progress::Nothing),
            Err(FrameError::Conflict) => {
                self.reassembler.reset();
                return Err(TransportError::Frame(FrameError::Conflict));
            }
            Err(e) => return Err(TransportError::Frame(e)),
        }
        self.bare_len = None;
        let (have, need) = self.reassembler.progress();
        if have == before {
            return Ok(Progress::Nothing);
        }
        if self.reassembler.is_complete() {
            if !self.reassembler.digest_matches() {
                self.reassembler.reset();
                return Err(TransportError::Frame(FrameError::DigestMismatch));
            }
            return Ok(Progress::Whole(self.reassembler.payload_len()));
        }
        Ok(Progress::Partial { have, need })
    }

    /// What the codes taken say is coming: a bare code's by its first bytes,
    /// frames' by their header.
    pub fn format(&self) -> Option<Format> {
        match self.bare_len {
            Some(_) if self.bare.starts_with(&kspt::MAGIC) => Some(Format::Kspt),
            Some(_) => Some(Format::Pskb),
            None => self.reassembler.format(),
        }
    }

    /// Which frames are in, bit `i` for frame `i` over the first 64 (a
    /// profile's most), for a dot per frame as a unit's scan screen draws.
    /// Zero after a bare reply or a reset.
    pub fn received(&self) -> u64 {
        self.reassembler.received()
    }

    /// The reply into `out`: its length.
    ///
    /// # Errors
    ///
    /// `TooLong` for an `out` shorter than what is held; `Frame` before the
    /// reply is whole.
    pub fn collect(&self, out: &mut [u8]) -> Result<usize, TransportError> {
        let needed = self
            .bare_len
            .unwrap_or_else(|| self.reassembler.payload_len());
        let out = out
            .get_mut(..needed)
            .ok_or(TransportError::TooLong { needed })?;
        if let Some(n) = self.bare_len {
            out.copy_from_slice(&self.bare[..n]);
            return Ok(n);
        }
        Ok(self.reassembler.collect(out)?)
    }
}

/// An `out` for [`Codes::bytes`] that fits any plan: a version-9 code and
/// frame 0's header.
pub const FRAME_BUF: usize = FIRST_HEADER_LEN + CODE_MAX;
