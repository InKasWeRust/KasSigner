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

//! Reading a transaction off the camera: a coordinator's QR frames become a
//! payload.
//!
//! [`Scan`] is the part that is not drawing: decoded codes in, a payload and
//! its progress out. Bytes alone decide what it does, so a test can feed it
//! recorded frames.
//!
//! # What a scan refuses
//!
//! A frame not of ours. The frame header starts `0x1B`, below `0x20`, so no
//! text payload begins with it; a shape test with no magic byte can read a hex
//! string as frame 48 of 50.
//!
//! A frame of another transmission mixed into the one in progress. Every frame
//! carries the format, the total and the payload's tag (its digest's first
//! byte); frame 0 carries the whole digest. A disagreeing frame replaces the
//! set in progress: the sending screen changed, and what it shows now is what
//! is read. A complete set is checked against frame 0's digest before it is
//! handed over, which catches a switch whose tag matched by chance.
//!
//! # What a scan still reads from v1.0.7
//!
//! A companion written for v1.0.7 sends requests as that unit read them, and
//! its owner should not have to update it to sign. Two shapes, told apart by
//! what they carry:
//!
//! - A payload that fits one code, sent bare: it begins `KSPT` or `PSKB`, or is
//!   a kpub's raw form ([`Step::Whole`]).
//! - A payload split across codes, each behind a three-byte header, `index`,
//!   `total`, `frag_len`, with nothing marking it as a frame. Accepted only
//!   with an exact length byte (or v1.0.7's zero padding) and a total of at
//!   least two, which a bare hex string fails. Only frame zero, whose fragment
//!   must begin as a bare payload does, says what is coming and starts a
//!   transmission; a later frame arriving first is dropped
//!   ([`Step::BeforeFrameZero`]) until frame zero comes round. These frames
//!   name nothing, so one that disagrees with the set in progress is dropped.
//!
//! The two framings never mix: a transmission begun in one completes in it.
//!
//! # A decoded frame is not a trusted frame
//!
//! Nothing here validates the payload: a completed scan says the transport
//! worked, nothing about what a coordinator sent. Parsing, and the review a
//! person approves, come after.

use kassigner_crypto::bip39::{ENTROPY_12, ENTROPY_24};
use kassigner_kaspa::pskb;
use kassigner_protocol::frame::{self, Format, Frame, FrameError, Reassembler};
use kassigner_protocol::kspt;

/// What one offered code did. Most outcomes are ordinary: a camera pointed at a
/// desk gives [`Step::NoCode`] many times a second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// No QR code in the frame.
    NoCode,
    /// A code that is not one of ours: a URL, a wifi code, a product label.
    NotOurs,
    /// A frame of ours declaring more frames than there are buffers for, as
    /// when a sender's frame limit is above this scan's. Apart from
    /// [`Step::NotOurs`] so the person learns the transaction is too large, not
    /// that the code is foreign. `limit` is what this device can take.
    TooLong { total: u8, limit: usize },
    /// A frame of another transmission that cannot replace the one in progress:
    /// one framing's frame amid the other's, or a v1.0.7 frame disagreeing with
    /// a v1.0.7 set (v1.0.7 frames name nothing). Dropped, not mixed in: halves
    /// of two transactions reassemble into neither. A `0x1B` frame naming
    /// another transmission starts that one instead.
    WrongTransmission,
    /// Frames of two transmissions taken as one set, dropped whole; the scan
    /// goes on. Either a complete set is not the payload frame 0 named (two
    /// transmissions whose tags matched), or a held frame arrived again
    /// changed, which is how mixed v1.0.7 frames show.
    Mismatched,
    /// A frame that belongs, and had already arrived.
    Duplicate,
    /// A frame that belongs and is new.
    Accepted {
        index: usize,
        have: usize,
        need: usize,
    },
    /// The last missing frame arrived.
    Complete { format: Format, len: usize },
    /// A whole payload in one code, as v1.0.7 read it: it begins `KSPT`, `PSKB`
    /// or a kpub's raw form, with no frame header, so the bytes offered are the
    /// payload.
    Whole,
    /// A v1.0.7 frame other than frame zero, with no transmission begun. Only
    /// frame zero says what the transmission is, so this one is dropped and the
    /// scan goes on until frame zero comes round. Not [`Step::NotOurs`], on
    /// which the flow ends the scan: a sender cycling its frames would be read
    /// only when frame zero came first.
    BeforeFrameZero { index: u8, total: u8 },
    /// As [`Step::BeforeFrameZero`], for a 32-byte code shaped as a v1.0.7
    /// set's last frame, also a 24-word compact SeedQR's length. About one such
    /// SeedQR in 266,000 has the shape and waits for a frame zero that never
    /// comes, so the flow, told each time it is read, says how else to load it.
    LastFrameOrSeed { total: u8 },
}

/// Why a scan failed outright.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The reassembled payload is larger than the caller's buffer.
    TooLarge { needed: usize },
    /// A frame was well formed and could not be stored.
    Frame(FrameError),
}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Error::Frame(e)
    }
}

/// A scan in progress. A caller offers it each decoded code (on a unit, from
/// `kassigner_hal`'s `Decoder`) and draws whatever [`Step`] says.
pub struct Scan<'a> {
    reassembler: Reassembler<'a>,
    /// Frames this scan can hold, the frame parser's bound. Not the total in
    /// progress, which would refuse a valid frame of another transmission as no
    /// frame at all.
    capacity: usize,
    /// The format of a transmission in progress in v1.0.7's three-byte frames,
    /// set by its frame zero and cleared with it; `None` for a `0x1B`
    /// transmission or none.
    legacy: Option<Format>,
}

impl<'a> Scan<'a> {
    /// Begin a scan in the caller's buffers (this crate allocates nothing):
    /// `buf` holds the payload, `seen` and `sizes` track which frames arrived,
    /// and `slot` is each frame's capacity.
    pub fn new(buf: &'a mut [u8], seen: &'a mut [bool], sizes: &'a mut [u8], slot: usize) -> Self {
        let capacity = seen.len();
        Self {
            reassembler: Reassembler::new(buf, seen, sizes, slot),
            capacity,
            legacy: None,
        }
    }

    /// Frames arrived and frames needed; `(0, 0)` until a first frame gives
    /// the total.
    pub fn progress(&self) -> (usize, usize) {
        self.reassembler.progress()
    }

    /// Which of the first 64 frames have arrived, bit `i` frame `i`: the
    /// scan screen's dots.
    pub fn received(&self) -> u64 {
        self.reassembler.received()
    }

    /// The format of the transmission in progress, once one is known.
    pub fn format(&self) -> Option<Format> {
        self.reassembler.format()
    }

    /// Whether every frame has arrived.
    pub fn is_complete(&self) -> bool {
        self.reassembler.is_complete()
    }

    /// Throw away a partial transmission, as when the camera is pointed at
    /// another screen: a scan that will never complete is worse than one
    /// started again.
    pub fn reset(&mut self) {
        self.reassembler.reset();
        self.legacy = None;
    }

    /// Offer bytes already decoded: what a unit's decoder read, or a test's
    /// recorded frame.
    ///
    /// # Errors
    ///
    /// `Frame` if a well-formed frame could not be stored.
    pub fn offer(&mut self, bytes: &[u8]) -> Result<Step, Error> {
        // Bounded by what this scan can hold, not the transmission in
        // progress: a frame declaring too many parts is refused, and one
        // declaring another total is another transmission's, for the
        // reassembler to judge.
        let f = match frame::parse(bytes, self.capacity) {
            Ok(f) => f,
            // A compact SeedQR's length, 16 or 32 bytes, is taken as a seed's:
            // random seed bytes form this header, too many frames and all,
            // about once in 23,000. The flow gets the code.
            Err(FrameError::TooManyFrames { .. }) if compact_length(bytes) => {
                return Ok(Step::NotOurs)
            }
            // Ours, and too big for this device: not reported as foreign.
            Err(FrameError::TooManyFrames { total, limit }) => {
                return Ok(Step::TooLong { total, limit })
            }
            // Not a `0x1B` frame; it may still be a request as v1.0.7 read it.
            Err(_) => return self.offer_legacy(bytes),
        };
        if self.legacy.is_some() {
            return Ok(Step::WrongTransmission);
        }
        self.store(&f)
    }

    /// A code that is not a `0x1B` frame: a whole request, a frame in
    /// v1.0.7's three-byte framing, or nothing of ours.
    fn offer_legacy(&mut self, bytes: &[u8]) -> Result<Step, Error> {
        if payload_format(bytes).is_some() {
            return Ok(Step::Whole);
        }
        let Some((index, total, fragment)) = legacy_frame(bytes) else {
            return Ok(Step::NotOurs);
        };
        if usize::from(total) > self.capacity {
            return Ok(Step::TooLong {
                total,
                limit: self.capacity,
            });
        }
        let in_progress = self.reassembler.progress().1 != 0;
        if in_progress && self.legacy.is_none() {
            return Ok(Step::WrongTransmission);
        }
        // Frame zero says what is coming; nothing else can. A later frame
        // is taken only into the transmission its frame zero began.
        let format = if index == 0 {
            match payload_format(fragment) {
                Some(format) => format,
                None => return Ok(Step::NotOurs),
            }
        } else {
            match self.legacy {
                Some(format) if in_progress => format,
                // A seed's length is taken as a seed's, and the flow gets the
                // code, save one shape: a v1.0.7 set's last frame, 32 bytes
                // when its fragment is 29. A v1.0.7 unit at KasSigner's Safe,
                // 40 bytes a frame, shows it for about one length in 30 (a
                // multisig reply, or a transaction loaded back from the card),
                // and taken as a seed it would be offered for loading. A
                // 24-word compact SeedQR has that shape once in about 266,000.
                _ if compact_length(bytes) && !last_of_v107(bytes, index, total) => {
                    return Ok(Step::NotOurs)
                }
                _ if compact_length(bytes) => return Ok(Step::LastFrameOrSeed { total }),
                _ => return Ok(Step::BeforeFrameZero { index, total }),
            }
        };
        let step = self.store(&Frame {
            format,
            index,
            total,
            named: None,
            fragment,
        })?;
        if matches!(step, Step::Accepted { .. } | Step::Complete { .. }) {
            self.legacy = Some(format);
        }
        Ok(step)
    }

    /// Put a frame into the transmission in progress, and say what it did.
    fn store(&mut self, f: &Frame<'_>) -> Result<Step, Error> {
        let index = f.index as usize;
        let mut already = self.reassembler.progress().0;

        match self.reassembler.push(f) {
            Ok(()) => {}
            // A frame of another transmission (format, total, tag or digest
            // differ). One that names its payload replaces the set in progress,
            // as the sending screen changed. A v1.0.7 frame names nothing, so
            // cannot claim to be newer, and is dropped.
            Err(FrameError::StreamChanged) if f.named.is_some() => {
                self.reassembler.reset();
                already = 0;
                self.reassembler.push(f).map_err(Error::Frame)?;
            }
            Err(FrameError::StreamChanged) => return Ok(Step::WrongTransmission),
            // A held frame arriving again changed: two transmissions mixed, the
            // only way v1.0.7's frames show it. The set is dropped whole; the
            // frames that come round again make one set.
            Err(FrameError::Conflict) => {
                self.reset();
                return Ok(Step::Mismatched);
            }
            Err(e) => return Err(Error::Frame(e)),
        }

        let (have, need) = self.reassembler.progress();
        if have == already {
            return Ok(Step::Duplicate);
        }

        // A whole set that is not the payload frame 0 named is dropped whole,
        // not handed over: frames of two transmissions whose tags matched.
        if self.reassembler.is_complete() && !self.reassembler.digest_matches() {
            self.reset();
            return Ok(Step::Mismatched);
        }

        if self.reassembler.is_complete() {
            let format = self.reassembler.format().unwrap_or(Format::Opaque);
            return Ok(Step::Complete {
                format,
                len: self.payload_len(),
            });
        }

        Ok(Step::Accepted { index, have, need })
    }

    /// Whether a code is one frame of several, in either framing, decided as
    /// [`Scan::offer`] decides but before it is offered: the camera then goes
    /// on to the next frame, where a lone code (a whole request or a seed)
    /// usually ends the scan.
    pub fn of_several(&self, bytes: &[u8]) -> bool {
        match frame::parse(bytes, self.capacity) {
            Ok(f) => f.total > 1,
            Err(FrameError::TooManyFrames { .. }) => false,
            Err(_) => {
                payload_format(bytes).is_none()
                    && legacy_frame(bytes)
                        .is_some_and(|(_, total, _)| usize::from(total) <= self.capacity)
            }
        }
    }

    /// How many bytes the frames received hold: once complete, the payload's
    /// length, to size a buffer before filling it.
    pub fn payload_len(&self) -> usize {
        self.reassembler.payload_len()
    }

    /// Copy the reassembled payload out.
    ///
    /// # Errors
    ///
    /// `TooLarge` if `out` cannot hold it, `Frame` if the scan is not complete.
    pub fn collect(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.payload_len() {
            return Err(Error::TooLarge {
                needed: self.payload_len(),
            });
        }
        self.reassembler.collect(out).map_err(Error::Frame)
    }
}

/// What a payload is, from how it begins: `KSPT`, `PSKB`, or a kpub's raw
/// form (the marker and a kpub's version), as v1.0.7 units sent kpubs to
/// each other.
fn payload_format(bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(&kspt::MAGIC) {
        Some(Format::Kspt)
    } else if bytes.starts_with(pskb::MAGIC) {
        Some(Format::Pskb)
    } else if crate::kpub::starts_raw(bytes) {
        Some(Format::Kpub)
    } else {
        None
    }
}

/// The most frames v1.0.7 sent or read, unit and kassigner.org alike; its
/// unit's shape test held the total to it.
const V107_MAX_FRAMES: usize = 64;

/// Whether `bytes` are a compact SeedQR's length, 16 or 32 bytes.
fn compact_length(bytes: &[u8]) -> bool {
    matches!(bytes.len(), ENTROPY_12 | ENTROPY_24)
}

/// Whether a seed-length code is the last frame of a v1.0.7 set: 32 bytes,
/// its index one below its total. Only a balanced split's last fragment is
/// shorter than the rest, and 16 bytes is never a v1.0.7 frame: fragments
/// under 20 bytes are padded to 20.
fn last_of_v107(bytes: &[u8], index: u8, total: u8) -> bool {
    bytes.len() == ENTROPY_24 && u16::from(index) + 1 == u16::from(total)
}

/// The length v1.0.7 zero-pads a shorter fragment to, unit and kassigner.org
/// alike, its length byte still the fragment's; both read the fragment by the
/// length byte and ignored the rest.
const V107_PADDED: usize = 20;

/// A frame in v1.0.7's framing: `index`, `total`, `frag_len`, then the
/// fragment. `None` unless the length byte is nonzero and exactly what follows
/// (or what follows is the fragment zero-padded to 20), the index is below the
/// total, and the total is from two (a single code went bare) to v1.0.7's 64.
///
/// A larger total is no v1.0.7 frame: its unit took none and its companion
/// never split into more. A compact SeedQR's random bytes form such a header
/// about once in 550, and refusing it as too long would leave that seed
/// unloadable.
///
/// The padded frame must be read: a v1.0.7 unit's reply at KasSigner's Safe, 40
/// bytes a frame, ends on one for about a quarter of the lengths it can show,
/// and the flow ends the scan on a code that is no request.
fn legacy_frame(bytes: &[u8]) -> Option<(u8, u8, &[u8])> {
    let [index, total, len, rest @ ..] = bytes else {
        return None;
    };
    let (index, total, len) = (*index, *total, *len);
    let fragment = rest.get(..usize::from(len))?;
    let padding = &rest[fragment.len()..];
    let shaped =
        padding.is_empty() || (rest.len() == V107_PADDED && padding.iter().all(|b| *b == 0));
    (shaped && len != 0 && total >= 2 && usize::from(total) <= V107_MAX_FRAMES && index < total)
        .then_some((index, total, fragment))
}
