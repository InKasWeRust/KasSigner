// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Multi-frame transport.
//!
//! A payload too large for one QR code is split across several. Each frame
//! carries a five-byte header, frame 0 an eight-byte one, and a fragment.
//! No length byte: a QR code carries its own byte count, and a decoder
//! returns exactly the bytes encoded or none.
//!
//! ```text
//! magic      1   0x1B, which no text payload can begin with
//! format     1   what is being assembled
//! index      1
//! total      1
//! tag        1   the first byte of the whole payload's SHA-256
//! digest     3   its next three, in frame 0 only
//! fragment   n   the rest of the code
//! ```
//!
//! The magic is one byte checked against one constant rather than a shape
//! test, which text can pass: in bare hex such as `02ab...` every digit,
//! `0x30` to `0x39`, reads as a plausible frame count. Nothing else a camera
//! might catch begins below `0x20`: base58 runs `0x31` to `0x7A`, hex `0x30`
//! to `0x66`, a mnemonic `0x61` to `0x7A`.
//!
//! The format is in every frame, so the first one caught, whatever its
//! index, says what is coming.
//!
//! Every frame names the payload. Otherwise a screen switching to another
//! payload of the same format and count, a transaction rebuilt with another
//! amount, could leave a reader with frame 0 of one and frame 1 of the
//! other: a transaction nobody sent, which parses. Frame 0 names the whole
//! four-byte digest, and a complete set is checked against it, so a mix of
//! two transmissions is collected once in four billion. Every other frame
//! names only the tag, which shows a switch on the frame it happens 255
//! times in 256; the rest are caught when the set completes. The tag leaves
//! those frames three bytes more than the whole digest would: 225 of a
//! version-9 code's 230 and 48 of a version-3 code's 53 (frame 0: 222 and
//! 45). A frame of the earlier five-byte layout, whose fifth byte was its
//! length, names a digest its set makes only by that same chance.
//!
//! Frames are slotted by their own index, so they may arrive in any order,
//! repeat, or interleave with a scan of something else. Nothing is
//! allocated: [`Reassembler`] works in buffers the caller lends it, static
//! arrays on a device, vectors in a browser.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Marks a multi-frame frame.
///
/// Below `0x20`, so no text payload can begin with it.
pub const MAGIC: u8 = 0x1B;

/// Bytes of a payload's digest a transmission carries, whole in frame 0.
pub const DIGEST_LEN: usize = 4;

/// Bytes of header every frame carries: the magic, the format, the index,
/// the total and the tag, the digest's first byte.
pub const HEADER_LEN: usize = 5;

/// Bytes of header frame 0 carries: the digest's other bytes besides.
pub const FIRST_HEADER_LEN: usize = HEADER_LEN + DIGEST_LEN - 1;

/// What frame 0 gives up to the digest, against any other frame.
const FIRST_EXTRA: usize = FIRST_HEADER_LEN - HEADER_LEN;

/// Bytes of header frame `index` carries.
pub const fn header_len(index: u8) -> usize {
    if index == 0 {
        FIRST_HEADER_LEN
    } else {
        HEADER_LEN
    }
}

/// A payload's digest, as frame 0 of it carries: the first [`DIGEST_LEN`]
/// bytes of its SHA-256.
pub fn digest(payload: &[u8]) -> [u8; DIGEST_LEN] {
    let full = sha256(payload);
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&full[..DIGEST_LEN]);
    out
}

/// Bytes of [`sha256`].
pub const SHA256_LEN: usize = 32;

/// A payload's whole SHA-256, of which [`digest`] is the start: for a
/// reader that must know a payload it holds is still the one it took, as
/// the firmware's request between its review and its signing.
pub fn sha256(payload: &[u8]) -> [u8; SHA256_LEN] {
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(&Sha256::digest(payload));
    out
}

/// What a frame sequence is carrying. The values are part of the format:
/// adding one is a specification change. A unit picks its parser by it, so
/// a wrong value fails to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Format {
    /// A KSPT transaction.
    Kspt = 1,
    /// A rusty-kaspa PSKB bundle.
    Pskb = 2,
    /// An extended public key export.
    Kpub = 3,
    /// A multisig descriptor.
    Descriptor = 4,
    /// An encrypted container.
    Container = 5,
    /// Bytes whose meaning the caller tracks.
    Opaque = 0xFF,
}

impl Format {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Format::Kspt),
            2 => Some(Format::Pskb),
            3 => Some(Format::Kpub),
            4 => Some(Format::Descriptor),
            5 => Some(Format::Container),
            0xFF => Some(Format::Opaque),
            _ => None,
        }
    }
}

/// What a frame says of the payload it is part of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Named {
    /// Frame 0's: the whole [`digest`].
    Digest([u8; DIGEST_LEN]),
    /// Any other frame's: the digest's first byte.
    Tag(u8),
}

impl Named {
    /// The digest's first byte, which every frame of a transmission names.
    pub const fn tag(&self) -> u8 {
        match self {
            Named::Digest(d) => d[0],
            Named::Tag(t) => *t,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Shorter than the header.
    TooShort,
    /// Does not begin with [`MAGIC`]: something else was in view, not a
    /// fault.
    NotAFrame,
    /// A format byte this reader does not know.
    UnknownFormat(u8),
    /// `total` is zero, or the index is not below it.
    BadIndex { index: u8, total: u8 },
    /// More frames than the caller's profile allows.
    TooManyFrames { total: u8, limit: usize },
    /// This frame disagrees with the frames already seen: another format,
    /// frame count or tag, or, frame 0, another digest. The sending screen
    /// changed, or two are in front of the camera.
    StreamChanged,
    /// A frame already held arrived again with another fragment. A sender
    /// never changes a frame, so the set mixes two transmissions and which
    /// frame came from where cannot be told; v1.0.7's frames, which name no
    /// digest, mostly end here.
    Conflict,
    /// Every frame arrived, and what they make is not the payload frame 0
    /// names: frames of two transmissions whose tags matched, or a set with
    /// no digest to check. Nothing is collected from such a set.
    DigestMismatch,
    /// A fragment longer than a slot or than a length byte holds, a slot
    /// past the caller's buffer or the address range, or a payload past the
    /// caller's buffer.
    TooLarge,
}

/// One parsed frame, borrowing its fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub format: Format,
    pub index: u8,
    pub total: u8,
    /// What the frame names of its payload: frame 0 the whole [`digest`],
    /// any other the tag. `None` for v1.0.7's three-byte frames, which name
    /// nothing; a reader builds their `Frame` itself.
    pub named: Option<Named>,
    pub fragment: &'a [u8],
}

/// Parse one frame. `max_frames` is the caller's profile bound: it comes
/// from a display and a camera, not from the format.
///
/// # Errors
///
/// `NotAFrame` without the magic, the ordinary case for a camera pointed at
/// anything else; `TooShort`, `UnknownFormat`, `BadIndex`, `TooManyFrames`.
pub fn parse(frame: &[u8], max_frames: usize) -> Result<Frame<'_>, FrameError> {
    if frame.len() < HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    if frame[0] != MAGIC {
        return Err(FrameError::NotAFrame);
    }
    let format = Format::from_u8(frame[1]).ok_or(FrameError::UnknownFormat(frame[1]))?;
    let index = frame[2];
    let total = frame[3];

    if total == 0 || index >= total {
        return Err(FrameError::BadIndex { index, total });
    }
    if total as usize > max_frames {
        return Err(FrameError::TooManyFrames {
            total,
            limit: max_frames,
        });
    }
    let header = header_len(index);
    if frame.len() < header {
        return Err(FrameError::TooShort);
    }
    let named = if index == 0 {
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(&frame[HEADER_LEN - 1..header]);
        Named::Digest(digest)
    } else {
        Named::Tag(frame[HEADER_LEN - 1])
    };
    Ok(Frame {
        format,
        index,
        total,
        named: Some(named),
        fragment: &frame[header..],
    })
}

/// Serialize a fragment into `out`, returning bytes written. `digest` is the
/// whole payload's, [`digest`]: frame 0 carries it whole, any other frame its
/// first byte.
pub fn write(
    format: Format,
    index: u8,
    total: u8,
    digest: [u8; DIGEST_LEN],
    fragment: &[u8],
    out: &mut [u8],
) -> Result<usize, FrameError> {
    if total == 0 || index >= total {
        return Err(FrameError::BadIndex { index, total });
    }
    // A reader records a fragment's length in a byte.
    if fragment.len() > u8::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let header = header_len(index);
    let n = header + fragment.len();
    if out.len() < n {
        return Err(FrameError::TooLarge);
    }
    out[0] = MAGIC;
    out[1] = format as u8;
    out[2] = index;
    out[3] = total;
    out[HEADER_LEN - 1..header].copy_from_slice(&digest[..header - (HEADER_LEN - 1)]);
    out[header..n].copy_from_slice(fragment);
    Ok(n)
}

/// Frame `index` of `payload` sent in `total` frames, serialized into `out`,
/// returning bytes written.
///
/// Split evenly, not greedily, frame 0's three extra header bytes counted
/// against its fragment, so the codes are the same size but the last and a
/// reader does not refocus: 297 bytes in two frames go as 147 and 150, both
/// codes 155 bytes, not 222 and 75. An `index` the split leaves no bytes
/// for, an empty payload's among them, is `BadIndex`.
pub fn write_split(
    format: Format,
    payload: &[u8],
    index: u8,
    total: u8,
    out: &mut [u8],
) -> Result<usize, FrameError> {
    if total == 0 || index >= total {
        return Err(FrameError::BadIndex { index, total });
    }
    // Frame 0's extra header taken as the payload's first bytes: every code
    // then carries `per` of them past the five-byte header.
    let per = (payload.len() + FIRST_EXTRA).div_ceil(usize::from(total));
    let i = usize::from(index);
    let start = (i * per).saturating_sub(FIRST_EXTRA);
    let end = ((i + 1) * per)
        .saturating_sub(FIRST_EXTRA)
        .min(payload.len());
    if start >= end {
        return Err(FrameError::BadIndex { index, total });
    }
    write(
        format,
        index,
        total,
        digest(payload),
        &payload[start..end],
        out,
    )
}

/// v1.0.7's frames, written for a wallet built on that release.
///
/// A frame is `index`, `total`, the fragment's length, then the fragment,
/// with nothing marking it as a frame and nothing naming the payload: what
/// [`MAGIC`] and the digest were added to fix. A payload that fits one code
/// goes bare. Kept apart from the frames above, and only written: a unit
/// reads them in its scan, where their shape test lives.
pub mod v107 {
    /// A frame's header: `index`, `total`, `frag_len`.
    pub const HEADER_LEN: usize = 3;

    /// The most a code carries, a version-9 code's bytes: a bare payload of
    /// up to this goes as one code.
    pub const CODE_LEN: usize = 230;

    /// The most of a payload one frame carries.
    pub const FRAGMENT_LEN: usize = CODE_LEN - HEADER_LEN;

    /// The most frames v1.0.7 sent or read.
    pub const MAX_FRAMES: usize = 64;

    /// The length a shorter fragment is zero-padded to, its length byte
    /// still the fragment's.
    pub const PADDED_LEN: usize = 20;

    /// How many codes `len` bytes take: one bare code up to
    /// [`CODE_LEN`], else frames of [`FRAGMENT_LEN`] at most. Zero for an
    /// empty payload.
    pub const fn codes(len: usize) -> usize {
        if len == 0 {
            0
        } else if len <= CODE_LEN {
            1
        } else {
            len.div_ceil(FRAGMENT_LEN)
        }
    }

    /// Code `index` of `payload`'s [`codes`], into `out`, returning its
    /// length: the payload itself when it goes bare, else a frame. Split
    /// evenly, as v1.0.7 split: every fragment the same size but the last,
    /// which is what is left. `None` for an index past the codes, more
    /// than [`MAX_FRAMES`] of them, or an `out` too short.
    pub fn write(payload: &[u8], index: usize, out: &mut [u8]) -> Option<usize> {
        let total = codes(payload.len());
        if index >= total || total > MAX_FRAMES {
            return None;
        }
        if total == 1 {
            out.get_mut(..payload.len())?.copy_from_slice(payload);
            return Some(payload.len());
        }
        let per = payload.len().div_ceil(total);
        let start = index * per;
        let fragment = payload.get(start..(start + per).min(payload.len()))?;
        let body = fragment.len().max(PADDED_LEN);
        let out = out.get_mut(..HEADER_LEN + body)?;
        out[0] = u8::try_from(index).ok()?;
        out[1] = u8::try_from(total).ok()?;
        out[2] = u8::try_from(fragment.len()).ok()?;
        out[HEADER_LEN..HEADER_LEN + fragment.len()].copy_from_slice(fragment);
        out[HEADER_LEN + fragment.len()..].fill(0);
        Some(HEADER_LEN + body)
    }
}

/// How many frames a payload of `len` bytes needs when a frame carries
/// `bytes_per_frame` of it, frame 0 three fewer for the digest.
pub const fn frames_needed(len: usize, bytes_per_frame: usize) -> usize {
    if len == 0 || bytes_per_frame == 0 {
        return 0;
    }
    (len + FIRST_EXTRA).div_ceil(bytes_per_frame)
}

/// The most bytes `frames` frames carry when a frame carries
/// `bytes_per_frame`, frame 0 three fewer for the digest: what
/// [`frames_needed`] fits in them.
pub const fn payload_capacity(frames: usize, bytes_per_frame: usize) -> usize {
    (frames * bytes_per_frame).saturating_sub(FIRST_EXTRA)
}

/// Collects frames until every index has arrived.
///
/// Generic over the caller's storage: `buf` receives the fragments at fixed
/// slot offsets, `seen` records which indices have arrived, `sizes` their
/// lengths.
pub struct Reassembler<'a> {
    buf: &'a mut [u8],
    seen: &'a mut [bool],
    sizes: &'a mut [u8],
    slot: usize,
    /// The transmission in progress: its format, its frame count and its
    /// tag, as its first frame gave them.
    stream: Option<(Format, u8, Option<u8>)>,
    /// The payload's whole digest, once frame 0 has given it.
    named: Option<[u8; DIGEST_LEN]>,
}

/// What a [`Reassembler`] knows beside its buffers: the transmission in
/// progress, as [`Reassembler::suspend`] hands it over and
/// [`Reassembler::resume`] takes it back. Opaque, and only meaningful over
/// the buffers it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    slot: usize,
    stream: Option<(Format, u8, Option<u8>)>,
    named: Option<[u8; DIGEST_LEN]>,
}

impl Drop for Reassembler<'_> {
    /// Clears the fragments however the borrow ends: the payload collected,
    /// an early return, a panic unwinding. [`Reassembler::reset`] is for a
    /// caller giving up on a transmission.
    fn drop(&mut self) {
        self.buf.zeroize();
        self.sizes.zeroize();
    }
}

impl<'a> Reassembler<'a> {
    /// `slot` is the byte stride between fragments in `buf`, at least the
    /// largest fragment the caller will accept. `seen` and `sizes` must be at
    /// least as long as the profile's frame limit.
    ///
    /// `seen` and `sizes` are cleared, so nothing left in them reads as a
    /// frame's. `buf` is read only where `seen` marks a frame, so it is left
    /// as is; [`Reassembler::reset`] and the drop clear it.
    pub fn new(buf: &'a mut [u8], seen: &'a mut [bool], sizes: &'a mut [u8], slot: usize) -> Self {
        for s in seen.iter_mut() {
            *s = false;
        }
        sizes.zeroize();
        Self {
            buf,
            seen,
            sizes,
            slot,
            stream: None,
            named: None,
        }
    }

    /// Give the buffers back uncleared, and keep the stream in progress for
    /// [`Reassembler::resume`] over the same buffers later: for a holder
    /// that cannot keep a borrow across calls, such as a language binding.
    ///
    /// The drop is skipped, since it would wipe the fragments a resume reads;
    /// clearing the buffers is then the holder's job. A `State` is only good
    /// over the buffers it was taken with, unchanged in between.
    pub fn suspend(self) -> State {
        let state = State {
            slot: self.slot,
            stream: self.stream,
            named: self.named,
        };
        core::mem::forget(self);
        state
    }

    /// A reassembler over `buf`, `seen` and `sizes` as [`Reassembler::suspend`]
    /// left them, carrying on from `state` with nothing cleared.
    ///
    /// Unless they do not fit together: a frame count past the arrays, or an
    /// arrived frame whose fragment would not sit in `buf` at its slot, would
    /// make [`Reassembler::is_complete`], [`Reassembler::digest_matches`] and
    /// [`Reassembler::collect`] index past them. Then everything is cleared,
    /// as [`Reassembler::reset`] does, and the scan starts again.
    pub fn resume(
        buf: &'a mut [u8],
        seen: &'a mut [bool],
        sizes: &'a mut [u8],
        state: State,
    ) -> Self {
        let mut r = Self {
            buf,
            seen,
            sizes,
            slot: state.slot,
            stream: state.stream,
            named: state.named,
        };
        if !r.fits() {
            r.reset();
        }
        r
    }

    /// Whether everything held can be read without indexing past the
    /// buffers: the frame count within the arrays, and every arrived frame
    /// inside the count, no longer than a slot, and in `buf` at its slot, as
    /// [`Reassembler::push`] places them.
    fn fits(&self) -> bool {
        let total = self.stream.map_or(0, |(_, t, _)| usize::from(t));
        if total > self.seen.len().min(self.sizes.len()) {
            return false;
        }
        self.seen
            .iter()
            .enumerate()
            .filter(|(_, arrived)| **arrived)
            .all(|(i, _)| {
                // `i < total`, so `sizes[i]` is inside the arrays.
                i < total && {
                    let len = usize::from(self.sizes[i]);
                    len <= self.slot
                        && i.checked_mul(self.slot)
                            .and_then(|start| start.checked_add(len))
                            .is_some_and(|end| end <= self.buf.len())
                }
            })
    }

    /// Forget everything received so far, the fragments too: a payload can
    /// be a seed. Zeroized rather than filled: a plain write would do for a
    /// buffer that outlives the call, as this one does, but zeroizing holds
    /// wherever a buffer later moves.
    pub fn reset(&mut self) {
        self.buf.zeroize();
        self.sizes.zeroize();
        for s in self.seen.iter_mut() {
            *s = false;
        }
        self.stream = None;
        self.named = None;
    }

    /// What is being assembled, from the first frame held, whatever its
    /// index.
    pub fn format(&self) -> Option<Format> {
        self.stream.map(|(f, _, _)| f)
    }

    /// Frames received so far, and how many are expected.
    pub fn progress(&self) -> (usize, usize) {
        let have = self.seen.iter().filter(|s| **s).count();
        (have, self.stream.map_or(0, |(_, t, _)| t as usize))
    }

    /// Which of the first 64 frames have been received, bit `i` frame `i`:
    /// what a scan screen draws one dot a frame from.
    pub fn received(&self) -> u64 {
        self.seen
            .iter()
            .take(64)
            .enumerate()
            .fold(0, |bits, (i, &s)| bits | (u64::from(s) << i))
    }

    /// Accept one frame.
    ///
    /// A repeat, the normal case for a camera on a looping display, is
    /// ignored: it names the same tag, frame 0 the same digest.
    ///
    /// # Errors
    ///
    /// `StreamChanged` when the format, the frame count or the tag disagrees
    /// with the transmission in progress, or a frame 0 names another digest:
    /// a KSPT and a PSKB of one transaction are close in size, and two
    /// transactions differing in an amount the same size. `Conflict` for a
    /// held frame with another fragment, `BadIndex` for an index not below
    /// the count, `TooManyFrames` and `TooLarge` for a frame the buffers
    /// cannot hold.
    pub fn push(&mut self, frame: &Frame<'_>) -> Result<(), FrameError> {
        // The count against the arrays: `max_frames` and the arrays' lengths
        // are separate caller numbers, and `Frame`'s fields are public, so a
        // frame need not come through `parse`. A count past the arrays would
        // make `is_complete`, `payload_len` and `collect` read `seen[..total]`
        // past its end, a panic.
        let total = frame.total as usize;
        let capacity = self.seen.len().min(self.sizes.len());
        if total > capacity {
            return Err(FrameError::TooManyFrames {
                total: frame.total,
                limit: capacity,
            });
        }
        // A frame outside its own set, refused as `parse` refuses it. Stored,
        // it would show in `progress` and `received`, which read past the
        // count, as more frames than the set holds.
        if frame.index >= frame.total {
            return Err(FrameError::BadIndex {
                index: frame.index,
                total: frame.total,
            });
        }
        // Held to the transmission in progress, and recorded only once the
        // frame is stored, below: a first frame refused for its size must not
        // tie the reassembler to its transmission with nothing held.
        let stream = (frame.format, frame.total, frame.named.map(|n| n.tag()));
        if self.stream.is_some_and(|held| held != stream) {
            return Err(FrameError::StreamChanged);
        }
        // A whole digest other than the one held is another transmission
        // whose tag matched by chance, a repeat of frame 0 included.
        let whole = match frame.named {
            Some(Named::Digest(d)) => Some(d),
            _ => None,
        };
        if let (Some(d), Some(held)) = (whole, self.named) {
            if d != held {
                return Err(FrameError::StreamChanged);
            }
        }
        // Already true by the checks above (`index < total <= capacity`);
        // kept beside the indexing it guards.
        let i = frame.index as usize;
        if i >= capacity {
            return Err(FrameError::TooManyFrames {
                total: frame.total,
                limit: capacity,
            });
        }
        if frame.fragment.len() > self.slot {
            return Err(FrameError::TooLarge);
        }
        // Its length is recorded in a byte, and a slot may be longer.
        let len = u8::try_from(frame.fragment.len()).map_err(|_| FrameError::TooLarge)?;
        // The slot is the caller's number, so its offset is a checked sum:
        // `usize` is 32 bits on a unit. A frame placed here fits `buf`, so
        // the readers' offsets for it cannot wrap.
        let place = i
            .checked_mul(self.slot)
            .and_then(|start| Some((start, start.checked_add(frame.fragment.len())?)))
            .filter(|&(_, end)| end <= self.buf.len());
        let Some((start, end)) = place else {
            return Err(FrameError::TooLarge);
        };
        if self.seen[i] {
            let held = &self.buf[start..start + usize::from(self.sizes[i])];
            if held != frame.fragment {
                return Err(FrameError::Conflict);
            }
            return Ok(());
        }
        self.buf[start..end].copy_from_slice(frame.fragment);
        self.sizes[i] = len;
        self.seen[i] = true;
        self.stream = Some(stream);
        if whole.is_some() {
            self.named = whole;
        }
        Ok(())
    }

    /// True once every frame has arrived.
    pub fn is_complete(&self) -> bool {
        match self.stream {
            None => false,
            Some((_, t, _)) => self.seen[..t as usize].iter().all(|s| *s),
        }
    }

    /// Whether a complete set makes the payload its frames named: its
    /// fragments, in order, hash to the digest frame 0 carried. True for
    /// frames that name nothing. False for a set not complete, or one with
    /// tags but no digest held, which only frames built by hand can make.
    pub fn digest_matches(&self) -> bool {
        let Some((_, total, tag)) = self.stream else {
            return false;
        };
        if !self.is_complete() {
            return false;
        }
        if tag.is_none() {
            return true;
        }
        let Some(named) = self.named else {
            return false;
        };
        let mut hash = Sha256::new();
        for i in 0..total as usize {
            let start = i * self.slot;
            hash.update(&self.buf[start..start + self.sizes[i] as usize]);
        }
        hash.finalize()[..DIGEST_LEN] == named
    }

    /// Bytes the frames received so far hold: once
    /// [`Reassembler::is_complete`], the payload's length, to size a buffer
    /// for [`Reassembler::collect`].
    pub fn payload_len(&self) -> usize {
        let Some((_, total, _)) = self.stream else {
            return 0;
        };
        (0..total as usize)
            .filter(|i| self.seen[*i])
            .map(|i| self.sizes[i] as usize)
            .sum()
    }

    /// Copy the reassembled payload into `out`, returning its length.
    /// Fragments sit at fixed slot offsets and any may be short, so the
    /// payload is gathered fragment by fragment.
    ///
    /// # Errors
    ///
    /// `TooShort` before the set is complete, `DigestMismatch` when it is
    /// complete and is not the payload its frames named, `TooLarge` when
    /// `out` cannot hold it. Every error leaves `out` as it was: nothing of
    /// the payload is written unless all of it is.
    pub fn collect(&self, out: &mut [u8]) -> Result<usize, FrameError> {
        let Some((_, total, _)) = self.stream else {
            return Err(FrameError::TooShort);
        };
        if !self.is_complete() {
            return Err(FrameError::TooShort);
        }
        if !self.digest_matches() {
            return Err(FrameError::DigestMismatch);
        }
        // Sized before the first byte is copied, so an error leaves no part
        // of the payload, seed words perhaps, in a buffer the caller has no
        // reason to wipe.
        if self.payload_len() > out.len() {
            return Err(FrameError::TooLarge);
        }
        let mut n = 0usize;
        for i in 0..total as usize {
            let len = self.sizes[i] as usize;
            let start = i * self.slot;
            out[n..n + len].copy_from_slice(&self.buf[start..start + len]);
            n += len;
        }
        Ok(n)
    }
}
