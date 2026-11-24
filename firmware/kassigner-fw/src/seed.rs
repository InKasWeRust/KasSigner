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

//! Making a seed, and moving one as a SeedQR.
//!
//! # Where this sits
//!
//! The hash and the dice function are level 2 (`kassigner_crypto::seed`),
//! as key material passes through them. Here is the device's policy around
//! them: which sources exist, what each is credited, what counts as a live
//! sample, and how much a seed must be fed before the device makes one. The
//! numbers, and the measurements behind them, are in [`crate::limits`].
//!
//! # Combine, and count honestly
//!
//! Every source goes into one pool, tagged, and the seed is the hash of all
//! of it. Sources need not run at once (on the M5 the camera and the touch
//! screen both want the person's attention, so they take turns); the hash
//! does not care when a sample came. The device enforces the count: credits
//! conservative against the measured figures, and no seed below
//! [`limits::SEED_MIN_BITS`].
//!
//! # A mixture means every source takes part
//!
//! A [`Collector`] is told which sources its unit has, and each must reach
//! its own share, [`limits::SEED_MIN_BITS`] divided between them. A total
//! alone is met by the fastest source: one camera frame can carry more
//! credited bits than the whole requirement, and the person's part would be
//! decoration.
//!
//! So a source producing nothing stops the seed instead of being carried by
//! the others, and a covered lens becomes an instruction to give the device
//! light. A source the unit lacks is not required: a board whose IMU did not
//! answer says so and asks the others for more. The Waveshare (a QMI8658)
//! and the M5 (a BMI270) have one; the P4 has none.
//!
//! The total may run past the requirement at no cost: the extra bytes go
//! into the same hash, and the count only decides when to stop asking.
//!
//! The chip's generator is absorbed and credited nothing: a seed never rests
//! on silicon nobody can inspect, and since an input cannot weaken a hash,
//! the draw is free insurance against every other source being wrong the
//! same way. Its health tests still run inside `fill`, and a generator that
//! fails them refuses the seed: a device whose generator is dead has no
//! business making one.
//!
//! # Gates, not just credits
//!
//! A credit says what a live source is worth, not whether it produces
//! anything: the M5's camera in a dark room returned a quarter of a megabyte
//! of one value while running normally. So every sample is judged first: a
//! repeat of any of the source's last [`REPEAT_WINDOW`] samples (the last
//! one, for dice), a camera chunk with too few distinct values or changed
//! bytes, an IMU chunk with a frozen axis (even with the other two alive),
//! and a touch at the same place as the last (a finger held still) are not
//! absorbed or credited, and each is reported so a screen can say why the
//! count is not moving.
//!
//! # Dice are not one of the device's sources
//!
//! A dice seed ([`kassigner_crypto::seed::from_dice`]) is a seed of its
//! own: a pure function of the rolls, SHA-256 over the digits as typed,
//! which a person who trusts none of the hardware can check on paper.
//! Dice Seed asks for [`crate::flow::DICE_ROLLS_12`] rolls for twelve words
//! and [`crate::flow::DICE_ROLLS_24`] for twenty-four, past the function's
//! own least, 50 and 99. [`Collector::absorb_dice`] is for a caller wanting
//! rolls in the mixture; nothing on a unit calls it.
//!
//! # SeedQR
//!
//! SeedSigner's standard and compact encodings are read and written at level
//! 2 ([`kassigner_crypto::slot`]); here a decoded payload is recognised as
//! one, and one is drawn. A standard SeedQR is 48 or 96 decimal digits, a
//! compact one 16 or 32 raw bytes, and no other length is either. Its digits
//! or bytes are the seed.
//!
//! # What is wiped, and by whom
//!
//! A camera chunk or an IMU buffer is the caller's to clear once absorbed,
//! as the signer's loop does. The generator scratch is drawn and wiped here.
//! A drawn SeedQR wipes itself: the digits and bytes handed to the encoder
//! are cleared here, the matrix and the encoder's buffers by `kassigner-qr`,
//! so a caller drops the matrix once it is drawn.

use kassigner_crypto::bip39::{self, Mnemonic, ENTROPY_12, ENTROPY_24, WORDS_12, WORDS_24};
use kassigner_crypto::seed::{Pool, SeedError, Words};
use kassigner_crypto::slot::{self, SlotError};
use kassigner_hal::entropy::{self, Entropy};
use zeroize::Zeroize;

use crate::limits;

/// Where a sample came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The chip's generator, through `fill`. Credited nothing.
    Generator,
    /// Frame-to-frame deltas of a band across the sensor.
    Camera,
    /// The low byte of each gyro axis, three interleaved.
    Imu,
    /// One touch: where, and microseconds since the last.
    Touch,
    /// Rolls typed in, `1` to `6`.
    Dice,
}

impl Source {
    /// The tag the pool frames this source's samples with.
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Source::Generator => b"generator",
            Source::Camera => b"camera",
            Source::Imu => b"imu",
            Source::Touch => b"touch",
            Source::Dice => b"dice",
        }
    }

    const fn index(self) -> usize {
        match self {
            Source::Generator => 0,
            Source::Camera => 1,
            Source::Imu => 2,
            Source::Touch => 3,
            Source::Dice => 4,
        }
    }
}

const SOURCES: usize = 5;

/// Samples a source's next one is held against, newest first: one matching
/// any of them is a repeat. A cycle is caught as well as a sample stuck:
/// the M5's camera takes turns between two buffers, and if they stopped
/// being written its samples would take turns too, each new against the
/// one before it. Eight is more than any unit's frame buffers.
///
/// Dice look one roll back only: a die has six faces, and a caller adding
/// a roll at a time would lose most of its rolls to a longer look.
pub const REPEAT_WINDOW: usize = 8;

/// What became of a sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Absorbed. `bits` is what it earned, `total` the running count.
    Credited { bits: u32, total: u32 },
    /// Identical to one of the last [`REPEAT_WINDOW`] samples from this
    /// source, the last one for dice. Not absorbed.
    Repeat,
    /// Failed its liveness gate. Not absorbed.
    Dead,
    /// Fewer bytes than the source's sample minimum. Not absorbed.
    Short { len: usize, min: usize },
    /// A touch at the same place as the last. Not absorbed.
    Still,
}

impl Verdict {
    /// Bits this sample earned, zero unless it was credited.
    pub const fn bits(self) -> u32 {
        match self {
            Verdict::Credited { bits, .. } => bits,
            _ => 0,
        }
    }
}

/// Why no seed was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer credited bits than [`limits::SEED_MIN_BITS`] in total.
    NotEnough {
        have: u32,
        need: u32,
    },
    /// A source this unit has that did not reach its share.
    SourceShort {
        source: Source,
        have: u32,
        need: u32,
    },
    /// A roll that is not `1` to `6`, at that position.
    BadRoll {
        position: usize,
    },
    /// The generator refused a draw.
    Entropy(entropy::Error),
    Seed(SeedError),
}

impl From<entropy::Error> for Error {
    fn from(e: entropy::Error) -> Self {
        Error::Entropy(e)
    }
}

impl From<SeedError> for Error {
    fn from(e: SeedError) -> Self {
        match e {
            SeedError::BadRoll { position } => Error::BadRoll { position },
            e => Error::Seed(e),
        }
    }
}

/// A seed being collected: feed it samples until [`Collector::is_enough`],
/// then [`Collector::finish`].
///
/// Clears itself on drop, finished or abandoned: the pool wipes its own hash
/// state, and this clears the rest, the fingerprints and the last touch,
/// which record what went in.
pub struct Collector {
    pool: Pool,
    credited: u32,
    /// Bits credited per source, and which sources this unit has.
    per_source: [u32; SOURCES],
    required: [bool; SOURCES],
    share: u32,
    /// Fingerprints of the last samples absorbed per source, newest first,
    /// and how many of each are held, for the repeat check. Sixty-four
    /// bits: a collision only leaves a fresh sample uncounted, one time in
    /// 2^64 for each fingerprint it is held against.
    last: [[u64; REPEAT_WINDOW]; SOURCES],
    held: [usize; SOURCES],
    last_touch: Option<(u16, u16)>,
    /// Moving touches absorbed, for the per-event credit.
    touches: u32,
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.last.zeroize();
        self.held.zeroize();
        // `None` alone writes the tag and leaves the place behind it.
        if let Some((x, y)) = self.last_touch.as_mut() {
            x.zeroize();
            y.zeroize();
        }
        self.last_touch = None;
        self.per_source.zeroize();
        self.credited = 0;
        self.touches = 0;
    }
}

impl core::fmt::Debug for Collector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Collector({} bits of {}, redacted)",
            self.credited,
            limits::SEED_MIN_BITS
        )
    }
}

impl Collector {
    /// A collector for a unit that has these sources, each to reach
    /// [`Collector::share`]. [`Source::Generator`] is credited nothing, so it
    /// is ignored here rather than made a share nobody can fill. An empty
    /// list leaves the total as the only rule.
    pub fn new(sources: &[Source]) -> Self {
        let mut required = [false; SOURCES];
        let mut n = 0u32;
        for &s in sources {
            if matches!(s, Source::Generator) || required[s.index()] {
                continue;
            }
            required[s.index()] = true;
            n += 1;
        }
        Self {
            pool: Pool::new(),
            credited: 0,
            per_source: [0; SOURCES],
            required,
            share: limits::SEED_MIN_BITS.div_ceil(n.max(1)),
            last: [[0; REPEAT_WINDOW]; SOURCES],
            held: [0; SOURCES],
            last_touch: None,
            touches: 0,
        }
    }

    /// Bits each of this unit's sources must reach on its own.
    pub const fn share(&self) -> u32 {
        self.share
    }

    /// Bits credited so far, from everything. It stops at the sum of the
    /// shares, since no source is credited past its own.
    pub const fn credited(&self) -> u32 {
        self.credited
    }

    /// Bits credited to one source.
    pub const fn credited_from(&self, source: Source) -> u32 {
        self.per_source[source.index()]
    }

    /// Bits still needed on the total, zero once there are enough.
    pub const fn remaining(&self) -> u32 {
        limits::SEED_MIN_BITS.saturating_sub(self.credited)
    }

    /// The first of this unit's sources still under its share, if any: what
    /// a screen names while the count is not moving.
    pub fn short(&self) -> Option<Source> {
        [Source::Camera, Source::Imu, Source::Touch, Source::Dice]
            .into_iter()
            .find(|&s| self.required[s.index()] && self.per_source[s.index()] < self.share)
    }

    /// Whether [`Collector::finish`] would make a seed.
    pub fn is_enough(&self) -> bool {
        self.credited >= limits::SEED_MIN_BITS && self.short().is_none()
    }

    /// Absorb a draw from the chip's generator, credited nothing. `scratch`
    /// is filled through `fill`, so the draw is health-tested, then absorbed
    /// and wiped before this returns.
    ///
    /// # Errors
    ///
    /// The generator's, and a seed should not be made after one: a dead
    /// generator is a dead device.
    pub fn absorb_generator<E: Entropy + ?Sized>(
        &mut self,
        rng: &mut E,
        scratch: &mut [u8],
    ) -> Result<(), entropy::Error> {
        rng.fill(scratch)?;
        self.pool.absorb(Source::Generator.tag(), scratch);
        crate::wipe::wipe(scratch);
        Ok(())
    }

    /// Absorb a camera sample: the byte-by-byte delta between two frames
    /// across a band of the sensor, as the capture modes take it.
    pub fn absorb_camera(&mut self, delta: &[u8]) -> Verdict {
        if delta.len() < limits::CAMERA_SAMPLE_MIN {
            return Verdict::Short {
                len: delta.len(),
                min: limits::CAMERA_SAMPLE_MIN,
            };
        }
        if !camera_alive(delta) {
            return Verdict::Dead;
        }
        let bits = (delta.len() as u32) / limits::CAMERA_BYTES_PER_BIT;
        self.absorb(Source::Camera, delta, bits)
    }

    /// Absorb an IMU sample: the low byte of each axis, three interleaved,
    /// as each board's IMU `collect` writes them.
    pub fn absorb_imu(&mut self, samples: &[u8]) -> Verdict {
        if samples.len() < limits::IMU_SAMPLE_MIN {
            return Verdict::Short {
                len: samples.len(),
                min: limits::IMU_SAMPLE_MIN,
            };
        }
        if !imu_alive(samples) {
            return Verdict::Dead;
        }
        let bits = (samples.len() as u32) / limits::IMU_BYTES_PER_BIT;
        self.absorb(Source::Imu, samples, bits)
    }

    /// Absorb one touch: where it is, and how long since the last one.
    ///
    /// Only a touch that moved counts: a finger held still reports the same
    /// position at every poll, which is the controller's clock, not the
    /// person. Credit is in whole bits: every
    /// [`limits::TOUCH_EVENTS_PER_BIT`]th moving touch earns one.
    pub fn absorb_touch(&mut self, x: u16, y: u16, since_us: u32) -> Verdict {
        if self.last_touch == Some((x, y)) {
            return Verdict::Still;
        }
        self.last_touch = Some((x, y));
        let mut record = [0u8; 8];
        record[..2].copy_from_slice(&x.to_le_bytes());
        record[2..4].copy_from_slice(&y.to_le_bytes());
        record[4..].copy_from_slice(&since_us.to_le_bytes());
        self.touches = self.touches.wrapping_add(1);
        let bits = u32::from(self.touches.is_multiple_of(limits::TOUCH_EVENTS_PER_BIT));
        let verdict = self.absorb(Source::Touch, &record, bits);
        // What went into the seed, wiped here rather than left on the stack
        // for the next scrub.
        record.zeroize();
        verdict
    }

    /// Absorb dice rolls into a mixed seed: `1` to `6`, one byte each.
    ///
    /// For a seed from dice alone, which a person can check by hand, use
    /// [`kassigner_crypto::seed::from_dice`] instead.
    ///
    /// # Errors
    ///
    /// `BadRoll` for a byte that is not a die face; nothing is absorbed.
    pub fn absorb_dice(&mut self, rolls: &[u8]) -> Result<Verdict, Error> {
        if let Some(position) = rolls.iter().position(|r| !(b'1'..=b'6').contains(r)) {
            return Err(Error::BadRoll { position });
        }
        if rolls.is_empty() {
            return Ok(Verdict::Short { len: 0, min: 1 });
        }
        let bits = (rolls.len() as u32) * limits::DICE_BITS_PER_ROLL;
        Ok(self.absorb(Source::Dice, rolls, bits))
    }

    /// Absorb a sample that passed its gate, unless it repeats one of the
    /// last its source gave ([`REPEAT_WINDOW`]).
    ///
    /// Credit stops at the source's share; the bytes are absorbed either
    /// way. A source past its share goes on feeding the hash, which costs
    /// nothing and can only help, but no longer moves the count, so a screen
    /// shows what is still missing rather than tens of thousands of bits
    /// from the fastest source.
    fn absorb(&mut self, source: Source, bytes: &[u8], bits: u32) -> Verdict {
        let print = fingerprint(bytes);
        let s = source.index();
        let look = if matches!(source, Source::Dice) {
            1
        } else {
            REPEAT_WINDOW
        };
        if self.last[s][..self.held[s].min(look)].contains(&print) {
            return Verdict::Repeat;
        }
        self.last[s].copy_within(..REPEAT_WINDOW - 1, 1);
        self.last[s][0] = print;
        self.held[s] = (self.held[s] + 1).min(REPEAT_WINDOW);
        self.pool.absorb(source.tag(), bytes);
        let per = &mut self.per_source[source.index()];
        let bits = bits.min(self.share.saturating_sub(*per));
        *per = per.saturating_add(bits);
        self.credited = self.credited.saturating_add(bits);
        Verdict::Credited {
            bits,
            total: self.credited,
        }
    }

    /// The seed, if enough was collected.
    ///
    /// # Errors
    ///
    /// `SourceShort` when one of this unit's sources did not reach its
    /// share, `NotEnough` when the total is under
    /// [`limits::SEED_MIN_BITS`].
    pub fn finish(mut self, words: Words) -> Result<Mnemonic, Error> {
        if let Some(source) = self.short() {
            return Err(Error::SourceShort {
                source,
                have: self.per_source[source.index()],
                need: self.share,
            });
        }
        crate::wipe::note_depth();
        if self.credited < limits::SEED_MIN_BITS {
            return Err(Error::NotEnough {
                have: self.credited,
                need: limits::SEED_MIN_BITS,
            });
        }
        // A type with `Drop` cannot give a field away, so the pool is swapped
        // for an empty one and `self` drops as usual behind it.
        let pool = core::mem::replace(&mut self.pool, Pool::new());
        Ok(pool.finish(words)?)
    }
}

// ── Gates ───────────────────────────────────────────────────────────────────

/// Distinct byte values in a sample.
fn distinct(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut n = 0;
    for &b in bytes {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n
}

/// A camera delta chunk that is not a dead sensor: enough distinct values,
/// and enough bytes that changed at all.
fn camera_alive(delta: &[u8]) -> bool {
    if distinct(delta) < limits::CAMERA_DISTINCT_MIN {
        return false;
    }
    let nonzero = delta.iter().filter(|&&b| b != 0).count();
    nonzero * limits::CAMERA_NONZERO_ONE_IN >= delta.len()
}

/// An IMU chunk in which every axis moved: of the three interleaved axes,
/// each must show [`limits::IMU_DISTINCT_PCT`] of its samples as distinct
/// values, so two live axes cannot carry a frozen one.
///
/// At most [`limits::IMU_DISTINCT_WINDOW`] samples of each axis are tested,
/// and not for speed: a byte holds 256 values, so 60% of 512 samples would
/// ask for 307 distinct, and any axis past about 426 samples would read as
/// dead.
fn imu_alive(samples: &[u8]) -> bool {
    let per_axis = (samples.len() / 3).min(limits::IMU_DISTINCT_WINDOW);
    if per_axis < 4 {
        return false;
    }
    let need = per_axis * limits::IMU_DISTINCT_PCT / 100;
    (0..3).all(|axis| {
        let mut seen = [false; 256];
        let mut n = 0;
        for &b in samples.iter().skip(axis).step_by(3).take(per_axis) {
            if !seen[b as usize] {
                seen[b as usize] = true;
                n += 1;
            }
        }
        n >= need
    })
}

/// FNV-1a over a sample, for the repeat check: not a cryptographic hash, and
/// only deciding whether a sample matches one of its source's last few.
fn fingerprint(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h ^ (bytes.len() as u64)
}

// ── SeedQR ──────────────────────────────────────────────────────────────────

/// Which SeedQR encoding a payload was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// Word indices as four decimal digits each: 48 or 96 characters.
    Standard,
    /// The entropy bytes: 16 or 32.
    Compact,
}

/// Why a payload did not read as a SeedQR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// Neither 48 or 96 digits nor 16 or 32 bytes. Not a fault: a camera
    /// pointed at anything else produces this.
    NotSeedQr,
    /// The right shape, and refused: a digit out of range, or a checksum
    /// that does not agree with the words.
    Slot(SlotError),
}

impl From<SlotError> for ReadError {
    fn from(e: SlotError) -> Self {
        ReadError::Slot(e)
    }
}

/// Read a decoded QR payload as a SeedQR, standard or compact.
///
/// # Errors
///
/// `NotSeedQr` for any other shape, `Slot` for a SeedQR-shaped payload the
/// level 2 reader refused.
pub fn read_qr(payload: &[u8]) -> Result<(Mnemonic, Encoding), ReadError> {
    crate::wipe::note_depth();
    match payload.len() {
        n if (n == WORDS_12 * 4 || n == WORDS_24 * 4) && payload.iter().all(u8::is_ascii_digit) => {
            Ok((slot::from_seedqr(payload)?, Encoding::Standard))
        }
        ENTROPY_12 | ENTROPY_24 => Ok((slot::from_compact_seedqr(payload)?, Encoding::Compact)),
        _ => Err(ReadError::NotSeedQr),
    }
}

/// What a text reads as to the main scanner: a seed phrase, words that are
/// not one, or text.
pub enum Text {
    /// Fewer than 12 words, or one not in the list: text.
    NotWords,
    /// Twelve or twenty-four words of the list that are a seed phrase.
    Seed(Mnemonic),
    /// Twelve words of the list or more that are not a seed phrase: a
    /// checksum that does not agree, or a count other than 12 or 24. Refused,
    /// and never shown as text.
    Invalid,
}

/// Read `text` as seed words: BIP39 words in any case, between spaces or
/// line breaks, as a Plain Words QR holds them, v1.0.7's and this unit's. A
/// phrase written otherwise (numbered, with commas) is text.
///
/// Any list of twelve words or more is held to being a seed, so words that
/// look like one, with a typo or a word too many, are refused as an invalid
/// seed rather than taken for text. What it read is wiped before it returns.
pub fn read_words(text: &[u8]) -> Text {
    crate::wipe::note_depth();
    let mut indices = [0u16; WORDS_24];
    let mut word = [0u8; 8];
    let mut count = 0usize;
    let mut words = true;
    for token in text
        .split(u8::is_ascii_whitespace)
        .filter(|t| !t.is_empty())
    {
        let Some(slot) = word.get_mut(..token.len()) else {
            words = false;
            break;
        };
        for (to, from) in slot.iter_mut().zip(token) {
            *to = from.to_ascii_lowercase();
        }
        let index = core::str::from_utf8(slot)
            .ok()
            .and_then(|w| bip39::word_to_index(w).ok());
        slot.zeroize();
        let Some(index) = index else {
            words = false;
            break;
        };
        if let Some(at) = indices.get_mut(count) {
            *at = index;
        }
        count += 1;
    }
    let read = match count {
        _ if !words || count < WORDS_12 => Text::NotWords,
        WORDS_12 | WORDS_24 => match bip39::from_indices(&indices[..count]) {
            Ok(m) => Text::Seed(m),
            Err(_) => Text::Invalid,
        },
        _ => Text::Invalid,
    };
    indices.zeroize();
    read
}

mod draw {
    use super::*;
    use kassigner_crypto::slot::SEEDQR_MAX;
    use kassigner_qr::encode::{encode, encode_numeric, QrError, QrMatrix};

    /// A standard SeedQR: the word indices as digits, in numeric mode. The
    /// digits go to a stack buffer, cleared after encoding. The matrix is the
    /// code, and the code is the seed: it wipes its modules on drop, so a
    /// caller draws it and lets it go rather than keeping it.
    ///
    /// # Errors
    ///
    /// The encoder's, which for 48 or 96 digits does not happen.
    pub fn standard_qr(m: &Mnemonic) -> Result<QrMatrix, QrError> {
        crate::wipe::note_depth();
        let mut digits = [0u8; SEEDQR_MAX];
        let n = slot::to_seedqr(m, &mut digits);
        let code = encode_numeric(&digits[..n]);
        crate::wipe::wipe(&mut digits);
        code
    }

    /// A compact SeedQR: the entropy bytes, in byte mode, wiped as in
    /// [`standard_qr`].
    ///
    /// # Errors
    ///
    /// The encoder's, which for 16 or 32 bytes does not happen.
    pub fn compact_qr(m: &Mnemonic) -> Result<QrMatrix, QrError> {
        crate::wipe::note_depth();
        let mut bytes = [0u8; ENTROPY_24];
        let n = slot::to_compact_seedqr(m, &mut bytes);
        let code = encode(&bytes[..n]);
        crate::wipe::wipe(&mut bytes);
        code
    }
}

pub use draw::{compact_qr, standard_qr};
