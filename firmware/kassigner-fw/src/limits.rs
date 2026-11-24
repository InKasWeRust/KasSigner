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

//! The device's own numbers: policy it chose, not Kaspa's or a format's,
//! kept on one page so "why does it refuse this" has one place to look.
//! Buffer sizes follow from a board's capacity, in [`crate::sizes`].

/// Seeds the device holds at once: two pages of the seeds screen, three to a
/// page. Only one is in use at a time.
pub const SLOTS: usize = 6;

/// How far a device looks to decide an input is its own: the bank it
/// derives up front and the search past it. Shared with a companion
/// ([`kassigner_protocol::check`]): a request that names no derivation for
/// an input past these is refused as not ours.
pub use kassigner_protocol::check::{CHANGE_DEPTH, RECEIVE_DEPTH, SEARCH_BATCH, SEARCH_DEPTH};

const _: () = assert!(SEARCH_BATCH > 0 && SEARCH_DEPTH.is_multiple_of(SEARCH_BATCH));

/// Most pages a review can have.
///
/// A summary, an output and a covenant page for each of a profile's eight
/// outputs, a lock time and a payload make 19. Each Time-Locked Savings
/// card spent adds a page, and a request with more cards than the pages
/// left is refused, nothing signed: eight outputs and a lock time leave
/// room for ten, one output for seventeen; kassigner.org claims one card
/// per request. Not raised to the 51 a request could bring: the flow's
/// seen mask is 32 bits, and the review is rebuilt on the stack at every
/// step.
pub const MAX_PAGES: usize = 20;

/// Most keys in a multisig this device signs; the smallest threshold is
/// one. Shared with a companion ([`kassigner_protocol::check`]).
pub use kassigner_protocol::check::MAX_MULTISIG_KEYS;

/// The most inputs and outputs any profile may declare.
///
/// The flow builds a transaction on its stack, in arrays of this size, at
/// every step that reads the review: this crate allocates nothing, and a
/// borrowed array cannot be filled from a request the same struct holds.
/// `Flow::new` refuses a profile past either, so a board that raises its
/// profile raises these and pays the stack.
pub const MAX_INPUTS: usize = 32;
pub const MAX_OUTPUTS: usize = 8;

/// The most script bytes a bundle's document may decode to: the flow
/// re-reads a held bundle into a stack array of this size at every draw. A
/// quarter of `Profile::ESP32S3`'s largest reassembled payload (16,381
/// bytes) fits; `Flow::new` refuses a profile past it.
pub const MAX_PSKB_BYTES: usize = 4096;

/// Payload bytes one shown frame carries at most: the encoder stops at
/// version 9 at level L, 230 bytes, less a five-byte header (eight for frame
/// 0, which carries the payload's digest). A board's
/// `display_bytes_per_frame` is capped to this when a reply is framed, so
/// what the screen reports is what is drawn.
pub const FRAME_PAYLOAD: usize = 225;

// A version-9 code holds a frame of it exactly.
const _: () = assert!(matches!(
    kassigner_qr::capacity::byte_capacity(9),
    Some(n) if n == FRAME_PAYLOAD + kassigner_protocol::frame::HEADER_LEN
));

// ── Seed generation ─────────────────────────────────────────────────────────
//
// What a new seed must have been fed before the device makes one. The
// credits sit well under the worst NIST SP 800-90B min-entropy measured on
// raw captures from the units, so a source must be far worse than ever seen
// before a credit overstates it. The gates catch what a credit cannot: a
// source producing nothing.

/// Bits a new seed must have been credited with, whatever its word count:
/// 256 for twelve words too, since the hash costs nothing and one number is
/// one fewer thing to get wrong.
///
/// A floor, not a budget: every source a unit has must reach its share of it
/// before a seed is made, so the total normally runs past it, and the extra
/// bytes go into the same hash.
pub const SEED_MIN_BITS: u32 = 256;

/// Camera: frame-delta bytes credited per bit.
///
/// NIST SP 800-90B `ea_non_iid` on the M5's camera, factory tables
/// (`m5-capture-cam`, 262,144-byte captures): 0.212 bits a byte in room
/// light, 0.013 with a bright bulb in view (the t-tuple estimate: runs of
/// unchanged bytes where light saturates). One bit per 160 bytes, about
/// 0.006 a byte, is half the worst; a covered lens is the gates' job. The
/// same rate on all three units: the Waveshare's worst is 0.310 a byte and
/// the P4's 0.781, both with the lens covered.
///
/// A seed's 512-byte camera sample earns 3 bits: 128 bits in about 43
/// passes, some 5 seconds, collected while the touch share (about 20
/// seconds) is still being made.
pub const CAMERA_BYTES_PER_BIT: u32 = 160;

/// IMU: sample bytes credited per bit. Measured on the Waveshare's QMI8658:
/// 5.54 bits a byte still, 2.21 moving; half a bit a byte is a quarter of
/// the worst.
pub const IMU_BYTES_PER_BIT: u32 = 2;

/// Touch: events credited per bit. An event is a finger's position and the
/// time since the pass before, counted only when the position changed.
/// Measured on the seed screen itself: the timing, which is the loop's own
/// jitter, is 5.00 bits an event at worst on the M5, 3.69 on the Waveshare
/// and 4.67 on the P4; a slow finger's position alone is as low as 0.19 on
/// the M5, under the credit, and the timing carries that case.
pub const TOUCH_EVENTS_PER_BIT: u32 = 2;

/// Dice, if a caller mixes rolls in: bits credited per roll, the floor of
/// 2.585. Nothing on a unit does; dice alone are a seed, not a source.
pub const DICE_BITS_PER_ROLL: u32 = 2;

/// Fewest bytes a camera sample may be: enough for the gates below to
/// judge, and a chunk this small still shows a dead sensor.
pub const CAMERA_SAMPLE_MIN: usize = 256;

/// Fewest bytes an IMU sample may be: sixteen passes of three axes.
pub const IMU_SAMPLE_MIN: usize = 48;

/// Distinct byte values a camera sample must show. The M5 in the dark gave
/// one value in a quarter of a megabyte; sixteen is far under any live
/// capture and far over that.
pub const CAMERA_DISTINCT_MIN: usize = 16;

/// Of every this-many camera delta bytes, at least one must be non-zero.
/// The covered Waveshare lens, the worst live capture measured, changed 44%
/// of its bytes; the dark M5, 0.03%.
pub const CAMERA_NONZERO_ONE_IN: usize = 8;

/// Samples per axis the IMU liveness test looks at: a bound, not a
/// statistical window. A byte holds 256 values, so past about 426 samples
/// 60% distinct cannot be met and a healthy axis would read as dead. 128
/// samples at [`IMU_DISTINCT_PCT`] asks for 76 distinct values, which a
/// live axis clears and a frozen one cannot.
pub const IMU_DISTINCT_WINDOW: usize = 128;

/// Per axis, the share of IMU samples that must be distinct values, in
/// percent: the Waveshare driver's rule (`HEALTHY_DISTINCT_PCT`), applied
/// again when a seed is drawn, since an axis alive at boot can freeze
/// later. A healthy axis gives about 94%.
pub const IMU_DISTINCT_PCT: usize = 60;

/// How long a code in Wallet's frames (version 9 at most) stays before the
/// next in Auto Cycle: a reply's frames, and a signed message's for a
/// wallet. Faster than KasSigner's, since a phone reads them.
pub const WALLET_FRAME_US: u64 = 400_000;

/// How long a code in KasSigner's frames (version 3) stays before the next
/// in Auto Cycle, for another unit's camera: a kpub's, Plain Text QR's, a
/// signed message's or a reply's for a unit. A version-3 code decodes in
/// about a quarter of a second on an S3 (`m5-decode`), so the reader gets
/// about four tries at every frame.
pub const KASSIGNER_FRAME_US: u64 = 1_000_000;

// A wallet's frames turn faster than a unit's.
const _: () = assert!(WALLET_FRAME_US < KASSIGNER_FRAME_US);

/// The largest photo the steganography carriers take from the card: two
/// megabytes, a phone photo at a modest size. It is read whole into PSRAM
/// with its re-encoded copy beside it, so the cap is memory, not the format;
/// a larger photo is refused by name ("Photo too large").
pub const PHOTO_MAX: usize = 2_000_000;

/// The buffer a photo is written into with the backup in it: the photo, the
/// room its EXIF block and re-encoded scan can grow by, and the largest EXIF
/// block a JPEG segment holds, carried forward.
pub const PHOTO_OUT: usize = PHOTO_MAX + kassigner_protocol::stego::carrier::OUT_EXTRA + 65_536;

/// Scratch for the photo's EXIF block carried forward with the backup in
/// it: the largest block a JPEG segment holds (a camera's, with its
/// thumbnail) and the room the carrier adds.
pub const APP1_SCRATCH: usize = 65_536 + kassigner_protocol::stego::exif::APP1_EXTRA;

/// Ranks the Picture carrier's window holds: the crate's.
pub const WINDOW_RANKS: usize = kassigner_protocol::stego::picture::RANK_WINDOW;

/// Bytes of the window's two bitmaps: which ranks were seen and which were
/// changed.
pub const WINDOW_BITS: usize = 2 * kassigner_protocol::stego::picture::bitmap_len(WINDOW_RANKS);
