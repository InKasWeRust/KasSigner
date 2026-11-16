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

//! Clearing what a secret passed through.
//!
//! # One mechanism
//!
//! Everything a secret can cross clears with `zeroize`: a volatile write and
//! a fence, so an optimiser that sees the memory is never read again cannot
//! drop the store. A plain `fill(0)` is enough where the buffer outlives the
//! call, but that is a judgement per site, invisible in the code, and
//! silently broken by moving a buffer into a local or splitting a function.
//! One mechanism costs a memset already paid and removes the question.
//!
//! # Self-clearing beats a caller remembering
//!
//! A type holding a secret clears itself in `Drop`, which runs on an early
//! return and when a panic unwinds past it; a `reset` runs only when a
//! caller remembers. Where both exist, the `Drop` is the guarantee and the
//! method the convenience.
//!
//! # Two exits, one of them in the clear
//!
//! **Sealed**: the backup, encrypted at level 2 before anything crosses to a
//! card, so level 0 writes ciphertext it cannot read; it may go anywhere.
//! **In the clear**: words on a panel, or a SeedQR drawn for a person to
//! photograph; it goes to the person and nowhere else (never a file, a card
//! or the serial port), and everything on it clears itself.
//!
//! # Where secret work runs, and the scrub after it
//!
//! HMAC runs under every derivation and password-based key. `hmac` 0.13,
//! built with `zeroize` as `kassigner-crypto` builds it, wipes its two hash
//! states on drop, but not the padded key block they are built from: a local
//! of its key setup, left in the frame. The curve arithmetic leaves
//! intermediates the same way, and a secret moved by value leaves its
//! source. No type reaches these, so each piece of secret work runs in an
//! `#[inline(never)]` frame of its own, and the caller runs [`scrub_flow`]
//! after it returns:
//!
//! - **Opening a wallet**, `open_step` from `Flow::on_opening`, a step a
//!   tick: BIP39's PBKDF2 over the words, the BIP32 master key and account
//!   derivations, the keyring's multiplications.
//! - **Planning a request**, `Flow::plan_request` from
//!   `Flow::start_request` and the sweep's `Flow::on_searching`: a private
//!   key per input the keyring matches.
//! - **Signing**, `Flow::write_signed` from `Flow::sign`: the keys derived
//!   again, and for a bundle once more in the read-back.
//! - **A password's derivation** (PBKDF2 a batch of rounds a tick, or
//!   Argon2id whole), opening or sealing a backup, a kpub file, a text file
//!   or a signed transaction: `Flow::derivation_over` at every end, done or
//!   failed.
//! - **BIP85**, `bip85_child` from `Flow::on_bip85_deriving`: scrubbed
//!   whatever the result, since a refusal goes to the error screen, not to
//!   a step that scrubs.
//!
//! ECIES is on no path the flow runs yet, and is owed the same frame and
//! scrub when it is.
//!
//! # What none of this closes
//!
//! A `Drop` clears its own binding, not a copy the compiler spilled to
//! another stack slot, a temporary, or a register. Rust guarantees no copy
//! elision, so moving a secret by value is a memcpy whose source is never
//! wiped: hence [`scrub_stack`], and a secret held in one place and passed
//! by reference.
//!
//! Three things stay open. PSRAM is off-chip and keeps its contents through
//! a reset, so no secret belongs on the heap on these boards. Flash is not
//! written with one. SRAM holds its state briefly after power is removed.

use core::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroize;

/// Clear a buffer a secret passed through: one named place, so a reader
/// looking for how wiping is done finds one answer.
pub fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Bytes of stack a fixed-depth scrub covers.
///
/// Too shallow for a seed flow: on an M5 one reached 16,992 bytes below the
/// scrubbing frame, and word indices survived there while this window was
/// clean. A fixed depth still suits a shallow flow and needs no mark; a seed
/// flow descends with [`scrub_below`] instead. A larger constant is no
/// answer: writing 20 KB below a frame guesses where the stack ends, and
/// past the end is not stack.
pub const SCRUB_BYTES: usize = 4096;

/// Bytes each frame of a descending scrub covers: small enough that
/// overshooting the mark wastes little, large enough that a deep flow (16,992
/// bytes on an M5, seventeen steps) does not cost hundreds of calls.
pub const SCRUB_STEP: usize = 1024;

/// The second pass's frame size.
///
/// A descent leaves a gap at every frame boundary: a frame cannot clear its
/// own prologue's bytes, between its array and the frame above (15 to 17
/// bytes in a dev build, none in release; still room for a secret). So the
/// descent runs twice: the second pass's boundaries drift 64 bytes a frame
/// against the first's, far more than a gap, so each pass covers the other's
/// gaps, without the raw pointer writes and `unsafe` this crate forbids.
pub const SCRUB_STEP_ALT: usize = SCRUB_STEP - 64;

/// Bytes left alone at the bottom of a stack.
///
/// A descent aimed at the floor stops when a frame's own address is at or
/// below it, so the last frame's array can begin up to one [`SCRUB_STEP`]
/// further down. The margin covers that overshoot and what lies under it:
/// `esp-hal` places a guard word at `_stack_end + 60` and by default watches
/// it, so a write there is reported as a stack overflow. Two kilobytes
/// covers both with room to spare.
pub const SCRUB_FLOOR_MARGIN: usize = 2048;

/// Frames a descending scrub makes when no window holds the frame it starts
/// from: the last stop for a mark given to [`scrub_below`] with no
/// [`begin_depth`] before it. Nothing here then knows where the stack ends,
/// and a mark that is not a stack address would be descended towards until
/// something broke.
///
/// A flow scrub does not rely on it: the M5Stack CoreS3's main stack is
/// 243,580 bytes, a descent to its floor 223 frames (237 on the second
/// pass), within 8% of this. With a window the limit comes from the window,
/// a real bound rather than a guess at a board's stack.
pub const SCRUB_MAX_FRAMES: usize = 256;

/// Frames added to a derived limit. A frame advances the stack by its array
/// plus a prologue, so a span takes slightly fewer frames than span over
/// array; the slack covers a target where it goes the other way, so a
/// descent does not stop a frame short of its floor.
pub const SCRUB_SLACK_FRAMES: usize = 4;

/// A stack address, and nothing else: no secret, nothing to wipe.
///
/// A mark is useful only below what it should clear. Taken by the code about
/// to run a flow, it sits above all of it, and a descent passes it on its
/// first step, cleaning nothing. So a flow scrub uses the stack's floor, and
/// [`note_depth`] and [`deepest`] only report how deep a flow went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark(usize);

impl Mark {
    /// Mark this frame.
    #[inline(never)]
    pub fn here() -> Self {
        let local = [0u8; 8];
        Self(core::hint::black_box(&local).as_ptr() as usize)
    }

    /// The address, for a probe that wants to report a depth.
    pub const fn addr(self) -> usize {
        self.0
    }
}

/// Overwrite the stack below this call.
///
/// Called where the secret is in its slot and nothing below this frame is
/// live (after a seed is made or read, after a SeedQR is drawn), to clear
/// what no `Drop` reaches: spilled copies and temporaries of values moved
/// rather than borrowed. `N` bytes of this frame are written, and the frame
/// sits below the caller's, so the deeper calls' memory is cleared.
/// `inline(never)` makes the frame exist, and `zeroize`'s volatile write
/// keeps the write from being removed as dead.
///
/// On Xtensa this also covers most register contents, as the register
/// windows spill to the stack. Whether a forced window spill is reachable
/// through `esp-hal` this crate cannot ask; that is the board layer's, if it
/// matters.
///
/// A scrub cleans up after moves; it does not make them safe, so a secret
/// is still held in one place.
///
/// # It must be deeper than what it cleans
///
/// A scrub cannot clear its own prologue's bytes, which sit at the top of
/// the region the flow below used, so a scrub only as deep as that flow can
/// leave a short tail (eight bytes in a dev build on the test host, none in
/// release). `tests/wipe.rs` checks both cases.
#[inline(never)]
pub fn scrub_stack<const N: usize>() {
    // The stack probe reads how deep flows went; a scrub would erase it.
    #[cfg(feature = "stack-probe")]
    return;
    #[allow(unreachable_code)]
    let mut below = [0xA5u8; N];
    below.zeroize();
    // So the array cannot be optimised away as unused before the wipe.
    core::hint::black_box(&below);
}

/// The stack a flow runs on, as the board states it.
///
/// A note is accepted only inside it, which makes the descent safe by
/// construction. A unit's QR decoder runs on the second core, on a stack of
/// its own; a note from there is not on this stack, and a descent towards it
/// would run out of this one into whatever lies past it. Nothing on that
/// core notes a depth, and with the window nothing there can: an accepted
/// mark is on this stack, and clearing one's own unused stack is harmless
/// whoever asked.
///
/// The board knows where its main stack is (on the ESP32-S3 the linker
/// exports it and the board crate reads the symbols); this crate does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stack {
    bottom: usize,
    top: usize,
}

impl Stack {
    /// The stack between two addresses, lowest first. `None` if they are
    /// not in that order.
    pub const fn new(bottom: usize, top: usize) -> Option<Self> {
        if bottom < top {
            Some(Self { bottom, top })
        } else {
            None
        }
    }

    /// The stack from a mark down `reach` bytes, for a host test or a board
    /// with no symbol to read. The mark is the top: nothing above the frame
    /// that begins a flow is part of it.
    pub fn below(mark: Mark, reach: usize) -> Self {
        Self {
            bottom: mark.0.saturating_sub(reach),
            top: mark.0,
        }
    }

    /// Whether an address is on this stack.
    pub const fn holds(self, addr: usize) -> bool {
        self.bottom <= addr && addr < self.top
    }
}

/// The deepest stack address noted since [`begin_depth`]: a minimum, as
/// stacks grow downward.
static DEEPEST: AtomicUsize = AtomicUsize::new(usize::MAX);

/// The window a note must fall in, `bottom` and `top`. Both zero means no
/// flow has begun, and every note is refused.
static WINDOW_BOTTOM: AtomicUsize = AtomicUsize::new(0);
static WINDOW_TOP: AtomicUsize = AtomicUsize::new(0);

fn window() -> Option<Stack> {
    Stack::new(
        WINDOW_BOTTOM.load(Ordering::Relaxed),
        WINDOW_TOP.load(Ordering::Relaxed),
    )
}

/// Note how deep the stack is here, at the cost of an atomic minimum and a
/// local.
///
/// Called inside a flow that handles a secret, where it goes deep: making
/// and reading a seed, the SeedQR encoders, the panel write that draws a
/// code. It measures, for a report of how far a flow reached; [`scrub_flow`]
/// descends to the stack's floor, not to the deepest note. A frame that has
/// returned cannot be sampled, so a deep call with no note in it is
/// invisible: the notes sit where the secret goes.
///
/// A note outside the window [`begin_depth`] set is dropped, as it is not on
/// the stack the scrub walks; before any `begin_depth`, every note is.
///
/// The minimum is a compare-exchange loop, not `fetch_min`, which the Xtensa
/// backend cannot emit: the release build fails at assembly with "Undefined
/// temporary symbol", which `cargo check` does not see.
#[inline(never)]
pub fn note_depth() {
    let local = [0u8; 8];
    let here = core::hint::black_box(&local).as_ptr() as usize;
    if !window().is_some_and(|w| w.holds(here)) {
        return;
    }
    let mut seen = DEEPEST.load(Ordering::Relaxed);
    while here < seen {
        match DEEPEST.compare_exchange_weak(seen, here, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(now) => seen = now,
        }
    }
}

/// Start measuring for a flow on this stack; called before it. Notes are
/// kept only inside `stack`, and the previous flow's depth is forgotten.
pub fn begin_depth(stack: Stack) {
    DEEPEST.store(usize::MAX, Ordering::Relaxed);
    WINDOW_BOTTOM.store(stack.bottom, Ordering::Relaxed);
    WINDOW_TOP.store(stack.top, Ordering::Relaxed);
}

/// The deepest point noted, if anything noted one.
pub fn deepest() -> Option<Mark> {
    match DEEPEST.load(Ordering::Relaxed) {
        usize::MAX => None,
        addr => Some(Mark(addr)),
    }
}

/// Scrub everything below this call down to the floor of the stack the flow
/// began on, and return the frames the descent took. What a seed flow
/// calls.
///
/// # Why the floor and not the deepest note
///
/// The deepest note ([`deepest`]) measures one call chain, and the copies
/// that matter are not all on it: opening a wallet (PBKDF2, derivations,
/// the keyring's multiplications) notes nothing, and on the SeedQR path the
/// only note, at the top of `seed::read_qr`, would stop a descent about
/// where the derivation begins, above the seed's copies and the master key.
///
/// Every board states its stack bounds and [`begin_depth`] stores them, so
/// everything between this frame and the bottom is stack nobody is using,
/// and clearing one's own unused stack is always safe, whatever call chain
/// ran. The floor keeps [`SCRUB_FLOOR_MARGIN`] clear, and `frames_for` caps
/// the frames at what the window holds, so a descent crosses this stack and
/// no more.
///
/// With no window, or one this frame is not inside, it falls back to the
/// fixed depth: a window that is not this stack is the hazard
/// [`begin_depth`] exists for, and descending to its floor would leave the
/// stack this call is on.
pub fn scrub_flow() -> usize {
    match floor() {
        Some(mark) => scrub_below(mark),
        None => {
            scrub_stack::<SCRUB_BYTES>();
            SCRUB_BYTES / SCRUB_STEP
        }
    }
}

/// The lowest address a flow scrub may write: the window's bottom plus
/// [`SCRUB_FLOOR_MARGIN`]. `None` when no flow has begun, when this frame is
/// not on the flow's stack, or when the floor is not below this frame.
#[inline(never)]
fn floor() -> Option<Mark> {
    let local = [0u8; 8];
    let here = core::hint::black_box(&local).as_ptr() as usize;
    let window = window()?;
    if !window.holds(here) {
        return None;
    }
    let floor = window.bottom.saturating_add(SCRUB_FLOOR_MARGIN);
    (floor < here).then_some(Mark(floor))
}

/// [`scrub_stack`] at [`SCRUB_BYTES`], for a shallow flow with no mark.
pub fn scrub() {
    scrub_stack::<SCRUB_BYTES>();
}

/// Overwrite the stack from here down past `mark`, one [`SCRUB_STEP`] frame
/// at a time, clearing each, until a frame is below the mark: a known depth
/// where [`SCRUB_BYTES`] is a guess.
///
/// **Call it from above the flow, and give the flow a frame of its own.** A
/// descent reaches only what is below it. At `opt-level = "z"` with LTO the
/// release build inlines a flow and all under it into whichever function ran
/// it, so a secret's copies land in that function's frame, which no call it
/// makes can wipe (on an M5, 22 KB of the scrubbing frame, word indices
/// included). So the flow's `#[inline(never)]` is load-bearing, and the
/// caller scrubs after it returns.
///
/// Safe by construction: the flow already ran that deep without
/// overflowing, so descending as far again cannot overflow. Nothing is
/// assumed about where the stack ends, which is why this is not a larger
/// constant: past a stack's end is other memory, and clearing it is a worse
/// bug than the one fixed.
///
/// Two passes with different frame sizes ([`SCRUB_STEP_ALT`]); returns the
/// frames the first took, so a caller can report the depth cleaned.
///
/// A mark from a returned frame is the normal case. One from a frame above
/// this call is passed on the first step, so one frame runs and nothing is
/// reached: harmless, and not worth checking at the cost of assuming which
/// way a stack grows. A mark from another stack is what [`begin_depth`]'s
/// window is for: [`scrub_flow`] descends only to the floor of a window this
/// frame is inside, so it stays on its own stack.
pub fn scrub_below(mark: Mark) -> usize {
    // The stack probe reads how deep flows went; a scrub would erase it.
    #[cfg(feature = "stack-probe")]
    return {
        let _ = mark;
        0
    };
    #[allow(unreachable_code)]
    let local = [0u8; 8];
    let here = core::hint::black_box(&local).as_ptr() as usize;
    let frames = descend::<SCRUB_STEP>(mark, 0, frames_for::<SCRUB_STEP>(here, mark.0));
    descend::<SCRUB_STEP_ALT>(mark, 0, frames_for::<SCRUB_STEP_ALT>(here, mark.0));
    frames
}

/// How many frames a descent from `from` down to `to` may take: the
/// distance in frames plus [`SCRUB_SLACK_FRAMES`], capped by a ceiling.
///
/// The ceiling, which a bogus mark runs into, comes from the window
/// [`begin_depth`] set, the stack the board states: a descent may cross that
/// stack and no more. **Only a window holding `from` says anything about
/// this stack.** One set by another flow, or on another thread in a host
/// test, describes other memory, and clamping to it would stop a descent a
/// few frames in with the secret still there. Without one, the ceiling is
/// [`SCRUB_MAX_FRAMES`].
fn frames_for<const N: usize>(from: usize, to: usize) -> usize {
    let wanted = from.saturating_sub(to) / N + SCRUB_SLACK_FRAMES;
    let ceiling = match window() {
        Some(w) if w.holds(from) => w.top.saturating_sub(w.bottom) / N + SCRUB_SLACK_FRAMES,
        _ => SCRUB_MAX_FRAMES,
    };
    if wanted < ceiling {
        wanted
    } else {
        ceiling
    }
}

#[inline(never)]
fn descend<const N: usize>(mark: Mark, depth: usize, limit: usize) -> usize {
    let mut frame = [0xA5u8; N];
    let here = core::hint::black_box(&frame).as_ptr() as usize;
    let done = here <= mark.0 || depth + 1 >= limit;
    let used = if done {
        depth + 1
    } else {
        // Deeper first, so the whole region below is cleared before this
        // frame's own bytes are, and nothing is written twice.
        descend::<N>(mark, depth + 1, limit)
    };
    frame.zeroize();
    core::hint::black_box(&frame);
    used
}
