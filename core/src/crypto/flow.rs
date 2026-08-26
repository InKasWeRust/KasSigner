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

// KasSigner — Flow Counter Anti-Glitch
// 100% Rust, no-std
//
// Execution flow accumulator to detect fault injection.
//
// A physical attacker could use voltage glitching or electromagnetic fault
// injection to "skip" instructions. This module records that each stage ran,
// in order, and lets the caller check the record against a compile-time
// constant.
//
// TWO PROPERTIES THIS MUST HAVE, AND THE OLD VERSION HAD NEITHER (M-11):
//
//  1. The state must live in memory, not a register. The previous version was
//     a plain `static mut u32` guarded by `compiler_fence`. A fence orders
//     memory operations relative to each other; it does not force a value to
//     BE a memory operation. LLVM was free to keep the counter in a register
//     across the whole verification, which is precisely what an anti-glitch
//     counter must not permit: a glitch that corrupts RAM would go unseen, and
//     a register is exactly what an EMFI pulse is aimed at. `AtomicU32` with
//     SeqCst forces a real load and a real store every time.
//
//  2. Skipping a stage must not be maskable by an extra step elsewhere. The
//     previous version was an unconditional `+= 1`, so any two glitches that
//     lose one stage and gain one step cancel out and the total still matches.
//     Each stage now mixes its OWN constant into a rotating accumulator, so
//     the final value depends on WHICH stages ran and IN WHAT ORDER, not just
//     how many. Rotation before XOR is what makes it order-dependent: without
//     it, XOR is commutative and a transposed pair would be invisible.
//
// What this still does NOT defend against: a glitch that skips the stage body
// but not its `step()`. Nothing in a counter can catch that. It is why the
// verification also runs twice and compares canaries.
//
// USAGE:
//   const EXPECTED: u32 = flow::expect(&[flow::TAG_A, flow::TAG_B]);
//   flow::reset();
//   flow::step(flow::TAG_A);
//   do_thing_1();
//   flow::step(flow::TAG_B);
//   do_thing_2();
//   if !flow::verify(EXPECTED) { /* glitch detected */ }

use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

// ─── Stage tags ───────────────────────────────────────────────────────
//
// Arbitrary but distinct 32-bit constants, one per stage. They only need to
// differ from each other; there is nothing secret about them. The 0x6B53
// prefix ("kS") is a readability aid when one shows up in a log.

/// `verify_firmware` entered.
pub const TAG_VERIFY_START: u32 = 0x6B53_0101;
/// Anti-rollback version check passed.
pub const TAG_ANTI_ROLLBACK: u32 = 0x6B53_0102;
/// `do_verify_mapped_code` entered.
pub const TAG_PASS_START: u32 = 0x6B53_0201;
/// Code segment size resolved and the region read.
pub const TAG_DATA_READ: u32 = 0x6B53_0202;
/// SHA-256 over the code segment about to run.
pub const TAG_HASH: u32 = 0x6B53_0203;
/// Constant-time hash comparison about to run.
pub const TAG_COMPARE: u32 = 0x6B53_0204;

// ─── State ────────────────────────────────────────────────────────────

/// Flow accumulator. Atomic so every access is a real memory access; see the
/// module header for why `static mut` plus `compiler_fence` was not enough.
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Mix one stage tag into an accumulator. The single definition of the
/// transform, shared by `step` and `expect` so the two cannot drift apart.
#[inline(always)]
const fn mix(acc: u32, tag: u32) -> u32 {
    acc.rotate_left(7) ^ tag
}

/// Compute, at compile time, the accumulator value a given stage sequence
/// produces. Callers declare their expected sequence as a `const` and pass the
/// result to `verify`, so adding or moving a stage cannot silently invalidate
/// a hand-computed total.
pub const fn expect(tags: &[u32]) -> u32 {
    let mut acc: u32 = 0;
    let mut i = 0;
    while i < tags.len() {
        acc = mix(acc, tags[i]);
        i += 1;
    }
    acc
}

/// Reset the flow accumulator to zero.
#[inline(never)]
pub fn reset() {
    compiler_fence(Ordering::SeqCst);
    COUNTER.store(0, Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

/// Record that the stage identified by `tag` has been reached.
#[inline(never)]
pub fn step(tag: u32) {
    compiler_fence(Ordering::SeqCst);
    let prev = COUNTER.load(Ordering::SeqCst);
    COUNTER.store(mix(prev, tag), Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

/// Read the current accumulator value. For logging only. A comparison must go
/// through `verify`, which double-reads.
#[inline(never)]
pub fn count() -> u32 {
    compiler_fence(Ordering::SeqCst);
    let val = COUNTER.load(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
    val
}

/// Verify the accumulator matches the expected stage sequence.
/// Double-reads so that glitching a single load does not produce a pass.
#[inline(never)]
pub fn verify(expected: u32) -> bool {
    let actual = count();
    compiler_fence(Ordering::SeqCst);

    // Second independent read: a fault that corrupts one load has to corrupt
    // both, identically, to go unnoticed.
    let actual2 = count();
    compiler_fence(Ordering::SeqCst);

    actual == expected && actual2 == expected
}
