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
// Execution flow counter to detect fault injection.
//
// A physical attacker could use voltage glitching or
// electromagnetic fault injection to "skip" instructions.
// The flow counter detects this: if a stage is skipped, the counter
// final value will not match the expected value.
//
// USAGE:
//   flow::reset();
//   flow::step();  // stage 1
//   do_thing_1();
//   flow::step();  // stage 2
//   do_thing_2();
//   flow::step();  // stage 3
//   if flow::count() != 3 { panic!("glitch detected"); }
//
// LIMITATIONS:
//   - A sophisticated glitch could increment the counter without executing
//     the actual stage. Combine with canaries and redundant verification.
//   - The counter uses a mutable global variable (required in no-std
//     without allocator). Access serialized with compiler_fence.

use core::sync::atomic::{compiler_fence, Ordering};

// Stage counter (global mutable variable)
static mut COUNTER: u32 = 0;

// Resets the counter to zero.
#[inline(never)]
/// Reset the flow integrity counter to zero.
pub fn reset() {
    compiler_fence(Ordering::SeqCst);
    unsafe { COUNTER = 0; }
    compiler_fence(Ordering::SeqCst);
}

// Increments the counter by 1.
#[inline(never)]
/// Increment the flow counter by one (marks a completed stage).
pub fn step() {
    compiler_fence(Ordering::SeqCst);
    unsafe { COUNTER += 1; }
    compiler_fence(Ordering::SeqCst);
}

// Reads the current counter value.
#[inline(never)]
/// Read the current flow counter value.
pub fn count() -> u32 {
    compiler_fence(Ordering::SeqCst);
    let val = unsafe { COUNTER };
    compiler_fence(Ordering::SeqCst);
    val
}

// Verifies the counter has the expected value.
// Returns true if it matches.
#[inline(never)]
/// Verify the counter matches the expected stage count.
/// Double-reads to resist voltage glitching attacks.
pub fn verify(expected: u32) -> bool {
    let actual = count();
    compiler_fence(Ordering::SeqCst);

    // Double read to make comparison glitching harder
    let actual2 = count();
    compiler_fence(Ordering::SeqCst);

    actual == expected && actual2 == expected
}
