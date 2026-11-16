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

//! The scrub, and that it really writes where a secret was.
//!
//! A test cannot see what the compiler spilled, so it checks the mechanism:
//! a frame below leaves a pattern, and after a scrub that reaches it the
//! pattern is gone. Were the scrub optimised away, or shallower than it
//! claims, the pattern would remain.

use kassigner_fw::wipe::{
    begin_depth, deepest, note_depth, scrub_below, scrub_flow, scrub_stack, wipe, Mark, Stack,
    SCRUB_BYTES, SCRUB_MAX_FRAMES, SCRUB_STEP,
};

/// Leave a pattern in a frame below the caller's, and report where it was.
#[inline(never)]
fn leave_pattern<const N: usize>() -> (usize, usize) {
    let mut buf = [0u8; N];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8 + 1;
    }
    core::hint::black_box(&buf);
    (buf.as_ptr() as usize, N)
}

/// The longest run of the pattern still in place at `at`. Its own frame
/// sits at the pattern's depth and clears a little of its top, so the checks
/// before a scrub ask for most of the pattern, not all.
fn longest_run(at: usize, len: usize) -> usize {
    let mut run = 0usize;
    let mut longest = 0usize;
    for i in 0..len {
        // SAFETY: the address is stack this thread owns, just below this
        // frame, and nothing else touches it meanwhile.
        if unsafe { peek(at + i) } == (i % 251) as u8 + 1 {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    longest
}

/// Leave a pattern several frames down, and report a mark taken at the
/// bottom and where the pattern is. Recursive, as a seed flow calls through
/// many frames rather than one large one.
#[inline(never)]
fn deep_pattern<const N: usize>(depth: usize) -> (Mark, usize, usize) {
    let mut filler = [0u8; N];
    core::hint::black_box(&mut filler);
    if depth > 0 {
        return deep_pattern::<N>(depth - 1);
    }
    let mut buf = [0u8; N];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8 + 1;
    }
    core::hint::black_box(&buf);
    (Mark::here(), buf.as_ptr() as usize, N)
}

/// As [`deep_pattern`], noting its depth on the way down as a flow does.
#[inline(never)]
fn deep_pattern_noting<const N: usize>(depth: usize) -> (Mark, usize, usize) {
    let mut filler = [0u8; N];
    core::hint::black_box(&mut filler);
    note_depth();
    if depth > 0 {
        return deep_pattern_noting::<N>(depth - 1);
    }
    let mut buf = [0u8; N];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8 + 1;
    }
    core::hint::black_box(&buf);
    note_depth();
    (Mark::here(), buf.as_ptr() as usize, N)
}

/// Read one byte of stack this thread owns.
///
/// # Safety
///
/// `at` must be inside the current thread's stack, at a depth the calls
/// around it keep live.
unsafe fn peek(at: usize) -> u8 {
    core::ptr::read_volatile(at as *const u8)
}

/// Nothing of a pattern left below the frame survives a deeper scrub.
///
/// The check is the longest run of the pattern left, not a count of
/// non-zero bytes: the top of the scrub's own frame holds its saved
/// registers and return address, neither zero nor the secret.
#[test]
fn nothing_of_a_pattern_survives_a_deeper_scrub() {
    const N: usize = 2048;
    let (at, len) = leave_pattern::<N>();
    // Most of it, not all: the calls that read it back reuse its top.
    assert!(
        longest_run(at, len) > len / 2,
        "the pattern should still be there before the scrub"
    );

    scrub_stack::<{ 4 * N }>();

    let left = longest_run(at, len);
    assert!(left < 8, "{left} bytes of the pattern are still in place");
}

/// A scrub as deep as the flow it cleans leaves a tail, so a scrub must
/// reach deeper. The gap is the scrub's frame overhead: its array cannot
/// cover its prologue's bytes, the top of the region the flow used. A
/// property of the calling convention, not a number to rely on.
#[test]
fn an_equal_depth_scrub_leaves_a_tail() {
    const N: usize = 2048;
    let (at, len) = leave_pattern::<N>();
    assert!(longest_run(at, len) > len / 2);

    scrub_stack::<N>();

    // Eight bytes in the dev profile, none in release, where frames fall
    // differently: any gap must be frame overhead, not a missed region.
    let left = longest_run(at, len);
    assert!(left < 64, "{left} bytes is more than frame overhead");
}

/// The fixed depth covers a shallower frame: the scrub is called at one
/// depth, and the secret was used at several.
#[test]
fn the_seed_flows_depth_covers_a_shallower_one() {
    const N: usize = 1024;
    let (at, len) = leave_pattern::<N>();

    scrub_stack::<SCRUB_BYTES>();

    let left = longest_run(at, len);
    assert!(left < 8, "{left} bytes still in place");
}

/// A descending scrub reaches a mark taken deeper than it: nothing of the
/// pattern below the mark survives.
#[test]
fn a_descending_scrub_reaches_the_mark() {
    const N: usize = 1024;
    let (mark, at, len) = deep_pattern::<N>(12);
    assert!(longest_run(at, len) > len / 2);

    let frames = scrub_below(mark);
    assert!(frames > 1, "one frame is not a descent");

    let left = longest_run(at, len);
    assert!(left < 8, "{left} bytes of the pattern are still in place");
}

/// A fixed scrub does not reach that deeper flow, as measured on a unit.
#[test]
fn a_fixed_scrub_does_not_reach_a_deeper_flow() {
    const N: usize = 1024;
    let (_, at, len) = deep_pattern::<N>(12);
    assert!(longest_run(at, len) > len / 2);

    scrub_stack::<SCRUB_BYTES>();

    let left = longest_run(at, len);
    assert!(
        left > len / 2,
        "the fixed scrub reached further than it can: {left} left"
    );
}

/// The descent stops rather than running away when the mark is not below.
#[test]
fn a_mark_above_the_call_costs_one_frame() {
    let mark = Mark::here();
    assert!(scrub_below(mark) <= 2);
    assert!(mark.addr() != 0);
}

/// How far below a mark a host test's window reaches, standing in for a
/// board's stack. A test thread has 2 MB of stack and the flows here use
/// under 20 KB, so 64 KB is a floor a descent reaches at little cost.
const HOST_REACH: usize = 64 * 1024;

/// The tests that use the depth tracker share it, one static for the whole
/// program; without this lock they race under the default thread count.
fn depth_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// A note taken inside the flow lies below a mark taken above it. A descent
/// to that mark passes it on the first step and cleans nothing; the flow
/// scrub, to the floor, cleans all.
#[test]
fn the_depth_is_measured_from_inside_the_flow() {
    const N: usize = 1024;
    let _held = depth_lock();
    begin_depth(Stack::below(Mark::here(), HOST_REACH));
    assert_eq!(deepest(), None, "nothing noted yet");

    let above = Mark::here();
    let (_, at, len) = deep_pattern_noting::<N>(12);
    let noted = deepest().expect("the flow noted its depth");
    assert!(
        noted.addr() < above.addr(),
        "the flow's own note is deeper than a mark taken above it"
    );

    // A descent to a mark above the flow.
    assert!(scrub_below(above) <= 2);
    assert!(
        longest_run(at, len) > len / 2,
        "a mark above the flow cleans nothing"
    );

    // The flow scrub: down to the stack's floor, past every note.
    assert!(scrub_flow() > 1);
    let left = longest_run(at, len);
    assert!(left < 8, "{left} bytes of the pattern are still in place");
}

/// What a flow left below its deepest note is cleared too: after a SeedQR
/// read, whose one note is a frame below the handler, `Wallet::open` runs
/// deeper and notes nothing, leaving the seed and the master key below.
#[test]
fn what_runs_deeper_than_the_notes_is_cleared_as_well() {
    const N: usize = 1024;
    let _held = depth_lock();
    begin_depth(Stack::below(Mark::here(), HOST_REACH));

    // A shallow flow that notes, the way a SeedQR read does.
    deep_pattern_noting::<N>(1);
    let noted = deepest().expect("the flow noted its depth");

    // Then something deeper that notes nothing, the way a derivation does.
    let (deeper, at, len) = deep_pattern::<N>(12);
    assert!(
        deeper.addr() < noted.addr(),
        "the unnoted call chain has to be the deeper one for this to test anything"
    );
    assert!(longest_run(at, len) > len / 2, "the pattern is there");

    assert!(scrub_flow() > 1);
    let left = longest_run(at, len);
    assert!(
        left < 8,
        "{left} bytes of the pattern survived below the notes"
    );
}

/// A flow that noted nothing is still scrubbed to the floor: the depth is
/// the stack's, not what anyone remembered to measure.
#[test]
fn a_flow_that_noted_nothing_is_still_scrubbed_to_the_floor() {
    const N: usize = 1024;
    let _held = depth_lock();
    begin_depth(Stack::below(Mark::here(), HOST_REACH));
    assert_eq!(deepest(), None);

    let (_, at, len) = deep_pattern::<N>(8);
    assert!(longest_run(at, len) > len / 2, "the pattern is there");
    assert!(
        scrub_flow() > SCRUB_BYTES / SCRUB_STEP,
        "the floor is deeper than the fixed depth"
    );
    let left = longest_run(at, len);
    assert!(left < 8, "{left} bytes of the pattern are still in place");
}

/// Without a window, and outside one, the flow scrub takes the fixed depth:
/// it will not descend towards a floor that is not this stack's.
#[test]
fn a_scrub_with_no_window_of_its_own_takes_the_fixed_depth() {
    let _held = depth_lock();
    begin_depth(Stack::new(0, 4096).expect("ordered"));
    assert_eq!(scrub_flow(), SCRUB_BYTES / SCRUB_STEP);
}

/// The frame limit comes from the window, not [`SCRUB_MAX_FRAMES`]: a
/// descent crosses its stack whatever its size (on the M5Stack CoreS3's
/// 243,580 bytes, 237 of that constant's 256 frames), and a mark below the
/// window is clamped to it.
#[test]
fn the_frame_limit_is_the_windows_span() {
    const N: usize = 1024;
    let _held = depth_lock();

    // A window far wider than the fixed stop allows.
    begin_depth(Stack::below(Mark::here(), 512 * 1024));
    let (_, at, len) = deep_pattern::<N>(8);
    assert!(longest_run(at, len) > len / 2, "the pattern is there");
    let wide = scrub_flow();
    assert!(
        wide > SCRUB_MAX_FRAMES,
        "a {wide}-frame descent stopped at the old constant"
    );
    let left = longest_run(at, len);
    assert!(left < 8, "{left} bytes of the pattern are still in place");

    // A narrow one keeps the descent short: the limit follows the window.
    begin_depth(Stack::below(Mark::here(), 8 * 1024));
    let narrow = scrub_flow();
    assert!(
        narrow * 4 < wide,
        "a {narrow}-frame descent in a narrow window against {wide} in a wide one"
    );
}

/// A note is kept only inside the stack the flow began on. A unit's decoder
/// runs on the second core, on a stack of its own: a note from there would
/// send a descent out of the bottom of the main stack. A note outside the
/// window is dropped, so the scrub stays on its own stack.
#[test]
fn a_note_off_the_stack_is_dropped() {
    const N: usize = 1024;
    let _held = depth_lock();

    // A window that is not this stack: the lowest page of the address space.
    begin_depth(Stack::new(0, 4096).expect("ordered"));
    deep_pattern_noting::<N>(4);
    assert_eq!(deepest(), None, "a note outside the window was kept");
    assert_eq!(
        scrub_flow(),
        SCRUB_BYTES / SCRUB_STEP,
        "a window that is not this stack is not a floor to descend to"
    );

    // And a window that is: the same notes are kept.
    begin_depth(Stack::below(Mark::here(), HOST_REACH));
    deep_pattern_noting::<N>(4);
    let noted = deepest().expect("a note inside the window is kept");
    assert!(Stack::below(Mark::here(), HOST_REACH).holds(noted.addr()));

    // Before any flow began, nothing is kept either.
    begin_depth(Stack::new(0, 4096).expect("ordered"));
    assert_eq!(deepest(), None);
}

/// `Stack` refuses an empty or reversed window, and answers membership at
/// both ends: the bottom is in, the top is out.
#[test]
fn a_stack_is_a_half_open_window() {
    assert_eq!(Stack::new(10, 10), None);
    assert_eq!(Stack::new(20, 10), None);
    let s = Stack::new(10, 20).unwrap();
    assert!(s.holds(10));
    assert!(s.holds(19));
    assert!(!s.holds(20));
    assert!(!s.holds(9));
    let mark = Mark::here();
    let below = Stack::below(mark, 64);
    assert!(
        !below.holds(mark.addr()),
        "the mark itself is the top, and out"
    );
    assert!(below.holds(mark.addr() - 1));
    assert!(below.holds(mark.addr() - 64));
    assert!(!below.holds(mark.addr() - 65));
}

/// `wipe` clears a buffer, an empty one included.
#[test]
fn wipe_clears_a_buffer() {
    let mut buf = [7u8; 64];
    wipe(&mut buf);
    assert_eq!(buf, [0u8; 64]);
    let mut empty: [u8; 0] = [];
    wipe(&mut empty);
}
