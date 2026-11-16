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

// Ping-pong DMA camera: two 4032-byte SRAM bounce buffers in a circular GDMA
// descriptor chain feed two 230 KB PSRAM frames (480x480 Y8). DMA runs from
// `start_capture` until `stop`; `poll_done` copies each filled bounce buffer
// (owner bit clear) into the frame being written, and at VSYNC end of frame
// swaps a whole frame in for readers while DMA fills the other.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::cache::write_back;

const GDMA_BASE: u32 = 0x6003_F000;
const LCD_CAM_BASE: u32 = 0x6004_1000;
const SYSTEM_BASE: u32 = 0x600C_0000;

const GDMA_IN_CONF0: u32 = GDMA_BASE; // + 0x0000
const GDMA_IN_CONF1: u32 = GDMA_BASE + 0x0004;
const GDMA_IN_INT_RAW: u32 = GDMA_BASE + 0x0008;
const GDMA_IN_INT_ENA: u32 = GDMA_BASE + 0x0010;
const GDMA_IN_INT_CLR: u32 = GDMA_BASE + 0x0014;
const GDMA_IN_LINK: u32 = GDMA_BASE + 0x0020;
const GDMA_IN_PRI: u32 = GDMA_BASE + 0x0044;
const GDMA_IN_PERI_SEL: u32 = GDMA_BASE + 0x0048;

const LCD_CAM_LCD_CLOCK: u32 = LCD_CAM_BASE; // + 0x0000
const LCD_CAM_CAM_CTRL: u32 = LCD_CAM_BASE + 0x0004;
const LCD_CAM_CAM_CTRL1: u32 = LCD_CAM_BASE + 0x0008;

/// `GDMA_IN_LINK`'s INLINK_STOP: stop reading the receive descriptors.
const INLINK_STOP: u32 = 1 << 21;
/// `GDMA_IN_LINK`'s INLINK_START: start reading the receive descriptors.
const INLINK_START: u32 = 1 << 22;
/// `GDMA_IN_LINK`'s INLINK_PARK: 1 once the receive descriptor engine is
/// idle (TRM 3.4).
const INLINK_PARK: u32 = 1 << 24;
/// `LCD_CAM_CAM_CTRL1`'s CAM_START: the camera module runs while it is set.
const CAM_START: u32 = 1 << 29;

const INT_IN_DONE: u32 = 1 << 0;
const INT_IN_SUC_EOF: u32 = 1 << 1;
const INT_IN_DSCR_ERR: u32 = 1 << 3;

// One resolution: the decode downsamples to 240x240 with a 2x2 box average,
// exactly 2:1 at 480, so every pixel is sampled.
pub const FRAME_W: usize = 480;
pub const FRAME_H: usize = 480;
pub const BPL: usize = FRAME_W; // Y8: 1 byte per pixel
pub const FRAME_BYTES: usize = BPL * FRAME_H; // 230,400

const BOUNCE_SIZE: usize = 4032;

#[derive(Copy, Clone)]
#[repr(C, align(16))]
struct Desc {
    dw0: u32,
    buf_addr: u32,
    next: u32,
}

// ═══ BSS statics (SRAM) ═══
//
// Single context, so no atomics: every static below is touched only from
// core 0's main loop, through `poll_done` and the init path. This channel's
// interrupts are off (`GDMA_IN_INT_ENA` is written 0 once, in `setup_gdma`,
// and `poll_done` polls GDMA_IN_INT_RAW), the firmware's two handlers only
// lower their own interrupts, and core 1 runs only
// `crate::decode_core::core1_main`, which never calls in here.
//
// The real concurrency is the GDMA engine writing BOUNCE_A and BOUNCE_B,
// which no atomic or critical section covers. The engine clears a
// descriptor's owner bit, bit 31 of its first word, when its buffer is
// full, and writes the bytes received beside it; `poll_done` sets the bit
// again once the buffer is copied. That word is the engine's as much as
// ours, so `poll_done` reads and writes it volatile, through `status` and
// `hand_back`: a plain read lets the compiler reuse an earlier one. With
// the owner check off (`GDMA_IN_CONF1` written 0 in `start_capture` and
// `setup_gdma`) the bit does not hold the engine back, though. Only time does:
// `poll_done` must copy each buffer out while the engine fills the other.
// Late by a whole buffer, a frame comes up short and is not kept; caught
// mid-refill, a copy takes part of the next fill, a damaged band left to the
// decoder's error correction.
/// A bounce buffer the DMA engine can burst into.
///
/// The channel runs with data bursts on, and a burst receive into a buffer
/// at an odd address reports running, fills the FIFO and writes nothing. A
/// plain `[u8; N]` is byte-aligned and lands wherever the linker puts it.
#[repr(C, align(16))]
struct Bounce([u8; BOUNCE_SIZE]);

// Each descriptor's length, so each bounce starts and ends on a burst.
const _: () = assert!(BOUNCE_SIZE.is_multiple_of(16));

static mut BOUNCE_A: Bounce = Bounce([0u8; BOUNCE_SIZE]);
static mut BOUNCE_B: Bounce = Bounce([0u8; BOUNCE_SIZE]);

/// Reads of `GDMA_IN_LINK` the wipe makes at most, waiting for the engine
/// to park after [`stop`].
const PARK_READS: u32 = 10_000;

/// How many reads the last wipe waited for the engine to park; `None` if it
/// did not within [`PARK_READS`]. For the hardware test.
static mut LAST_PARK: Option<u32> = None;
static mut DESCS: [Desc; 2] = [Desc {
    dw0: 0,
    buf_addr: 0,
    next: 0,
}; 2];

// Double-buffered PSRAM: DMA writes frame[WRITE_IDX], readers the other.
static mut FRAME_PTRS: [*mut u8; 2] = [core::ptr::null_mut(); 2];
static mut WRITE_IDX: usize = 0; // which PSRAM buffer DMA is filling
static mut PSRAM_OFF: usize = 0; // current write offset
static mut STARTED: bool = false;

static mut STATE: Option<DmaState> = None;

pub struct DmaState {
    _bufs: [Vec<u8>; 2], // owns [frame0, frame1]
    pub frame_ready: bool,
    pub frame_count: u32,
    /// Bytes captured in the last completed frame
    pub last_captured: usize,
    /// Frames kept since [`take_counts`] last ran. With the next two, what
    /// refusing a frame that lost a bounce buffer costs; this crate's `log!`
    /// prints nothing, so the binary asks for them.
    pub kept: u32,
    /// Frames skipped since [`take_counts`] last ran.
    pub skipped: u32,
    /// The fewest bytes a skipped frame had since then.
    pub fewest: usize,
}

// ═══ PUBLIC API ═══

/// Frames kept and skipped since the last call, and the fewest bytes a
/// skipped one had (the full frame if none was skipped); the counts start
/// again from zero.
pub fn take_counts() -> (u32, u32, usize) {
    // SAFETY: core 0 only, as every access to `STATE`; nothing else runs
    // while this reads and clears three counters.
    unsafe {
        match (*core::ptr::addr_of_mut!(STATE)).as_mut() {
            Some(s) => {
                let counts = (
                    s.kept,
                    s.skipped,
                    if s.skipped == 0 {
                        FRAME_BYTES
                    } else {
                        s.fewest
                    },
                );
                s.kept = 0;
                s.skipped = 0;
                s.fewest = usize::MAX;
                counts
            }
            None => (0, 0, 0),
        }
    }
}

pub fn init() -> bool {
    crate::log!(
        "   cam_dma: init {}×{} double-buffered PSRAM",
        FRAME_W,
        FRAME_H
    );

    let mut f0: Vec<u8> = vec![0u8; FRAME_BYTES];
    let mut f1: Vec<u8> = vec![0u8; FRAME_BYTES];

    let p0 = f0.as_mut_ptr();
    let p1 = f1.as_mut_ptr();

    if !(crate::cache::is_external(p0) && crate::cache::is_external(p1)) {
        crate::log!("   cam_dma: FATAL — not PSRAM!");
        return false;
    }
    crate::log!(
        "   cam_dma: frame0=0x{:08X} frame1=0x{:08X}",
        p0 as u32,
        p1 as u32
    );

    // SAFETY: core 0 only (see the statics), and before any capture, so
    // nothing reads these while they are set.
    unsafe {
        FRAME_PTRS = [p0, p1];
        WRITE_IDX = 0;
        PSRAM_OFF = 0;
        STARTED = false;
    }

    ensure_clocks();
    setup_gdma();
    setup_cam();

    // SAFETY: as above: core 0 only, before capture starts.
    unsafe {
        STATE = Some(DmaState {
            _bufs: [f0, f1],
            frame_ready: false,
            frame_count: 0,
            last_captured: 0,
            kept: 0,
            skipped: 0,
            fewest: usize::MAX,
        });
    }
    crate::log!("   cam_dma: ready");
    true
}

/// Start DMA capture; does nothing while one runs, until [`stop`].
pub fn start_capture() {
    // SAFETY: core 0 only, as above. The registers written are GDMA's and
    // LCD_CAM's, at their fixed addresses.
    unsafe {
        if STARTED {
            return;
        }
        STARTED = true;
        PSRAM_OFF = 0;
        WRITE_IDX = 0;

        // `addr_of!`, not `as_ptr()`: `as_ptr` takes `&self`, and a shared
        // reference asserts the memory is not mutated while it lives, which
        // the GDMA engine writing the bounce buffers breaks. `addr_of!`
        // forms no reference.
        let a = core::ptr::addr_of!(BOUNCE_A) as *const u8 as u32;
        let b = core::ptr::addr_of!(BOUNCE_B) as *const u8 as u32;
        let d0 = core::ptr::addr_of!(DESCS[0]) as u32;
        let d1 = core::ptr::addr_of!(DESCS[1]) as u32;

        DESCS[0] = Desc {
            dw0: (1 << 31) | (BOUNCE_SIZE as u32 & 0xFFF),
            buf_addr: a,
            next: d1,
        };
        DESCS[1] = Desc {
            dw0: (1 << 31) | (BOUNCE_SIZE as u32 & 0xFFF),
            buf_addr: b,
            next: d0,
        };

        wrv(GDMA_IN_INT_CLR, 0xFFFF_FFFF);
        wrv(GDMA_IN_CONF0, 1);
        nop(20);
        wrv(GDMA_IN_CONF0, 0);
        nop(10);
        wrv(GDMA_IN_CONF0, (1 << 2) | (1 << 3));
        // Owner check off: the engine does not wait for a buffer to be
        // handed back (see the statics above).
        wrv(GDMA_IN_CONF1, 0);
        wrv(GDMA_IN_PERI_SEL, 5);
        wrv(GDMA_IN_PRI, 9);
        wrv(GDMA_IN_LINK, (d0 & 0x000F_FFFF) | (1 << 20));
        let c1 = 1u32 << 23;
        wrv(LCD_CAM_CAM_CTRL1, c1 | (1 << 31));
        nop(20);
        let link = rdv(GDMA_IN_LINK);
        wrv(GDMA_IN_LINK, link | INLINK_START);
        nop(10);
        wrv(LCD_CAM_CAM_CTRL1, c1 | CAM_START);
        crate::log!("   cam_dma: capture started (never stops)");
    }
}

/// Call as often as possible. Drains bounce buffers → PSRAM.
/// Returns true on VSYNC EOF when the frame was kept (at most half a bounce
/// buffer short) and the frames swapped.
pub fn poll_done() -> bool {
    // SAFETY: core 0 only, as above. Bounce buffers are read through raw
    // pointers, so no reference to memory the engine writes is formed; each
    // copy stays within a bounce buffer and the PSRAM frame `init` allocated
    // and `STATE` keeps alive.
    unsafe {
        // Drain all completed bounce buffers
        let dst = FRAME_PTRS[WRITE_IDX];
        for idx in [0usize, 1] {
            // One read: the owner bit and the length the engine wrote
            // with it.
            let word = status(idx);
            let owner = (word >> 31) & 1;
            if owner == 0 {
                // Clamped to the bounce buffer: the length field is twelve
                // bits, up to 4095 against BOUNCE_SIZE's 4032, and the check
                // below guards only the write. Unclamped, the read could run
                // 63 bytes past the buffer.
                let len = (((word >> 12) & 0xFFF) as usize).min(BOUNCE_SIZE);
                if len > 0 && PSRAM_OFF + len <= FRAME_BYTES {
                    // Raw pointers: the engine may be writing either buffer.
                    let src = if idx == 0 {
                        core::ptr::addr_of!(BOUNCE_A) as *const u8
                    } else {
                        core::ptr::addr_of!(BOUNCE_B) as *const u8
                    };
                    core::ptr::copy_nonoverlapping(src, dst.add(PSRAM_OFF), len);
                    PSRAM_OFF += len;
                }
                hand_back(idx);
            }
        }

        let raw = rdv(GDMA_IN_INT_RAW);
        if raw & INT_IN_DONE != 0 {
            wrv(GDMA_IN_INT_CLR, INT_IN_DONE);
        }
        if raw & INT_IN_DSCR_ERR != 0 {
            wrv(GDMA_IN_INT_CLR, INT_IN_DSCR_ERR);
        }

        if raw & INT_IN_SUC_EOF != 0 {
            wrv(GDMA_IN_INT_CLR, INT_IN_SUC_EOF);

            // Final drain
            for idx in [0usize, 1] {
                let word = status(idx);
                let owner = (word >> 31) & 1;
                if owner == 0 {
                    // Clamped and copied as above.
                    let len = (((word >> 12) & 0xFFF) as usize).min(BOUNCE_SIZE);
                    if len > 0 && PSRAM_OFF + len <= FRAME_BYTES {
                        let src = if idx == 0 {
                            core::ptr::addr_of!(BOUNCE_A) as *const u8
                        } else {
                            core::ptr::addr_of!(BOUNCE_B) as *const u8
                        };
                        core::ptr::copy_nonoverlapping(src, dst.add(PSRAM_OFF), len);
                        PSRAM_OFF += len;
                    }
                    hand_back(idx);
                }
            }

            // Swap buffers ONLY if frame is complete enough
            let captured = PSRAM_OFF;
            // Kept only if no bounce buffer was lost: one refilled before it
            // was copied takes 4032 bytes, about eight rows, out of the frame
            // and moves every row after it up, a break across the picture
            // when something moves. Half a buffer short is still kept, for a
            // sensor that ends a frame a few bytes early.
            let is_good = captured + BOUNCE_SIZE / 2 >= FRAME_BYTES;

            if is_good {
                // Good frame → swap: this buffer becomes readable, the other
                // writable.
                WRITE_IDX ^= 1;
            }
            // Either way, the next frame starts at offset 0 of the write
            // buffer, the same one if this frame was skipped.
            PSRAM_OFF = 0;

            // `as_mut` forms a `&mut` to STATE: sound, as nothing else
            // touches it (single context, above).
            if let Some(s) = (*core::ptr::addr_of_mut!(STATE)).as_mut() {
                s.last_captured = captured;
                if is_good {
                    s.frame_ready = true;
                }
                s.frame_count += 1;
                if is_good {
                    s.kept += 1;
                } else {
                    s.skipped += 1;
                    s.fewest = s.fewest.min(captured);
                }
                if s.frame_count <= 5 {
                    crate::log!(
                        "   cam_dma: frame #{} — {} bytes{}",
                        s.frame_count,
                        captured,
                        if is_good { "" } else { " (partial, skipped)" }
                    );
                }
            }
            return is_good;
        }

        false
    }
}

/// The last completed frame, the one not being written to.
///
/// # Safety
///
/// Core 0 only, and the slice dropped before the next [`poll_done`]: that
/// may swap the frames, and the polls after it then write this one. The
/// camera's `frame` ties the slice to `&mut self` for that reason.
pub unsafe fn get_frame() -> Option<&'static [u8]> {
    // SAFETY: core 0 only, as the caller promises. The frame lives in
    // `STATE`, which is never dropped once set, and the caller uses the
    // slice before the next capture writes it.
    unsafe {
        (*core::ptr::addr_of!(STATE))
            .as_ref()
            .filter(|s| s.frame_ready)
            .map(|_| {
                let read_idx = WRITE_IDX ^ 1; // opposite of current write target
                core::slice::from_raw_parts(FRAME_PTRS[read_idx] as *const u8, FRAME_BYTES)
            })
    }
}

// What a frame is worth to the seed is judged in `kassigner-fw`'s `seed`
// module, the same for every unit, not here.

/// Stop DMA + camera. Call before heavy PSRAM work; the next
/// [`start_capture`] sets them up again.
pub fn stop() {
    // SAFETY: read-modify-writes at fixed addresses, clearing CAM_START in
    // LCD_CAM and setting INLINK_STOP in GDMA; core 0 only, as above.
    unsafe {
        let c1 = rdv(LCD_CAM_CAM_CTRL1);
        wrv(LCD_CAM_CAM_CTRL1, c1 & !CAM_START);
        let link = rdv(GDMA_IN_LINK);
        wrv(GDMA_IN_LINK, link | INLINK_STOP);
        STARTED = false;
        if let Some(ref mut s) = STATE {
            s.last_captured = 0;
        }
    }
}

/// Zero the two frame buffers and the two bounce buffers.
///
/// The frames sit in PSRAM, which keeps its contents through a reset, and a
/// frame of a SeedQR decodes back to the seed. The capture is stopped and
/// left stopped, as by [`stop`]: writing the buffers while GDMA fills them
/// would race the engine. Volatile word writes, so the optimiser keeps
/// them: about 460 KB, which is milliseconds.
///
/// Then written back: the S3 reaches PSRAM only through its data cache, and
/// zeros still in the cache at a reset are lost, the frame left in PSRAM.
/// Measured on the unit across a reset: zeroing alone left 65,312 bytes,
/// one data cache's worth; with the write-back, none.
///
/// The bounce buffers, internal RAM without a cache, hold the last 8 KB the
/// camera sent. The engine writes them, so they are zeroed once it reports
/// itself idle, not merely told to stop.
pub fn clear() {
    zero_all();
    // SAFETY: as in `zero_all`: the capture is stopped and the pointers are
    // null or `init`'s two allocations.
    unsafe {
        for p in FRAME_PTRS {
            write_back(p, FRAME_BYTES);
        }
    }
}

/// [`clear`], for a panic, so a capture cut short does not leave its frames
/// in PSRAM until the reset. The board's `quiesce` runs it on whichever core
/// panicked, the other parked, so "core 0 only" holds. Only once [`init`] has
/// run: before, no frame is taken and the engine's clocks may be off.
pub fn clear_for_panic() {
    // SAFETY: a read of `STATE`'s discriminant; the other core is parked
    // and this one is halting, so nothing writes it meanwhile.
    let up = unsafe { (*core::ptr::addr_of!(STATE)).is_some() };
    if up {
        clear();
    }
}

/// The two frames and the two bounce buffers, by place and length, for the
/// panic probe to look in; a frame not yet taken is at zero.
#[cfg(feature = "panic-probe")]
pub(crate) fn probe_spans() -> [(usize, usize); 4] {
    // SAFETY: the frame pointers read by value, on core 0, as above.
    let frames = unsafe { *core::ptr::addr_of!(FRAME_PTRS) };
    [
        (frames[0] as usize, FRAME_BYTES),
        (frames[1] as usize, FRAME_BYTES),
        (core::ptr::addr_of!(BOUNCE_A) as usize, BOUNCE_SIZE),
        (core::ptr::addr_of!(BOUNCE_B) as usize, BOUNCE_SIZE),
    ]
}

/// Stop the capture and zero the two frames through the data cache, and
/// the two bounce buffers once the engine is idle.
fn zero_all() {
    stop();
    let parked = wait_parked();
    // SAFETY: core 0 only, as above, and the DMA stopped, so this is the
    // frames' only writer; the pointers are null or `init`'s allocations,
    // which live for the program. Once parked the engine no longer writes
    // the bounce buffers; if not parked within the bound they are zeroed
    // anyway, a late burst only landing among the zeros, and `LAST_PARK`
    // says so.
    unsafe {
        for p in FRAME_PTRS {
            wipe_raw(p, FRAME_BYTES);
        }
        wipe_raw(core::ptr::addr_of_mut!(BOUNCE_A).cast::<u8>(), BOUNCE_SIZE);
        wipe_raw(core::ptr::addr_of_mut!(BOUNCE_B).cast::<u8>(), BOUNCE_SIZE);
        LAST_PARK = parked;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Wait for the receive channel's descriptor engine to report itself idle
/// after [`stop`], at most [`PARK_READS`] reads; how many it took, or
/// `None`.
fn wait_parked() -> Option<u32> {
    (0..PARK_READS).find(|_| {
        // SAFETY: a read of GDMA_IN_LINK at its fixed address, which has no
        // side effect; core 0 only, as above.
        let link = unsafe { core::ptr::read_volatile(GDMA_IN_LINK as *const u32) };
        link & INLINK_PARK != 0
    })
}

/// Diagnostic, for the hardware test: the bytes set in the two bounce
/// buffers, read as the engine may be writing them, and how many reads the
/// last wipe waited for the engine to park.
pub fn bounce_report() -> (usize, Option<u32>) {
    // SAFETY: volatile byte reads of this module's two statics, whose
    // addresses are fixed; the engine may write them meanwhile, which can
    // change a count and nothing else. Core 0 only, as above.
    unsafe {
        let mut set = 0usize;
        for b in [
            core::ptr::addr_of!(BOUNCE_A).cast::<u8>(),
            core::ptr::addr_of!(BOUNCE_B).cast::<u8>(),
        ] {
            for i in 0..BOUNCE_SIZE {
                if core::ptr::read_volatile(b.add(i)) != 0 {
                    set += 1;
                }
            }
        }
        (set, *core::ptr::addr_of!(LAST_PARK))
    }
}

/// A frame buffer's address, for a test that wants to look at one.
///
/// # Safety
///
/// The caller reads it only while the capture is stopped.
pub unsafe fn frame_ptr(i: usize) -> *const u8 {
    FRAME_PTRS[i & 1]
}

/// Zero `len` bytes at `p`, in words, volatile. Null is a no-op.
///
/// # Safety
///
/// `p` is null or points at `len` writable bytes that nothing else is
/// writing for the duration.
unsafe fn wipe_raw(p: *mut u8, len: usize) {
    if p.is_null() {
        return;
    }
    let words = len / 4;
    let w = p.cast::<u32>();
    for i in 0..words {
        core::ptr::write_volatile(w.add(i), 0);
    }
    for i in words * 4..len {
        core::ptr::write_volatile(p.add(i), 0);
    }
}

pub fn log_status() {
    // SAFETY: reads two capture statics by value, on core 0 only, as above.
    unsafe {
        // Copied out first: `log!` formats its arguments by reference,
        // which would borrow the statics.
        let off = PSRAM_OFF;
        let widx = WRITE_IDX;
        crate::log!(
            "   cam_dma: INT=0x{:08X} LINK=0x{:08X} CAM_CTRL1=0x{:08X} off={} widx={}",
            rdv(GDMA_IN_INT_RAW),
            rdv(GDMA_IN_LINK),
            rdv(LCD_CAM_CAM_CTRL1),
            off,
            widx
        );
    }
}

// ═══ INTERNAL ═══

fn ensure_clocks() {
    // SAFETY: read-modify-writes of the GDMA and LCD_CAM clock and reset
    // bits in SYSTEM_PERIP_CLK_EN1 and SYSTEM_PERIP_RST_EN1; no other
    // peripheral's bit changes.
    unsafe {
        // SYSTEM_PERIP_CLK_EN1: bit 6 GDMA, bit 8 LCD_CAM. Clocks on.
        let a = SYSTEM_BASE + 0x001C;
        wrv(a, rdv(a) | (1 << 6) | (1 << 8));
        // SYSTEM_PERIP_RST_EN1 (0x0024; 0x0020 is RST_EN0), same bits as
        // CLK_EN1: both out of reset. From esp-hal 1.1 each driver releases
        // only its own peripherals, and this driver is raw registers. A
        // clocked peripheral held in reset reads back zero from every
        // register written.
        let r = SYSTEM_BASE + 0x0024;
        wrv(r, rdv(r) & !((1 << 6) | (1 << 8)));
        let lc = rdv(LCD_CAM_LCD_CLOCK);
        if lc & (1 << 31) == 0 {
            wrv(LCD_CAM_LCD_CLOCK, lc | (1 << 31));
        }
    }
}

fn setup_gdma() {
    // SAFETY: writes GDMA's input channel registers at their fixed
    // addresses, before capture starts; core 0 only, as above.
    unsafe {
        wrv(GDMA_IN_CONF0, 1);
        nop(20);
        wrv(GDMA_IN_CONF0, 0);
        nop(10);
        wrv(GDMA_IN_CONF0, (1 << 2) | (1 << 3));
        // Owner check off: the engine does not wait for a buffer to be
        // handed back (see the statics above).
        wrv(GDMA_IN_CONF1, 0);
        wrv(GDMA_IN_PERI_SEL, 5);
        wrv(GDMA_IN_PRI, 9);
        wrv(GDMA_IN_INT_ENA, 0);
        wrv(GDMA_IN_INT_CLR, 0xFFFF_FFFF);
    }
}

fn setup_cam() {
    // SAFETY: writes LCD_CAM's camera control registers at their fixed
    // addresses, before capture starts; core 0 only, as above.
    unsafe {
        let mut c = 0u32;
        c |= 2 << 29;
        c |= 12 << 9;
        c |= 1 << 8;
        c |= 7 << 1;
        c |= 1;
        wrv(LCD_CAM_CAM_CTRL, c);
        wrv(LCD_CAM_CAM_CTRL, c | (1 << 4));
        let c1 = 1u32 << 23;
        wrv(LCD_CAM_CAM_CTRL1, c1);
        wrv(LCD_CAM_CAM_CTRL1, c1 | (1 << 30));
        nop(20);
        wrv(LCD_CAM_CAM_CTRL1, c1 | (1 << 31));
        nop(20);
    }
}

/// Descriptor `idx`'s first word as the engine last left it: the owner bit
/// (31) and the bytes received (12 to 23). Volatile, as the engine rewrites
/// it when the buffer fills.
///
/// # Safety
///
/// Core 0 only, with `idx` 0 or 1.
#[inline(always)]
unsafe fn status(idx: usize) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(DESCS[idx].dw0))
}

/// Give descriptor `idx` back to the engine: the owner bit set and the
/// buffer's size, as `start_capture` first wrote it.
///
/// # Safety
///
/// As [`status`].
#[inline(always)]
unsafe fn hand_back(idx: usize) {
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!(DESCS[idx].dw0),
        (1 << 31) | (BOUNCE_SIZE as u32 & 0xFFF),
    );
}

#[inline(always)]
unsafe fn rdv(a: u32) -> u32 {
    core::ptr::read_volatile(a as *const u32)
}
#[inline(always)]
unsafe fn wrv(a: u32, v: u32) {
    core::ptr::write_volatile(a as *mut u32, v);
}
#[inline(always)]
fn nop(n: u32) {
    for _ in 0..n {
        // SAFETY: a volatile read of a local, valid for the read; it keeps
        // the compiler from removing the delay loop.
        unsafe {
            core::ptr::read_volatile(&0u32);
        }
    }
}
