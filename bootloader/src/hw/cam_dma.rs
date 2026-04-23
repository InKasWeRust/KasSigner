// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// hw/cam_dma.rs — Ping-pong DMA camera: SRAM bounce → double PSRAM frames
//
// Architecture:
//   - 2 SRAM bounce buffers (4032 bytes each) in circular GDMA descriptor chain
//   - 2 PSRAM frame buffers (460KB each) — double-buffered
//   - DMA runs continuously, never stops
//   - poll_done() drains bounce→PSRAM on every call (owner-bit check)
//   - VSYNC EOF swaps the active PSRAM frame: display reads "back" while
//     DMA fills "front". No contention, no stopping.
//   - Camera loop reads the completed back buffer at any time

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

const GDMA_BASE: u32    = 0x6003_F000;
const LCD_CAM_BASE: u32 = 0x6004_1000;
const SYSTEM_BASE: u32  = 0x600C_0000;

#[allow(dead_code)]
const GDMA_IN_CONF0: u32    = GDMA_BASE + 0x0000;
const GDMA_IN_CONF1: u32    = GDMA_BASE + 0x0004;
const GDMA_IN_INT_RAW: u32  = GDMA_BASE + 0x0008;
const GDMA_IN_INT_ENA: u32  = GDMA_BASE + 0x0010;
const GDMA_IN_INT_CLR: u32  = GDMA_BASE + 0x0014;
const GDMA_IN_LINK: u32     = GDMA_BASE + 0x0020;
const GDMA_IN_PRI: u32      = GDMA_BASE + 0x0044;
const GDMA_IN_PERI_SEL: u32 = GDMA_BASE + 0x0048;

const LCD_CAM_LCD_CLOCK: u32 = LCD_CAM_BASE + 0x0000;
const LCD_CAM_CAM_CTRL: u32  = LCD_CAM_BASE + 0x0004;
const LCD_CAM_CAM_CTRL1: u32 = LCD_CAM_BASE + 0x0008;

#[allow(dead_code)]
const INT_IN_DONE: u32     = 1 << 0;
const INT_IN_SUC_EOF: u32  = 1 << 1;
const INT_IN_DSCR_ERR: u32 = 1 << 3;

pub const FRAME_W: usize = 480;
pub const FRAME_H: usize = 480;
pub const BPL: usize = FRAME_W; // Y8: 1 byte per pixel
pub const FRAME_BYTES: usize = BPL * FRAME_H; // 230,400
pub const Y_PLANE_SIZE: usize = FRAME_W * FRAME_H; // 230,400

const BOUNCE_SIZE: usize = 4032;

#[derive(Copy, Clone)]
#[repr(C, align(4))]
struct Desc { dw0: u32, buf_addr: u32, next: u32 }

// ═══ BSS statics (SRAM) ═══
static mut BOUNCE_A: [u8; BOUNCE_SIZE] = [0u8; BOUNCE_SIZE];
static mut BOUNCE_B: [u8; BOUNCE_SIZE] = [0u8; BOUNCE_SIZE];
static mut DESCS: [Desc; 2] = [Desc { dw0: 0, buf_addr: 0, next: 0 }; 2];

// Double-buffered PSRAM: DMA writes to frame[write_idx], display reads frame[read_idx]
static mut FRAME_PTRS: [*mut u8; 2] = [core::ptr::null_mut(); 2];
static mut WRITE_IDX: usize = 0;   // which PSRAM buffer DMA is filling
static mut PSRAM_OFF: usize = 0;   // current write offset
static mut STARTED: bool = false;

// Y-plane decode buffer
static mut Y_PLANE_PTR: *mut u8 = core::ptr::null_mut();

static mut STATE: Option<DmaState> = None;

pub struct DmaState {
    _bufs: [Vec<u8>; 3], // owns [frame0, frame1, y_plane]
    pub frame_ready: bool,
    pub frame_count: u32,
    /// Bytes captured in the last completed frame
    pub last_captured: usize,
}

// ═══ PUBLIC API ═══

pub fn init() -> bool {
    crate::log!("   cam_dma: init {}×{} double-buffered PSRAM", FRAME_W, FRAME_H);

    let mut f0: Vec<u8> = vec![0u8; FRAME_BYTES];
    let mut f1: Vec<u8> = vec![0u8; FRAME_BYTES];
    let mut yp: Vec<u8> = vec![0u8; Y_PLANE_SIZE];

    let p0 = f0.as_mut_ptr(); let p1 = f1.as_mut_ptr(); let ypp = yp.as_mut_ptr();

    if !((p0 as u32) >= 0x3C00_0000 && (p1 as u32) >= 0x3C00_0000) {
        crate::log!("   cam_dma: FATAL — not PSRAM!"); return false;
    }
    crate::log!("   cam_dma: frame0=0x{:08X} frame1=0x{:08X} y=0x{:08X}",
        p0 as u32, p1 as u32, ypp as u32);

    unsafe {
        FRAME_PTRS = [p0, p1];
        Y_PLANE_PTR = ypp;
        WRITE_IDX = 0;
        PSRAM_OFF = 0;
        STARTED = false;
    }

    ensure_clocks();
    setup_gdma();
    setup_cam();

    unsafe {
        STATE = Some(DmaState {
            _bufs: [f0, f1, yp],
            frame_ready: false,
            frame_count: 0,
            last_captured: 0,
        });
    }
    crate::log!("   cam_dma: ready");
    true
}

/// Start DMA capture (first call only — runs forever after).
pub fn start_capture() {
    unsafe {
        if STARTED { return; }
        STARTED = true;
        PSRAM_OFF = 0;
        WRITE_IDX = 0;

        let a = BOUNCE_A.as_ptr() as u32;
        let b = BOUNCE_B.as_ptr() as u32;
        let d0 = core::ptr::addr_of!(DESCS[0]) as u32;
        let d1 = core::ptr::addr_of!(DESCS[1]) as u32;

        DESCS[0] = Desc { dw0: (1<<31)|(BOUNCE_SIZE as u32 & 0xFFF), buf_addr: a, next: d1 };
        DESCS[1] = Desc { dw0: (1<<31)|(BOUNCE_SIZE as u32 & 0xFFF), buf_addr: b, next: d0 };

        wrv(GDMA_IN_INT_CLR, 0xFFFF_FFFF);
        wrv(GDMA_IN_CONF0, 1); nop(20);
        wrv(GDMA_IN_CONF0, 0); nop(10);
        wrv(GDMA_IN_CONF0, (1<<2)|(1<<3));
        wrv(GDMA_IN_CONF1, 0);
        wrv(GDMA_IN_PERI_SEL, 5);
        wrv(GDMA_IN_PRI, 9);
        wrv(GDMA_IN_LINK, (d0 & 0x000F_FFFF) | (1<<20));
        let c1 = 1u32 << 23;
        wrv(LCD_CAM_CAM_CTRL1, c1 | (1<<31)); nop(20);
        let link = rdv(GDMA_IN_LINK);
        wrv(GDMA_IN_LINK, link | (1<<22)); nop(10);
        wrv(LCD_CAM_CAM_CTRL1, c1 | (1<<29));
        crate::log!("   cam_dma: capture started (never stops)");
    }
}

/// Call as often as possible. Drains bounce buffers → PSRAM.
/// Returns true on VSYNC EOF (frame complete, buffers swapped).
pub fn poll_done() -> bool {
    unsafe {
        // Drain all completed bounce buffers
        let dst = FRAME_PTRS[WRITE_IDX];
        for idx in 0..2usize {
            let owner = (DESCS[idx].dw0 >> 31) & 1;
            if owner == 0 {
                let len = ((DESCS[idx].dw0 >> 12) & 0xFFF) as usize;
                if len > 0 && PSRAM_OFF + len <= FRAME_BYTES {
                    let src = if idx == 0 { BOUNCE_A.as_ptr() } else { BOUNCE_B.as_ptr() };
                    core::ptr::copy_nonoverlapping(src, dst.add(PSRAM_OFF), len);
                    PSRAM_OFF += len;
                }
                DESCS[idx].dw0 = (1<<31) | (BOUNCE_SIZE as u32 & 0xFFF);
            }
        }

        let raw = rdv(GDMA_IN_INT_RAW);
        if raw & INT_IN_DONE != 0 { wrv(GDMA_IN_INT_CLR, INT_IN_DONE); }
        if raw & INT_IN_DSCR_ERR != 0 { wrv(GDMA_IN_INT_CLR, INT_IN_DSCR_ERR); }

        if raw & INT_IN_SUC_EOF != 0 {
            wrv(GDMA_IN_INT_CLR, INT_IN_SUC_EOF);

            // Final drain
            for idx in 0..2usize {
                let owner = (DESCS[idx].dw0 >> 31) & 1;
                if owner == 0 {
                    let len = ((DESCS[idx].dw0 >> 12) & 0xFFF) as usize;
                    if len > 0 && PSRAM_OFF + len <= FRAME_BYTES {
                        let src = if idx == 0 { BOUNCE_A.as_ptr() } else { BOUNCE_B.as_ptr() };
                        core::ptr::copy_nonoverlapping(src, dst.add(PSRAM_OFF), len);
                        PSRAM_OFF += len;
                    }
                    DESCS[idx].dw0 = (1<<31) | (BOUNCE_SIZE as u32 & 0xFFF);
                }
            }

            // Swap buffers ONLY if frame is complete enough
            let captured = PSRAM_OFF;
            let is_good = captured >= FRAME_BYTES * 98 / 100;

            if is_good {
                // Good frame → swap: this buffer becomes readable, other becomes writable
                WRITE_IDX ^= 1;
            }
            // Either way, reset offset for next frame into the (possibly same) write buffer
            PSRAM_OFF = 0;

            if let Some(s) = STATE.as_mut() {
                s.last_captured = captured;
                if is_good { s.frame_ready = true; }
                s.frame_count += 1;
                if s.frame_count <= 5 {
                    crate::log!("   cam_dma: frame #{} — {} bytes{}", s.frame_count, captured,
                        if is_good { "" } else { " (partial, skipped)" });
                }
            }
            return is_good;
        }

        false
    }
}

/// Get the last completed frame (the one NOT being written to).
pub fn get_frame() -> Option<&'static [u8]> {
    unsafe {
        STATE.as_ref()
            .filter(|s| s.frame_ready)
            .map(|_| {
                let read_idx = WRITE_IDX ^ 1; // opposite of current write target
                core::slice::from_raw_parts(FRAME_PTRS[read_idx] as *const u8, FRAME_BYTES)
            })
    }
}

/// Get whatever frame data is available, even partial.
/// For entropy mixing only — any pixel data is good randomness.
pub fn get_frame_any() -> Option<&'static [u8]> {
    unsafe {
        STATE.as_ref()
            .filter(|s| s.last_captured > 0)
            .map(|s| {
                let read_idx = WRITE_IDX ^ 1;
                let len = s.last_captured.min(FRAME_BYTES);
                core::slice::from_raw_parts(FRAME_PTRS[read_idx] as *const u8, len)
            })
    }
}

/// Stop DMA + camera. Call before heavy PSRAM reads (Y extraction, decode).
/// Next start_capture() call will reinitialize.
pub fn stop() {
    unsafe {
        let c1 = core::ptr::read_volatile(0x6004_1008u32 as *const u32);
        core::ptr::write_volatile(0x6004_1008u32 as *mut u32, c1 & !(1 << 29)); // CAM_START=0
        let link = core::ptr::read_volatile(0x6003_F020u32 as *const u32);
        core::ptr::write_volatile(0x6003_F020u32 as *mut u32, link | (1 << 21)); // INLINK_STOP
        STARTED = false;
    }
}

pub fn log_status() {
    unsafe {
        crate::log!("   cam_dma: INT=0x{:08X} LINK=0x{:08X} CAM_CTRL1=0x{:08X} off={} widx={}",
            rdv(GDMA_IN_INT_RAW), rdv(GDMA_IN_LINK), rdv(LCD_CAM_CAM_CTRL1), PSRAM_OFF, WRITE_IDX);
    }
}

// ═══ INTERNAL ═══

fn ensure_clocks() {
    unsafe {
        let a = SYSTEM_BASE + 0x001C;
        wrv(a, rdv(a) | (1<<6)|(1<<8));
        let lc = rdv(LCD_CAM_LCD_CLOCK);
        if lc & (1<<31) == 0 { wrv(LCD_CAM_LCD_CLOCK, lc | (1<<31)); }
    }
}

fn setup_gdma() {
    unsafe {
        wrv(GDMA_IN_CONF0, 1); nop(20); wrv(GDMA_IN_CONF0, 0); nop(10);
        wrv(GDMA_IN_CONF0, (1<<2)|(1<<3));
        wrv(GDMA_IN_CONF1, 0);
        wrv(GDMA_IN_PERI_SEL, 5);
        wrv(GDMA_IN_PRI, 9);
        wrv(GDMA_IN_INT_ENA, 0);
        wrv(GDMA_IN_INT_CLR, 0xFFFF_FFFF);
    }
}

fn setup_cam() {
    unsafe {
        let mut c = 0u32;
        c |= 2 << 29; c |= 12 << 9; c |= 1 << 8; c |= 7 << 1; c |= 1;
        wrv(LCD_CAM_CAM_CTRL, c);
        wrv(LCD_CAM_CAM_CTRL, c | (1<<4));
        let c1 = 1u32 << 23;
        wrv(LCD_CAM_CAM_CTRL1, c1);
        wrv(LCD_CAM_CAM_CTRL1, c1 | (1<<30)); nop(20);
        wrv(LCD_CAM_CAM_CTRL1, c1 | (1<<31)); nop(20);
    }
}

#[inline(always)]
unsafe fn rdv(a: u32) -> u32 { core::ptr::read_volatile(a as *const u32) }
#[inline(always)]
unsafe fn wrv(a: u32, v: u32) { core::ptr::write_volatile(a as *mut u32, v); }
#[inline(always)]
fn nop(n: u32) { for _ in 0..n { unsafe { core::ptr::read_volatile(&0u32); } } }
