// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Development-only screen capture and UART mirror support.
//!
//! The framebuffer is allocated once in PSRAM and accessed only through
//! scoped callbacks. No mutable reference or raw pointer can escape the
//! storage facade, which keeps the screenshot and display paths from
//! creating long-lived aliases.

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;

const W: usize = 320;
const H: usize = 240;
const BUF_SIZE: usize = W * H * 2;

static FRAMEBUFFER: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static FRAMEBUFFER_LOCK: AtomicBool = AtomicBool::new(false);

struct FramebufferGuard;

impl FramebufferGuard {
    fn acquire() -> Self {
        while FRAMEBUFFER_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for FramebufferGuard {
    fn drop(&mut self) {
        FRAMEBUFFER_LOCK.store(false, Ordering::Release);
    }
}

fn ensure_framebuffer() -> *mut u8 {
    let existing = FRAMEBUFFER.load(Ordering::Acquire);
    if !existing.is_null() {
        return existing;
    }

    let layout = alloc::alloc::Layout::from_size_align(BUF_SIZE, 4)
        .expect("screenshot framebuffer layout");
    let candidate = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if candidate.is_null() {
        return ptr::null_mut();
    }

    match FRAMEBUFFER.compare_exchange(
        ptr::null_mut(),
        candidate,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => candidate,
        Err(winner) => {
            unsafe { alloc::alloc::dealloc(candidate, layout) };
            winner
        }
    }
}

/// Access the screenshot framebuffer for the duration of one callback.
pub(crate) fn with_framebuffer_mut<R>(f: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
    let pointer = ensure_framebuffer();
    if pointer.is_null() {
        return None;
    }
    let _guard = FramebufferGuard::acquire();
    let framebuffer = unsafe { core::slice::from_raw_parts_mut(pointer, BUF_SIZE) };
    Some(f(framebuffer))
}

fn with_framebuffer<R>(f: impl FnOnce(&[u8]) -> R) -> Option<R> {
    let pointer = FRAMEBUFFER.load(Ordering::Acquire);
    if pointer.is_null() {
        return None;
    }
    let _guard = FramebufferGuard::acquire();
    let framebuffer = unsafe { core::slice::from_raw_parts(pointer, BUF_SIZE) };
    Some(f(framebuffer))
}

/// A minimal DrawTarget backed by the scoped singleton framebuffer.
pub struct ScreenshotBuffer;

impl ScreenshotBuffer {
    pub fn get() -> Self {
        let _ = ensure_framebuffer();
        Self
    }
}

impl DrawTarget for ScreenshotBuffer {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let _ = with_framebuffer_mut(|framebuffer| {
            for Pixel(point, color) in pixels {
                if (0..W as i32).contains(&point.x) && (0..H as i32).contains(&point.y) {
                    let index = (point.y as usize * W + point.x as usize) * 2;
                    let raw = embedded_graphics::pixelcolor::raw::RawU16::from(color).into_inner();
                    framebuffer[index] = (raw >> 8) as u8;
                    framebuffer[index + 1] = raw as u8;
                }
            }
        });
        Ok(())
    }
}

impl OriginDimensions for ScreenshotBuffer {
    fn size(&self) -> Size {
        Size::new(W as u32, H as u32)
    }
}

fn print_rows(framebuffer: &[u8], start_row: usize, end_row: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for row in start_row..end_row {
        let row_start = row * W * 2;
        let row_data = &framebuffer[row_start..row_start + W * 2];
        let mut position = 0;
        while position < row_data.len() {
            let chunk_end = (position + 64).min(row_data.len());
            let chunk = &row_data[position..chunk_end];
            let mut hex = [0u8; 128];
            for (index, byte) in chunk.iter().copied().enumerate() {
                hex[index * 2] = HEX[(byte >> 4) as usize];
                hex[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
            }
            if let Ok(text) = core::str::from_utf8(&hex[..chunk.len() * 2]) {
                esp_println::print!("{}", text);
            }
            position = chunk_end;
        }
        esp_println::println!();
    }
}

pub fn dump_uart() {
    let Some(()) = with_framebuffer(|framebuffer| {
        esp_println::println!("SCREENSHOT_BEGIN {} {}", W, H);
        print_rows(framebuffer, 0, H);
        esp_println::println!("SCREENSHOT_END");
    }) else {
        esp_println::println!("SCREENSHOT_ERROR: buffer not allocated");
        return;
    };
}

#[cfg(feature = "mirror")]
mod mirror_state {
    use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

    use super::{FRAMEBUFFER, H, W, print_rows, with_framebuffer};

    const ROWS_PER_CHUNK: u16 = 4;
    static ROW: AtomicU16 = AtomicU16::new(0);
    static PENDING: AtomicBool = AtomicBool::new(false);

    pub fn request_frame() {
        PENDING.store(true, Ordering::Release);
        ROW.store(0, Ordering::Release);
    }

    pub fn pump_rows() -> bool {
        if FRAMEBUFFER.load(Ordering::Acquire).is_null() {
            return true;
        }

        let mut row = ROW.load(Ordering::Acquire);
        if PENDING.swap(false, Ordering::AcqRel) && row == 0 {
            row = 1;
            ROW.store(row, Ordering::Release);
            esp_println::println!("SCREENSHOT_BEGIN {} {}", W, H);
        }
        if row == 0 {
            return true;
        }

        let start = (row - 1) as usize;
        let end = (start + ROWS_PER_CHUNK as usize).min(H);
        let _ = with_framebuffer(|framebuffer| print_rows(framebuffer, start, end));

        if end >= H {
            esp_println::println!("SCREENSHOT_END");
            ROW.store(0, Ordering::Release);
            true
        } else {
            ROW.store(end as u16 + 1, Ordering::Release);
            false
        }
    }
}

#[cfg(feature = "mirror")]
pub use mirror_state::{pump_rows, request_frame};

#[cfg(feature = "mirror")]
pub fn mirror_flush() {
    dump_uart();
}

#[cfg(not(feature = "mirror"))]
pub fn mirror_flush() {}
