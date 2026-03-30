// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// hw/screenshot.rs — Screen capture to UART for development
//
// Allocates a 320×240 RGB565 framebuffer in PSRAM and provides
// a dump function that outputs the buffer as hex lines over UART.
// Gated behind the "screenshot" feature flag.
//
// Usage: triple-tap the top-right corner to trigger a screenshot.
// On the PC side, run tools/screenshot.py to capture and display.

use embedded_graphics::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;

/// Width and height of the display
const W: usize = 320;
const H: usize = 240;
const BUF_SIZE: usize = W * H * 2; // RGB565 = 2 bytes per pixel

/// Static pointer to the PSRAM-allocated framebuffer (lazy init)
static mut FB_PTR: *mut u8 = core::ptr::null_mut();
static mut FB_READY: bool = false;

/// Ensure the framebuffer is allocated in PSRAM.
/// Must be called after PSRAM is initialized.
fn ensure_fb() {
    unsafe {
        if !FB_READY {
            let layout = alloc::alloc::Layout::from_size_align(BUF_SIZE, 4)
                .expect("screenshot fb layout");
            let ptr = alloc::alloc::alloc_zeroed(layout);
            if !ptr.is_null() {
                FB_PTR = ptr;
                FB_READY = true;
            }
        }
    }
}

/// Get the framebuffer as a mutable slice (allocates on first call).
pub fn fb_slice() -> Option<&'static mut [u8]> {
    ensure_fb();
    unsafe {
        if FB_READY {
            Some(core::slice::from_raw_parts_mut(FB_PTR, BUF_SIZE))
        } else {
            None
        }
    }
}

/// A minimal DrawTarget that writes RGB565 pixels to a flat buffer.
/// This is used as the screenshot render target.
pub struct ScreenshotBuffer {
    _private: (), // force use of get()
}

impl ScreenshotBuffer {
    /// Get the singleton screenshot buffer (allocates on first call).
    pub fn get() -> Self {
        ensure_fb();
        Self { _private: () }
    }

    /// Get the raw pixel data as a slice.
    pub fn pixels(&self) -> &[u8] {
        unsafe {
            if FB_READY {
                core::slice::from_raw_parts(FB_PTR, BUF_SIZE)
            } else {
                &[]
            }
        }
    }
}

impl DrawTarget for ScreenshotBuffer {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let fb = unsafe {
            if !FB_READY { return Ok(()); }
            core::slice::from_raw_parts_mut(FB_PTR, BUF_SIZE)
        };

        for Pixel(point, color) in pixels.into_iter() {
            let x = point.x;
            let y = point.y;
            if x >= 0 && x < W as i32 && y >= 0 && y < H as i32 {
                let idx = ((y as usize) * W + (x as usize)) * 2;
                let raw = embedded_graphics::pixelcolor::raw::RawU16::from(color).into_inner();
                fb[idx] = (raw >> 8) as u8;
                fb[idx + 1] = (raw & 0xFF) as u8;
            }
        }
        Ok(())
    }
}

impl OriginDimensions for ScreenshotBuffer {
    fn size(&self) -> Size {
        Size::new(W as u32, H as u32)
    }
}

/// Dump the screenshot buffer over UART as hex lines.
/// Format:
///   SCREENSHOT_BEGIN <width> <height>
///   <row 0: 640 hex chars = 320 pixels × 2 bytes × 2 hex chars>
///   <row 1: ...>
///   ...
///   SCREENSHOT_END
pub fn dump_uart() {
    let fb = unsafe {
        if !FB_READY {
            esp_println::println!("SCREENSHOT_ERROR: buffer not allocated");
            return;
        }
        core::slice::from_raw_parts(FB_PTR, BUF_SIZE)
    };

    esp_println::println!("SCREENSHOT_BEGIN {} {}", W, H);

    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Output one row per line (320 pixels × 2 bytes = 640 hex chars)
    for row in 0..H {
        let row_start = row * W * 2;
        let row_end = row_start + W * 2;
        let row_data = &fb[row_start..row_end];

        // Build hex string in chunks to avoid huge stack allocation
        // Print 64 bytes (128 hex chars) at a time
        let mut pos = 0;
        while pos < row_data.len() {
            let chunk_end = (pos + 64).min(row_data.len());
            let chunk = &row_data[pos..chunk_end];
            let mut hex_buf = [0u8; 128];
            for (i, &b) in chunk.iter().enumerate() {
                hex_buf[i * 2] = HEX[(b >> 4) as usize];
                hex_buf[i * 2 + 1] = HEX[(b & 0x0F) as usize];
            }
            let hex_str = core::str::from_utf8(&hex_buf[..chunk.len() * 2]).unwrap_or("");
            esp_println::print!("{}", hex_str);
            pos = chunk_end;
        }
        esp_println::println!();
    }

    esp_println::println!("SCREENSHOT_END");
}

// ═══════════════════════════════════════════════════════════════
// Non-blocking mirror — sends framebuffer in chunks across
// multiple main loop iterations so touch stays responsive.
// Gated behind the "mirror" feature flag.
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "mirror")]
mod mirror_state {
    /// Current row being sent (0 = idle/done, 1..=240 = sending)
    static mut MIRROR_ROW: u16 = 0;
    /// Flag: a new frame is pending
    static mut MIRROR_PENDING: bool = false;

    pub fn request_frame() {
        unsafe {
            MIRROR_PENDING = true;
            MIRROR_ROW = 0;
        }
    }

    pub fn is_idle() -> bool {
        unsafe { MIRROR_ROW == 0 && !MIRROR_PENDING }
    }

    /// Send a chunk of rows (up to ROWS_PER_CHUNK).
    /// Returns true when the full frame has been sent.
    pub fn pump_rows() -> bool {
        const ROWS_PER_CHUNK: u16 = 4; // ~2.5KB per chunk at 115200 = ~220ms
        const W: usize = super::W;
        const H: u16 = super::H as u16;
        const HEX: &[u8; 16] = b"0123456789abcdef";

        unsafe {
            if !super::FB_READY {
                return true; // nothing to send
            }

            // Start new frame
            if MIRROR_PENDING && MIRROR_ROW == 0 {
                MIRROR_PENDING = false;
                MIRROR_ROW = 1; // start from row 1 (1-indexed, 0=idle)
                esp_println::println!("SCREENSHOT_BEGIN {} {}", W, H);
            }

            if MIRROR_ROW == 0 {
                return true; // idle
            }

            let fb = core::slice::from_raw_parts(super::FB_PTR, super::BUF_SIZE);

            let start_row = (MIRROR_ROW - 1) as usize;
            let end_row = ((MIRROR_ROW - 1 + ROWS_PER_CHUNK) as usize).min(H as usize);

            for row in start_row..end_row {
                let row_start = row * W * 2;
                let row_end = row_start + W * 2;
                let row_data = &fb[row_start..row_end];

                let mut pos = 0;
                while pos < row_data.len() {
                    let chunk_end = (pos + 64).min(row_data.len());
                    let chunk = &row_data[pos..chunk_end];
                    let mut hex_buf = [0u8; 128];
                    for (i, &b) in chunk.iter().enumerate() {
                        hex_buf[i * 2] = HEX[(b >> 4) as usize];
                        hex_buf[i * 2 + 1] = HEX[(b & 0x0F) as usize];
                    }
                    if let Ok(hex_str) = core::str::from_utf8(&hex_buf[..chunk.len() * 2]) {
                        esp_println::print!("{}", hex_str);
                    }
                    pos = chunk_end;
                }
                esp_println::println!();
            }

            MIRROR_ROW = (end_row as u16) + 1;

            if end_row >= H as usize {
                // Frame complete
                esp_println::println!("SCREENSHOT_END");
                MIRROR_ROW = 0;

                // If another frame was requested while sending, start it next call
                return true;
            }

            false // more rows to send
        }
    }
}

#[cfg(feature = "mirror")]
pub use mirror_state::{request_frame, pump_rows, is_idle};

/// Blocking mirror flush — dumps the entire framebuffer synchronously.
/// Used for transient screens (success/warning/error) that auto-advance
/// and would be missed by the non-blocking chunked pump.
/// When mirror is not active, this is a no-op.
#[cfg(feature = "mirror")]
pub fn mirror_flush() {
    dump_uart();
}

#[cfg(not(feature = "mirror"))]
pub fn mirror_flush() {
    // no-op when mirror feature is off
}
