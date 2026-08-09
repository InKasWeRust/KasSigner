// bootloader/src/hw/entropy_capture.rs
//
// E-12: capture the raw camera bytes the seed path hashes, for offline
// SP 800-90B analysis. No measurement, no hashing, no gate.
//
// BOARD-AGNOSTIC BY CONSTRUCTION. `cam_dma` is Waveshare-only
// (hw/mod.rs:126) and M5Stack captures through DvpCamera, so this module
// never touches a camera itself. The caller feeds it the same `pixels`
// slice it already passes to `frame_noise::measure`, which both capture
// branches in handlers/menu.rs already have in scope.
//
// REGISTER IN hw/mod.rs, ungated (it compiles on both boards):
//     #[cfg(feature = "e12-capture")]
//     pub mod entropy_capture;
//
// AND IN Cargo.toml [features]:
//     e12-capture = []

use crate::hw::sdcard;

/// Run counter. One flash, several captures: the tag advances per successful
/// write so ENTCAPA, ENTCAPB ... come from one build under different light
/// conditions. Single-threaded, only touched from the menu handler.
static mut E12_RUN: u8 = 0;

/// Accumulator for one capture run. Lives in PSRAM.
pub struct Capture {
    blob: alloc::vec::Vec<u8>,
    frames: usize,
}

impl Capture {
    /// `expect_bytes` is frames x frame_size, used to reserve once.
    pub fn new(expect_bytes: usize) -> Result<Self, &'static str> {
        let mut blob = alloc::vec::Vec::new();
        blob.try_reserve(expect_bytes).map_err(|_| "E12: PSRAM alloc failed")?;
        Ok(Self { blob, frames: 0 })
    }

    /// Call beside the existing `frame_noise::measure(pixels)` in whichever
    /// capture branch is active. One line, same slice, same borrow window.
    pub fn push_frame(&mut self, pixels: &[u8]) {
        self.blob.extend_from_slice(pixels);
        self.frames += 1;
    }

    /// Write to SD as ENTCAP<tag>.BIN, tag advancing A, B, C ... per call.
    ///
    /// No argument: a per-run constant would need a reflash between light
    /// conditions, which is the whole set this exists to collect.
    pub fn write_sd(
        self,
        card_type: sdcard::SdCardType,
        fat32: &sdcard::Fat32Info,
    ) -> Result<usize, &'static str> {
        if self.frames < 2 {
            return Err("E12: need >= 2 frames for a delta");
        }
        // A..Z then stop, rather than wrapping onto an earlier file.
        let tag = unsafe {
            if E12_RUN >= 26 {
                return Err("E12: 26 runs written, reset the device");
            }
            let t = b'A' + E12_RUN;
            E12_RUN += 1;
            t
        };
        let mut name = *b"ENTCAP_ BIN";
        name[6] = tag;
        sdcard::overwrite_file(card_type, fat32, &name, &self.blob)?;
        let n = self.blob.len();
        crate::log!(
            "   [E12] ENTCAP{}.BIN written: {} B, {} frames, {} B/frame",
            tag as char, n, self.frames, n / self.frames
        );
        Ok(n)
    }
}

// ─── WIRING ──────────────────────────────────────────────────────────────
//
// Two insertion points in bootloader/src/handlers/menu.rs, one per capture
// branch. Both already have `pixels` in scope at the `frame_noise::measure`
// call:
//
//   :737   the DvpCamera branch   (M5Stack)
//   :793   the cam_dma branch     (Waveshare)
//
// Before the `for frame_idx in 0..8u8` loop:
//
//     #[cfg(feature = "e12-capture")]
//     let mut e12 = crate::hw::entropy_capture::Capture::new(8 * 76_800).ok();
//
// Immediately before each `frame_noise::measure(pixels)` call:
//
//     #[cfg(feature = "e12-capture")]
//     if let Some(c) = e12.as_mut() { c.push_frame(pixels); }
//
// After the loop, where the card handle and Fat32Info are in scope:
//
//     #[cfg(feature = "e12-capture")]
//     if let Some(c) = e12.take() {
//         let _ = c.write_sd(card_type, &fat32);
//     }
//
// The tag advances itself, so ONE FLASH collects the whole series: generate a
// seed per light condition and the files come out ENTCAPA, ENTCAPB, ...
// Suggested set: bright, mid, dim, very dim, and lens fully covered as the
// floor control. The counter resets on reboot, so do the series in one
// session or the tags restart at A and overwrite.
