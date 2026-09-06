//! E-12 raw camera-input capture for offline entropy characterization.
//!
//! This module performs no entropy estimation and never influences seed acceptance.
//! It records the exact camera byte slices already mixed by the seed-generation
//! path and writes them to `ENTCAPA.BIN`, `ENTCAPB.BIN`, ... on SD for offline
//! NIST SP 800-90B analysis. The feature policy forbids this module in silent /
//! production firmware.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

use crate::hw::sdcard;

const MAX_RUNS: u8 = 26;
const EXPECTED_CAPTURE_BYTES: usize = 8 * 76_800;

/// Run counter for one powered diagnostic session. The value advances only
/// after a successful SD write, preventing failed writes from consuming a filename.
static E12_RUN: AtomicU8 = AtomicU8::new(0);

pub(crate) struct Capture {
    blob: Vec<u8>,
    frames: usize,
}

impl Capture {
    pub(crate) fn new() -> Result<Self, &'static str> {
        let mut blob = Vec::new();
        blob.try_reserve(EXPECTED_CAPTURE_BYTES)
            .map_err(|_| "E12: PSRAM allocation failed")?;
        Ok(Self { blob, frames: 0 })
    }

    /// Record exactly the byte slice already presented to the production
    /// camera entropy tracker/mixer. No additional camera path exists here.
    pub(crate) fn push_frame(&mut self, pixels: &[u8]) {
        self.blob.extend_from_slice(pixels);
        self.frames += 1;
    }

    pub(crate) fn write_sd(
        self,
        i2c: &mut I2c<'_, Blocking>,
        delay: &mut Delay,
    ) -> Result<usize, &'static str> {
        if self.frames < 2 {
            return Err("E12: need at least two captured frames");
        }
        let tag = next_tag()?;
        let mut name = *b"ENTCAP_ BIN";
        name[6] = tag;
        let bytes = self.blob.len();

        let _ = &mut *i2c;
        sdcard::with_sd_card!(i2c, delay, |card| {
            let fat32 = sdcard::mount_fat32(card)?;
            sdcard::overwrite_file(card, &fat32, &name, &self.blob)
        })?;
        commit_tag();

        crate::log!(
            "   [E12] ENTCAP{}.BIN written: {} B, {} frames, {} B/frame",
            tag as char,
            bytes,
            self.frames,
            bytes / self.frames
        );
        Ok(bytes)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.blob);
    }
}

fn next_tag() -> Result<u8, &'static str> {
    let run = E12_RUN.load(Ordering::Relaxed);
    if run >= MAX_RUNS {
        return Err("E12: 26 runs written; reset the device");
    }
    Ok(b'A' + run)
}

fn commit_tag() {
    E12_RUN.fetch_add(1, Ordering::Relaxed);
}
