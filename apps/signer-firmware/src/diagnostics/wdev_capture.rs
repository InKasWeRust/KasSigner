//! Dev-only raw WDEV_RND measurement capture for offline NIST SP 800-90B.
//! This is measurement output, never seed material and never a production gate.

use alloc::vec::Vec;
use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

const WORDS_PER_CAPTURE: usize = 1_000_000;
const SPACINGS: [u32; 5] = [0, 16, 64, 256, 1024];

pub(crate) fn run_and_halt(
    i2c: &mut I2c<'_, Blocking>, delay: &mut Delay,
) -> ! {
    crate::log!("[wdev-capture] raw measurement mode; {} words x {} spacings", WORDS_PER_CAPTURE, SPACINGS.len());
    for (run, spacing) in SPACINGS.into_iter().enumerate() {
        match capture_one(spacing).and_then(|blob| write_one(i2c, delay, run as u8, spacing, &blob)) {
            Ok(bytes) => crate::log!("[wdev-capture] run {} spacing {} wrote {} bytes", run, spacing, bytes),
            Err(error) => crate::log!("[wdev-capture] FAIL run {} spacing {}: {}", run, spacing, error),
        }
    }
    crate::log!("[wdev-capture] complete; analyze WDEV*.BIN with SP 800-90B non-IID estimators");
    crate::halt_forever(delay)
}

fn capture_one(spacing: u32) -> Result<Vec<u8>, &'static str> {
    crate::services::entropy::wdev_capture_prepare().map_err(|_| "RNG source enable failed")?;
    let bytes = WORDS_PER_CAPTURE.checked_mul(4).ok_or("capture size overflow")?;
    let mut blob = Vec::new();
    blob.try_reserve_exact(bytes).map_err(|_| "PSRAM allocation failed")?;
    for _ in 0..WORDS_PER_CAPTURE {
        blob.extend_from_slice(&crate::services::entropy::wdev_capture_sample().to_le_bytes());
        for _ in 0..spacing { core::hint::spin_loop(); }
    }
    Ok(blob)
}

fn write_one(
    i2c: &mut I2c<'_, Blocking>, delay: &mut Delay, run: u8, spacing: u32, blob: &[u8],
) -> Result<usize, &'static str> {
    if run >= 26 { return Err("too many capture files"); }
    let mut name = *b"WDEV00  BIN";
    name[4] = b'A' + run;
    // Encode the spacing experiment in the second tag when it is one of the
    // canonical five runs; serial log remains the authoritative metadata.
    name[5] = b'0' + run.min(9);
    let _ = &mut *i2c;
    crate::hw::sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = crate::hw::sdcard::mount_fat32(card)?;
        crate::hw::sdcard::overwrite_file(card, &fat32, &name, blob)
    })?;
    crate::log!("[wdev-capture] file WDEV{}{}.BIN spacing={}", (b'A'+run) as char, (b'0'+run.min(9)) as char, spacing);
    Ok(blob.len())
}
