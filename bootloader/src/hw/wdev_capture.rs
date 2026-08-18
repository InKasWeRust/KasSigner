// bootloader/src/hw/wdev_capture.rs
// E-13: capture raw WDEV_RND words to SD for offline SP 800-90B analysis.
// No measurement, no hashing, no gate. Same shape and same reasoning as
// E-12 (hw/entropy_capture.rs), which does this for the camera.
//
// WHY THIS EXISTS
//
// Nothing in the firmware measures WDEV entropy, and two things that look like
// it are not:
//
//   `probe_wdev` (crypto/entropy.rs)  256 words, reports distinct / ones /
//                                     zero_words / repeats
//   `WdevHealth` (crypto/entropy.rs)  32-word window per fill(), enforced
//
// Both are LIVENESS checks. They catch a dead or stuck source and nothing
// more: a plain counter passes every one of them. Min-entropy needs the NIST
// SP 800-90B estimators, which is ten tests including collision, Markov,
// compression and the four predictors, and they want at least a million
// samples. That work belongs on a real machine, not here, so this module only
// collects and writes.
//
// REGISTER IN hw/mod.rs, ungated (it compiles on both boards):
//     #[cfg(feature = "wdev-capture")]
//     pub mod wdev_capture;
// AND IN Cargo.toml [features]:
//     wdev-capture = []
//
// NEVER ENABLE FOR A SHIPPED BUILD. It writes raw noise-source output to a
// removable card, and it holds megabytes of it in PSRAM while it runs.

use crate::crypto::entropy;
use crate::hw::sdcard;

/// Run counter, so one flash can produce several captures under different
/// conditions. Single-threaded, touched only from the menu handler.
static mut E13_RUN: u8 = 0;

/// One capture run. The blob lives in PSRAM.
pub struct WdevCapture {
    blob: alloc::vec::Vec<u8>,
    words: usize,
    spacing: u32,
}

impl WdevCapture {
    /// Collect `words` raw samples, `spacing` spin-loop iterations apart.
    ///
    /// SPACING IS THE WHOLE EXPERIMENT, AND IT IS NOT A CONSTANT TO COPY.
    /// `probe_wdev` uses 64 because the TRM rate-limits the RNG and
    /// back-to-back reads return the same word even from a healthy source.
    /// That figure was chosen to make a liveness probe read sensibly, not
    /// because it is the point where the noise source stops being
    /// oversampled. Capture at several spacings, e.g. 0, 16, 64, 256, 1024,
    /// and let the offline min-entropy estimate say where the rate limiter
    /// stops dominating. A single spacing measures the limiter as much as the
    /// source, and reports it as entropy.
    ///
    /// Both sources are enabled first, and this is not optional. The first
    /// version of `probe_wdev` omitted them, read all-zero, and looked like a
    /// catastrophic finding; it was a broken measurement. That is recorded in
    /// `entropy.rs` and repeated here because it is the exact mistake this
    /// module is positioned to make again at a million times the scale.
    pub fn collect(words: usize, spacing: u32) -> Result<Self, &'static str> {
        entropy::enable_rc_fast();
        entropy::enable_sar_adc_noise();

        let mut blob = alloc::vec::Vec::new();
        blob.try_reserve(words * 4).map_err(|_| "E13: PSRAM alloc failed")?;

        for _ in 0..words {
            let v = entropy::wdev_read_raw();
            // Little-endian, so the file is a flat u32 array a host tool can
            // read with numpy.fromfile(dtype='<u4') or feed to the NIST tool
            // as 4-byte samples.
            blob.extend_from_slice(&v.to_le_bytes());
            for _ in 0..spacing {
                core::hint::spin_loop();
            }
        }

        Ok(Self { blob, words, spacing })
    }

    /// Cheap sanity figures, logged only. NOT an entropy estimate, and named
    /// so nobody quotes them as one: a counter scores perfectly on all three.
    /// Their only job is to tell you the capture is worth carrying to a host
    /// before you unmount the card.
    pub fn liveness(&self) -> (usize, u32, usize) {
        let mut ones = 0u32;
        let mut zero_words = 0usize;
        let mut prev = [0u8; 4];
        let mut repeats = 0usize;
        for (i, c) in self.blob.chunks_exact(4).enumerate() {
            let v = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            ones += v.count_ones();
            if v == 0 {
                zero_words += 1;
            }
            if i > 0 && c == prev {
                repeats += 1;
            }
            prev.copy_from_slice(c);
        }
        (repeats, ones, zero_words)
    }

    /// Write the raw blob to SD as `WDEVCP_x.BIN`.
    ///
    /// The file is PURE raw little-endian u32 words, no header. The NIST tool
    /// and every host script want a flat sample array, and a header is one
    /// more thing to strip and get wrong. The metadata that matters, word
    /// count and spacing, goes to the serial log instead, and both are in the
    /// log line below. Record which spacing produced which tag.
    pub fn write_sd(
        &self,
        card_type: sdcard::SdCardType,
        fat32: &sdcard::Fat32Info,
    ) -> Result<usize, &'static str> {
        let tag = unsafe {
            if E13_RUN >= 26 {
                return Err("E13: 26 runs written, reset the device");
            }
            let t = b'A' + E13_RUN;
            E13_RUN += 1;
            t
        };
        let mut name = *b"WDEVCP_ BIN";
        name[6] = tag;
        sdcard::overwrite_file(card_type, fat32, &name, &self.blob)?;

        let (repeats, ones, zero_words) = self.liveness();
        let bits = self.words as u32 * 32;
        crate::log!(
            "   [E13] WDEVCP{}.BIN written: {} words, spacing {}, {} B",
            tag as char,
            self.words,
            self.spacing,
            self.blob.len()
        );
        crate::log!(
            "   [E13] liveness only (NOT entropy): repeats {}  ones {}/{}  zero_words {}",
            repeats,
            ones,
            bits,
            zero_words
        );
        Ok(self.blob.len())
    }
}

// ─── WIRING ──────────────────────────────────────────────────────────────
//
// One insertion point, in whichever menu branch already has the card handle
// and `Fat32Info` in scope inside a `with_sd_card` closure. On M5Stack that
// closure also power-cycles the card, so collect BEFORE entering it: a
// million reads inside the closure holds the SD bus open for no reason.
//
//     #[cfg(feature = "wdev-capture")]
//     {
//         // 1_000_000 words = 4 MB in PSRAM.
//         match crate::hw::wdev_capture::WdevCapture::collect(1_000_000, 64) {
//             Ok(cap) => {
//                 let _ = sdcard::with_sd_card(i2c, delay, |ct| {
//                     let fat32 = sdcard::mount_fat32(ct)?;
//                     cap.write_sd(ct, &fat32).map(|_| ())
//                 });
//             }
//             Err(e) => crate::log!("   [E13] {}", e),
//         }
//     }
//
// ─── OFFLINE ─────────────────────────────────────────────────────────────
//
// The NIST SP 800-90B reference tool (github.com/usnistgov/SP800-90B_EntropyAssessment)
// takes a raw sample file. Run the non-IID battery, which is the honest
// choice for a hardware source with no independence argument, and take the
// minimum across the ten estimators. Compare per-spacing.
//
// What the answer is FOR. Two things currently rest on judgement rather than
// measurement, and both become answerable:
//   1. Whether WDEV deserves the weight it carries in the pool, alongside the
//      camera, touch, IMU and SYSTIMER sources.
//   2. Whether the `WdevHealth` thresholds sit anywhere near the right place.
//      They are enforced (fill() refuses on !healthy), so they are already
//      load-bearing, and they were set without a distribution to set them
//      against.
