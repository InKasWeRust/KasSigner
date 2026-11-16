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

//! KasSigner P4: entropy source check.
//!
//! Run before trusting any random number from this board.
//!
//! ## Why a restart test
//!
//! 256 reads before and after `enable()` both look healthy (256/256
//! distinct, ~50% ones): a hardware RNG with NO entropy input passes such
//! checks, as Espressif documents for `rng_data` with neither the SAR ADC
//! nor RF active. But a DETERMINISTIC source starts from the same state
//! after every reset, so its first outputs repeat or correlate across power
//! cycles. Only the FIRST words compared across cold boots show it, which
//! is why NIST SP 800-90B asks for this test.
//!
//! ## How to run it
//!
//! 1. Flash (`cargo p4-entropy` in this crate) and note the four RESTART
//!    words printed at the very top.
//! 2. Power-cycle the board: a full power removal, not CTRL+R, so the
//!    analog state resets too. Note the words again.
//! 3. Repeat four or five times.
//!
//! * **Words differ every boot**: the source has real entropy at reset.
//! * **Words identical or near-identical**: DETERMINISTIC. Do not generate
//!   keys. It will look fine on every other test.
//!
//! A pass is a floor, not a certification: anything protecting real value
//! should go through a DRBG and, ideally, mix in a second independent
//! source.
//!
//! ## The capture
//!
//! On a source that came up and is not stuck, the binary then writes a
//! mebibyte of it raw, as hex between markers in the S3 units' `cap_rng`
//! format, for the SP 800-90B assessment:
//!
//! ```text
//! -----BEGIN KASSIGNER CAPTURE rng 8192 128-----
//! -----END KASSIGNER CAPTURE-----
//! ```
//!
//! Every word is drawn as the generator draws it, through `HwSource` at
//! `settle::RNG_READ_GAP_US`, and split into bytes in the health tests'
//! order, so the assessment measures what a seed is made of; the tests
//! themselves are left out, so a trip cannot cut the capture short. Save
//! the whole log to a file; the analyser cuts the capture out. It takes
//! about three and a half minutes over the UART; a power-cycle for the
//! restart test can come at any point.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]

#[cfg(not(target_arch = "riscv32"))]
fn main() {}

#[cfg(target_arch = "riscv32")]
mod app {

    use esp_backtrace as _;
    use esp_hal::{delay::Delay, main, time::Instant};
    use kassigner_hal_esp32p4::drbg::Entropy as _;
    use kassigner_hal_esp32p4::{
        entropy,
        soc::{settle, uart::*, watchdog},
    };

    fn show_verify(
        delay_label: &str,
        v: Result<(bool, u16, u32, u32), kassigner_hal_esp32p4::soc::RegI2cError>,
    ) -> Option<(bool, u16)> {
        puts(delay_label);
        match v {
            Ok((run, cal, c, c2)) => {
                puts("  adc trigger running = ");
                puts(if run { "yes" } else { "no" });
                puts("   calibration = ");
                putdec(cal as u32);
                puts("\r\n  adc ctrl ");
                puthex(c);
                puts("  ctrl2 ");
                puthex(c2);
                puts("\r\n");
                Some((run, cal))
            }
            Err(_) => {
                puts("  REGI2C master stuck: cannot read calibration back.\r\n");
                None
            }
        }
    }

    esp_bootloader_esp_idf::esp_app_desc!();

    const READS: u32 = 256;

    #[main]
    fn main() -> ! {
        watchdog::disable_lp();
        // The fork's maximum, 360 MHz, as the signer runs; the noise source
        // does not care, but the draw is faster than at the 100 MHz default.
        let _p = esp_hal::init(
            esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()),
        );
        // The board crate links the decoder, which allocates; this example
        // never does, but a binary must have an allocator to link.
        esp_alloc::heap_allocator!(size: 8 * 1024);
        let delay = Delay::new();

        // ---- RESTART TEST: first, before anything perturbs the state --------
        puts("\r\n=========================================\r\n");
        puts(" RESTART WORDS (compare across cold boots)\r\n");
        puts("   ");
        for _ in 0..4 {
            puthex(entropy::read());
            puts(" ");
        }
        puts("\r\n=========================================\r\n");
        puts(" Power-cycle the board and compare. Identical\r\n");
        puts(" or near-identical words = DETERMINISTIC.\r\n");
        puts("=========================================\r\n");

        puts("\r\nrng_data @ ");
        puthex(entropy::rng_data_addr());
        puts("\r\n");

        // ---- did enable() actually land? ------------------------------------
        show_verify("\r\n--- before enable ---\r\n", entropy::verify());

        let en = entropy::enable(&delay);

        show_verify("\r\n--- after enable ---\r\n", entropy::verify());
        puts("  want calibration ");
        putdec(entropy::EXPECTED_CALIBRATION as u32);
        puts("\r\n");

        let landed = en.is_ok();
        puts("\r\n  ");
        if landed {
            puts(">> enable() took: the ADC is triggering and the REGI2C\r\n");
            puts("     calibration read back correctly.\r\n");
        } else {
            puts(">> enable() DID NOT take: ");
            puts(match en {
                Err(entropy::Error::RegI2c(_)) => "REGI2C write failed or timed out.\r\n     The analog master writes are not landing. That is the\r\n     step most likely to be broken.",
                Err(entropy::Error::NotRunning) => "the ADC trigger is not running.\r\n     Check the clock and reset steps.",
                Err(entropy::Error::CalibrationMismatch(_)) => "calibration read back a different value.",
                Ok(()) => "",
            });
            puts("\r\n");
        }

        // ---- histogram, with its limits stated ------------------------------
        puts("\r\n--- histogram (informational only) ---\r\n");
        let (distinct, ones, bits) = entropy::sanity(READS, &delay);
        puts("  distinct ");
        putdec(distinct);
        puts("/");
        putdec(READS);
        puts("   ones ");
        putdec(ones * 100 / bits);
        puts("%\r\n");
        let stuck = distinct < READS - 4 || !(35..=65).contains(&(ones * 100 / bits));
        if stuck {
            puts("  >> STUCK OR PERIODIC. Broken regardless of anything else.\r\n");
        } else {
            puts("  >> Not stuck. This says NOTHING about entropy quality -\r\n");
            puts("     a starved RNG passes this test comfortably.\r\n");
        }

        // ---- verdict ---------------------------------------------------------
        puts("\r\n-----------------------------------------\r\n");
        if stuck {
            puts("FAIL - register is stuck or periodic.\r\n");
        } else if !landed {
            puts("INCONCLUSIVE - enable() did not take, so the source\r\n");
            puts("is whatever it was before. Fix that first.\r\n");
        } else {
            puts("enable() verified. The capture below is what the\r\n");
            puts("SP 800-90B assessment reads. At runtime the DRBG re-checks\r\n");
            puts("the source continuously (RCT + APT).\r\n");
            puts("The RESTART WORDS above are a quick cross-boot sanity check\r\n");
            puts("only, not a substitute for the assessment.\r\n");
        }
        puts("-----------------------------------------\r\n");

        if landed && !stuck {
            capture();
        }

        idle(&delay)
    }

    /// Raw bytes per chunk, and chunks: a mebibyte, past the million
    /// samples SP 800-90B asks of an assessment.
    const CHUNK: usize = 8192;
    const CHUNKS: u32 = 128;
    /// 64 bytes a line, as the S3 capture writes them.
    const LINE: usize = 64;
    const HEX: &[u8; 16] = b"0123456789abcdef";

    /// Write the source out raw. A chunk is drawn whole before any of it is
    /// written, so the gap between its reads is the generator's, not the
    /// UART's; the average gap is printed after the capture.
    fn capture() {
        let mut source = entropy::HwSource::new(Delay::new());
        let mut chunk = [0u8; CHUNK];
        let mut drawn_us = 0u64;

        say("\r\ncapture: rng, ");
        say_dec(CHUNKS);
        say(" chunks of ");
        say_dec(CHUNK as u32);
        say(" bytes, raw hex between markers\n");
        say("redirect this whole log to a file; the analyser cuts it out\n\n");
        say("-----BEGIN KASSIGNER CAPTURE rng ");
        say_dec(CHUNK as u32);
        say(" ");
        say_dec(CHUNKS);
        say("-----\n");

        for done in 1..=CHUNKS {
            let start = now_us();
            for bytes in chunk.chunks_exact_mut(4) {
                // The source checks the converter before each read, as the
                // generator draws it; a stopped one ends the capture.
                let Ok(word) = source.sample() else {
                    say("\ncapture: the converter stopped; capture abandoned\n");
                    return;
                };
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            drawn_us += now_us() - start;

            for row in chunk.chunks(LINE) {
                let mut text = [0u8; LINE * 2 + 1];
                for (i, b) in row.iter().enumerate() {
                    text[i * 2] = HEX[usize::from(b >> 4)];
                    text[i * 2 + 1] = HEX[usize::from(b & 0x0F)];
                }
                text[row.len() * 2] = b'\n';
                write_bytes(&text[..row.len() * 2 + 1]);
            }
            if done.is_multiple_of(16) {
                say("(chunk ");
                say_dec(done);
                say(" of ");
                say_dec(CHUNKS);
                say(")\n");
            }
        }

        say("-----END KASSIGNER CAPTURE-----\n");
        say("done: ");
        say_dec(CHUNK as u32 * CHUNKS);
        say(" bytes of rng\n");
        // Nanoseconds a read, averaged over the whole draw: the gap the
        // assessment measured, as the chip ran it.
        let reads = (CHUNK / 4) as u64 * u64::from(CHUNKS);
        say("read gap: ");
        say_dec((drawn_us * 1000 / reads) as u32);
        say(" ns a read, RNG_READ_GAP_US = ");
        say_dec(settle::RNG_READ_GAP_US);
        say("\n");
    }

    /// Microseconds since boot.
    fn now_us() -> u64 {
        Instant::now().duration_since_epoch().as_micros()
    }

    /// A string, with the FIFO checked: `puts` drops bytes once the hex
    /// lines have filled it.
    fn say(s: &str) {
        write_bytes(s.as_bytes());
    }

    /// Unsigned decimal, with the FIFO checked as [`say`] does.
    fn say_dec(v: u32) {
        let mut digits = [0u8; 10];
        let mut at = digits.len();
        let mut v = v;
        loop {
            at -= 1;
            digits[at] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        write_bytes(&digits[at..]);
    }

    /// Park, printing a dot a second.
    pub fn idle(delay: &esp_hal::delay::Delay) -> ! {
        loop {
            delay.delay_millis(1000);
            putc(b'.');
        }
    }
}
