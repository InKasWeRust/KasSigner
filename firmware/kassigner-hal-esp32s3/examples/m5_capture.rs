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

//! Write one of the M5Stack CoreS3's sources out raw, for measuring it
//! elsewhere.
//!
//! ```text
//! cargo +esp195 m5-capture-cam
//! cargo +esp195 m5-capture-rng
//! cargo +esp195 m5-capture-touch
//! cargo +esp195 m5-capture-imu
//! cargo +esp195 m5-capture-qr
//! cargo +esp195 m5-capture-qr-read
//! ```
//!
//! The unit comes up as the firmware brings it up, writes one source to the
//! console as hex between markers, and stops. Each source takes the console,
//! so it is chosen at build time: the camera's frame-to-frame delta by
//! default, the generator with `cap_rng`, touch with `cap_touch`, the gyro
//! with `cap_imu`. Nothing is conditioned or mixed, so a bits-per-byte
//! figure measures the part itself.
//!
//! The QR pair runs on two units facing each other until reset: `cap_qr`
//! shows the version sweep, `cap_qr_read` prints every decode with a focus
//! score.

#![cfg_attr(target_arch = "xtensa", no_std)]
#![cfg_attr(target_arch = "xtensa", no_main)]

/// A host build compiles this and nothing else: a capture is for a unit.
#[cfg(not(target_arch = "xtensa"))]
fn main() {}

#[cfg(target_arch = "xtensa")]
extern crate alloc;

#[cfg(target_arch = "xtensa")]
mod app {
    use esp_hal::clock::CpuClock;
    use esp_hal::main;
    // `print!` is the console sink's, and the reader does not build one.
    #[cfg(not(feature = "cap_qr_read"))]
    use esp_println::print;
    use esp_println::println;

    #[cfg(feature = "cap_qr_read")]
    use kassigner_hal::decoder::{Attempt, Decoder, Outcome};
    #[cfg(feature = "cap_qr_read")]
    use kassigner_hal::display::{Backlight, Display, Rect};
    #[cfg(feature = "cap_qr_read")]
    use kassigner_hal::timer::Timer;
    use kassigner_hal_esp32s3::capture;
    #[cfg(feature = "cap_qr_read")]
    use kassigner_hal_esp32s3::m5stack::camera;
    use kassigner_hal_esp32s3::m5stack::unit;

    esp_bootloader_esp_idf::esp_app_desc!();

    /// The backlight while showing codes, and while reading. Set at build
    /// time, since the right level depends on the pair of units and the
    /// distance:
    ///
    /// ```text
    /// KS_SHOW_BRIGHT=60 KS_READ_BRIGHT=10 cargo +esp195 m5-capture-qr
    /// ```
    #[cfg(feature = "cap_qr")]
    const SHOW_BRIGHT: u8 = level(option_env!("KS_SHOW_BRIGHT"), 110);
    #[cfg(feature = "cap_qr_read")]
    const READ_BRIGHT: u8 = level(option_env!("KS_READ_BRIGHT"), 120);

    /// A backlight level from the environment, or `fallback` if it is absent
    /// or not a number.
    #[cfg(any(feature = "cap_qr", feature = "cap_qr_read"))]
    const fn level(text: Option<&str>, fallback: u8) -> u8 {
        let Some(t) = text else { return fallback };
        let b = t.as_bytes();
        let mut i = 0;
        let mut v: u16 = 0;
        while i < b.len() {
            if b[i] < b'0' || b[i] > b'9' {
                return fallback;
            }
            v = v * 10 + (b[i] - b'0') as u16;
            i += 1;
        }
        if v > 255 {
            fallback
        } else {
            v as u8
        }
    }

    /// A decoded code's bytes: version 40's 2,953, more than the sweep shows.
    #[cfg(any(feature = "cap_qr", feature = "cap_qr_read"))]
    const PAYLOAD: usize = 2953;

    #[cfg(feature = "cap_qr_read")]
    const BLACK: u16 = 0x0000;

    /// Where a capture's bytes go: the crate has no console, so the example
    /// passes its own. The reader prints its own commentary instead.
    #[cfg(not(feature = "cap_qr_read"))]
    struct Console;

    #[cfg(not(feature = "cap_qr_read"))]
    impl core::fmt::Write for Console {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            print!("{}", s);
            Ok(())
        }
    }

    #[main]
    fn main() -> ! {
        run(esp_hal::init(
            esp_hal::Config::default().with_cpu_clock(CpuClock::max()),
        ))
    }

    /// The whole example, in a frame of its own.
    fn run(peripherals: esp_hal::peripherals::Peripherals) -> ! {
        println!("KasSigner capture, M5Stack CoreS3");

        // PSRAM mode stated, not probed: an octal probe takes GPIO 36 and 37,
        // this unit's panel clock and data. The CoreS3 is quad.
        let heap = |psram| {
            let psram = esp_hal::psram::Psram::new(
                psram,
                esp_hal::psram::PsramConfig {
                    mode: esp_hal::psram::PsramMode::QuadSpi,
                    ..Default::default()
                },
            );
            let (_, bytes) = psram.raw_parts();
            if bytes > 0 {
                esp_alloc::psram_allocator!(&psram);
            }
            bytes
        };
        let (unit, _checks) = match unit::bring_up(peripherals, heap) {
            Ok(up) => up,
            Err(e) => {
                println!("HALT: the board did not come up: {e:?}");
                loop {
                    core::hint::spin_loop();
                }
            }
        };

        // The `imu` branch borrows the bus through `device()` and would warn
        // on a mutable binding; every other branch needs one.
        #[cfg(not(all(
            feature = "cap_imu",
            not(feature = "cap_touch"),
            not(feature = "cap_qr"),
            not(feature = "cap_qr_read")
        )))]
        let mut unit = unit;

        #[cfg(not(feature = "cap_qr_read"))]
        let mut console = Console;

        #[cfg(feature = "cap_touch")]
        capture::touch(&mut unit.touch, &unit.timer, &mut console);

        #[cfg(feature = "cap_imu")]
        capture::imu(&mut unit.device(), &unit.timer, &mut console);

        #[cfg(feature = "cap_qr")]
        {
            let mut payload = alloc::vec![0u8; PAYLOAD];
            capture::qr_show(
                &mut unit.cam,
                &mut unit.dec,
                &mut unit.lcd,
                &unit.timer,
                &mut payload,
                SHOW_BRIGHT,
                &mut console,
            )
        }

        #[cfg(feature = "cap_qr_read")]
        {
            let mut payload = alloc::vec![0u8; PAYLOAD];
            reader(
                &mut unit.cam,
                &mut unit.dec,
                &mut unit.lcd,
                &unit.timer,
                &mut payload,
            )
        }

        #[cfg(not(any(
            feature = "cap_touch",
            feature = "cap_imu",
            feature = "cap_qr",
            feature = "cap_qr_read"
        )))]
        {
            let source = if cfg!(feature = "cap_rng") {
                capture::Source::Rng
            } else {
                capture::Source::Camera
            };
            // The raw source beneath the generator: the capture measures the
            // chip's words, not ChaCha20 output.
            capture::raw(
                &mut unit.cam,
                unit.rng.source(),
                &unit.timer,
                source,
                &mut console,
            )
        }
    }

    /// Watch, and print every decode, with a focus meter.
    ///
    /// The other half of the two-unit measurement: one unit runs the sweep,
    /// this one reports what it reads. The viewfinder is here, not in the
    /// capture module, because where a pixel sits in a frame is the board's;
    /// the dither comes from the module.
    ///
    /// This camera cannot be focused (the GC0308 has a fixed lens): move the
    /// units and watch the focus score to find the sharpest distance.
    #[cfg(feature = "cap_qr_read")]
    fn reader<C, D, L, T>(cam: &mut C, dec: &mut D, lcd: &mut L, timer: &T, payload: &mut [u8]) -> !
    where
        C: kassigner_hal::camera::Camera,
        D: Decoder,
        L: Display,
        T: Timer + ?Sized,
    {
        println!(
            "reader: viewfinder up at brightness {}, printing every decode",
            READ_BRIGHT
        );
        let _ = lcd.set_backlight(Backlight::Level(READ_BRIGHT));
        let _ = lcd.clear(BLACK);
        let mut line = [0u16; 240];
        let mut reads = 0u32;
        let mut frames = 0u32;
        let mut focus = 0u32;
        let mut best = 0u32;

        // The signer's attempt policy (`kassigner-signer`'s scan loop), so a
        // run measures the device: `Fast`, and one `Thorough` pass after each
        // `Unreadable`. Any other cadence would measure the cadence, forcing
        // the expensive escalation on frames the device would not escalate.
        let mut attempt = Attempt::Fast;

        // `located`: frames with a code found but unread, each owing an
        // escalation; `escalations`: the thorough submits that followed. A
        // run that reads every frame never escalates, so read counts alone
        // cannot tell two `Thorough` builds apart.
        let mut located = 0u32;
        let mut escalations = 0u32;
        loop {
            // One poll: a result is consumed by the call that returns it.
            match dec.poll(payload) {
                Ok(Some(Outcome::Found { len })) => {
                    attempt = Attempt::Fast;
                    reads += 1;
                    let head = &payload[..len.min(13)];
                    println!(
                        "  read #{}: {} bytes, {} (focus {})",
                        reads,
                        len,
                        core::str::from_utf8(head).unwrap_or("not text"),
                        focus
                    );
                    payload.fill(0);
                }
                Ok(Some(Outcome::Unreadable)) => {
                    located += 1;
                    attempt = Attempt::Thorough;
                }
                _ => {}
            }
            let Ok(frame) = cam.frame_within(timer, 1_000_000) else {
                continue;
            };
            let mut sharp = 0u32;
            for cy in 0..180usize {
                let row = camera::source_row(30 + cy) * camera::FRAME_W + 40;
                let mut last = frame[row];
                for (cx, px) in line.iter_mut().enumerate() {
                    let y = frame[row + cx];
                    // Pixel-to-pixel change: a blurred code is a grey smear
                    // and scores low, a sharp one steps black to white.
                    sharp += u32::from(y.abs_diff(last));
                    last = y;
                    *px = capture::grey(y, cx as u16, cy as u16);
                }
                let _ = lcd.blit(Rect::new(40, 30 + cy as u16, 240, 1), &line);
            }
            focus = sharp / 180;
            best = best.max(focus);
            frames += 1;
            if frames.is_multiple_of(30) {
                println!(
                    "  {} frames, {} reads, {} located-unread, {} escalations, focus {} (best {})",
                    frames, reads, located, escalations, focus, best
                );
            }
            if matches!(attempt, Attempt::Thorough) {
                escalations += 1;
            }
            let _ = dec.submit(frame, attempt);

            // One thorough pass per unreadable frame, as the signer does; left
            // set until a read, the count would measure this latch, not the
            // decoder.
            attempt = Attempt::Fast;
        }
    }

    /// Ours, because `esp-backtrace` keeps its handler behind a feature this
    /// build does not turn on, and an example is its own crate root.
    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo) -> ! {
        println!("PANIC: {}", info);
        loop {
            core::hint::spin_loop();
        }
    }
}
