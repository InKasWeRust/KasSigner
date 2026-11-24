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

//! The P4's camera and touch screen written out raw, for measuring what a
//! seed's two sources are worth on this board.
//!
//! The S3 units have this in their own crate (`capture`, behind its
//! `capture` feature); this is the same capture on the P4, in the same
//! format, so one analyser reads all three. `p4_entropy` does the generator.
//! Nothing is hashed or mixed: a hash makes any source look perfect.
//!
//! One binary does both, since a locked P4 takes a signed image and each
//! write to it takes minutes. For five seconds after start-up it watches the
//! screen: **a finger on it then chooses the touch capture, none the
//! camera's.** A capture done, it parks; reset the unit for the next.
//!
//! The camera: the change of each sampled byte between two frames, the bytes
//! spread over the whole sensor, 8,192 a frame and 32 frames, as hex between
//!
//! ```text
//! -----BEGIN KASSIGNER CAPTURE cam 8192 32-----
//! -----END KASSIGNER CAPTURE-----
//! ```
//!
//! One condition a run: room light and still, a bright bulb in view, the
//! lens covered.
//!
//! The touch screen: 2,048 events, one a line, `x y microseconds-since-the-
//! last`, counted only when the position changed, between
//!
//! ```text
//! -----BEGIN KASSIGNER TOUCH 2048-----
//! -----END KASSIGNER TOUCH-----
//! ```
//!
//! One hand a run: slow, moderate, very fast.
//!
//! Save the whole log to a file; the analyser cuts the capture out.
//!
//!   cargo +esp195 p4-capture-build

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]

#[cfg(not(target_arch = "riscv32"))]
fn main() {}

#[cfg(target_arch = "riscv32")]
extern crate alloc;

#[cfg(target_arch = "riscv32")]
mod app {
    use core::fmt::Write;

    use esp_backtrace as _;
    use esp_hal::main;

    use kassigner_hal::camera::Camera;
    use kassigner_hal::input::Touch;
    use kassigner_hal::timer::Timer;
    use kassigner_hal_esp32p4::{
        soc::{uart, watchdog},
        unit,
    };

    esp_bootloader_esp_idf::esp_app_desc!();

    /// Bytes of camera delta per frame, and frames: the S3 capture's, a
    /// quarter of a mebibyte in all.
    const CHUNK: usize = 8192;
    const CHUNKS: u32 = 32;
    /// Touch events a capture collects: the S3 capture's.
    const TOUCH_EVENTS: u32 = 2048;
    /// How long the start-up watches the screen for a finger.
    const CHOICE_US: u64 = 5_000_000;
    /// 64 bytes a line, as the S3 capture writes them.
    const LINE: usize = 64;
    const HEX: &[u8; 16] = b"0123456789abcdef";

    /// UART0, each byte waited for: the hex lines fill its FIFO.
    struct Console;

    impl Write for Console {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            uart::write_bytes(s.as_bytes());
            Ok(())
        }
    }

    #[main]
    fn main() -> ! {
        watchdog::disable_lp();
        // The fork's maximum, 360 MHz, as the signer runs.
        let p = esp_hal::init(
            esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()),
        );
        let mut out = Console;
        let _ = writeln!(out, "\nKasSigner ESP32-P4 capture: camera and touch, raw");

        // The module's PSRAM as the heap, at 125 MHz, as the signer runs it.
        let heap = |psram| {
            let psram = esp_hal::psram::Psram::new(
                psram,
                esp_hal::psram::PsramConfig {
                    timing: esp_hal::psram::PsramTimingParams::MHZ_125,
                    ..Default::default()
                },
            );
            let (_, bytes) = psram.raw_parts();
            if bytes > 0 {
                esp_alloc::psram_allocator!(&psram);
            }
            bytes
        };
        let (mut unit, checks) = match unit::bring_up(p, heap) {
            Ok(up) => up,
            Err(e) => {
                let _ = writeln!(out, "bring_up failed: {e:?}");
                park();
            }
        };
        let _ = writeln!(out, "bring_up ok: {checks:?}");

        // The choice. The camera runs through it, so its exposure has
        // settled before a camera capture's first frame.
        let _ = writeln!(
            out,
            "a finger on the screen in the next five seconds: touch capture; none: camera"
        );
        let start = unit.timer.now_us();
        let mut finger = false;
        while unit.timer.since(start) < CHOICE_US {
            if let Ok(state) = unit.touch.read() {
                finger |= state.first().is_some();
            }
            let _ = unit.cam.frame_within(&unit.timer, 200_000);
        }

        if finger {
            touch(&mut unit.touch, &unit.timer, &mut out);
        } else {
            camera(&mut unit.cam, &unit.timer, &mut out);
        }
        let _ = writeln!(out, "reset the unit for another capture");
        park();
    }

    /// The change of each sampled byte between consecutive frames, not the
    /// picture: a unit on a table sees the same scene at every seed.
    fn camera<C, T, W>(cam: &mut C, timer: &T, out: &mut W)
    where
        C: Camera,
        T: Timer + ?Sized,
        W: Write,
    {
        let _ = writeln!(
            out,
            "capture: cam, {CHUNKS} chunks of {CHUNK} bytes, raw hex between markers"
        );
        let _ = writeln!(
            out,
            "redirect this whole log to a file; the analyser cuts it out\n"
        );
        let mut prev = alloc::vec![0u8; CHUNK];
        let mut cur = alloc::vec![0u8; CHUNK];
        let mut have_prev = false;
        let mut missed = 0u32;

        let _ = writeln!(
            out,
            "-----BEGIN KASSIGNER CAPTURE cam {CHUNK} {CHUNKS}-----"
        );
        let mut done = 0u32;
        while done < CHUNKS {
            let Ok(frame) = cam.frame_within(timer, 1_000_000) else {
                missed += 1;
                if missed.is_multiple_of(10) {
                    let _ = writeln!(out, "(no frame, {missed} times)");
                }
                continue;
            };
            // One byte in every few, so a chunk spans the whole sensor.
            let stride = frame.len() / CHUNK;
            if stride == 0 {
                let _ = writeln!(out, "(a frame of {} bytes: too small)", frame.len());
                return;
            }
            for (i, b) in cur.iter_mut().enumerate() {
                *b = frame[i * stride];
            }
            if !have_prev {
                prev.copy_from_slice(&cur);
                have_prev = true;
                continue;
            }
            // The delta; this frame becomes the next one's reference.
            for (c, p) in cur.iter_mut().zip(prev.iter_mut()) {
                let d = c.wrapping_sub(*p);
                *p = *c;
                *c = d;
            }
            hex_lines(out, &cur);
            done += 1;
            if done.is_multiple_of(4) {
                let _ = writeln!(out, "(chunk {done} of {CHUNKS})");
            }
        }
        let _ = writeln!(out, "-----END KASSIGNER CAPTURE-----");
        let _ = writeln!(out, "done: {} bytes of cam", CHUNK * CHUNKS as usize);
    }

    /// Raw touch events, one a line: `x y microseconds-since-the-last`. An
    /// unchanged position, a finger held still, records nothing.
    fn touch<D, T, W>(touch: &mut D, timer: &T, out: &mut W)
    where
        D: Touch,
        T: Timer + ?Sized,
        W: Write,
    {
        let _ = writeln!(
            out,
            "capture: touch, {TOUCH_EVENTS} events; move a finger on the screen"
        );
        let _ = writeln!(out, "-----BEGIN KASSIGNER TOUCH {TOUCH_EVENTS}-----");
        let start = timer.now_us();
        let mut last = start;
        let mut seen = 0u32;
        let mut prev = (u16::MAX, u16::MAX);
        while seen < TOUCH_EVENTS {
            let Ok(state) = touch.read() else {
                continue;
            };
            let Some(p) = state.first() else {
                continue;
            };
            if (p.x, p.y) == prev {
                continue;
            }
            prev = (p.x, p.y);
            let now = timer.now_us();
            let _ = writeln!(out, "{} {} {}", p.x, p.y, now - last);
            last = now;
            seen += 1;
        }
        let _ = writeln!(out, "-----END KASSIGNER TOUCH-----");
        let _ = writeln!(
            out,
            "done: {TOUCH_EVENTS} events in {} ms",
            timer.since(start) / 1000
        );
    }

    /// `bytes` as hex, 64 a line.
    fn hex_lines<W: Write>(out: &mut W, bytes: &[u8]) {
        for row in bytes.chunks(LINE) {
            let mut text = [0u8; LINE * 2];
            for (i, b) in row.iter().enumerate() {
                text[i * 2] = HEX[usize::from(b >> 4)];
                text[i * 2 + 1] = HEX[usize::from(b & 0x0F)];
            }
            let _ = writeln!(
                out,
                "{}",
                core::str::from_utf8(&text[..row.len() * 2]).unwrap_or("")
            );
        }
    }

    /// Stop here.
    fn park() -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}
