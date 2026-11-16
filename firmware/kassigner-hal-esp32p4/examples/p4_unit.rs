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

//! The P4 behind the traits: `bring_up`, the viewfinder, the decoder and
//! the touch controller, driven as the signer's loop drives them.
//!
//! `p4_hwtest` proves the hardware through the bring-up crate's own APIs;
//! this proves the layer the flow talks to. Show it a code; it prints what
//! it read. At frame 30 it restarts the camera ten times; at frame 60 it
//! wipes the frame and prints `[ ok ] frame buffer wiped` or
//! `[FAIL] frame buffer wiped`; at frame 90 it cancels a decode in flight.
//! Every 30 frames it prints the seam, the picture's edge, stale cache
//! lines and timings.
//!
//!   cargo +esp195 p4-unit

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]

#[cfg(not(target_arch = "riscv32"))]
fn main() {}

#[cfg(target_arch = "riscv32")]
extern crate alloc;

#[cfg(target_arch = "riscv32")]
mod app {
    use esp_backtrace as _;
    use esp_hal::main;
    use esp_println::println;

    use kassigner_hal::camera::{Camera, Power};
    use kassigner_hal::decoder::{Attempt, Decoder, Outcome};
    use kassigner_hal::display::{Display, Rect};
    use kassigner_hal::input::{State, Touch};
    use kassigner_hal::provisioning::Provisioning;
    use kassigner_hal::timer::Timer;
    use kassigner_hal_esp32p4::{board, cam, decode_core, efuse, soc::watchdog, stack, unit};

    esp_bootloader_esp_idf::esp_app_desc!();

    #[main]
    fn main() -> ! {
        watchdog::disable_lp();
        // `max()` is the fork's 360 MHz preset (CPLL 360, APB 90), ECO2's
        // maximum, as ESP-IDF configures chips below v3.0. esp-hal 1.2.2
        // would boot at 100 MHz; v3's 400 is outside this revision's rating.
        let p = esp_hal::init(
            esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()),
        );
        println!("KasSigner ESP32-P4 unit test: the board behind the traits");

        // The module's 32 MB of hex PSRAM as the heap, made inside
        // `bring_up` before anything there allocates. At 125 MHz, as the
        // signer runs it: at esp-hal's default of 250, words come back with
        // a byte wrong.
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
                println!("bring_up failed: {e:?}");
                loop {
                    core::hint::spin_loop();
                }
            }
        };
        println!("bring_up ok: {checks:?}");
        println!("panel {:?}", unit.lcd.size());
        let (bottom, top) = stack::core0();
        println!("main stack {bottom:#x}..{top:#x}, {} bytes", top - bottom);
        println!("fuses: {:?}", efuse::Fuses.verdict());
        let mut bytes = [0u8; 8];
        println!(
            "generator: {:?} -> {:02x?}",
            unit.rng.fill(&mut bytes).is_ok(),
            bytes
        );

        let mut payload = [0u8; 4096];
        let mut frames = 0u32;
        let mut attempt = Attempt::Fast;
        // Microseconds spent in each stage, summed over 30 frames.
        let (mut t_poll, mut t_cap, mut t_view) = (0u64, 0u64, 0u64);
        loop {
            // The frame wipe, once: `clear` is what the flow calls when the
            // camera goes off after a SeedQR is read (its image decodes back
            // to the seed), and only a count before and after shows it
            // worked. At the top of an iteration, where the last frame's
            // borrow of the camera has ended.
            if frames == 60 {
                frames += 1;
                // SAFETY: between two captures; this slice, like each below,
                // is gone before the clear or the next capture.
                let set = unsafe { cam::frame_buffer() }
                    .iter()
                    .filter(|&&b| b != 0)
                    .count();
                unit.cam.clear();
                // SAFETY: as above.
                let left = unsafe { cam::frame_buffer() }
                    .iter()
                    .filter(|&&b| b != 0)
                    .count();
                println!(
                    "frame wipe: {set} bytes set before, {left} after, of {} KB",
                    // SAFETY: as above.
                    unsafe { cam::frame_buffer() }.len() / 1024
                );
                // The count above reads through the L1 data cache; with its
                // lines dropped, the same count reads memory: what a SeedQR
                // image would leave in RAM if the zeros had not reached it.
                // SAFETY: as above; `buf` is gone before the next capture.
                let buf = unsafe { cam::frame_buffer() };
                kassigner_hal_esp32p4::soc::cache::invalidate(
                    buf.as_ptr() as u32,
                    buf.len() as u32,
                );
                // SAFETY: as above.
                let held = unsafe { cam::frame_buffer() }
                    .iter()
                    .filter(|&&b| b != 0)
                    .count();
                println!("  in memory, past the cache: {held} bytes set");
                // And memory read with no cache operation at all, through
                // PSRAM's uncached window, 0x8800_0000 for the cached
                // 0x4800_0000 (the TRM's 9.3.3.1), where the frame now is.
                let direct = buf.as_ptr() as usize + 0x4000_0000;
                let raw = (0..buf.len())
                    .filter(|i| {
                        // SAFETY: the frame's own bytes, through the
                        // uncached window, read only.
                        unsafe { core::ptr::read_volatile((direct + i) as *const u8) != 0 }
                    })
                    .count();
                println!("  in memory, read uncached: {raw} bytes set");
                // The verdict: the frame held something, and none of the
                // three readings finds any of it.
                let wiped = set > 0 && left == 0 && held == 0 && raw == 0;
                println!(
                    "  {} frame buffer wiped",
                    if wiped { "[ ok ]" } else { "[FAIL]" }
                );
            }

            // The camera off and on ten times as the flow does it, each time
            // with three tries for a frame: every restart should start and
            // deliver.
            if frames == 30 {
                frames += 1;
                let (mut down, mut none) = (0u32, 0u32);
                for cycle in 0..10u32 {
                    let _ = unit.cam.set_power(Power::Off);
                    unit.timer.delay_us(100_000);
                    if let Err(e) = unit.cam.set_power(Power::On) {
                        down += 1;
                        println!("  restart {cycle}: would not start: {e:?}");
                        continue;
                    }
                    let got = (0..3).any(|_| unit.cam.frame_within(&unit.timer, 1_000_000).is_ok());
                    if !got {
                        none += 1;
                        println!("  restart {cycle}: no frame in three tries");
                    }
                }
                println!(
                    "restarts: 10; would not start {down}; no frame {none}; DMA channel aborts {}, controller resets {}",
                    kassigner_hal_esp32p4::camera::dma::aborts(),
                    kassigner_hal_esp32p4::camera::dma::resets()
                );
            }

            // A cancel with a job in flight, once: the job is drained, not
            // left finished with nobody to take it, and the worker takes the
            // next. As in the Waveshare's hardware test.
            if frames == 90 {
                frames += 1;
                if let Ok(frame) = unit.cam.frame_within(&unit.timer, 1_000_000) {
                    let _ = unit.dec.poll(&mut payload);
                    let sent = unit.dec.submit(frame, Attempt::Fast).is_ok();
                    unit.dec.cancel();
                    let idle = decode_core::STATE.load(core::sync::atomic::Ordering::Acquire)
                        == decode_core::IDLE;
                    println!("cancel mid-decode: submitted {sent}, worker idle {idle}");
                }
                let mut back = false;
                if let Ok(frame) = unit.cam.frame_within(&unit.timer, 1_000_000) {
                    if unit.dec.submit(frame, Attempt::Fast).is_ok() {
                        let t = unit.timer.now_us();
                        while unit.timer.since(t) < 2_000_000 {
                            if let Ok(Some(_)) = unit.dec.poll(&mut payload) {
                                back = true;
                                break;
                            }
                        }
                    }
                }
                payload.fill(0);
                println!("job after a cancel: result back {back}");
            }

            if let Ok(State::One(pt)) = unit.touch.read() {
                println!("touch at ({}, {})", pt.x, pt.y);
            }
            let t = unit.timer.now_us();
            let polled = unit.dec.poll(&mut payload);
            t_poll += unit.timer.since(t);
            match polled {
                Ok(Some(Outcome::Found { len })) => {
                    attempt = Attempt::Fast;
                    println!("decoded {len} bytes: {:?}", &payload[..len.min(64)]);
                }
                Ok(Some(Outcome::Unreadable)) => {
                    attempt = Attempt::Thorough;
                    println!("a code, unreadable: trying harder");
                }
                _ => {}
            }
            let t = unit.timer.now_us();
            let Ok(frame) = unit.cam.frame_within(&unit.timer, 1_000_000) else {
                println!("no frame");
                continue;
            };
            t_cap += unit.timer.since(t);
            let t = unit.timer.now_us();
            let panel = Rect::new(0, 0, board::LCD_W, board::LCD_H);
            unit::viewfinder(&mut unit.lcd, frame, panel);
            t_view += unit.timer.since(t);
            let t = unit.timer.now_us();
            let _ = unit.dec.submit(frame, attempt);
            t_poll += unit.timer.since(t);
            frames += 1;

            if frames.is_multiple_of(30) {
                let (seam, weight) = unit::seam_column(frame);
                println!(
                    "seam at plane column {seam} (raw column {}), weight {weight}",
                    seam * 2
                );
                println!(
                    "picture ends at plane column {} of {} (raw column {})",
                    unit::content_edge(frame, 24),
                    kassigner_hal_esp32p4::decoder::PLANE_W,
                    unit::content_edge(frame, 24) * 2
                );
                // The frame, in PSRAM, hashed by 64-byte line as read, then
                // again after both caches drop it: a line that differs was
                // stale in a cache, which the capture's invalidate prevents.
                {
                    // SAFETY: after this pass's capture and before the next,
                    // and `buf` gone with this block; `frame` reads the same
                    // buffer, and only reads.
                    let buf = unsafe { cam::frame_buffer() };
                    let hashes = |into: &mut [u32]| {
                        for (l, h) in into.iter_mut().enumerate() {
                            let mut x: u32 = 0x811C_9DC5;
                            for b in &buf[l * 64..(l + 1) * 64] {
                                // SAFETY: a byte of the frame buffer.
                                let v = unsafe { core::ptr::read_volatile(b) };
                                x = (x ^ u32::from(v)).wrapping_mul(0x0100_0193);
                            }
                            *h = x;
                        }
                    };
                    let lines = buf.len() / 64;
                    let mut first = alloc::vec![0u32; lines];
                    let mut again = alloc::vec![0u32; lines];
                    hashes(&mut first);
                    kassigner_hal_esp32p4::soc::cache::invalidate(
                        buf.as_ptr() as u32,
                        buf.len() as u32,
                    );
                    hashes(&mut again);
                    let stale = first.iter().zip(&again).filter(|(a, b)| a != b).count();
                    println!("stale 64-byte lines in this frame: {stale} of {lines}");
                }
                // The frame starts past the lead lines (`cam::LEAD_LINES`):
                // its first rows, each against the next of its own colour,
                // step no more than any others do.
                let width = usize::from(cam::FORMAT.width);
                let row = |r: usize| &frame[r * width..(r + 1) * width];
                let steps: [u32; 32] = core::array::from_fn(|r| {
                    let sum: u32 = row(r)
                        .iter()
                        .zip(row(r + 2))
                        .map(|(a, b)| u32::from(a.abs_diff(*b)))
                        .sum();
                    sum / width as u32
                });
                let most = steps.iter().copied().max().unwrap_or(0);
                let mut sorted = steps;
                sorted.sort_unstable();
                println!(
                    "first rows: biggest step {most} (typical {})",
                    sorted[sorted.len() / 2]
                );
                println!(
                    "{frames} frames; per frame: capture {} ms, viewfinder {} ms, submit+poll {} ms",
                    t_cap / 30_000,
                    t_view / 30_000,
                    t_poll / 30_000
                );
                t_cap = 0;
                t_view = 0;
                t_poll = 0;
            }
        }
    }
}
