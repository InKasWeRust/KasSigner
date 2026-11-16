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

//! Light the screen, plant a marker where a seed would be, panic, and say
//! what the panic left. From `firmware/kassigner-signer`, through the
//! aliases in its `.cargo/config.toml`:
//!
//! ```text
//! cargo +esp195 m5-panicprobe       panic on core 0
//! cargo +esp195 m5-panicprobe1      panic on core 1, the decoder's
//! cargo +esp195 ws-panicprobe       panic on core 0
//! cargo +esp195 ws-panicprobe1      panic on core 1, the decoder's
//! cargo +esp195 p4-panicprobe       panic on core 0
//! cargo +esp195 p4-panicprobe1      panic on core 1, the decoder's
//! ```
//!
//! # What it runs
//!
//! The unit comes up as the firmware brings it up, the screen lit white and
//! the camera running, as a SeedQR and a scan leave them (the bytes set in
//! their buffers are printed). The marker goes in `main`'s frame, where the
//! flow keeps its seed slots, in the decode image, where a SeedQR's picture
//! would be, and in two PSRAM buffers lent to `stack::clear_on_panic`, as
//! the firmware lends the frames and payload a seed's words cross mid-scan.
//! Three seconds later it panics: on core 0 from a frame holding the marker,
//! or, with `panicprobe1`, on core 1, whose decode worker's `panic-probe`
//! hook panics at its next job with the marker on its stack. The firmware's
//! panic path follows, `stack::wipe_and_halt` with the unit's `quiesce`,
//! then this probe's report.
//!
//! # What to see
//!
//! After `PANIC:`, the bytes cleared, then the markers left on each core's
//! stack, in the decode image and in the scan buffers, the bytes still set
//! in the camera and panel buffers, and whether each core runs. Every count
//! should be 0, the other core stopped, and the screen dark. Each marker is
//! printed with its address: beside the report's own address, it shows
//! whether the marker lies in the few hundred bytes the wipe keeps around
//! its own frame or is one the wipe missed.
//!
//! On the P4, "read from memory" marks a region read past the data cache,
//! so a zero the wipe left only in the cache does not count as cleared.

#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_std)]
#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_main)]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "m5stack", feature = "waveshare"),
    all(feature = "m5stack", feature = "p4"),
    all(feature = "waveshare", feature = "p4")
))]
compile_error!("pick one unit: --features m5stack, --features waveshare or --features p4");

#[cfg(all(
    any(target_arch = "xtensa", target_arch = "riscv32"),
    not(any(feature = "m5stack", feature = "waveshare", feature = "p4"))
))]
compile_error!("the probe needs a unit: --features m5stack, waveshare or p4");

#[cfg(not(any(target_arch = "xtensa", target_arch = "riscv32")))]
fn main() {}

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
#[path = "../src/heap.rs"]
mod heap;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod common;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod device {
    extern crate alloc;

    use esp_hal::clock::CpuClock;
    use esp_hal::delay::Delay;
    use esp_hal::main;
    use esp_println::println;

    use kassigner_fw::wipe;
    use kassigner_hal::camera::Camera;
    use kassigner_hal::display::{Backlight, Display, Rect};
    use kassigner_hal::timer::Deadline;

    use crate::common::UNIT;

    #[cfg(feature = "p4")]
    use kassigner_hal_esp32p4::{decode_core, stack, unit};
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    use kassigner_hal_esp32s3::stack;
    #[cfg(feature = "waveshare")]
    use kassigner_hal_esp32s3::waveshare::{decode_core, unit};
    #[cfg(feature = "m5stack")]
    use kassigner_hal_esp32s3::{decode_core, m5stack::unit};

    esp_bootloader_esp_idf::esp_app_desc!();

    /// Which core panics.
    const CORE: u8 = if cfg!(feature = "panicprobe1") { 1 } else { 0 };

    /// The marker: the decode worker's own, so the one core 1 plants is the
    /// one looked for.
    const MARKER: [u8; 32] = decode_core::PROBE_MARKER;

    /// What the report compares against, in flash: never a copy on a stack
    /// it is searching.
    static NEEDLE: [u8; 32] = MARKER;

    /// Each scan buffer the probe lends, a few KB as the firmware's.
    const SCAN_BYTES: usize = 4096;

    #[main]
    fn main() -> ! {
        let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        println!("KasSigner panic probe, {UNIT}: panic on core {CORE}");

        #[cfg(feature = "waveshare")]
        let up = unit::bring_up(
            peripherals,
            kassigner_hal_esp32s3::waveshare::sensor::Module::AutoFocus,
            super::heap::make,
        );
        #[cfg(not(feature = "waveshare"))]
        let up = unit::bring_up(peripherals, super::heap::make);
        let (mut unit, _checks) = match up {
            Ok(up) => up,
            Err(e) => {
                println!("HALT: the board did not come up: {e:?}");
                loop {
                    core::hint::spin_loop();
                }
            }
        };
        println!("core 1 stack: {:x?}", stack::core1());

        // The screen as a SeedQR leaves it: lit, and white.
        let size = unit.lcd.size();
        let _ = unit
            .lcd
            .fill(Rect::new(0, 0, size.width, size.height), 0xFFFF);
        let _ = unit.lcd.set_backlight(Backlight::Level(255));
        // The camera as a scan leaves it: frames taken, and on the units
        // whose capture runs ahead, the next one coming in.
        for _ in 0..4 {
            let _ = unit.cam.frame(Deadline::after(&unit.timer, 1_000_000));
        }
        unit::probe_quiesced(|name, set| println!("before the panic, {name}: {set} byte(s) set"));

        // Where the seed would be: `main`'s frame, and the decode image.
        let held = core::hint::black_box(MARKER);
        let _ = core::hint::black_box(&held);
        decode_core::fill_image(MARKER.len(), |image| image.copy_from_slice(&MARKER));
        // And the scan buffers, made as the firmware makes them, the marker
        // at each end.
        #[cfg(feature = "p4")]
        let lent = [
            kassigner_hal_esp32p4::psram::buffer::<u8>(SCAN_BYTES),
            kassigner_hal_esp32p4::psram::buffer::<u8>(SCAN_BYTES),
        ];
        #[cfg(not(feature = "p4"))]
        let lent = [
            Some(alloc::vec![0u8; SCAN_BYTES].leak()),
            Some(alloc::vec![0u8; SCAN_BYTES].leak()),
        ];
        for buf in lent {
            let Some(buf) = buf else {
                println!("no PSRAM for a scan buffer");
                continue;
            };
            buf[..MARKER.len()].copy_from_slice(&MARKER);
            buf[SCAN_BYTES - MARKER.len()..].copy_from_slice(&MARKER);
            if !stack::clear_on_panic(buf) {
                println!("a scan buffer was not taken");
            }
        }

        // On the P4, the markers so far written back to memory, so that
        // memory read after the panic shows whether the wipe's zeros reached
        // it.
        #[cfg(feature = "p4")]
        {
            let image = decode_core::probe_image();
            stack::to_memory(image.0, image.1);
            let (bottom, top) = stack::core0();
            stack::to_memory(bottom, top);
        }

        println!("marker planted; the screen is lit; panic in 3 s");
        let delay = Delay::new();
        delay.delay_millis(3000);
        panic_now(&delay)
    }

    /// Panic on core 0 from a frame holding the marker, as a derivation's
    /// frames would hold a seed's bytes.
    #[cfg(not(feature = "panicprobe1"))]
    #[inline(never)]
    fn panic_now(_: &Delay) -> ! {
        let marker = core::hint::black_box(MARKER);
        let _ = core::hint::black_box(&marker);
        panic!("panic probe: core 0");
    }

    /// Have core 1 panic at its next job, give it one, and wait without a
    /// word: core 1 parks this core, and a core parked mid-print would hold
    /// the console core 1 reports on.
    #[cfg(feature = "panicprobe1")]
    fn panic_now(delay: &Delay) -> ! {
        decode_core::PANIC_NEXT_JOB.store(true, core::sync::atomic::Ordering::Release);
        #[cfg(any(feature = "m5stack", feature = "waveshare"))]
        let given = decode_core::submit(16, 16, 8, decode_core::KIND_FAST);
        #[cfg(feature = "p4")]
        let given = decode_core::submit(kassigner_hal::decoder::Attempt::Fast);
        delay.delay_millis(5000);
        // Only reached if core 1 did not stop this core.
        println!("core 1 did not panic (job given: {given})");
        loop {
            core::hint::spin_loop();
        }
    }

    /// The firmware's panic path, with this probe's report.
    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo) -> ! {
        println!("PANIC: {}", info);
        stack::wipe_and_halt(wipe::SCRUB_FLOOR_MARGIN, unit::quiesce, report)
    }

    /// Markers left in a stack, each printed; none for a range the board
    /// does not call a stack.
    fn markers(from: usize, to: usize) -> u32 {
        stack::find(from, to, &NEEDLE, print_marker).unwrap_or(0)
    }

    /// One marker found.
    fn print_marker(at: usize) {
        println!("    marker at {:#x}", at);
    }

    /// What the panic left, once `wipe_and_halt` has cleared and quiesced.
    fn report(bytes: usize) {
        println!("stacks cleared, {bytes} bytes");
        let here = core::hint::black_box(&bytes) as *const usize as usize;
        println!("  this report runs at {:#x}", here);
        let (bottom, top) = stack::core0();
        println!("  core 0 stack {:#x}..{:#x}:", bottom, top);
        // On the P4, the stack this report does not run on and the decode
        // image are read from memory, not the data cache: a zero the wipe
        // left only in the cache is not in memory.
        #[cfg(feature = "p4")]
        if CORE == 1 {
            stack::from_memory(bottom, top);
            println!("    read from memory");
        }
        println!("    {} marker(s)", markers(bottom, top));
        match stack::core1() {
            Some((bottom, top)) => {
                println!("  core 1 stack {:#x}..{:#x}:", bottom, top);
                #[cfg(feature = "p4")]
                if CORE == 0 {
                    stack::from_memory(bottom, top);
                    println!("    read from memory");
                }
                println!("    {} marker(s)", markers(bottom, top));
            }
            None => println!("  core 1: not started"),
        }
        let image = decode_core::probe_image();
        println!("  decode image {:#x}..{:#x}:", image.0, image.1);
        #[cfg(feature = "p4")]
        {
            stack::from_memory(image.0, image.1);
            println!("    read from memory");
        }
        println!(
            "    {} marker(s)",
            stack::find_in_image(&NEEDLE, print_marker)
        );
        println!("  scan buffers:");
        println!(
            "    {} marker(s)",
            stack::find_in_cleared(&NEEDLE, print_marker)
        );
        println!("  camera and panel buffers:");
        unit::probe_quiesced(|name, set| println!("    {name}: {set} byte(s) set"));
        use esp_hal::system::{is_running, Cpu};
        println!(
            "  core 0 running: {}, core 1 running: {}",
            is_running(Cpu::ProCpu),
            is_running(Cpu::AppCpu)
        );
        println!("panic probe: done. Every count should be 0; the screen should be dark.");
    }
}
