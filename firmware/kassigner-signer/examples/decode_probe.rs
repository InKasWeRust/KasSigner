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

//! What the QR decoder costs on a unit: the same frames decoded the same way
//! on all three, to compare the decoder before and after a change.
//!
//! ```text
//! cargo +esp195 m5-decode
//! cargo +esp195 ws-decode
//! cargo +esp195 p4-decode
//! ```
//!
//! Three codes drawn in memory into a 240 by 240 grayscale frame, the size
//! the units decode: a 24-word Standard SeedQR (version 3), a kpub as text
//! (version 6) and a request frame (version 9, the largest a unit shows).
//! Each is decoded [`RUNS`] times at every window in [`DENOMS`] through
//! `kassigner-qr` on core 0 (the firmware decodes on core 1, an identical
//! core). A decode thresholds the frame in place, so it is redrawn, untimed,
//! before each run.
//!
//! No camera and no bring-up, so only the decoder is measured. The frame and
//! the scratch are in internal RAM, as the decoders' own are.
//!
//! # What it prints
//!
//! One line per code and window, led by the code's name, then a total:
//!
//! ```text
//! v3 29x29, 6 px a module, denom 8: avg 31.42 ms, worst 32.10 ms, read back
//! ```
//!
//! "read back" when every run gave the code's own bytes, else "NOT READ".
//!
//! On a laptop, `cargo run -p kassigner-signer --example decode_probe`
//! decodes the same frames: its times say nothing about a unit, but it
//! checks that every frame reads.

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

use kassigner_qr::{encode, encode_numeric, Decoder, QrMatrix, Scratch};

/// The frame's side, the units' decode plane.
const SIDE: usize = 240;
/// Decodes a code and window, averaged.
const RUNS: u64 = 20;
/// Every threshold window the units' decoders use: the S3 units' 8 and 3,
/// the P4's 4 and 2.
const DENOMS: [usize; 4] = [8, 4, 3, 2];
/// The longest payload: a request frame, header and fragment.
const LONGEST: usize = 230;

/// The three codes' payloads, and whether a code is numeric.
fn payloads() -> [(&'static str, [u8; LONGEST], usize, bool); 3] {
    let mut seedqr = [0u8; LONGEST];
    for (i, d) in seedqr[..96].iter_mut().enumerate() {
        *d = b'0' + ((i * 7 + 3) % 10) as u8;
    }
    let mut kpub = [0u8; LONGEST];
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    kpub[..4].copy_from_slice(b"kpub");
    for (i, c) in kpub[4..111].iter_mut().enumerate() {
        *c = alphabet[(i * 13 + 5) % alphabet.len()];
    }
    let mut request = [0u8; LONGEST];
    for (i, b) in request.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    [
        ("SeedQR, 24 words", seedqr, 96, true),
        ("kpub text", kpub, 111, false),
        ("request frame", request, LONGEST, false),
    ]
}

/// Draw `code` centred in `frame`, black on white with a quiet zone of four
/// modules, as large as whole pixels allow. Returns the pixels a module.
fn draw(code: &QrMatrix, frame: &mut [u8]) -> usize {
    let n = usize::from(code.size);
    let px = SIDE / (n + 8);
    let off = (SIDE - n * px) / 2;
    frame.fill(255);
    for y in 0..n {
        for x in 0..n {
            if code.get(x as u8, y as u8) {
                for dy in 0..px {
                    let at = (off + y * px + dy) * SIDE + off + x * px;
                    frame[at..at + px].fill(0);
                }
            }
        }
    }
    px
}

/// Every code at every window, each line printed by `say`, the clock read
/// in microseconds by `now`, the decode working in `scratch`. Returns the
/// decodes that did not read back.
fn measure(
    frame: &mut [u8],
    scratch: &mut Scratch,
    now: &dyn Fn() -> u64,
    say: &mut dyn FnMut(core::fmt::Arguments),
) -> u64 {
    let mut qr = Decoder::new(scratch);
    let mut out = [0u8; 512];
    let mut unread = 0;
    let mut all = 0;
    for (name, payload, len, numeric) in payloads() {
        let payload = &payload[..len];
        let code = if numeric {
            encode_numeric(payload)
        } else {
            encode(payload)
        };
        let Ok(code) = code else {
            say(format_args!("{name}: does not encode"));
            unread += RUNS;
            continue;
        };
        for denom in DENOMS {
            let (mut total, mut worst, mut misses) = (0u64, 0u64, 0u64);
            let mut px = 0;
            for _ in 0..RUNS {
                px = draw(&code, frame);
                let started = now();
                let read = qr.decode(SIDE, SIDE, denom, frame, &mut out);
                let took = now().saturating_sub(started);
                total += took;
                worst = worst.max(took);
                if !matches!(read, Ok(d) if &out[..d.len] == payload) {
                    misses += 1;
                }
            }
            all += total;
            unread += misses;
            let avg = total / RUNS;
            say(format_args!(
                "{name}: v{} {}x{}, {px} px a module, denom {denom}: avg {}.{:02} ms, worst {}.{:02} ms, {}",
                (code.size - 17) / 4,
                code.size,
                code.size,
                avg / 1000,
                avg % 1000 / 10,
                worst / 1000,
                worst % 1000 / 10,
                if misses == 0 { "read back" } else { "NOT READ" },
            ));
        }
    }
    say(format_args!(
        "total decode time {} ms over {} decodes; {unread} did not read back",
        all / 1000,
        RUNS * (DENOMS.len() * 3) as u64
    ));
    unread
}

/// The laptop: the same frames, decoded here, to check that every one reads.
#[cfg(not(any(target_arch = "xtensa", target_arch = "riscv32")))]
fn main() {
    let start = std::time::Instant::now();
    let now = || start.elapsed().as_micros() as u64;
    let mut frame = vec![0u8; SIDE * SIDE];
    let mut scratch = Scratch::new();
    let unread = measure(&mut frame, &mut scratch, &now, &mut |line| {
        println!("{line}")
    });
    assert_eq!(unread, 0, "every frame reads back");
}

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
#[path = "../src/heap.rs"]
mod heap;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod common;

#[cfg(any(target_arch = "xtensa", target_arch = "riscv32"))]
mod device {
    use esp_hal::clock::CpuClock;
    use esp_hal::main;
    use esp_hal::time::Instant;
    use esp_println::println;
    use static_cell::ConstStaticCell;

    use super::{measure, Scratch, SIDE};
    use crate::common::{halt, UNIT};

    esp_bootloader_esp_idf::esp_app_desc!();

    /// The frame, in internal RAM as the decoders' own images are, taken
    /// once without a copy through the stack.
    static FRAME: ConstStaticCell<[u8; SIDE * SIDE]> = ConstStaticCell::new([0; SIDE * SIDE]);
    /// The decode's scratch, likewise.
    static SCRATCH: ConstStaticCell<Scratch> = ConstStaticCell::new(Scratch::new());

    #[main]
    fn main() -> ! {
        let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        println!("KasSigner decode probe, {UNIT}");

        // The heap, made by the firmware's `heap.rs`: the decoder's search
        // allocates from it.
        if super::heap::make(peripherals.PSRAM) == 0 {
            println!("HALT: no external RAM found, or not all of it cleared");
            halt();
        }

        let frame = FRAME.take();
        let scratch = SCRATCH.take();
        let now = || Instant::now().duration_since_epoch().as_micros();
        let unread = measure(frame, scratch, &now, &mut |line| println!("{line}"));
        println!(
            "done: {}",
            if unread == 0 {
                "every frame read back"
            } else {
                "SOME DID NOT READ"
            }
        );
        halt();
    }
}
