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

//! Put a seed in a slot, derive from it, scrub, and then search RAM for what
//! is left.
//!
//! From `firmware/kassigner-signer`, through the aliases in its
//! `.cargo/config.toml`:
//!
//! ```text
//! cargo +esp195 m5-seedprobe
//! cargo +esp195 ws-seedprobe
//! cargo +esp195 p4-seedprobe
//! ```
//!
//! The measurement behind `kassigner_fw::wipe`. The seed is a constant, so
//! the needle is known before the sweep and two runs compare.
//!
//! # What it runs, in a unit's order when a seed is stored
//!
//! 1. `provision` puts the mnemonic in a slot, in a frame of its own below
//!    this one: a frame cannot clear itself, so the flow handling a secret
//!    returns before anything scrubs.
//! 2. The seed-flow scrub.
//! 3. `Wallet::open`, the probe's needle (receive address 0's private key)
//!    and `Keyring::new`: PBKDF2, derivations and multiplications that copy
//!    the seed and keys onto the stack without noting a depth.
//! 4. The scrub again, down to the stack's floor rather than the deepest
//!    noted depth, so it clears all of that.
//! 5. A SeedQR of the seed decoded through the board's decoder, as a scan
//!    does.
//! 6. The sweep: the stack from the anchor down to the bottom the board
//!    states, and a stretch of the PSRAM heap.
//!
//! # What it prints
//!
//! A count per needle and the first stack hit's address, never the bytes.
//! The slot holds the seed by design and the probe holds a copy of each
//! needle: those ranges are named ("not swept") and excluded, so any hit
//! left is a copy nothing accounts for.
//!
//! The frame counts say how far each scrub went: both scrubs should report
//! the same count, as both descend to the floor.
//!
//! A hit in PSRAM is the serious one: that memory keeps its contents through
//! a reset, and on the M5 it is a separate chip on the board.

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

/// A host build compiles this and nothing else: the probe is for a unit.
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
    use esp_hal::main;
    use esp_println::println;

    use kassigner_hal::camera::Camera;
    use kassigner_hal::decoder::{Attempt, Decoder, Error as DecodeError, Outcome};
    use kassigner_hal::timer::Timer;

    use kassigner_crypto::bip39;
    use kassigner_crypto::slot::{self, Slot, Slots, SEEDQR_MAX};
    use kassigner_crypto::wallet::Wallet;
    use kassigner_fw::keyring::Keyring;
    use kassigner_fw::wipe;
    use kassigner_kaspa::derivation::Path;

    use crate::common::UNIT;

    // ── The board-dependent lines ────────────────────────────────────────
    #[cfg(feature = "p4")]
    use kassigner_hal_esp32p4::{stack, unit};
    #[cfg(feature = "m5stack")]
    use kassigner_hal_esp32s3::m5stack::unit;
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    use kassigner_hal_esp32s3::stack;
    #[cfg(feature = "waveshare")]
    use kassigner_hal_esp32s3::waveshare::unit;

    esp_bootloader_esp_idf::esp_app_desc!();

    /// The seed the probe stores: a fixed twelve words.
    ///
    /// **Not a bench vector.** The BIP39 test vectors' entropy is a pattern:
    /// the twelve-word `abandon` one is sixteen zero bytes, and a search for
    /// those finds every byte a scrub cleared, tens of thousands of hits.
    ///
    /// These words carry `sha256("KasSigner seed probe")[..16]` as entropy,
    /// `26857af953aa25fbf1a46800f35417e5`, with its BIP39 checksum. No run
    /// longer than a byte repeats, so a hit is a copy, not an accident.
    const WORDS: &str = "charge cloth salad point pelican worth \
                         shoot minimum abstract one album slight";

    /// No passphrase.
    const PASSPHRASE: &[u8] = b"";

    /// PSRAM the sweep covers, in bytes.
    ///
    /// Uninitialised capacity, taken **after** a decode has run and freed its
    /// buffers, so it holds the memory the decoder was using; a zeroed
    /// allocation would erase what this looks for. The vendored decoder's
    /// working buffers are 8,896 bytes each, so this covers many of them.
    const PSRAM_BYTES: usize = 256 * 1024;

    #[main]
    fn main() -> ! {
        let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        println!("KasSigner seed probe, {UNIT}");

        // The board up and the heap made as the firmware does (`heap.rs`):
        // the probe measures a unit's real memory map.

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

        // The window every scrub below works in, the main stack as the
        // linker placed it: a flow scrub descends to its floor.
        let (bottom, top) = stack::core0();
        let stack = wipe::Stack::new(bottom, top).expect("the linker orders the stack");
        wipe::begin_depth(stack);
        println!("stack {:#x} to {:#x} ({} bytes)", bottom, top, top - bottom);

        // The anchor: a local in this frame, taken before anything runs, so
        // the swept window is the same on every build (one in `seed_probe`'s
        // frame moves between builds).
        let anchor = [0u8; 16];
        let anchor_at = anchor.as_ptr() as usize;

        let mut slots: Slots<1> = Slots::new();
        let index = provision(&mut slots);
        println!("seed stored in slot {index}");
        println!("seed flow scrub: {} frames", wipe::scrub_flow());

        let mut stretch = [0u8; 128];
        let wallet = Wallet::open(slots.get(index).expect("the slot"), &mut stretch).expect("open");
        // The key needle, in this frame, which the sweep skips; taken before
        // the scrub below, which clears its derivation's copies.
        let mut derived = [0u8; 32];
        private_key(&wallet, &mut derived);
        let keys = Keyring::new(&wallet).expect("keyring");
        println!("derivation scrub: {} frames", wipe::scrub_flow());
        let fp = wallet.fingerprint();
        println!(
            "seed fingerprint {:02x}{:02x}{:02x}{:02x}",
            fp[0], fp[1], fp[2], fp[3]
        );

        // Through the decoder, as a SeedQR read: the sweep finds what that
        // path leaves.
        decode_a_seedqr(&mut unit.cam, &mut unit.dec, &unit.timer, &slots, index);

        // After the decode: the allocator hands back memory the decoder was
        // just using, not written over since.
        let mut heap_region: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(PSRAM_BYTES);
        let region = &heap_region.spare_capacity_mut()[..PSRAM_BYTES];

        seed_probe(bottom, anchor_at, &slots, index, &keys, &derived, region);
        heap_region.clear();
        wipe::wipe(&mut derived);

        println!("probe done; the unit sits here until it is reset");
        loop {
            core::hint::spin_loop();
        }
    }

    /// Run the stored seed through the decoder, as a SeedQR read does.
    ///
    /// No camera: the seed is encoded as a Standard SeedQR, drawn into a
    /// camera-sized frame and handed to the board's decoder, as a scanned
    /// code is. The decoder's heap buffers must wipe themselves on drop;
    /// seed bytes in freed PSRAM are what the sweep looks for.
    #[inline(never)]
    fn decode_a_seedqr<C, D, T>(cam: &mut C, dec: &mut D, timer: &T, slots: &Slots<1>, index: usize)
    where
        C: Camera,
        D: Decoder,
        T: Timer + ?Sized,
    {
        let Slot::Mnemonic { mnemonic, .. } = slots.get(index).expect("the slot") else {
            panic!("the probe stores a mnemonic");
        };
        let Ok(code) = kassigner_fw::seed::standard_qr(mnemonic) else {
            println!("the encoder refused the seed; no decode to measure");
            return;
        };

        // A frame the decoder accepts: the probe asks its length (an empty
        // submit is refused with `WrongLength` and the length expected)
        // rather than assume `format().frame_bytes()`.
        let format = cam.format();
        let (w, h) = (format.width as usize, format.height as usize);
        let bytes = match dec.submit(&[], Attempt::Fast) {
            Err(DecodeError::WrongLength { expected, .. }) => expected,
            _ => format.frame_bytes(),
        };
        let mut frame = alloc::vec![0xFFu8; bytes];
        let modules = usize::from(code.size);
        let scale = (h.min(w) / (modules + 8)).max(1);
        let side = modules * scale;
        let (x0, y0) = ((w - side) / 2, (h - side) / 2);

        // The code, row-major, a pixel at a time: all three boards read a
        // frame drawn this way.
        frame.fill(0xFF);
        for my in 0..modules {
            for mx in 0..modules {
                if !code.get(mx as u8, my as u8) {
                    continue;
                }
                for py in 0..scale {
                    for px in 0..scale {
                        let at = (y0 + my * scale + py) * w + x0 + mx * scale + px;
                        if at < frame.len() {
                            frame[at] = 0x00;
                        }
                    }
                }
            }
        }
        drop(code);

        println!(
            "decoding a {modules}-module SeedQR at {scale} px per module, {w}x{h}, {} bytes",
            frame.len()
        );

        // Submit, then poll until the worker answers or four seconds pass.
        // The submit count and time are printed: without them a read on the
        // first submit and one on the fortieth look alike, as do a failure
        // with no result and one that ran out of time.
        let mut out = [0u8; 2953];
        let mut read = 0usize;
        let mut submits = 0u32;

        // The firmware's attempt policy: `Fast`, and `Thorough` only after
        // the decoder answers `Unreadable`. Thorough from the start would time
        // a path a scan takes only then: on the Waveshare, a full-resolution
        // 480 px job from the PSRAM buffer instead of its internal fast image.
        let mut attempt = Attempt::Fast;
        let started = timer.now_us();
        while read == 0 && timer.since(started) < 4_000_000 {
            submits += 1;
            match dec.submit(&frame, attempt) {
                Ok(()) | Err(DecodeError::Busy) => {}
                Err(e) => {
                    println!("  the decoder refused the frame: {e:?}");
                    break;
                }
            }
            // Poll to the overall deadline, not a window per submit: the
            // Waveshare takes about 600 ms on a 480 by 480 frame, and a
            // shorter window would count a submit still running as missed.
            while timer.since(started) < 4_000_000 {
                match dec.poll(&mut out) {
                    Ok(Some(Outcome::Found { len })) => {
                        read = len;
                        break;
                    }
                    // Why a pass did not read. `Unreadable`: a code found but
                    // not read, so the next pass is thorough. `NotFound`: no
                    // code seen, which points at the plane decoded from
                    // rather than at the threshold window.
                    Ok(Some(Outcome::Unreadable)) => {
                        println!("    submit {submits}: a code, unreadable; trying harder");
                        attempt = Attempt::Thorough;
                        break;
                    }
                    Ok(Some(Outcome::NotFound)) => {
                        println!("    submit {submits}: no code in the frame");
                        break;
                    }
                    Ok(None) => core::hint::spin_loop(),
                    Err(e) => {
                        println!("  the decoder failed: {e:?}");
                        break;
                    }
                }
            }
        }
        let took = timer.since(started) / 1000;
        if read == 0 {
            println!("  no read after {submits} submits in {took} ms; the sweep measures nothing");
        } else {
            let how = match attempt {
                Attempt::Fast => "fast",
                _ => "thorough",
            };
            println!(
                "  read {read} bytes back after {submits} {how} submits in {took} ms, \
                 the path a scanned SeedQR takes"
            );
        }

        // Everything this function held, gone before the sweep looks.
        wipe::wipe(&mut out[..]);
        wipe::wipe(&mut frame[..]);
        drop(frame);
    }

    /// Put the seed in a slot, in a frame of its own.
    ///
    /// `inline(never)` is load-bearing: at `opt-level = "z"` with LTO the
    /// release build would inline this, leaving its copies in the caller's
    /// frame, which a scrub the caller runs cannot clear.
    #[inline(never)]
    fn provision(slots: &mut Slots<1>) -> usize {
        let mut mnemonic = bip39::from_words(WORDS.split_whitespace()).expect("the seed's words");
        slots
            .store_mnemonic(&mut mnemonic, PASSPHRASE)
            .expect("store the seed")
    }

    /// Receive address 0's private key into `out`.
    ///
    /// A frame of its own, `inline(never)` as [`provision`] is, so what the
    /// derivation copies onto the stack lies below the caller, where the
    /// scrub that follows reaches it. The key wipes itself when it drops.
    #[inline(never)]
    fn private_key(wallet: &Wallet, out: &mut [u8; 32]) {
        let key = wallet.signing_key(Path::receive(0)).expect("receive 0");
        out.copy_from_slice(key.private_key());
    }

    /// Search RAM for the seed that was just stored, and say what is left.
    ///
    /// The stack this thread used and `heap` are swept for the mnemonic's
    /// word indices (two little-endian bytes each, as a `Mnemonic` holds
    /// them), the entropy bytes (as a compact SeedQR holds them), `derived`
    /// (receive address 0's private key) and a Standard SeedQR's digits.
    fn seed_probe(
        low: usize,
        anchor: usize,
        slots: &Slots<1>,
        index: usize,
        keys: &Keyring<&Wallet>,
        derived: &[u8; 32],
        heap: &[core::mem::MaybeUninit<u8>],
    ) {
        let mut words = [0u8; 48];
        let mut entropy = [0u8; 32];
        // The digits a Standard SeedQR carries, as the decoder's buffers hold
        // them: neither other needle has this shape.
        let mut digits = [0u8; SEEDQR_MAX];
        let (wlen, elen, dlen) = match slots.get(index).expect("the slot") {
            Slot::Mnemonic { mnemonic, .. } => {
                for i in 0..mnemonic.len() {
                    let idx = mnemonic.index(i).unwrap_or(0);
                    words[i * 2] = idx as u8;
                    words[i * 2 + 1] = (idx >> 8) as u8;
                }
                let n = mnemonic.entropy(&mut entropy).unwrap_or(0);
                let d = slot::to_seedqr(mnemonic, &mut digits);
                (mnemonic.len() * 2, n, d)
            }
            _ => panic!("the probe stores a mnemonic"),
        };

        // Where the seed is expected, so a hit there is not a leak: the slot,
        // which holds it until power-off by design, the keyring, and the
        // probe's own copy of each needle, which it would otherwise report.
        let known: [(&str, usize, usize); 6] = [
            (
                "the slot",
                slots as *const Slots<1> as usize,
                slots as *const Slots<1> as usize + core::mem::size_of::<Slots<1>>(),
            ),
            (
                "the probe's word buffer",
                words.as_ptr() as usize,
                words.as_ptr() as usize + words.len(),
            ),
            (
                "the probe's entropy buffer",
                entropy.as_ptr() as usize,
                entropy.as_ptr() as usize + entropy.len(),
            ),
            (
                "the keyring",
                keys as *const Keyring<&Wallet> as usize,
                keys as *const Keyring<&Wallet> as usize + core::mem::size_of::<Keyring<&Wallet>>(),
            ),
            (
                "the probe's key buffer",
                derived.as_ptr() as usize,
                derived.as_ptr() as usize + derived.len(),
            ),
            (
                "the probe's digit buffer",
                digits.as_ptr() as usize,
                digits.as_ptr() as usize + digits.len(),
            ),
        ];
        for (name, lo, hi) in known {
            println!("  not swept: {} at {:#x}..{:#x}", name, lo, hi);
        }

        // The window's top: the highest of the anchor and every known range's
        // end, as the compiler may place the anchor below the slot, the
        // keyring and these buffers, leaving the rest of that frame
        // unchecked.
        let mut base = anchor;
        for (_, _, hi) in known {
            if hi > base {
                base = hi;
            }
        }
        // Down to the floor the board states, as the scrub descends: a sweep
        // stopping higher could not say what the scrub left.
        println!(
            "\nseed probe: stack {:#x} down to {:#x} ({} bytes)",
            base,
            low,
            base - low
        );

        let needles: [(&str, &[u8]); 4] = [
            ("word indices", &words[..wlen]),
            ("entropy bytes", &entropy[..elen]),
            ("a derived private key", &derived[..]),
            ("the SeedQR's digits", &digits[..dlen]),
        ];

        for (name, needle) in needles {
            if needle.is_empty() {
                continue;
            }
            let mut hits = 0u32;
            let mut first = 0usize;
            let swept = stack::find(low, base, needle, |at| {
                if !known.iter().any(|r| at >= r.1 && at < r.2) {
                    if hits == 0 {
                        first = at;
                    }
                    hits += 1;
                }
            });
            if swept.is_none() {
                println!("  stack, {}: the window is not inside a stack", name);
            }
            println!(
                "  stack, {}: {} hit(s){}",
                name,
                hits,
                if hits > 0 {
                    " — see the address below"
                } else {
                    ""
                }
            );
            if hits > 0 {
                println!(
                    "    first at {:#x}, {} bytes below the marker",
                    first,
                    base - first
                );
            }

            let heap_hits = stack::find_in(heap, needle, |_| {});
            println!("  psram, {}: {} hit(s)", name, heap_hits);
        }

        words.fill(0);
        entropy.fill(0);
        digits.fill(0);
        println!("\nany hit above is a copy nothing accounts for.");
    }
}
