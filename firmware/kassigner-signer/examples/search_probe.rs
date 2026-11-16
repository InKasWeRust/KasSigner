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

//! What one address costs to derive on a unit, and what the curve's
//! precomputed tables change.
//!
//! ```text
//! cargo +esp195 m5-search           cargo +esp195 m5-search-tables
//! cargo +esp195 ws-search           cargo +esp195 ws-search-tables
//! cargo +esp195 p4-search           cargo +esp195 p4-search-tables
//! ```
//!
//! Each way is averaged over twenty addresses past the seed's first ones,
//! where the search for a request's keys runs:
//!
//! - **as now**: `Wallet::signing_key`, which derives from the account key
//!   down, three curve multiplications an address.
//! - **from the chain**: the receive chain's public key worked out once, and
//!   each address derived from it, one multiplication.
//!
//! It prints the time per address each way and "same keys: yes" if both
//! give the same keys, then what a full search would take each way.
//!
//! The `-tables` builds turn on `k256`'s base-point tables, which only
//! `mul_by_generator` uses; the key code's `GENERATOR * k` does not, so that
//! multiplication is also timed both ways. The tables are built in internal
//! RAM at the first `mul_by_generator`: compare that call's time, and the
//! main stack's size (their RAM comes out of it), across the builds.
//!
//! The seed is the public test vector, `abandon` eleven times and `about`.

#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_std)]
#![cfg_attr(any(target_arch = "xtensa", target_arch = "riscv32"), no_main)]
#![forbid(unsafe_code)]

#[cfg(any(
    all(feature = "m5stack", feature = "waveshare"),
    all(feature = "m5stack", feature = "p4"),
    all(feature = "waveshare", feature = "p4")
))]
compile_error!("pick one unit: --features m5stack, --features waveshare or --features p4");

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
    use esp_hal::clock::CpuClock;
    use esp_hal::main;
    use esp_println::println;

    use crate::common::{halt, UNIT};

    use k256::elliptic_curve::PrimeField;
    use k256::{ProjectivePoint, Scalar};
    use kassigner_crypto::bip32::ExtendedPrivateKey;
    use kassigner_crypto::bip39;
    use kassigner_crypto::slot::Slot;
    use kassigner_crypto::wallet::Wallet;
    use kassigner_hal::timer::Timer;
    use kassigner_kaspa::bip32_public::ChildNumber;
    use kassigner_kaspa::derivation::{Path, SINGLE_ACCOUNT};

    #[cfg(feature = "p4")]
    use kassigner_hal_esp32p4::{stack, unit};
    #[cfg(feature = "m5stack")]
    use kassigner_hal_esp32s3::m5stack::unit;
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    use kassigner_hal_esp32s3::stack;
    #[cfg(feature = "waveshare")]
    use kassigner_hal_esp32s3::waveshare::unit;

    esp_bootloader_esp_idf::esp_app_desc!();

    /// The bench's test vector.
    const WORDS: &str = "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about";

    /// Addresses timed each way, from where the seed's first ones stop.
    const COUNT: u32 = 20;
    const FROM: u32 = 25;

    /// Addresses a full search derives, as `kassigner_fw::keyring::SWEEP`.
    const SWEEP: u64 = 1975;

    #[main]
    fn main() -> ! {
        let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
        println!(
            "KasSigner search probe, {UNIT}; curve tables {}",
            if cfg!(feature = "k256-tables") {
                "ON"
            } else {
                "off"
            }
        );

        // The heap as the firmware makes it, through `heap.rs`.
        #[cfg(feature = "waveshare")]
        let up = unit::bring_up(
            peripherals,
            kassigner_hal_esp32s3::waveshare::sensor::Module::AutoFocus,
            super::heap::make,
        );
        #[cfg(not(feature = "waveshare"))]
        let up = unit::bring_up(peripherals, super::heap::make);
        let Ok((unit, _checks)) = up else {
            println!("HALT: the board did not come up");
            halt();
        };
        let timer = &unit.timer;
        let (bottom, top) = stack::core0();
        println!("main stack: {} bytes", top - bottom);

        // The seed and the account key.
        let Ok(words) = bip39::from_words(WORDS.split(' ')) else {
            println!("HALT: the test vector did not parse");
            halt();
        };
        let mut scratch = [0u8; 128];
        let t = timer.now_us();
        let Ok(seed) = bip39::to_seed(&words, "", &mut scratch) else {
            println!("HALT: no seed");
            halt();
        };
        println!("seed (PBKDF2): {} ms", timer.since(t) / 1000);
        let Ok(account) = ExtendedPrivateKey::from_seed(seed.as_bytes())
            .and_then(|m| m.derive_path(&SINGLE_ACCOUNT))
        else {
            println!("HALT: no account key");
            halt();
        };

        // One public key, twice. `public_key` multiplies with `GENERATOR * k`,
        // which the tables do not serve, so neither call builds them.
        let t = timer.now_us();
        let _ = account.public_key();
        println!("first public key: {} us", timer.since(t));
        let t = timer.now_us();
        let _ = account.public_key();
        println!("next public key: {} us", timer.since(t));

        // As the flow derives now.
        let Ok(slot) = Slot::mnemonic(words, b"") else {
            println!("HALT: no slot");
            halt();
        };
        let Ok(wallet) = Wallet::open(&slot, &mut scratch) else {
            println!("HALT: no wallet");
            halt();
        };
        let mut now_keys = [[0u8; 32]; COUNT as usize];
        let t = timer.now_us();
        for (k, out) in now_keys.iter_mut().enumerate() {
            match wallet.signing_key(Path::receive(FROM + k as u32)) {
                Ok(key) => *out = key.x_only(),
                Err(_) => {
                    println!("HALT: a derivation failed");
                    halt();
                }
            }
        }
        let as_now = timer.since(t) / u64::from(COUNT);

        // From the receive chain's public key.
        let Ok(chain) = account
            .to_extended_public_key()
            .derive_child(ChildNumber(0))
        else {
            println!("HALT: no chain key");
            halt();
        };
        let mut same = true;
        let t = timer.now_us();
        for (k, want) in now_keys.iter().enumerate() {
            match chain.derive_child(ChildNumber(FROM + k as u32)) {
                Ok(child) => same &= child.public_key[1..] == want[..],
                Err(_) => {
                    println!("HALT: a public derivation failed");
                    halt();
                }
            }
        }
        let from_chain = timer.since(t) / u64::from(COUNT);

        println!(
            "per address: as now {} us, from the chain {} us; same keys: {}",
            as_now,
            from_chain,
            if same { "yes" } else { "NO" }
        );
        println!(
            "a full search, {} addresses: as now {} s, from the chain {} s",
            SWEEP,
            as_now * SWEEP / 1_000_000,
            from_chain * SWEEP / 1_000_000
        );
        // The base-point multiplication itself: `GENERATOR * k`, as the key
        // code does it, and `mul_by_generator`, which the tables serve and
        // whose first call builds them, when they are on.
        let Some(k) = Option::<Scalar>::from(Scalar::from_repr(now_keys[0].into())) else {
            println!("HALT: not a scalar");
            halt();
        };
        let t = timer.now_us();
        let _ = ProjectivePoint::mul_by_generator(&k);
        println!("first mul_by_generator: {} us", timer.since(t));
        let t = timer.now_us();
        for _ in 0..COUNT {
            let _ = core::hint::black_box(ProjectivePoint::GENERATOR * k);
        }
        let general = timer.since(t) / u64::from(COUNT);
        let t = timer.now_us();
        for _ in 0..COUNT {
            let _ = core::hint::black_box(ProjectivePoint::mul_by_generator(&k));
        }
        let by_generator = timer.since(t) / u64::from(COUNT);
        println!(
            "base-point multiplication: GENERATOR * k {} us, mul_by_generator {} us",
            general, by_generator
        );
        println!("done");
        halt();
    }
}
