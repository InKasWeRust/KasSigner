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

//! Board support for the Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5, rev1.3
//! silicon, ROM ECO2. Level 3, beside `kassigner-hal-esp32s3`.
//!
//! ```text
//!   soc/       ECO2 silicon layer: clocks, cache, regi2c, watchdog, uart
//!   board/     this board: pins, shared I2C, addresses, touch→screen map
//!   drivers/   standalone chips: st7796, ft6336/gt911, axp2101
//!   camera/    MIPI-CSI pipeline: ldo, dphy, host, isp, bridge, dma, ov5647
//!   audio/     es8311 codec + I2S player and its ring
//!   entropy    SAR ADC noise source
//!   drbg/      SP 800-90B health tests over the source, host-tested; the
//!              ChaCha20 DRBG they feed is kassigner-hal's
//! ```
//!
//! `examples/p4_hwtest.rs` checks the board; this crate puts it behind
//! `kassigner-hal`'s traits, with `unit::bring_up` and the viewfinder,
//! `stack`, the eFuse verdict and the console.
//!
//! # Host and device
//!
//! Everything that names esp-hal or the PAC is device-only, so the host
//! builds this crate and tests `drbg`, its only host-visible module.
//!
//! # This board is not officially supported
//!
//! esp-hal declares `min-chip-revision = 300` for the P4 and will not run on
//! pre-v3 silicon. The fork in `esp-hal-fork/`, made by its `fork.sh`,
//! carries five fixes, all required:
//!
//! 1. **esp-sync**: `SingleCoreInterruptLock::enter()` writes the CLIC
//!    `mintthresh` register (`csrrw 0x347`, a v3.2/ECO7 Zcmp errata
//!    workaround) on every P4. ECO2 lacks that CSR, the write traps, and
//!    every critical section hangs. Made conditional.
//! 2. **esp-rom-sys**: the ECO5 ROM jump table is swapped for
//!    `esp32p4.rom.ld`, the one ESP-IDF links below revision 3.0, and the
//!    ECO5-only `libgcc` and `rvfp` scripts are removed: on ECO2 all 75
//!    libgcc symbols resolve to wrong addresses, and `u64 / u64` silently
//!    returned `sum - count`. `compiler_builtins` provides them instead.
//! 3. **esp-hal I2S**: clock source forced to XTAL. Upstream picks EXTERNAL,
//!    a pin this board does not wire, so `I2s::new()` spins forever. The
//!    dividers are worked out from XTAL's 40 MHz: from PLL_F160M's 160,
//!    every rate came out a quarter of what was asked.
//! 4. **esp-hal memory.x**: RAM ceiling lowered to 0x4FFA0000. On ECO2 the
//!    top 128 KB of L2MEM is not backed (writes vanish, reads return zero),
//!    and upstream put the main stack there. `dram2_seg`, wholly in it, is
//!    given no length.
//! 5. **esp-hal clocks**: a 360 MHz preset, as ESP-IDF sets below v3.0
//!    (CPLL 360, APB 90), and `max()` returning it; upstream's `max()` is
//!    v3's 400, past ECO2's rating.
//!
//! Plus, in `.cargo/config.toml`: `ESP_HAL_CONFIG_MIN_CHIP_REVISION = "0"`
//! and `--no-stub` on the runner, since the flash stub fails to attach.
//!
//! Two more ECO2 behaviours, handled here: the MIPI D-PHY analog LDO is off
//! by default and `psram_phy_ldo_init()` clobbers it (`camera::mipi_ldo`);
//! esp-hal enables no entropy source on the P4 (`entropy`).
//!
//! # Hard rules
//!
//! * Nothing that takes a critical section may run before `esp_hal::init()`:
//!   no esp-println, no locks. Raw UART stores only, see `soc::uart`.
//! * `esp_hal::init()` disables the bootloader watchdog; before it, a hang
//!   shows as a reboot loop.
//! * Never use `u64`/`u128` division without the fork.
//! * If PSRAM is used, initialise it first: esp-hal's PSRAM driver overwrites
//!   every PMU LDO including the MIPI D-PHY supply.
//! * Physical settle times are microseconds in `soc::settle`, never spin
//!   counts.
//!
//! # The `unstable` feature
//!
//! Register-level modules (`soc`'s cache, clocks and regi2c; the camera's
//! bridge, CSI host, DMA, D-PHY, ISP and MIPI LDO) are `pub` only with
//! `features = ["unstable"]`, which the examples require.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
// Every `unsafe` block says why it is sound in a `// SAFETY:` comment, which
// clippy checks is there. One of the two firmware crates allowed `unsafe`.
#![deny(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

use kassigner_protocol::profile::{Capacity, Profile};

pub mod drbg;

/// What this board holds. Transaction and frame figures are the S3 units',
/// as the companion generates for one envelope. A displayed frame carries
/// 225 bytes, what a version-9 code holds after the frame header (frame 0
/// three fewer, for the payload's digest).
pub const CAPACITY: Capacity = Capacity {
    transaction_bytes: 16_384,
    bytes_per_frame: 256,
    frames: 64,
    display_bytes_per_frame: 225,
};

/// The envelope this board accepts: its capacity over the S3 units'
/// protocol base, a statement about the companion, not the chip.
pub const PROFILE: Profile = CAPACITY.derive(&Profile::ESP32S3);

#[cfg(target_arch = "riscv32")]
pub mod audio;
#[cfg(target_arch = "riscv32")]
pub mod backlight;
#[cfg(target_arch = "riscv32")]
pub mod battery;
#[cfg(target_arch = "riscv32")]
pub mod board;
#[cfg(target_arch = "riscv32")]
pub mod brownout;
#[cfg(target_arch = "riscv32")]
pub mod camera;
#[cfg(target_arch = "riscv32")]
pub mod drivers;
#[cfg(target_arch = "riscv32")]
pub mod entropy;
#[cfg(target_arch = "riscv32")]
pub mod soc;

// ── Behind `kassigner-hal`'s traits ──────────────────────────────────────────
#[cfg(target_arch = "riscv32")]
pub mod cam;
#[cfg(target_arch = "riscv32")]
pub mod console;
#[cfg(target_arch = "riscv32")]
pub mod decode_core;
#[cfg(target_arch = "riscv32")]
pub mod decoder;
#[cfg(target_arch = "riscv32")]
pub mod efuse;
#[cfg(target_arch = "riscv32")]
pub mod image;
#[cfg(target_arch = "riscv32")]
pub mod input;
#[cfg(target_arch = "riscv32")]
pub mod memory;
#[cfg(target_arch = "riscv32")]
pub mod panel;
#[cfg(target_arch = "riscv32")]
pub mod psram;
#[cfg(target_arch = "riscv32")]
pub mod speaker;
#[cfg(target_arch = "riscv32")]
pub mod stack;
#[cfg(target_arch = "riscv32")]
pub mod storage;
#[cfg(target_arch = "riscv32")]
pub mod systimer;
#[cfg(target_arch = "riscv32")]
pub mod unit;
#[cfg(target_arch = "riscv32")]
pub mod watchdog;

/// The board's generator: `kassigner-hal`'s DRBG, seeded from the SAR ADC
/// through this crate's continuous health tests.
#[cfg(target_arch = "riscv32")]
pub type Rng = drbg::Drbg<drbg::Guarded<entropy::HwSource>>;

/// Build [`Rng`]: wrap the enabled source in its health tests, run the
/// start-up test, then seed the generator.
///
/// # Errors
///
/// `CipherBroken` for a build whose cipher fails its known-answer test;
/// `Source` if the start-up test trips or the first seed cannot be drawn;
/// `SeedDegenerate` for an all-zero or all-one seed. A failed seed poisons
/// the generator, and its reason is returned instead; `unit::bring_up`
/// refuses the board on any of these.
///
/// On the target, call this once, after any PSRAM initialisation and after
/// [`entropy::enable`]: nothing here turns the ADC on.
#[cfg(target_arch = "riscv32")]
pub fn rng(source: entropy::HwSource) -> Result<Rng, drbg::DrbgError> {
    let mut guarded = drbg::Guarded::new(source);
    guarded
        .startup()
        .map_err(|_| drbg::DrbgError::Source(kassigner_hal::entropy::Error::Unhealthy))?;
    let rng = drbg::Drbg::new(guarded)?;
    match rng.poisoned() {
        None => Ok(rng),
        Some(e) => Err(e),
    }
}
