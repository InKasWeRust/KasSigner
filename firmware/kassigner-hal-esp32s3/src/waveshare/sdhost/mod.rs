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

// MicroSD card driver over the SDHOST controller. 100% Rust, no-std,
// no-alloc.
//
// Hardware: Waveshare ESP32-S3-Touch-LCD-2
//   - SD_CLK  = GPIO39 (shared with LCD SPI2 SCK)
//   - SD_CMD  = GPIO38 (shared with LCD SPI2 MOSI)
//   - SD_D0   = GPIO40 (dedicated to SD)
//   - SD_D3   = GPIO41 (dedicated to SD, directly tied to card detect)
//   - LCD_CS  = GPIO45
//   - LCD_DC  = GPIO42
//
// Architecture:
//   - SDHOST controller at 0x60028000 (TRM Chapter 34)
//   - 1-bit SD native mode (CLK + CMD + D0)
//   - FIFO mode (non-DMA, polled via BUFFIFO register at 0x200)
//   - GPIO matrix routing for display coexistence
//   - `with_sd_card` pattern: save SPI2 routing → SDHOST → restore
//
// SD Native Protocol (not SPI mode):
//   CMD0   → GO_IDLE_STATE (no response)
//   CMD8   → SEND_IF_COND (R7 response)
//   CMD55  → APP_CMD prefix
//   ACMD41 → SD_SEND_OP_COND (R3 response)
//   CMD2   → ALL_SEND_CID (R2 long response)
//   CMD3   → SEND_RELATIVE_ADDR (R6 response)
//   CMD7   → SELECT_CARD (R1b response)
//   CMD16  → SET_BLOCKLEN (R1 response)
//   CMD17  → READ_SINGLE_BLOCK (R1 + data)
//   CMD24  → WRITE_BLOCK (R1 + data)
//   CMD18  → READ_MULTIPLE_BLOCK (R1 + data stream)
//   CMD25  → WRITE_MULTIPLE_BLOCK (R1 + data stream)
//   CMD12  → STOP_TRANSMISSION (R1b response)

//! The SD card, over the ESP32-S3's own SDHOST controller.
//!
//! Drives the peripheral directly, not through a HAL: card init, the CSD
//! read, single and multi-block transfers. Native SD, not SPI as on the M5.
//!
//! # The files
//!
//! Here: the waits, the card found at start-up, and the entry points the
//! unit calls. `regs`: the controller's registers and bits, the routing
//! signals, the GPIO and system addresses, the pins, and the raw register
//! and GPIO helpers. `routing`: the pins the card shares with the display,
//! handed over and back. `controller`: the controller's set-up, clock and
//! commands, and the card's start-up. `transfer`: single and multi-block
//! reads and writes.
//!
//! # The registers this does not touch
//!
//! The rest of the map (TRM chapter 34, GPIO and system registers), for
//! debugging:
//!
//! | register | address |
//! |---|---|
//! | SDHOST `MINTSTS` | `SDHOST_BASE + 0x040` |
//! | SDHOST `CDETECT`, `WRTPRT` | `+ 0x050`, `+ 0x054` |
//! | SDHOST `TCBCNT`, `TBBCNT` | `+ 0x05C`, `+ 0x060` |
//! | SDHOST `USRID`, `HCON`, `UHS` | `+ 0x068`, `+ 0x070`, `+ 0x074` |
//! | SDHOST `BMOD`, `PLDMND`, `DBADDR`, `IDSTS`, `IDINTEN` | `+ 0x080` to `+ 0x090` |
//! | SDHOST `CARDTHRCTL` | `+ 0x100` |
//! | GPIO `IN`, `IN1` | `0x6000_403C`, `0x6000_4040` |
//! | GPIO `ENABLE_W1TC`, `ENABLE1_W1TC` | `0x6000_4028`, `0x6000_4034` |
//! | SPI2 `CLOCK`, `USER` | `0x6002_400C`, `0x6002_4010` |
//! | SYSTEM `PERIP_CLK_EN0`, `PERIP_RST_EN0` | `0x600C_0018`, `0x600C_0020` |
//!
//! And two bits: `CMD` bit 14 is stop/abort, `RINTSTS` bits 4 and 5 are the
//! FIFO's transmit and receive data requests.

// `log!` needs no import: `lib.rs` declares it before this module.
use crate::systimer::SysTimer;
use kassigner_fat32::fat32::{csd_plausible, csd_sectors};
use kassigner_hal::card::Kind;
use kassigner_hal::timer::{Deadline, Timer};

mod controller;
mod regs;
mod routing;
mod transfer;

use controller::*;
use regs::*;
pub use routing::*;
pub use transfer::*;

// ═══════════════════════════════════════════════════════════════
// How long each wait is given
// ═══════════════════════════════════════════════════════════════
//
// Times on the system timer, each several times what the specification or
// the controller asks: a slow card that works keeps working, and one that
// stops answering is refused in that time.

/// The controller's own bits: a reset, a FIFO reset, a clock latched. A few
/// of its clocks; 100 ms.
const REG_US: u32 = 100_000;
/// A command's response: at most 64 card clocks, 160 µs at 400 kHz; 100 ms.
const CMD_US: u32 = 100_000;
/// A block's data, from the command or from the last word that moved: the
/// specification's longest read access, 100 ms, five times over.
const DATA_US: u32 = 500_000;
/// The card busy after a write: an SDXC card's 500 ms, twice.
const BUSY_US: u32 = 1_000_000;

/// Polls `done` for up to `us` microseconds; true if it said so in time.
fn within(us: u32, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Deadline::after(&SysTimer, us);
    loop {
        if done() {
            return true;
        }
        if deadline.expired(&SysTimer) {
            return false;
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// The card found at init
// ═══════════════════════════════════════════════════════════════

/// The card's RCA (Relative Card Address), assigned during init. Written at
/// init, read on the command path: an atomic at `Relaxed` costs nothing.
static CARD_RCA: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);

/// Card type found by the last full initialisation; `None` until one
/// answers. `static mut`: an atomic would need a `repr(u8)` on [`Kind`] and
/// byte conversions, code that makes nothing safer. Sound:
/// no interrupt handler touches SD (core 0's alarm and core 1's wake each
/// only lower their own interrupt), and core 1 runs only the rqrr decoder.
pub static mut BOOT_CARD_TYPE: Option<Kind> = None;

/// Sector count read from the CSD during init; zero if the read failed.
///
/// CMD9 is only legal in stand-by: after CMD3 assigns the RCA and before CMD7
/// selects the card. Later it returns RTO, so the value is kept from then.
static CARD_SECTORS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Sectors on the card, or zero if the CSD read failed: for
/// `BlockDevice::blocks`, where zero means unknown, not empty.
pub fn card_sectors() -> u32 {
    CARD_SECTORS.load(core::sync::atomic::Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════════
// Boot-time SD pin set-up (called from bring-up BEFORE the display)
// ═══════════════════════════════════════════════════════════════

/// Pre-SPI power-up. No PMU on this board: this sets the pin levels so the
/// card is not glitched into native mode before it is wanted.
pub fn sd_pre_init() {
    // D3 and CMD HIGH (idle), CLK low, before esp-hal claims GPIO38/39
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    gpio_clear(PIN_SCK);
}

/// Send 80+ clocks with CS(D3) HIGH, CMD HIGH — SD spec power-up requirement.
/// Uses bitbang since SDHOST isn't set up yet.
pub fn sd_power_up_clocks() {
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    for _ in 0..200u32 {
        gpio_clear(PIN_SCK);
        for _ in 0..50u32 {
            // SAFETY: a volatile read of a valid local, so the compiler
            // cannot remove the delay loop.
            unsafe {
                core::ptr::read_volatile(&0u32 as *const u32);
            }
        }
        gpio_set(PIN_SCK);
        for _ in 0..50u32 {
            // SAFETY: as above.
            unsafe {
                core::ptr::read_volatile(&0u32 as *const u32);
            }
        }
    }
    gpio_clear(PIN_SCK);
}

/// Card init with the display up: saves the display's routing, routes the
/// pins to SDHOST, initialises the card, and restores the routing.
///
/// Called by [`with_sd_card`] when no card is known, and by the hardware
/// test; not at bring-up, so no card is touched before the generator is
/// checked and the fuses judged.
pub fn init_sdhost(delay: &mut SysTimer) -> Result<Kind, &'static str> {
    log!("[SDHOST] Post-display SD init...");

    let saved = save_display_state();

    sdhost_enable_peripheral();
    route_pins_to_sdhost();

    let result = sdhost_init_card(delay);

    // While selected, the card drives D0 (GPIO40) to signal busy, which can
    // corrupt the ST7789T3's MADCTL while the display routing is restored.
    // CMD7(0) deselects (stand-by, D0 released) and keeps the RCA, so the
    // next `with_sd_card` re-selects with CMD13 + CMD7, not a full init.
    if result.is_ok() {
        let _ = sdhost_send_cmd(7, 0, CMD_RESP_EXPECT); // deselect

        // SAFETY: points SDHOST's data-in signal in the GPIO matrix at the
        // constant-low source, away from GPIO40; one routing register.
        unsafe {
            reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), 0xBC); // constant LOW
        }
    }

    restore_display_state(&saved);

    match result {
        Ok(ct) => {
            // SAFETY: `BOOT_CARD_TYPE` is only touched on the single-threaded
            // SD path (see its declaration).
            unsafe {
                BOOT_CARD_TYPE = Some(ct);
            }
            Ok(ct)
        }
        Err(e) => Err(e),
    }
}

// ═══════════════════════════════════════════════════════════════
// with_sd_card — main SD access pattern
// ═══════════════════════════════════════════════════════════════

/// Execute a closure with an active SD card connection.
///
/// Brings a card up if none is known, saves the display's routing, routes
/// the pins to SDHOST, re-selects the card (or initialises it again), runs
/// the closure, deselects the card and restores the display's routing.
pub fn with_sd_card<I2C, F, T>(
    _i2c: &mut I2C,
    delay: &mut SysTimer,
    f: F,
) -> Result<T, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
    F: FnOnce(Option<Kind>) -> Result<T, &'static str>,
{
    // No card known (the first job since boot, or none at the last look):
    // look again, since a card can go in at any time. `init_sdhost` routes
    // the pins to the card and back to the display itself, and records what
    // it found; the session below then re-selects that card.
    // SAFETY: a read of `BOOT_CARD_TYPE`, sound as its declaration says.
    if unsafe { BOOT_CARD_TYPE }.is_none() && init_sdhost(delay).is_err() {
        return Err("No SD card");
    }

    // Save display state
    let saved = save_display_state();

    // Route to SDHOST
    route_pins_to_sdhost();

    // Re-enable SDHOST peripheral clock
    // SAFETY: sets SDHOST's clock-enable bit in SYSTEM_PERIP_CLK_EN1,
    // read-modify-write so no other peripheral's bit changes.
    unsafe {
        reg_set_bits(SYSTEM_PERIP_CLK_EN1, SDHOST_CLK_EN_BIT);
    }

    // Full clock re-setup (CLKDIV, CLKSRC, CLKENA): the registers survive
    // the pin swap, but the CIU clock output stops when the pins go.
    let clk_ok = sdhost_set_clock(2); // 20MHz: 80/(2*2)

    // Give card time with clock running after reconnection
    delay.delay_ms(5);

    // Fast re-select via CMD13 + CMD7: the exits deselect with CMD7(0) but
    // keep the RCA, so a card in stand-by is selected in one command. Any
    // other answer, or none (a card swapped while the display had the pins,
    // a card that lost power), falls through to the full init.
    let t0 = SysTimer.now_us();
    let rca = CARD_RCA.load(core::sync::atomic::Ordering::Relaxed);
    let mut reselect_ok = false;
    if rca != 0 && clk_ok.is_ok() {
        // CMD13: SEND_STATUS; card state in bits 12:9 (3 stand-by, 4 transfer).
        if let Ok(status) =
            sdhost_send_cmd(13, (rca as u32) << 16, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)
        {
            let card_state = (status >> 9) & 0xF;
            if card_state == 3 {
                // Standby → select via CMD7
                if sdhost_send_cmd(7, (rca as u32) << 16, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)
                    .is_ok()
                {
                    let _ = sdhost_wait_not_busy();
                    reselect_ok = true;
                }
            } else if card_state == 4 {
                // Already in transfer — no CMD7 needed
                reselect_ok = true;
            }
        }
    }

    if !reselect_ok {
        // Re-select failed or no RCA — full re-init
        match sdhost_init_card(delay) {
            // SAFETY: a write of `BOOT_CARD_TYPE` on the single-threaded SD
            // path, sound as its declaration says.
            Ok(ct) => unsafe {
                BOOT_CARD_TYPE = Some(ct);
            },
            Err(e) => {
                restore_display_state(&saved);
                return Err(e);
            }
        }
    }
    log!(
        "[SD] card ready via {} in {} ms",
        if reselect_ok {
            "CMD13+CMD7 reselect"
        } else {
            "full init"
        },
        SysTimer.since(t0) / 1000
    );

    // Run the closure. No sound here: a caller that wants a tick while the
    // card is busy does it around `with_sd_card`.
    // SAFETY: a read of `BOOT_CARD_TYPE`, sound as its declaration says.
    let result = f(unsafe { BOOT_CARD_TYPE });

    // Deselect the card so it releases D0 before the display gets the pins
    // back (see `init_sdhost`); the RCA is kept for the next re-select.
    let _ = sdhost_send_cmd(7, 0, CMD_RESP_EXPECT); // CMD7 with RCA=0 → deselect

    // Disconnect SDHOST D0 input before restoring display
    // SAFETY: points SDHOST's data-in signal at the constant-low source
    // before the display takes the pins back; one routing register.
    unsafe {
        reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), 0xBC);
    }

    // Restore display
    restore_display_state(&saved);

    result
}

// ═══════════════════════════════════════════════════════════════
// Card capacity, and the FAT32 layer
// ═══════════════════════════════════════════════════════════════
//
// The capacity arithmetic, `csd_sectors` and `csd_plausible`, is
// `kassigner_fat32::fat32`'s, shared with the M5 unit. The block device
// trait, `kassigner_fat32::block::BlockDevice`, is implemented in
// `super::storage`, and FAT32 is `kassigner_fat32::fat32`: this module is
// block I/O only.
