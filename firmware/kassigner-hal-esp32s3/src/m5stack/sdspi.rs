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

//! The microSD card in SPI mode, bit-banged on the display's bus: the block
//! layer under `kassigner_fat32::fat32`, used inside
//! [`super::storage::with_card`].
//!
//! The socket is four-wire SPI on the ILI9342C's bus, and the card's MISO is
//! the display's D/C pin; there is no SDHOST wiring. Commands go at about
//! 100 kHz on the system timer, block data as fast as the GPIO registers
//! toggle. A read's wait for its data token and a write's wait for busy are
//! deadlines on the system timer, five and two times the SD specification's
//! longest, so a dead card does not hold the unit, and a write whose busy
//! never ends is [`SdError::BusyTimeout`], never reported as saved.
//!
//! CMD59 makes the card check the CRC of every command and written block;
//! this checks the CRC-16 after every block read and after the CSD. The data
//! clock is as fast as the pins toggle, on a bus the display shares, so a
//! bit can change on the wires; the CRCs turn that into a refused write
//! ([`SdError::WriteRejected`]) or read ([`SdError::DataCrc`]), never wrong
//! data.
//!
//! Register addresses are the ESP32-S3 manual's. The GPIO set and clear
//! registers are write-one-to-set and write-one-to-clear, so a write touches
//! only the bits it names.

use kassigner_hal::card::Kind;
use kassigner_hal::pins::m5stack as pins;
use kassigner_hal::timer::{Deadline, Timer};

use crate::systimer::SysTimer;

// ── Registers ───────────────────────────────────────────────────────────────

/// `GPIO_OUT_W1TS_REG`, GPIO0 to 31.
const GPIO_OUT_W1TS: u32 = 0x6000_4008;
/// `GPIO_OUT_W1TC_REG`.
const GPIO_OUT_W1TC: u32 = 0x6000_400C;
/// `GPIO_ENABLE_W1TS_REG`.
const GPIO_ENABLE_W1TS: u32 = 0x6000_4024;
/// `GPIO_ENABLE_W1TC_REG`.
const GPIO_ENABLE_W1TC: u32 = 0x6000_4028;
/// `GPIO_IN_REG`.
const GPIO_IN: u32 = 0x6000_403C;
/// `GPIO_OUT1_W1TS_REG`, GPIO32 to 48.
const GPIO_OUT1_W1TS: u32 = 0x6000_4014;
/// `GPIO_OUT1_W1TC_REG`.
const GPIO_OUT1_W1TC: u32 = 0x6000_4018;
/// `GPIO_ENABLE1_W1TS_REG`.
const GPIO_ENABLE1_W1TS: u32 = 0x6000_4030;
/// `GPIO_ENABLE1_W1TC_REG`.
const GPIO_ENABLE1_W1TC: u32 = 0x6000_4034;
/// `GPIO_IN1_REG`.
const GPIO_IN1: u32 = 0x6000_4040;
/// `GPIO_FUNC0_OUT_SEL_CFG_REG`.
const GPIO_FUNC_OUT_SEL_BASE: u32 = 0x6000_4554;
/// `GPIO_FUNC0_IN_SEL_CFG_REG`.
const GPIO_FUNC_IN_SEL_BASE: u32 = 0x6000_4154;
/// `IO_MUX_GPIO0_REG`.
const IO_MUX_BASE: u32 = 0x6000_9004;
/// `SPI_CLOCK_REG` of SPI2.
const SPI2_CLOCK: u32 = 0x6002_400C;
/// `SPI_USER_REG` of SPI2.
const SPI2_USER: u32 = 0x6002_4010;

/// `FSPIQ_IN`, SPI2's MISO input, in the matrix's signal table.
const FSPIQ_IN_SIGNAL: u32 = 102;
/// `FUNC_OUT_SEL` value that makes a pin a plain GPIO output.
const SIG_GPIO_OUT: u32 = 256;
/// IO MUX `FUN_IE`, the input buffer.
const FUN_IE: u32 = 1 << 9;
/// IO MUX `MCU_SEL` field.
const MCU_SEL_MASK: u32 = 0x7 << 12;
/// Function 1, GPIO.
const MCU_SEL_GPIO: u32 = 1 << 12;

// ── Pins, from the checked map ──────────────────────────────────────────────

/// Display chip select, held high while the card has the bus.
pub const PIN_LCD_CS: u8 = pins::DISPLAY[0].gpio;
/// Card chip select.
pub const PIN_SD_CS: u8 = pins::SD[0].gpio;
/// Card MISO, which is the display's D/C.
pub const PIN_MISO: u8 = pins::SD[1].gpio;
/// SPI clock.
pub const PIN_SCK: u8 = pins::SPI[0].gpio;
/// SPI MOSI.
pub const PIN_MOSI: u8 = pins::SPI[1].gpio;

/// A pin's bit in the `OUT1`, `ENABLE1` and `IN1` registers, GPIO32 upward,
/// where the fast paths' three bus pins all are.
pub const fn bank1_bit(pin: u8) -> u32 {
    1 << (pin - 32)
}

// ── Commands ────────────────────────────────────────────────────────────────

/// `GO_IDLE_STATE`.
const CMD0: u8 = 0;
/// `SEND_IF_COND`.
const CMD8: u8 = 8;
/// `SEND_CSD`.
const CMD9: u8 = 9;
/// `STOP_TRANSMISSION`.
const CMD12: u8 = 12;
/// `SET_BLOCKLEN`.
const CMD16: u8 = 16;
/// `READ_SINGLE_BLOCK`.
const CMD17: u8 = 17;
/// `READ_MULTIPLE_BLOCK`.
const CMD18: u8 = 18;
/// `WRITE_BLOCK`.
const CMD24: u8 = 24;
/// `WRITE_MULTIPLE_BLOCK`.
const CMD25: u8 = 25;
/// `APP_CMD`.
const CMD55: u8 = 55;
/// `READ_OCR`.
const CMD58: u8 = 58;
/// `CRC_ON_OFF`.
const CMD59: u8 = 59;
/// `SD_SEND_OP_COND`.
const ACMD41: u8 = 41;

/// Half a command-phase clock period, in microseconds.
const HALF_PERIOD_US: u32 = 5;
/// How long a read waits for its data token, in microseconds: five times the
/// SD specification's longest read access, 100 ms.
const TOKEN_US: u32 = 500_000;
/// How long a write waits for the card's busy to end, in microseconds: twice
/// the specification's longest, 500 ms (SDXC).
const BUSY_US: u32 = 1_000_000;
/// How long the busy after a multi-block read's stop is waited out, in
/// microseconds.
const STOP_US: u32 = 500_000;

/// Why a card operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdError {
    /// The card slot's rail would not switch.
    Power,
    /// No card entered the idle state on CMD0: none fitted, or not answering.
    NoCard,
    /// CMD8 came back with a different voltage or check pattern.
    VoltageMismatch,
    /// ACMD41 never reported the card ready.
    InitTimeout,
    /// A command answered with an error.
    Command { cmd: u8, r1: u8 },
    /// A data transfer began with an error token.
    ErrorToken(u8),
    /// No data token arrived within `TOKEN_US`.
    TokenTimeout,
    /// The card refused a written block: its data response, low five bits
    /// `0x0B` for a bad CRC.
    WriteRejected(u8),
    /// The card stayed busy past `BUSY_US` after a written block, or past
    /// `STOP_US` after a multi-block read was stopped.
    BusyTimeout,
    /// A block number too large for a byte-addressed card.
    Address,
    /// A block read whose CRC-16 did not match the one sent with it.
    DataCrc,
}

// ── GPIO ────────────────────────────────────────────────────────────────────

fn write(addr: u32, val: u32) {
    // SAFETY: a volatile store to a GPIO, IO MUX or SPI2 register; every
    // caller in this file passes an address from the constants above.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

fn read(addr: u32) -> u32 {
    // SAFETY: a volatile load of a register as in `write`.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn gpio_set(pin: u8) {
    if pin < 32 {
        write(GPIO_OUT_W1TS, 1 << pin);
    } else {
        write(GPIO_OUT1_W1TS, bank1_bit(pin));
    }
}

fn gpio_clear(pin: u8) {
    if pin < 32 {
        write(GPIO_OUT_W1TC, 1 << pin);
    } else {
        write(GPIO_OUT1_W1TC, bank1_bit(pin));
    }
}

fn gpio_read(pin: u8) -> bool {
    if pin < 32 {
        (read(GPIO_IN) >> pin) & 1 != 0
    } else {
        read(GPIO_IN1) & bank1_bit(pin) != 0
    }
}

fn gpio_enable_output(pin: u8) {
    if pin < 32 {
        write(GPIO_ENABLE_W1TS, 1 << pin);
    } else {
        write(GPIO_ENABLE1_W1TS, bank1_bit(pin));
    }
}

fn gpio_disable_output(pin: u8) {
    if pin < 32 {
        write(GPIO_ENABLE_W1TC, 1 << pin);
    } else {
        write(GPIO_ENABLE1_W1TC, bank1_bit(pin));
    }
}

const fn iomux_addr(pin: u8) -> u32 {
    IO_MUX_BASE + pin as u32 * 4
}

const fn func_out_sel_addr(pin: u8) -> u32 {
    GPIO_FUNC_OUT_SEL_BASE + pin as u32 * 4
}

const fn func_in_sel_addr(signal: u32) -> u32 {
    GPIO_FUNC_IN_SEL_BASE + signal * 4
}

/// Put a pin on function 1, a plain GPIO, keeping its other IO MUX fields.
fn iomux_gpio(pin: u8) {
    let v = read(iomux_addr(pin));
    write(iomux_addr(pin), (v & !MCU_SEL_MASK) | MCU_SEL_GPIO);
}

/// As [`iomux_gpio`], with the input buffer on.
fn iomux_gpio_input(pin: u8) {
    let v = read(iomux_addr(pin));
    write(
        iomux_addr(pin),
        ((v | FUN_IE) & !MCU_SEL_MASK) | MCU_SEL_GPIO,
    );
}

// ── Bit-banged SPI ──────────────────────────────────────────────────────────

fn half_period() {
    SysTimer.delay_us(HALF_PERIOD_US);
}

/// One byte, full duplex, SPI mode 0, at command speed.
fn transfer(tx: u8) -> u8 {
    let mut rx = 0u8;
    for bit in (0..8).rev() {
        if (tx >> bit) & 1 == 1 {
            gpio_set(PIN_MOSI);
        } else {
            gpio_clear(PIN_MOSI);
        }
        gpio_clear(PIN_SCK);
        half_period();
        gpio_set(PIN_SCK);
        half_period();
        if gpio_read(PIN_MISO) {
            rx |= 1 << bit;
        }
    }
    rx
}

/// The SD command CRC-7, polynomial `x^7 + x^3 + 1`, with the end bit.
/// `command` sends it for every command but CMD0 and CMD8, whose known
/// constants this reproduces.
pub fn crc7(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        let mut d = byte;
        for _ in 0..8 {
            crc <<= 1;
            if (d ^ crc) & 0x80 != 0 {
                crc ^= 0x09;
            }
            d <<= 1;
        }
    }
    (crc << 1) | 1
}

/// The SD data CRC-16: polynomial `x^16 + x^12 + x^5 + 1`, from zero, sent
/// after every data block, read or written.
pub fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |crc, &b| {
        (crc << 8) ^ CRC16_TABLE[usize::from((crc >> 8) as u8 ^ b)]
    })
}

/// [`crc16`] a byte at a time: the CRC of each byte value shifted in from
/// zero, 512 bytes made at compile time.
const CRC16_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 0x8000 != 0 {
                (c << 1) ^ 0x1021
            } else {
                c << 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// The two CRC bytes that follow a data block, as the card sent them.
fn crc_in() -> u16 {
    let hi = transfer(0xFF);
    let lo = transfer(0xFF);
    u16::from_be_bytes([hi, lo])
}

/// A block's CRC-16, after the block.
fn crc_out(data: &[u8]) {
    let [hi, lo] = crc16(data).to_be_bytes();
    transfer(hi);
    transfer(lo);
}

/// Send a command and return its R1 byte, `0xFF` if none came.
fn command(cmd: u8, arg: u32) -> u8 {
    let frame = [
        0x40 | cmd,
        (arg >> 24) as u8,
        (arg >> 16) as u8,
        (arg >> 8) as u8,
        arg as u8,
    ];
    let crc = if cmd == CMD0 {
        0x95
    } else if cmd == CMD8 {
        0x87
    } else {
        crc7(&frame)
    };

    transfer(0xFF);
    for &b in &frame {
        transfer(b);
    }
    transfer(crc);

    for _ in 0..64 {
        let r = transfer(0xFF);
        if r & 0x80 == 0 {
            return r;
        }
    }
    0xFF
}

/// An application command: CMD55, then `cmd`.
fn app_command(cmd: u8, arg: u32) -> u8 {
    command(CMD55, 0);
    command(cmd, arg)
}

/// Wait for a data token. Leaves chip select alone: on failure a
/// single-block read deselects, a multi-block read stops the stream first.
fn wait_token() -> Result<(), SdError> {
    let deadline = Deadline::after(&SysTimer, TOKEN_US);
    loop {
        let token = transfer(0xFF);
        if token == 0xFE {
            return Ok(());
        }
        if token != 0xFF {
            return Err(SdError::ErrorToken(token));
        }
        if deadline.expired(&SysTimer) {
            return Err(SdError::TokenTimeout);
        }
    }
}

/// Select the card and send a command that must answer zero; deselect on
/// failure.
fn select_and_command(cmd: u8, arg: u32) -> Result<(), SdError> {
    gpio_clear(PIN_SD_CS);
    half_period();
    let r1 = command(cmd, arg);
    if r1 != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err(SdError::Command { cmd, r1 });
    }
    Ok(())
}

// ── Taking the bus ──────────────────────────────────────────────────────────

/// Configure the four card pins for bit-banging: chip select out and high,
/// clock out and low, MOSI out and high, MISO in.
pub(crate) fn claim_pins() {
    iomux_gpio(PIN_SD_CS);
    write(func_out_sel_addr(PIN_SD_CS), SIG_GPIO_OUT);
    gpio_enable_output(PIN_SD_CS);
    gpio_set(PIN_SD_CS);

    iomux_gpio(PIN_SCK);
    write(func_out_sel_addr(PIN_SCK), SIG_GPIO_OUT);
    gpio_enable_output(PIN_SCK);
    gpio_clear(PIN_SCK);

    iomux_gpio(PIN_MOSI);
    write(func_out_sel_addr(PIN_MOSI), SIG_GPIO_OUT);
    gpio_enable_output(PIN_MOSI);
    gpio_set(PIN_MOSI);

    gpio_disable_output(PIN_MISO);
    iomux_gpio_input(PIN_MISO);
}

/// The display bus as it was before the card took it.
pub(crate) struct SavedBus {
    out_sck: u32,
    out_mosi: u32,
    out_miso: u32,
    in_fspiq: u32,
    spi2_clock: u32,
    spi2_user: u32,
    iomux_miso: u32,
    iomux_sck: u32,
    iomux_mosi: u32,
}

/// Save the display's routing and SPI2 state, then take the pins. SPI2's
/// clock and user registers and the MISO input select are not written while
/// the card has the bus, but are restored anyway, in case code above draws
/// inside a session.
pub(crate) fn save_and_reclaim() -> SavedBus {
    let saved = SavedBus {
        out_sck: read(func_out_sel_addr(PIN_SCK)),
        out_mosi: read(func_out_sel_addr(PIN_MOSI)),
        out_miso: read(func_out_sel_addr(PIN_MISO)),
        in_fspiq: read(func_in_sel_addr(FSPIQ_IN_SIGNAL)),
        spi2_clock: read(SPI2_CLOCK),
        spi2_user: read(SPI2_USER),
        iomux_miso: read(iomux_addr(PIN_MISO)),
        iomux_sck: read(iomux_addr(PIN_SCK)),
        iomux_mosi: read(iomux_addr(PIN_MOSI)),
    };

    iomux_gpio(PIN_SCK);
    write(func_out_sel_addr(PIN_SCK), SIG_GPIO_OUT);
    gpio_enable_output(PIN_SCK);
    gpio_clear(PIN_SCK);

    iomux_gpio(PIN_MOSI);
    write(func_out_sel_addr(PIN_MOSI), SIG_GPIO_OUT);
    gpio_enable_output(PIN_MOSI);
    gpio_set(PIN_MOSI);

    gpio_disable_output(PIN_MISO);
    write(func_out_sel_addr(PIN_MISO), SIG_GPIO_OUT);
    iomux_gpio_input(PIN_MISO);

    gpio_set(PIN_SD_CS);
    gpio_set(PIN_LCD_CS);

    saved
}

/// Give the pins back to SPI2 and the display.
pub(crate) fn restore(saved: &SavedBus) {
    write(func_out_sel_addr(PIN_SCK), saved.out_sck);
    write(func_out_sel_addr(PIN_MOSI), saved.out_mosi);
    write(func_out_sel_addr(PIN_MISO), saved.out_miso);
    write(func_in_sel_addr(FSPIQ_IN_SIGNAL), saved.in_fspiq);
    // MISO goes back to being the display's D/C, an output.
    gpio_enable_output(PIN_MISO);
    write(SPI2_CLOCK, saved.spi2_clock);
    write(SPI2_USER, saved.spi2_user);
    write(iomux_addr(PIN_MISO), saved.iomux_miso);
    write(iomux_addr(PIN_SCK), saved.iomux_sck);
    write(iomux_addr(PIN_MOSI), saved.iomux_mosi);
}

/// Before the card slot's rail drops: every card line high, then released,
/// so the card is not powered through its inputs.
pub(crate) fn float_pins() {
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    gpio_set(PIN_SCK);
    gpio_disable_output(PIN_SCK);
    gpio_disable_output(PIN_MOSI);
    gpio_disable_output(PIN_SD_CS);
}

/// Deselect the card.
pub(crate) fn deselect() {
    gpio_set(PIN_SD_CS);
}

// ── Card initialisation ─────────────────────────────────────────────────────

/// Bring a freshly powered card into SPI mode and identify it. The pins
/// must already be claimed (`claim_pins`).
///
/// # Errors
///
/// `NoCard`, `VoltageMismatch`, `InitTimeout` or `Command` (CMD59 included:
/// a card that will not check CRCs), for the step that failed.
pub(crate) fn init() -> Result<Kind, SdError> {
    let mut timer = SysTimer;

    // Power-up: at least 74 clocks with chip select and MOSI high.
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    for _ in 0..100 {
        gpio_clear(PIN_SCK);
        half_period();
        gpio_set(PIN_SCK);
        half_period();
    }

    gpio_clear(PIN_SD_CS);
    half_period();
    half_period();

    let mut r1 = 0xFF;
    for _ in 0..10 {
        r1 = command(CMD0, 0);
        if r1 == 0x01 {
            break;
        }
        timer.delay_ms(10);
    }
    if r1 != 0x01 {
        gpio_set(PIN_SD_CS);
        return Err(SdError::NoCard);
    }

    let v2 = if command(CMD8, 0x0000_01AA) == 0x01 {
        let mut r7 = [0u8; 4];
        for b in r7.iter_mut() {
            *b = transfer(0xFF);
        }
        if r7[2] != 0x01 || r7[3] != 0xAA {
            gpio_set(PIN_SD_CS);
            return Err(SdError::VoltageMismatch);
        }
        true
    } else {
        false
    };

    let hcs = if v2 { 1u32 << 30 } else { 0 };
    let mut ready = false;
    for _ in 0..1000 {
        let r = app_command(ACMD41, hcs);
        if r == 0x00 {
            ready = true;
            break;
        }
        if r != 0x01 {
            break;
        }
        timer.delay_ms(1);
    }
    if !ready {
        gpio_set(PIN_SD_CS);
        return Err(SdError::InitTimeout);
    }

    // CRC checking on from here (see the module doc); every card supports
    // it in SPI mode.
    let r = command(CMD59, 1);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err(SdError::Command { cmd: CMD59, r1: r });
    }

    let card = if v2 {
        let r = command(CMD58, 0);
        if r != 0x00 {
            gpio_set(PIN_SD_CS);
            return Err(SdError::Command { cmd: CMD58, r1: r });
        }
        let mut ocr = [0u8; 4];
        for b in ocr.iter_mut() {
            *b = transfer(0xFF);
        }
        if (ocr[0] >> 6) & 1 == 1 {
            Kind::SdV2High
        } else {
            Kind::SdV2Standard
        }
    } else {
        Kind::SdV1
    };

    // A refusal is ignored: 512 is every card's default.
    if card != Kind::SdV2High {
        let _ = command(CMD16, 512);
    }

    gpio_set(PIN_SD_CS);
    for _ in 0..8 {
        gpio_clear(PIN_SCK);
        half_period();
        gpio_set(PIN_SCK);
        half_period();
    }

    Ok(card)
}

// ── Blocks ──────────────────────────────────────────────────────────────────

/// The command argument for a block: its index on a block-addressed card, its
/// byte offset otherwise.
///
/// # Errors
///
/// `Address` when the byte offset does not fit 32 bits.
pub fn block_addr(card: Kind, block: u32) -> Result<u32, SdError> {
    match card {
        Kind::SdV2High => Ok(block),
        _ => block.checked_mul(512).ok_or(SdError::Address),
    }
}

/// Clock in one block's bytes as fast as the pins toggle. MOSI stays high.
fn fast_read(buf: &mut [u8]) {
    let sck_set = GPIO_OUT1_W1TS as *mut u32;
    let sck_clr = GPIO_OUT1_W1TC as *mut u32;
    let sck_bit = bank1_bit(PIN_SCK);
    let miso_in = GPIO_IN1 as *const u32;
    let miso_bit = bank1_bit(PIN_MISO);

    // The eight bits unrolled, so the loop body is one straight line.
    macro_rules! bit {
        ($rx:ident, $mask:expr) => {
            // SAFETY: two write-one-to-set/clear stores to `GPIO_OUT1` and one
            // load of `GPIO_IN1`, addresses from the constants above.
            unsafe {
                core::ptr::write_volatile(sck_clr, sck_bit);
                core::ptr::write_volatile(sck_set, sck_bit);
                if core::ptr::read_volatile(miso_in) & miso_bit != 0 {
                    $rx |= $mask;
                }
            }
        };
    }

    for byte in buf.iter_mut() {
        let mut rx = 0u8;
        bit!(rx, 0x80);
        bit!(rx, 0x40);
        bit!(rx, 0x20);
        bit!(rx, 0x10);
        bit!(rx, 0x08);
        bit!(rx, 0x04);
        bit!(rx, 0x02);
        bit!(rx, 0x01);
        *byte = rx;
    }
}

/// Clock out one block's bytes as fast as the pins toggle, then leave MOSI
/// high.
fn fast_write(buf: &[u8]) {
    // Both pins are in bank 1, so one pair of registers drives them.
    let set = GPIO_OUT1_W1TS as *mut u32;
    let clr = GPIO_OUT1_W1TC as *mut u32;
    let sck_bit = bank1_bit(PIN_SCK);
    let mosi_bit = bank1_bit(PIN_MOSI);

    for &tx in buf {
        for bit in (0..8).rev() {
            // SAFETY: write-one-to-set/clear stores to `GPIO_OUT1`.
            unsafe {
                if (tx >> bit) & 1 == 1 {
                    core::ptr::write_volatile(set, mosi_bit);
                } else {
                    core::ptr::write_volatile(clr, mosi_bit);
                }
                core::ptr::write_volatile(clr, sck_bit);
                core::ptr::write_volatile(set, sck_bit);
            }
        }
    }
    gpio_set(PIN_MOSI);
}

/// Read one block.
///
/// # Errors
///
/// `Address`, `Command`, `ErrorToken`, `TokenTimeout` or `DataCrc`.
pub(crate) fn read_block(card: Kind, block: u32, buf: &mut [u8; 512]) -> Result<(), SdError> {
    let addr = block_addr(card, block)?;
    select_and_command(CMD17, addr)?;
    if let Err(e) = wait_token() {
        gpio_set(PIN_SD_CS);
        return Err(e);
    }
    fast_read(buf);
    let crc = crc_in();
    gpio_set(PIN_SD_CS);
    transfer(0xFF);
    if crc != crc16(buf) {
        return Err(SdError::DataCrc);
    }
    Ok(())
}

/// Write one block.
///
/// # Errors
///
/// `Address`, `Command`, `WriteRejected` or `BusyTimeout`.
pub(crate) fn write_block(card: Kind, block: u32, buf: &[u8; 512]) -> Result<(), SdError> {
    let addr = block_addr(card, block)?;
    select_and_command(CMD24, addr)?;

    transfer(0xFF);
    transfer(0xFE);
    fast_write(buf);
    crc_out(buf);

    let resp = transfer(0xFF);
    if resp & 0x1F != 0x05 {
        gpio_set(PIN_SD_CS);
        return Err(SdError::WriteRejected(resp));
    }

    if wait_not_busy() {
        gpio_set(PIN_SD_CS);
        transfer(0xFF);
        return Ok(());
    }

    gpio_set(PIN_SD_CS);
    Err(SdError::BusyTimeout)
}

/// Read consecutive blocks into `out`, whose length is a whole number of
/// blocks.
///
/// # Errors
///
/// As [`read_block`], and `BusyTimeout` if the card stays busy after the
/// stop command.
pub(crate) fn read_blocks(card: Kind, block: u32, out: &mut [u8]) -> Result<(), SdError> {
    if out.len() == 512 {
        let one: &mut [u8; 512] = out.try_into().map_err(|_| SdError::Address)?;
        return read_block(card, block, one);
    }

    let addr = block_addr(card, block)?;
    select_and_command(CMD18, addr)?;

    for chunk in out.chunks_exact_mut(512) {
        if let Err(e) = wait_token() {
            // Stop the stream, then deselect.
            command(CMD12, 0);
            transfer(0xFF);
            gpio_set(PIN_SD_CS);
            return Err(e);
        }
        fast_read(chunk);
        if crc_in() != crc16(chunk) {
            // Stop the stream, then deselect, as for a missing token.
            command(CMD12, 0);
            transfer(0xFF);
            gpio_set(PIN_SD_CS);
            return Err(SdError::DataCrc);
        }
    }

    command(CMD12, 0);
    // The stuff byte, then the busy period. A card still busy at the limit
    // has not stopped: the blocks are in hand and checked, but the card is
    // not in a state to take the next command, and the read says so.
    transfer(0xFF);
    let deadline = Deadline::after(&SysTimer, STOP_US);
    let mut stopped = true;
    while transfer(0xFF) == 0x00 {
        if deadline.expired(&SysTimer) {
            stopped = false;
            break;
        }
    }

    gpio_set(PIN_SD_CS);
    transfer(0xFF);
    if stopped {
        Ok(())
    } else {
        Err(SdError::BusyTimeout)
    }
}

/// Write consecutive blocks from `data`, whose length is a whole number of
/// blocks.
///
/// # Errors
///
/// `Address`, `Command`, `WriteRejected`, or `BusyTimeout` if the card stays
/// busy after a block or after the stop token.
pub(crate) fn write_blocks(card: Kind, block: u32, data: &[u8]) -> Result<(), SdError> {
    if data.len() == 512 {
        let one: &[u8; 512] = data.try_into().map_err(|_| SdError::Address)?;
        return write_block(card, block, one);
    }

    let addr = block_addr(card, block)?;
    select_and_command(CMD25, addr)?;

    for chunk in data.chunks_exact(512) {
        // Multi-block writes use `0xFC` as the start token.
        transfer(0xFF);
        transfer(0xFC);
        fast_write(chunk);
        crc_out(chunk);

        let resp = transfer(0xFF);
        if resp & 0x1F != 0x05 {
            // The stop token.
            transfer(0xFF);
            transfer(0xFD);
            transfer(0xFF);
            gpio_set(PIN_SD_CS);
            return Err(SdError::WriteRejected(resp));
        }

        if !wait_not_busy() {
            // Stop the stream before giving up, as for a rejected block.
            transfer(0xFF);
            transfer(0xFD);
            transfer(0xFF);
            gpio_set(PIN_SD_CS);
            return Err(SdError::BusyTimeout);
        }
    }

    transfer(0xFF);
    transfer(0xFD);
    transfer(0xFF);
    if !wait_not_busy() {
        gpio_set(PIN_SD_CS);
        return Err(SdError::BusyTimeout);
    }

    gpio_set(PIN_SD_CS);
    transfer(0xFF);
    Ok(())
}

/// Poll until the card releases MISO from busy. `false` if it never does
/// within `BUSY_US`.
fn wait_not_busy() -> bool {
    let deadline = Deadline::after(&SysTimer, BUSY_US);
    loop {
        if transfer(0xFF) != 0x00 {
            return true;
        }
        if deadline.expired(&SysTimer) {
            return false;
        }
    }
}

/// The card's CSD register.
///
/// CMD9 takes no address in SPI mode. The card's size is asked, not probed:
/// a read past the end leaves a card in an error state where writes are
/// acknowledged and discarded.
///
/// # Errors
///
/// `Command`, `ErrorToken`, `TokenTimeout` or `DataCrc`.
pub(crate) fn read_csd() -> Result<[u8; 16], SdError> {
    select_and_command(CMD9, 0)?;
    if let Err(e) = wait_token() {
        gpio_set(PIN_SD_CS);
        return Err(e);
    }
    let mut csd = [0u8; 16];
    for b in csd.iter_mut() {
        *b = transfer(0xFF);
    }
    let crc = crc_in();
    gpio_set(PIN_SD_CS);
    transfer(0xFF);
    if crc != crc16(&csd) {
        return Err(SdError::DataCrc);
    }
    Ok(csd)
}
