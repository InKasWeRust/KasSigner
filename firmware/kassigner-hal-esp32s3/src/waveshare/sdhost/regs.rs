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

//! The SDHOST controller's registers and bits, the GPIO matrix signals it
//! is routed by, the GPIO, IO_MUX and system registers, the pins, and the
//! raw register and GPIO helpers the rest of the driver writes through.

// ═══════════════════════════════════════════════════════════════
// SDHOST Controller Registers (base 0x60028000, TRM Ch.34)
// ═══════════════════════════════════════════════════════════════

const SDHOST_BASE: u32 = 0x6002_8000;

pub(super) const SDHOST_CTRL: u32 = SDHOST_BASE; // + 0x000
pub(super) const SDHOST_CLKDIV: u32 = SDHOST_BASE + 0x008;
pub(super) const SDHOST_CLKSRC: u32 = SDHOST_BASE + 0x00C;
pub(super) const SDHOST_CLKENA: u32 = SDHOST_BASE + 0x010;
pub(super) const SDHOST_TMOUT: u32 = SDHOST_BASE + 0x014;
pub(super) const SDHOST_CTYPE: u32 = SDHOST_BASE + 0x018;
pub(super) const SDHOST_BLKSIZ: u32 = SDHOST_BASE + 0x01C;
pub(super) const SDHOST_BYTCNT: u32 = SDHOST_BASE + 0x020;
pub(super) const SDHOST_INTMASK: u32 = SDHOST_BASE + 0x024;
pub(super) const SDHOST_CMDARG: u32 = SDHOST_BASE + 0x028;
pub(super) const SDHOST_CMD: u32 = SDHOST_BASE + 0x02C;
pub(super) const SDHOST_RESP0: u32 = SDHOST_BASE + 0x030;
pub(super) const SDHOST_RESP1: u32 = SDHOST_BASE + 0x034;
pub(super) const SDHOST_RESP2: u32 = SDHOST_BASE + 0x038;
pub(super) const SDHOST_RESP3: u32 = SDHOST_BASE + 0x03C;
pub(super) const SDHOST_RINTSTS: u32 = SDHOST_BASE + 0x044;
pub(super) const SDHOST_STATUS: u32 = SDHOST_BASE + 0x048;
pub(super) const SDHOST_FIFOTH: u32 = SDHOST_BASE + 0x04C;
pub(super) const SDHOST_DEBNCE: u32 = SDHOST_BASE + 0x064;
pub(super) const SDHOST_VERID: u32 = SDHOST_BASE + 0x06C;
pub(super) const SDHOST_RST_N: u32 = SDHOST_BASE + 0x078;
pub(super) const SDHOST_BUFFIFO: u32 = SDHOST_BASE + 0x200;
pub(super) const SDHOST_CLK_EDGE: u32 = SDHOST_BASE + 0x800;

// CMD register bits (TRM 34.13, Register 34.11)
pub(super) const CMD_START: u32 = 1 << 31;
pub(super) const CMD_USE_HOLE: u32 = 1 << 29; // use hold register (default=1)
pub(super) const CMD_UPDATE_CLK_ONLY: u32 = 1 << 21;
pub(super) const CMD_SEND_INIT: u32 = 1 << 15;
pub(super) const CMD_WAIT_PRVDATA: u32 = 1 << 13;
pub(super) const CMD_SEND_AUTO_STOP: u32 = 1 << 12;
pub(super) const CMD_WRITE: u32 = 1 << 10;
pub(super) const CMD_DATA_EXPECTED: u32 = 1 << 9;
pub(super) const CMD_CHECK_RESP_CRC: u32 = 1 << 8;
pub(super) const CMD_RESP_LONG: u32 = 1 << 7;
pub(super) const CMD_RESP_EXPECT: u32 = 1 << 6;

// CTRL register bits
pub(super) const CTRL_FIFO_RESET: u32 = 1 << 1;
pub(super) const CTRL_CONTROLLER_RESET: u32 = 1 << 0;
pub(super) const CTRL_INT_ENABLE: u32 = 1 << 4;

// RINTSTS interrupt bits
pub(super) const INT_CD: u32 = 1 << 2; // Command Done
pub(super) const INT_DTO: u32 = 1 << 3; // Data Transfer Over
pub(super) const INT_RCRC: u32 = 1 << 6; // Response CRC Error
const INT_DCRC: u32 = 1 << 7; // Data CRC Error
pub(super) const INT_RTO: u32 = 1 << 8; // Response Timeout
const INT_DRTO: u32 = 1 << 9; // Data Read Timeout
const INT_HTO: u32 = 1 << 10; // Data Starvation by Host Timeout
const INT_FRUN: u32 = 1 << 11; // FIFO underrun/overrun
pub(super) const INT_HLE: u32 = 1 << 12; // Hardware Locked write Error
const INT_SBE: u32 = 1 << 13; // Start Bit Error
const INT_EBE: u32 = 1 << 15; // End Bit Error

pub(super) const INT_ALL_ERRORS: u32 =
    INT_RCRC | INT_DCRC | INT_RTO | INT_DRTO | INT_HTO | INT_FRUN | INT_HLE | INT_SBE | INT_EBE;

// STATUS register bits
pub(super) const STATUS_FIFO_FULL: u32 = 1 << 3;
pub(super) const STATUS_FIFO_EMPTY: u32 = 1 << 2;
pub(super) const STATUS_DATA_BUSY: u32 = 1 << 9;

// ═══════════════════════════════════════════════════════════════
// GPIO Matrix Signal Numbers for SDHOST Card1 (TRM Table 6-2)
// ═══════════════════════════════════════════════════════════════

pub(super) const SDHOST_CCLK_OUT_1: u32 = 172; // output: clock
pub(super) const SDHOST_CCMD_IN_1: u32 = 178; // input: command response
pub(super) const SDHOST_CCMD_OUT_1: u32 = 178; // output: command (same signal, bidirectional)
pub(super) const SDHOST_CDATA_IN_10: u32 = 180; // input: data[0] from card
pub(super) const SDHOST_CDATA_OUT_10: u32 = 180; // output: data[0] to card
pub(super) const SDHOST_CARD_DETECT_1: u32 = 194; // input: card detect (active low)

// ═══════════════════════════════════════════════════════════════
// GPIO / IO_MUX / System Registers
// ═══════════════════════════════════════════════════════════════

const GPIO_OUT_W1TS: u32 = 0x6000_4008;
const GPIO_OUT_W1TC: u32 = 0x6000_400C;
const GPIO_ENABLE_W1TS: u32 = 0x6000_4024;
const GPIO_OUT1_W1TS: u32 = 0x6000_4014;
const GPIO_OUT1_W1TC: u32 = 0x6000_4018;
const GPIO_ENABLE1_W1TS: u32 = 0x6000_4030;
const GPIO_FUNC_OUT_SEL_BASE: u32 = 0x6000_4554;
const GPIO_FUNC_IN_SEL_BASE: u32 = 0x6000_4154;
const IO_MUX_BASE: u32 = 0x6000_9004;

// FSPIQ input signal (SPI2 MISO — must disconnect from GPIO40)
pub(super) const FSPIQ_IN_SIGNAL: u32 = 102;

// System peripheral clock/reset
pub(super) const SYSTEM_PERIP_CLK_EN1: u32 = 0x600C_001C;
pub(super) const SYSTEM_PERIP_RST_EN1: u32 = 0x600C_0024;

// SDHOST clock is bit 7 of CLK_EN1/RST_EN1
pub(super) const SDHOST_CLK_EN_BIT: u32 = 1 << 7;

// GPIO pin numbers (Waveshare ESP32-S3-Touch-LCD-2)
pub(super) const PIN_LCD_CS: u8 = 45;
pub(super) const PIN_SD_CS: u8 = 41; // D3 in SD mode — used as card-select by SDHOST
pub(super) const PIN_MISO: u8 = 40; // D0 in SD mode
pub(super) const PIN_SCK: u8 = 39; // CLK in SD mode
pub(super) const PIN_MOSI: u8 = 38; // CMD in SD mode

// ═══════════════════════════════════════════════════════════════
// Low-level register helpers
// ═══════════════════════════════════════════════════════════════

#[inline(always)]
pub(super) unsafe fn reg_write(addr: u32, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
pub(super) unsafe fn reg_read(addr: u32) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

#[inline(always)]
pub(super) unsafe fn reg_set_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v | bits);
}

#[inline(always)]
pub(super) unsafe fn reg_clear_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v & !bits);
}

// ═══════════════════════════════════════════════════════════════
// GPIO helpers
// ═══════════════════════════════════════════════════════════════

#[inline(always)]
pub(super) fn gpio_set(pin: u8) {
    // SAFETY: writes the GPIO output set registers (W1TS), which set only
    // this pin's bit. The SD path is single-threaded (see `BOOT_CARD_TYPE`).
    unsafe {
        if pin < 32 {
            reg_write(GPIO_OUT_W1TS, 1u32 << pin);
        } else {
            reg_write(GPIO_OUT1_W1TS, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
pub(super) fn gpio_clear(pin: u8) {
    // SAFETY: writes the GPIO output clear registers (W1TC), which clear only
    // this pin's bit; single-threaded as `gpio_set` says.
    unsafe {
        if pin < 32 {
            reg_write(GPIO_OUT_W1TC, 1u32 << pin);
        } else {
            reg_write(GPIO_OUT1_W1TC, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
pub(super) fn gpio_enable_output(pin: u8) {
    // SAFETY: writes the GPIO output-enable set registers (W1TS), which set
    // only this pin's bit; single-threaded as `gpio_set` says.
    unsafe {
        if pin < 32 {
            reg_write(GPIO_ENABLE_W1TS, 1u32 << pin);
        } else {
            reg_write(GPIO_ENABLE1_W1TS, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
pub(super) fn iomux_addr(pin: u8) -> u32 {
    IO_MUX_BASE + (pin as u32) * 4
}

#[inline(always)]
pub(super) fn func_out_sel_addr(pin: u8) -> u32 {
    GPIO_FUNC_OUT_SEL_BASE + (pin as u32) * 4
}

#[inline(always)]
pub(super) fn func_in_sel_addr(signal: u32) -> u32 {
    GPIO_FUNC_IN_SEL_BASE + signal * 4
}
