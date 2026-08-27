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

// hw/sdcard.rs — MicroSD card driver (SDHOST controller + FAT32 + LFN)
// 100% Rust, no-std, no-alloc
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

use crate::log;
use esp_hal::delay::Delay;

// ═══════════════════════════════════════════════════════════════
// SDHOST Controller Registers (base 0x60028000, TRM Ch.34)
// ═══════════════════════════════════════════════════════════════

const SDHOST_BASE: u32 = 0x6002_8000;

const SDHOST_CTRL:       u32 = SDHOST_BASE + 0x000;
const SDHOST_CLKDIV:     u32 = SDHOST_BASE + 0x008;
const SDHOST_CLKSRC:     u32 = SDHOST_BASE + 0x00C;
const SDHOST_CLKENA:     u32 = SDHOST_BASE + 0x010;
const SDHOST_TMOUT:      u32 = SDHOST_BASE + 0x014;
const SDHOST_CTYPE:      u32 = SDHOST_BASE + 0x018;
const SDHOST_BLKSIZ:     u32 = SDHOST_BASE + 0x01C;
const SDHOST_BYTCNT:     u32 = SDHOST_BASE + 0x020;
const SDHOST_INTMASK:    u32 = SDHOST_BASE + 0x024;
const SDHOST_CMDARG:     u32 = SDHOST_BASE + 0x028;
const SDHOST_CMD:        u32 = SDHOST_BASE + 0x02C;
const SDHOST_RESP0:      u32 = SDHOST_BASE + 0x030;
const SDHOST_RESP1:      u32 = SDHOST_BASE + 0x034;
const SDHOST_RESP2:      u32 = SDHOST_BASE + 0x038;
const SDHOST_RESP3:      u32 = SDHOST_BASE + 0x03C;
const SDHOST_MINTSTS:    u32 = SDHOST_BASE + 0x040;
const SDHOST_RINTSTS:    u32 = SDHOST_BASE + 0x044;
const SDHOST_STATUS:     u32 = SDHOST_BASE + 0x048;
const SDHOST_FIFOTH:     u32 = SDHOST_BASE + 0x04C;
const SDHOST_CDETECT:    u32 = SDHOST_BASE + 0x050;
const SDHOST_WRTPRT:     u32 = SDHOST_BASE + 0x054;
const SDHOST_TCBCNT:     u32 = SDHOST_BASE + 0x05C;
const SDHOST_TBBCNT:     u32 = SDHOST_BASE + 0x060;
const SDHOST_DEBNCE:     u32 = SDHOST_BASE + 0x064;
const SDHOST_USRID:      u32 = SDHOST_BASE + 0x068;
const SDHOST_VERID:      u32 = SDHOST_BASE + 0x06C;
const SDHOST_HCON:       u32 = SDHOST_BASE + 0x070;
const SDHOST_UHS:        u32 = SDHOST_BASE + 0x074;
const SDHOST_RST_N:      u32 = SDHOST_BASE + 0x078;
const SDHOST_BMOD:       u32 = SDHOST_BASE + 0x080;
const SDHOST_PLDMND:     u32 = SDHOST_BASE + 0x084;
const SDHOST_DBADDR:     u32 = SDHOST_BASE + 0x088;
const SDHOST_IDSTS:      u32 = SDHOST_BASE + 0x08C;
const SDHOST_IDINTEN:    u32 = SDHOST_BASE + 0x090;
const SDHOST_CARDTHRCTL: u32 = SDHOST_BASE + 0x100;
const SDHOST_BUFFIFO:    u32 = SDHOST_BASE + 0x200;
const SDHOST_CLK_EDGE:   u32 = SDHOST_BASE + 0x800;

// CMD register bits (TRM 34.13, Register 34.11)
const CMD_START:              u32 = 1 << 31;
const CMD_USE_HOLE:           u32 = 1 << 29; // use hold register (default=1)
const CMD_UPDATE_CLK_ONLY:    u32 = 1 << 21;
const CMD_SEND_INIT:          u32 = 1 << 15;
const CMD_STOP_ABORT:         u32 = 1 << 14;
const CMD_WAIT_PRVDATA:       u32 = 1 << 13;
const CMD_SEND_AUTO_STOP:     u32 = 1 << 12;
const CMD_WRITE:              u32 = 1 << 10;
const CMD_DATA_EXPECTED:      u32 = 1 << 9;
const CMD_CHECK_RESP_CRC:     u32 = 1 << 8;
const CMD_RESP_LONG:          u32 = 1 << 7;
const CMD_RESP_EXPECT:        u32 = 1 << 6;

// CTRL register bits
const CTRL_FIFO_RESET:        u32 = 1 << 1;
const CTRL_CONTROLLER_RESET:  u32 = 1 << 0;
const CTRL_INT_ENABLE:        u32 = 1 << 4;

// RINTSTS interrupt bits
const INT_CD:    u32 = 1 << 2;  // Command Done
const INT_DTO:   u32 = 1 << 3;  // Data Transfer Over
const INT_TXDR:  u32 = 1 << 4;  // TX FIFO Data Request
const INT_RXDR:  u32 = 1 << 5;  // RX FIFO Data Request
const INT_RCRC:  u32 = 1 << 6;  // Response CRC Error
const INT_DCRC:  u32 = 1 << 7;  // Data CRC Error
const INT_RTO:   u32 = 1 << 8;  // Response Timeout
const INT_DRTO:  u32 = 1 << 9;  // Data Read Timeout
const INT_HTO:   u32 = 1 << 10; // Data Starvation by Host Timeout
const INT_FRUN:  u32 = 1 << 11; // FIFO underrun/overrun
const INT_HLE:   u32 = 1 << 12; // Hardware Locked write Error
const INT_SBE:   u32 = 1 << 13; // Start Bit Error
const INT_EBE:   u32 = 1 << 15; // End Bit Error

const INT_ALL_ERRORS: u32 = INT_RCRC | INT_DCRC | INT_RTO | INT_DRTO
    | INT_HTO | INT_FRUN | INT_HLE | INT_SBE | INT_EBE;

// STATUS register bits
const STATUS_FIFO_FULL:  u32 = 1 << 3;
const STATUS_FIFO_EMPTY: u32 = 1 << 2;
const STATUS_DATA_BUSY:  u32 = 1 << 9;

// ═══════════════════════════════════════════════════════════════
// GPIO Matrix Signal Numbers for SDHOST Card1 (TRM Table 6-2)
// ═══════════════════════════════════════════════════════════════

const SDHOST_CCLK_OUT_1:    u32 = 172;  // output: clock
const SDHOST_CCMD_IN_1:     u32 = 178;  // input: command response
const SDHOST_CCMD_OUT_1:    u32 = 178;  // output: command (same signal, bidirectional)
const SDHOST_CDATA_IN_10:   u32 = 180;  // input: data[0] from card
const SDHOST_CDATA_OUT_10:  u32 = 180;  // output: data[0] to card
const SDHOST_CARD_DETECT_1: u32 = 194;  // input: card detect (active low)

// ═══════════════════════════════════════════════════════════════
// GPIO / IO_MUX / System Registers
// ═══════════════════════════════════════════════════════════════

const GPIO_OUT_W1TS: u32     = 0x6000_4008;
const GPIO_OUT_W1TC: u32     = 0x6000_400C;
const GPIO_ENABLE_W1TS: u32  = 0x6000_4024;
const GPIO_ENABLE_W1TC: u32  = 0x6000_4028;
const GPIO_IN_REG: u32       = 0x6000_403C;
const GPIO_OUT1_W1TS: u32    = 0x6000_4014;
const GPIO_OUT1_W1TC: u32    = 0x6000_4018;
const GPIO_ENABLE1_W1TS: u32 = 0x6000_4030;
const GPIO_ENABLE1_W1TC: u32 = 0x6000_4034;
const GPIO_IN1_REG: u32      = 0x6000_4040;
const GPIO_FUNC_OUT_SEL_BASE: u32 = 0x6000_4554;
const GPIO_FUNC_IN_SEL_BASE: u32  = 0x6000_4154;
const IO_MUX_BASE: u32 = 0x6000_9004;

// SPI2 registers (for LCD state save/restore only)
const SPI2_CLOCK_REG: u32 = 0x6002_400C;
const SPI2_USER_REG: u32  = 0x6002_4010;

// FSPIQ input signal (SPI2 MISO — must disconnect from GPIO40)
const FSPIQ_IN_SIGNAL: u32 = 102;

// System peripheral clock/reset
const SYSTEM_PERIP_CLK_EN0: u32  = 0x600C_0018;
const SYSTEM_PERIP_RST_EN0: u32  = 0x600C_0020;
const SYSTEM_PERIP_CLK_EN1: u32  = 0x600C_001C;
const SYSTEM_PERIP_RST_EN1: u32  = 0x600C_0024;

// SDHOST clock is bit 7 of CLK_EN1/RST_EN1
const SDHOST_CLK_EN_BIT: u32 = 1 << 7;

// GPIO pin numbers (Waveshare ESP32-S3-Touch-LCD-2)
const PIN_LCD_CS: u8  = 45;
const PIN_SD_CS: u8   = 41;  // D3 in SD mode — used as card-select by SDHOST
const PIN_MISO: u8    = 40;  // D0 in SD mode
const PIN_SCK: u8     = 39;  // CLK in SD mode
const PIN_MOSI: u8    = 38;  // CMD in SD mode

// ═══════════════════════════════════════════════════════════════
// SD Card Type
// ═══════════════════════════════════════════════════════════════

/// SD card type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SdCardType {
    None,
    SdV1,    // SD v1 (byte addressing)
    SdV2Sc,  // SD v2 Standard Capacity (byte addressing)
    SdV2Hc,  // SD v2 High/Extended Capacity (block addressing)
}

/// Card's RCA (Relative Card Address) assigned during init
/// Atomic for the same reason as the SPI flags on M5: written at init, read
/// on the command path, and free at `Relaxed`.
static CARD_RCA: core::sync::atomic::AtomicU16 =
    core::sync::atomic::AtomicU16::new(0);

/// Card type detected at boot
/// Stays `static mut`, unlike the primitives above.
///
/// `SdCardType` is a plain enum with no `repr`, so an atomic form means
/// adding `repr(u8)`, a to-byte conversion and a fallible from-byte mapping:
/// code added to remove an `unsafe`, not code that makes anything safer. A
/// mutex is worse still, a critical section on the SD path for a value
/// written twice at init.
///
/// Sound for the same checked reasons as the rest of this driver: no
/// interrupt handlers exist anywhere in the firmware, and core 1 runs only
/// the rqrr decoder, which never touches SD.
pub static mut BOOT_CARD_TYPE: SdCardType = SdCardType::None;

/// Sector count read from the CSD during init.
///
/// CMD9 is only legal while the card is in stand-by, which on this controller
/// means after CMD3 assigns the RCA and before CMD7 selects the card. Asking
/// later returns RTO, so the value is taken at the one point it is available
/// and kept for the formatter. Zero means the read did not succeed.
static CARD_SECTORS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

// ═══════════════════════════════════════════════════════════════
// Low-level register helpers
// ═══════════════════════════════════════════════════════════════

#[inline(always)]
unsafe fn reg_write(addr: u32, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
unsafe fn reg_read(addr: u32) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

#[inline(always)]
unsafe fn reg_set_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v | bits);
}

#[inline(always)]
unsafe fn reg_clear_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v & !bits);
}

// ═══════════════════════════════════════════════════════════════
// GPIO helpers
// ═══════════════════════════════════════════════════════════════

#[inline(always)]
fn gpio_set(pin: u8) {
    unsafe {
        if pin < 32 {
            reg_write(GPIO_OUT_W1TS, 1u32 << pin);
        } else {
            reg_write(GPIO_OUT1_W1TS, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
fn gpio_clear(pin: u8) {
    unsafe {
        if pin < 32 {
            reg_write(GPIO_OUT_W1TC, 1u32 << pin);
        } else {
            reg_write(GPIO_OUT1_W1TC, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
fn gpio_read(pin: u8) -> bool {
    unsafe {
        if pin < 32 {
            (reg_read(GPIO_IN_REG) >> pin) & 1 != 0
        } else {
            (reg_read(GPIO_IN1_REG) >> (pin - 32)) & 1 != 0
        }
    }
}

#[inline(always)]
fn gpio_enable_output(pin: u8) {
    unsafe {
        if pin < 32 {
            reg_write(GPIO_ENABLE_W1TS, 1u32 << pin);
        } else {
            reg_write(GPIO_ENABLE1_W1TS, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
fn gpio_disable_output(pin: u8) {
    unsafe {
        if pin < 32 {
            reg_write(GPIO_ENABLE_W1TC, 1u32 << pin);
        } else {
            reg_write(GPIO_ENABLE1_W1TC, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
fn iomux_addr(pin: u8) -> u32 {
    IO_MUX_BASE + (pin as u32) * 4
}

#[inline(always)]
fn func_out_sel_addr(pin: u8) -> u32 {
    GPIO_FUNC_OUT_SEL_BASE + (pin as u32) * 4
}

#[inline(always)]
fn func_in_sel_addr(signal: u32) -> u32 {
    GPIO_FUNC_IN_SEL_BASE + signal * 4
}

// ═══════════════════════════════════════════════════════════════
// Saved SPI2 state for display coexistence
// ═══════════════════════════════════════════════════════════════

pub struct SavedDisplayState {
    fout_sck: u32,
    fout_mosi: u32,
    fout_miso: u32,
    fin_fspiq: u32,
    iomux_sck: u32,
    iomux_mosi: u32,
    iomux_miso: u32,
}

fn save_display_state() -> SavedDisplayState {
    unsafe {
        SavedDisplayState {
            fout_sck:  reg_read(func_out_sel_addr(PIN_SCK)),
            fout_mosi: reg_read(func_out_sel_addr(PIN_MOSI)),
            fout_miso: reg_read(func_out_sel_addr(PIN_MISO)),
            fin_fspiq: reg_read(func_in_sel_addr(FSPIQ_IN_SIGNAL)),
            iomux_sck:  reg_read(iomux_addr(PIN_SCK)),
            iomux_mosi: reg_read(iomux_addr(PIN_MOSI)),
            iomux_miso: reg_read(iomux_addr(PIN_MISO)),
        }
    }
}

fn restore_display_state(s: &SavedDisplayState) {
    unsafe {
        reg_write(func_out_sel_addr(PIN_SCK), s.fout_sck);
        reg_write(func_out_sel_addr(PIN_MOSI), s.fout_mosi);
        reg_write(func_out_sel_addr(PIN_MISO), s.fout_miso);
        reg_write(func_in_sel_addr(FSPIQ_IN_SIGNAL), s.fin_fspiq);
        reg_write(iomux_addr(PIN_SCK), s.iomux_sck);
        reg_write(iomux_addr(PIN_MOSI), s.iomux_mosi);
        reg_write(iomux_addr(PIN_MISO), s.iomux_miso);
        // Re-enable MISO output for SPI2
        gpio_enable_output(PIN_MISO);
    }
}

// ═══════════════════════════════════════════════════════════════
// SDHOST GPIO routing
// ═══════════════════════════════════════════════════════════════

/// Route GPIO38/39/40 to SDHOST controller via GPIO matrix
fn route_pins_to_sdhost() {
    unsafe {
        // Disconnect FSPIQ_IN from GPIO40 (prevent SPI2 interference)
        reg_write(func_in_sel_addr(FSPIQ_IN_SIGNAL), 0xBC); // 0x3C | (1<<7) = constant LOW via matrix

        // --- GPIO39 → sdhost_cclk_out_1 (output-only, signal 172) ---
        // IOMUX: MCU_SEL=1(GPIO), FUN_DRV=2(20mA for driving through C26=1µF), no IE
        reg_write(iomux_addr(PIN_SCK), 0x0000_1800); // MCU_SEL=1, FUN_DRV=2(bits11:10=10)
        // FUNC_OUT_SEL: signal 172, OEN_SEL=1 (always output via GPIO_ENABLE)
        reg_write(func_out_sel_addr(PIN_SCK), SDHOST_CCLK_OUT_1 | (1 << 10));
        gpio_enable_output(PIN_SCK);

        // --- GPIO38 → sdhost_ccmd (BIDIRECTIONAL, signal 178) ---
        // IOMUX: MCU_SEL=1(GPIO), FUN_IE=1(input enable), FUN_WPU=1(pullup), drive=2
        // 0x1300 = bits: MCU_SEL=1(bit12), FUN_IE=1(bit9), FUN_WPU=1(bit8)
        reg_write(iomux_addr(PIN_MOSI), 0x0000_1300);
        // FUNC_OUT_SEL: signal 178, OEN_SEL=0 → peripheral's sdhost_ccmd_out_en_1 controls OE
        reg_write(func_out_sel_addr(PIN_MOSI), SDHOST_CCMD_OUT_1);
        // GPIO_ENABLE must be set for the peripheral OE to work through the matrix
        gpio_enable_output(PIN_MOSI);
        // Input: route pin to sdhost_ccmd_in_1 via GPIO matrix (SIG_IN_SEL=1)
        reg_write(func_in_sel_addr(SDHOST_CCMD_IN_1), PIN_MOSI as u32 | (1 << 7));

        // --- GPIO40 → sdhost_cdata[0] (BIDIRECTIONAL, signal 180) ---
        // IOMUX: MCU_SEL=1(GPIO), FUN_IE=1(input enable), FUN_WPU=1(pullup)
        reg_write(iomux_addr(PIN_MISO), 0x0000_1300);
        // FUNC_OUT_SEL: signal 180, OEN_SEL=0 → peripheral's sdhost_cdata_out_en_10 controls OE
        reg_write(func_out_sel_addr(PIN_MISO), SDHOST_CDATA_OUT_10);
        gpio_enable_output(PIN_MISO);
        // Input: route pin to sdhost_cdata_in_10 via GPIO matrix
        reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), PIN_MISO as u32 | (1 << 7));

        // --- Card detect: route to constant LOW (card always present, no detect switch) ---
        reg_write(func_in_sel_addr(SDHOST_CARD_DETECT_1), 0x3C | (1 << 7));

        // LCD CS HIGH during SD access
        gpio_set(PIN_LCD_CS);
    }
}

// ═══════════════════════════════════════════════════════════════
// SDHOST Controller Init / Clock / Reset
// ═══════════════════════════════════════════════════════════════

/// Enable SDHOST peripheral clock and deassert reset
fn sdhost_enable_peripheral() {
    unsafe {
        // Enable SDHOST clock (bit 7 in PERIP_CLK_EN1)
        reg_set_bits(SYSTEM_PERIP_CLK_EN1, SDHOST_CLK_EN_BIT);
        // Pulse reset
        reg_set_bits(SYSTEM_PERIP_RST_EN1, SDHOST_CLK_EN_BIT);
        for _ in 0..200u32 { reg_read(SDHOST_VERID); } // barrier
        reg_clear_bits(SYSTEM_PERIP_RST_EN1, SDHOST_CLK_EN_BIT);
        for _ in 0..200u32 { reg_read(SDHOST_VERID); } // barrier

        // CRITICAL: Configure SDHOST internal clock source BEFORE anything else.
        // SDHOST_CLK_DIV_EDGE_REG (0x0800):
        //   bit 23: CLK_SOURCE_REG — 0=40MHz XTAL, 1=160MHz PLL
        //   bits 20:17: CCLKIN_EDGE_N (must equal CCLKIN_EDGE_L)
        //   bits 16:13: CCLKIN_EDGE_L (low phase count)
        //   bits 12:9:  CCLKIN_EDGE_H (high phase count, must be < L)
        //   bits 8:6:   CCLKIN_EDGE_SLF_SEL (phase for internal/core)
        //   bits 5:3:   CCLKIN_EDGE_SAM_SEL (phase for sampling/din)
        //   bits 2:0:   CCLKIN_EDGE_DRV_SEL (phase for driving/dout)
        //
        // ESP-IDF uses: clk_sel=1 (160MHz PLL), div=2 minimum → H=0, L=1, N=1
        // This gives 160/2 = 80MHz base clock into the CLKDIV stage.
        // phase_dout=1 (90° for output driving), phase_din=0, phase_core=0.
        let clk_edge = (1u32 << 23)     // CLK_SOURCE=1: 160MHz PLL (MUST use PLL, not XTAL!)
            | (1u32 << 17)              // CCLKIN_EDGE_N = 1 (must equal L)
            | (1u32 << 13)              // CCLKIN_EDGE_L = 1
            | (0u32 << 9)               // CCLKIN_EDGE_H = 0
            | (0u32 << 6)               // SLF_SEL = phase0 (core)
            | (0u32 << 3)               // SAM_SEL = phase0 (din sampling)
            | (1u32 << 0);              // DRV_SEL = phase90 (dout driving)
        reg_write(SDHOST_CLK_EDGE, clk_edge);
    }
}

/// Reset SDHOST controller and FIFO
fn sdhost_reset() {
    unsafe {
        // Controller reset + FIFO reset
        // NOTE: reset needs sdhost_cclk_in cycles to complete, so GPIO must be
        // routed and clock source configured BEFORE calling this.
        reg_write(SDHOST_CTRL, CTRL_CONTROLLER_RESET | CTRL_FIFO_RESET);
        // Wait for reset to complete (bits auto-clear after 2 AHB + 2 cclk cycles)
        for _ in 0..1_000_000u32 {
            if reg_read(SDHOST_CTRL) & (CTRL_CONTROLLER_RESET | CTRL_FIFO_RESET) == 0 {
                return;
            }
        }
        log!("[SDHOST] WARNING: reset bits did not auto-clear, forcing");
        // Force clear — write 0 to the reset bits
        reg_write(SDHOST_CTRL, 0);
    }
}

/// Update card clock settings (CLKDIV, CLKENA, CLKSRC) into CIU
fn sdhost_update_clock() -> Result<(), &'static str> {
    unsafe {
        // Clear pending interrupts
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);
        // Send "update clock only" command — do NOT use CMD_WAIT_PRVDATA for clock updates
        reg_write(SDHOST_CMD, CMD_START | CMD_USE_HOLE | CMD_UPDATE_CLK_ONLY);
        // Wait for START_CMD to clear
        for _ in 0..1_000_000u32 {
            let cmd = reg_read(SDHOST_CMD);
            if cmd & CMD_START == 0 { return Ok(()); }
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_HLE != 0 {
                reg_write(SDHOST_RINTSTS, INT_HLE);
                return Err("HLE during clock update");
            }
        }
        Err("Clock update timeout")
    }
}

/// Set SDHOST card clock divider.
/// f_card = f_base / (2 * divider), where f_base = 80MHz (160MHz PLL / edge_div=2).
/// divider=0 means bypass → 80MHz, divider=100 → 400kHz, divider=4 → 10MHz.
fn sdhost_set_clock(divider: u32) -> Result<(), &'static str> {
    unsafe {
        // Disable clock first
        reg_write(SDHOST_CLKENA, 0);
        sdhost_update_clock()?;

        // Set divider (divider 0 in CLKDIV register = bypass = /1)
        reg_write(SDHOST_CLKSRC, 0); // card 0 uses clock divider 0
        reg_write(SDHOST_CLKDIV, divider); // divider 0 value
        sdhost_update_clock()?;

        // Enable clock for card 0
        reg_write(SDHOST_CLKENA, 0x01);
        sdhost_update_clock()?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// SDHOST Command Engine
// ═══════════════════════════════════════════════════════════════

/// Send a command via SDHOST and wait for completion.
/// Returns RESP0 (short response) on success.
fn sdhost_send_cmd(cmd_idx: u32, arg: u32, flags: u32) -> Result<u32, &'static str> {
    unsafe {
        // Clear all pending interrupts
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Set argument
        reg_write(SDHOST_CMDARG, arg);

        // Build command word
        let cmd_val = CMD_START | CMD_USE_HOLE | (cmd_idx & 0x3F) | flags;
        reg_write(SDHOST_CMD, cmd_val);

        // Wait for Command Done or error
        for _ in 0..1_000_000u32 {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_HLE != 0 {
                reg_write(SDHOST_RINTSTS, INT_HLE);
                return Err("HLE");
            }
            if rint & INT_CD != 0 {
                // Command done — check for errors
                reg_write(SDHOST_RINTSTS, INT_CD);
                if rint & INT_RTO != 0 {
                    reg_write(SDHOST_RINTSTS, INT_RTO);
                    return Err("RTO");
                }
                if rint & INT_RCRC != 0 {
                    reg_write(SDHOST_RINTSTS, INT_RCRC);
                    // Some commands (CMD0, ACMD41) don't have valid CRC — ignore
                    if flags & CMD_CHECK_RESP_CRC != 0 {
                        return Err("RCRC");
                    }
                }
                return Ok(reg_read(SDHOST_RESP0));
            }
        }
        Err("CMD timeout")
    }
}

/// Wait for card data busy to clear (for R1b responses)
fn sdhost_wait_not_busy() -> Result<(), &'static str> {
    unsafe {
        for _ in 0..5_000_000u32 {
            if reg_read(SDHOST_STATUS) & STATUS_DATA_BUSY == 0 {
                return Ok(());
            }
        }
    }
    Err("Data busy timeout")
}

// ═══════════════════════════════════════════════════════════════
// SD Native Protocol — Card Initialization
// ═══════════════════════════════════════════════════════════════

/// Full SD card initialization using SDHOST in native SD mode.
/// Returns card type on success.
fn sdhost_init_card(delay: &mut Delay) -> Result<SdCardType, &'static str> {
    log!("[SDHOST] Initializing...");

    // Read hardware version for sanity
    let ver = unsafe { reg_read(SDHOST_VERID) };
    log!("[SDHOST] VERID=0x{:08x}", ver);

    // Reset controller and FIFO
    sdhost_reset();

    // Configure: 1-bit mode, 512-byte blocks, max timeout, FIFO polling
    unsafe {
        reg_write(SDHOST_CTYPE, 0x00000000);  // 1-bit mode for card 0
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, 512);
        reg_write(SDHOST_TMOUT, 0xFFFF_FF40);  // data timeout max, response timeout 64
        reg_write(SDHOST_INTMASK, 0);          // mask all interrupts (we poll RINTSTS)
        reg_write(SDHOST_FIFOTH, (1 << 16) | 0); // RX watermark=1, TX watermark=0
        reg_write(SDHOST_CTRL, CTRL_INT_ENABLE); // enable global int flag but all masked
        reg_write(SDHOST_RST_N, 0x01);          // card 0 not in reset
        reg_write(SDHOST_DEBNCE, 0x00FFFFFF);    // max debounce
    }

    // Set slow clock for init: base=80MHz, divider=100 → 80/(2*100) = 400kHz
    sdhost_set_clock(100)?;
    delay.delay_millis(50); // Give card time with clock running

    // CMD0: GO_IDLE_STATE (with 80 init clocks, no response)
    let _ = sdhost_send_cmd(0, 0, CMD_SEND_INIT);
    unsafe { reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF); }
    delay.delay_millis(10);
    let _ = sdhost_send_cmd(0, 0, 0); // retry without init flag
    unsafe { reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF); }
    delay.delay_millis(10);

    // CMD8: SEND_IF_COND (SDv2 detection)
    let sd_v2 = match sdhost_send_cmd(8, 0x000001AA, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC) {
        Ok(resp) => {
            resp & 0xFFF == 0x1AA
        }
        Err(_) => false,
    };

    // ACMD41: SD_SEND_OP_COND — wait for card ready
    let hcs = if sd_v2 { 1u32 << 30 } else { 0 };
    let mut ocr = 0u32;
    let mut ready = false;
    for _i in 0..200u32 {
        let _ = sdhost_send_cmd(55, 0, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC);
        match sdhost_send_cmd(41, 0x00FF_8000 | hcs, CMD_RESP_EXPECT) {
            Ok(resp) => {
                ocr = resp;
                if resp & (1 << 31) != 0 {
                    ready = true;
                    break;
                }
            }
            Err(_) => {}
        }
        delay.delay_millis(10);
    }
    if !ready {
        return Err("ACMD41 timeout");
    }

    // Determine card type from OCR
    let card_type = if sd_v2 {
        if ocr & (1 << 30) != 0 { SdCardType::SdV2Hc } else { SdCardType::SdV2Sc }
    } else {
        SdCardType::SdV1
    };

    // CMD2: ALL_SEND_CID
    sdhost_send_cmd(2, 0, CMD_RESP_EXPECT | CMD_RESP_LONG | CMD_CHECK_RESP_CRC)?;

    // CMD3: SEND_RELATIVE_ADDR
    let resp3 = sdhost_send_cmd(3, 0, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;
    let rca = (resp3 >> 16) as u16;
    CARD_RCA.store(rca, core::sync::atomic::Ordering::Relaxed);

    // CMD9: SEND_CSD, while the card is still in stand-by. After CMD7 below
    // it is in transfer state and CMD9 is refused, which is where the
    // formatter used to ask and get RTO.
    CARD_SECTORS.store(0, core::sync::atomic::Ordering::Relaxed);
    if sdhost_send_cmd(9, (rca as u32) << 16,
        CMD_RESP_EXPECT | CMD_RESP_LONG | CMD_CHECK_RESP_CRC).is_ok()
    {
        let (r0, r1, r2, r3) = unsafe {
            (reg_read(SDHOST_RESP0), reg_read(SDHOST_RESP1),
             reg_read(SDHOST_RESP2), reg_read(SDHOST_RESP3))
        };
        log!("[SDHOST] CSD regs {:08x} {:08x} {:08x} {:08x}", r0, r1, r2, r3);
        // Which end of the response lands in RESP0 is a controller property,
        // so both orders are parsed and the believable one wins.
        let mut csd = [0u8; 16];
        for (i, w) in [r3, r2, r1, r0].iter().enumerate() {
            csd[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        let mut found = match csd_sectors(&csd) {
            Ok(n) if csd_plausible(n) => n,
            _ => 0,
        };
        if found == 0 {
            for (i, w) in [r0, r1, r2, r3].iter().enumerate() {
                csd[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            if let Ok(n) = csd_sectors(&csd) {
                if csd_plausible(n) { found = n; }
            }
        }
        if found != 0 {
            log!("[SDHOST] Card capacity {} sectors", found);
        } else {
            log!("[SDHOST] CSD not understood");
        }
        CARD_SECTORS.store(found, core::sync::atomic::Ordering::Relaxed);
    } else {
        log!("[SDHOST] CMD9 failed");
    }

    // CMD7: SELECT_CARD
    sdhost_send_cmd(7, (rca as u32) << 16, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;
    sdhost_wait_not_busy()?;

    // CMD16: SET_BLOCKLEN = 512
    sdhost_send_cmd(16, 512, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;

    // Speed up clock for data transfers: base=80MHz, divider=2 → 80/(2*2) = 20MHz
    sdhost_set_clock(2)?;
    log!("[SDHOST] Clock set to 20MHz for data transfers");

    log!("[SDHOST] SD card init complete: {:?}", card_type);
    Ok(card_type)
}

// ═══════════════════════════════════════════════════════════════
// Block I/O via SDHOST FIFO (polled, non-DMA)
// ═══════════════════════════════════════════════════════════════

/// Read a single 512-byte block.
pub fn sd_read_block(card_type: SdCardType, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
    let addr = if card_type == SdCardType::SdV2Hc { block } else { block * 512 };

    unsafe {
        // Setup for single block read
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, 512);

        // Clear interrupts
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO before read
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        for _ in 0..10_000u32 {
            if reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0 { break; }
        }

        // CMD17: READ_SINGLE_BLOCK (R1 + data)
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START | CMD_USE_HOLE | 17
            | CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED | CMD_WAIT_PRVDATA;
        reg_write(SDHOST_CMD, cmd_flags);

        // Wait for command done
        for _ in 0..1_000_000u32 {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_HLE != 0 { return Err("CMD17 HLE"); }
            if rint & INT_CD != 0 { break; }
        }

        // Check command response errors
        let rint = reg_read(SDHOST_RINTSTS);
        if rint & INT_RTO != 0 { return Err("CMD17 RTO"); }

        // Read 512 bytes from FIFO (128 x 32-bit words)
        let mut bytes_read = 0usize;

        for _attempt in 0..5_000_000u32 {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                log!("[SDHOST] Read error RINT=0x{:08x} at byte {}", rint, bytes_read);
                reg_write(SDHOST_RINTSTS, rint);
                return Err("Read error");
            }
            if rint & INT_DTO != 0 {
                // Data transfer over — drain remaining FIFO
                while bytes_read < 512 {
                    let status = reg_read(SDHOST_STATUS);
                    if status & STATUS_FIFO_EMPTY != 0 { break; }
                    let word = reg_read(SDHOST_BUFFIFO);
                    let base = bytes_read;
                    for j in 0..4 {
                        if base + j < 512 {
                            buf[base + j] = ((word >> (j * 8)) & 0xFF) as u8;
                        }
                    }
                    bytes_read += 4;
                }
                reg_write(SDHOST_RINTSTS, INT_DTO);
                break;
            }

            // Read available words from FIFO
            let status = reg_read(SDHOST_STATUS);
            if status & STATUS_FIFO_EMPTY == 0 {
                let word = reg_read(SDHOST_BUFFIFO);
                let base = bytes_read;
                for j in 0..4 {
                    if base + j < 512 {
                        buf[base + j] = ((word >> (j * 8)) & 0xFF) as u8;
                    }
                }
                bytes_read += 4;
            }
        }

        if bytes_read < 512 {
            log!("[SDHOST] Read incomplete: {} bytes", bytes_read);
            return Err("Read incomplete");
        }
    }
    Ok(())
}

/// Write a single 512-byte block.
fn sd_write_block(card_type: SdCardType, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
    let addr = if card_type == SdCardType::SdV2Hc { block } else { block * 512 };

    unsafe {
        // Setup
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, 512);
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        for _ in 0..10_000u32 {
            if reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0 { break; }
        }

        // Pre-fill FIFO with data (up to FIFO size, 512 bytes = 128 words fits in 512-byte FIFO)
        for i in 0..128 {
            let base = i * 4;
            let word = (buf[base] as u32)
                | ((buf[base + 1] as u32) << 8)
                | ((buf[base + 2] as u32) << 16)
                | ((buf[base + 3] as u32) << 24);
            reg_write(SDHOST_BUFFIFO, word);
        }

        // CMD24: WRITE_BLOCK (R1 + data)
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START | CMD_USE_HOLE | 24
            | CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED | CMD_WRITE | CMD_WAIT_PRVDATA;
        reg_write(SDHOST_CMD, cmd_flags);

        // Wait for command + data transfer over
        for _ in 0..5_000_000u32 {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                log!("[SDHOST] Write error RINT=0x{:08x}", rint);
                reg_write(SDHOST_RINTSTS, rint);
                return Err("Write error");
            }
            if rint & INT_DTO != 0 {
                reg_write(SDHOST_RINTSTS, INT_DTO | INT_CD);
                break;
            }
        }

        // Wait for card not busy
        sdhost_wait_not_busy()?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Multi-block I/O
// ═══════════════════════════════════════════════════════════════

/// Multi-block read: CMD18 + auto CMD12 stop.
pub fn fast_read_multi_block(
    card_type: SdCardType,
    block: u32,
    out: &mut [u8],
    count: u32,
) -> Result<(), &'static str> {
    if count == 0 { return Ok(()); }
    // Bounds before any slicing. The per-sector `out[offset..offset + 512]`
    // below panics on an undersized buffer, and a panic is the worst outcome
    // available here: every caller already handles this `Result`, and the
    // callers that exist DO size correctly (see `read_file` / `write_file`,
    // which only take this path when the remaining buffer covers the whole
    // cluster). This turns an unreachable panic into an error, at one
    // comparison per call.
    if out.len() < count as usize * 512 {
        return Err("buffer too small");
    }
    if count == 1 {
        let buf: &mut [u8; 512] = (&mut out[..512]).try_into().map_err(|_| "buf align")?;
        return sd_read_block(card_type, block, buf);
    }

    let addr = if card_type == SdCardType::SdV2Hc { block } else { block * 512 };
    let total_bytes = count * 512;

    unsafe {
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, total_bytes);
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        for _ in 0..10_000u32 {
            if reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0 { break; }
        }

        // CMD18: READ_MULTIPLE_BLOCK with auto-stop
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START | CMD_USE_HOLE | 18
            | CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED | CMD_WAIT_PRVDATA
            | CMD_SEND_AUTO_STOP;
        reg_write(SDHOST_CMD, cmd_flags);

        // Wait for command done
        for _ in 0..1_000_000u32 {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & (INT_CD | INT_HLE) != 0 { break; }
        }

        // Read all data from FIFO
        let mut bytes_read = 0usize;
        let total = total_bytes as usize;

        for _ in 0..50_000_000u32 {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                reg_write(SDHOST_RINTSTS, rint);
                return Err("Multi-read error");
            }

            // Read from FIFO while data available
            let status = reg_read(SDHOST_STATUS);
            if status & STATUS_FIFO_EMPTY == 0 && bytes_read < total {
                let word = reg_read(SDHOST_BUFFIFO);
                for j in 0..4 {
                    if bytes_read + j < total {
                        out[bytes_read + j] = ((word >> (j * 8)) & 0xFF) as u8;
                    }
                }
                bytes_read += 4;
            }

            if rint & INT_DTO != 0 {
                // Drain remaining
                while bytes_read < total {
                    let st = reg_read(SDHOST_STATUS);
                    if st & STATUS_FIFO_EMPTY != 0 { break; }
                    let word = reg_read(SDHOST_BUFFIFO);
                    for j in 0..4 {
                        if bytes_read + j < total {
                            out[bytes_read + j] = ((word >> (j * 8)) & 0xFF) as u8;
                        }
                    }
                    bytes_read += 4;
                }
                reg_write(SDHOST_RINTSTS, INT_DTO);
                break;
            }
        }

        if bytes_read < total {
            return Err("Multi-read incomplete");
        }
    }
    Ok(())
}

/// Multi-block write: CMD25 + auto CMD12 stop.
pub fn fast_write_multi_block(
    card_type: SdCardType,
    block: u32,
    data: &[u8],
    count: u32,
) -> Result<(), &'static str> {
    if count == 0 { return Ok(()); }
    // Bounds before any slicing. The per-sector `out[offset..offset + 512]`
    // below panics on an undersized buffer, and a panic is the worst outcome
    // available here: every caller already handles this `Result`, and the
    // callers that exist DO size correctly (see `read_file` / `write_file`,
    // which only take this path when the remaining buffer covers the whole
    // cluster). This turns an unreachable panic into an error, at one
    // comparison per call.
    if data.len() < count as usize * 512 {
        return Err("buffer too small");
    }
    if count == 1 {
        let buf: &[u8; 512] = (&data[..512]).try_into().map_err(|_| "buf align")?;
        return sd_write_block(card_type, block, buf);
    }

    let addr = if card_type == SdCardType::SdV2Hc { block } else { block * 512 };
    let total_bytes = count * 512;

    unsafe {
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, total_bytes);
        reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF);

        // Reset FIFO
        reg_set_bits(SDHOST_CTRL, CTRL_FIFO_RESET);
        for _ in 0..10_000u32 {
            if reg_read(SDHOST_CTRL) & CTRL_FIFO_RESET == 0 { break; }
        }

        // CMD25: WRITE_MULTIPLE_BLOCK with auto-stop
        reg_write(SDHOST_CMDARG, addr);
        let cmd_flags = CMD_START | CMD_USE_HOLE | 25
            | CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC
            | CMD_DATA_EXPECTED | CMD_WRITE | CMD_WAIT_PRVDATA
            | CMD_SEND_AUTO_STOP;
        reg_write(SDHOST_CMD, cmd_flags);

        // Feed data through FIFO
        let total = total_bytes as usize;
        let mut bytes_written = 0usize;

        for _ in 0..50_000_000u32 {
            let rint = reg_read(SDHOST_RINTSTS);
            if rint & INT_ALL_ERRORS != 0 {
                reg_write(SDHOST_RINTSTS, rint);
                return Err("Multi-write error");
            }

            // Write to FIFO when not full
            let status = reg_read(SDHOST_STATUS);
            if status & STATUS_FIFO_FULL == 0 && bytes_written < total {
                let base = bytes_written;
                let word = (data[base] as u32)
                    | ((data[base + 1] as u32) << 8)
                    | ((data[base + 2] as u32) << 16)
                    | ((data[base + 3] as u32) << 24);
                reg_write(SDHOST_BUFFIFO, word);
                bytes_written += 4;
            }

            if rint & INT_DTO != 0 {
                reg_write(SDHOST_RINTSTS, INT_DTO);
                break;
            }
        }

        sdhost_wait_not_busy()?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Boot-time SD init (called from main.rs BEFORE display)
// ═══════════════════════════════════════════════════════════════

/// Pre-SPI power-up sequence. On Waveshare there's no PMU,
/// so this just sets GPIO levels to avoid glitching the card
/// into native mode before we're ready.
pub fn sd_pre_init() {
    // Set all SD pins HIGH (idle) before esp-hal claims GPIO38/39
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
        for _ in 0..50u32 { unsafe { core::ptr::read_volatile(&0u32 as *const u32); } }
        gpio_set(PIN_SCK);
        for _ in 0..50u32 { unsafe { core::ptr::read_volatile(&0u32 as *const u32); } }
    }
    gpio_clear(PIN_SCK);
}

/// Post-display SD card init via SDHOST controller.
/// Saves display GPIO state, routes to SDHOST, initializes card,
/// then restores display routing.
pub fn init_sdhost(delay: &mut Delay) -> Result<SdCardType, &'static str> {
    log!("[SDHOST] Post-display SD init...");

    let saved = save_display_state();

    sdhost_enable_peripheral();
    route_pins_to_sdhost();

    let result = sdhost_init_card(delay);

    // After CMD7 SELECT_CARD, the card drives D0 (GPIO40) for busy signaling.
    // On the eFuse board, the card holding D0 during restore_display_state
    // corrupts the ST7789T3 MADCTL register.
    // Fix: deselect card so it releases D0, disconnect SDHOST D0 input signal.
    //
    // The RCA is kept. CMD7 with argument 0 deselects the card (stand-by
    // state, D0 released) without invalidating the address CMD3 assigned, so
    // the next `with_sd_card` can re-select it with CMD13 + CMD7 instead of
    // re-running CMD0/CMD8/ACMD41/CMD2/CMD3/CMD9. Until 1.0.7 the RCA was
    // zeroed here, which made that fast path unreachable.
    if result.is_ok() {
        let _ = sdhost_send_cmd(7, 0, CMD_RESP_EXPECT); // deselect
        // Disconnect SDHOST data input from GPIO40 so card can't drive it
        unsafe {
            reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), 0xBC); // constant LOW
        }
    }

    restore_display_state(&saved);

    match result {
        Ok(ct) => {
            unsafe { BOOT_CARD_TYPE = ct; }
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
/// Handles the full lifecycle:
/// 1. Save SPI2/display GPIO state
/// 2. Route GPIOs to SDHOST
/// 3. Re-select card (CMD7)
/// 4. Run closure
/// 5. Restore display GPIO routing
pub fn with_sd_card<I2C, F, T>(
    _i2c: &mut I2C,
    delay: &mut Delay,
    f: F,
) -> Result<T, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
    F: FnOnce(SdCardType) -> Result<T, &'static str>,
{
    let card_type = unsafe { BOOT_CARD_TYPE };
    if card_type == SdCardType::None {
        return Err("No SD card");
    }

    // Save display state
    let saved = save_display_state();

    // Route to SDHOST
    route_pins_to_sdhost();

    // Re-enable SDHOST peripheral clock
    unsafe { reg_set_bits(SYSTEM_PERIP_CLK_EN1, SDHOST_CLK_EN_BIT); }

    // Full clock re-setup: CLKDIV + CLKSRC + CLKENA
    // The SDHOST registers survive the GPIO swap, but the CIU clock output
    // stops when pins are disconnected. We must re-run the full clock sequence.
    let clk_ok = sdhost_set_clock(2); // 20MHz: 80/(2*2)

    // Give card time with clock running after reconnection
    delay.delay_millis(5);

    // Try fast re-select via CMD13 + CMD7. Live since 1.0.7: the exits below
    // deselect with CMD7(0) but keep the RCA, so a card that answered CMD13
    // in stand-by is selected in one command. Any other answer, or none (a
    // card swapped while the display had the pins, a card that lost power),
    // falls through to the full init as before.
    let t0 = esp_hal::time::Instant::now();
    let rca = CARD_RCA.load(core::sync::atomic::Ordering::Relaxed);
    let mut reselect_ok = false;
    if rca != 0 && clk_ok.is_ok() {
        // CMD13: SEND_STATUS — check if card is alive
        match sdhost_send_cmd(13, (rca as u32) << 16, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC) {
            Ok(status) => {
                let card_state = (status >> 9) & 0xF;
                if card_state == 3 {
                    // Standby → select via CMD7
                    if sdhost_send_cmd(7, (rca as u32) << 16, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC).is_ok() {
                        let _ = sdhost_wait_not_busy();
                        reselect_ok = true;
                    }
                } else if card_state == 4 {
                    // Already in transfer — no CMD7 needed
                    reselect_ok = true;
                }
            }
            Err(_) => {} // Card not responding — will fall back to full init
        }
    }

    if !reselect_ok {
        // Re-select failed or no RCA — full re-init
        match sdhost_init_card(delay) {
            Ok(ct) => { unsafe { BOOT_CARD_TYPE = ct; } }
            Err(e) => {
                restore_display_state(&saved);
                return Err(e);
            }
        }
    }
    log!("[SD] card ready via {} in {} ms",
        if reselect_ok { "CMD13+CMD7 reselect" } else { "full init" },
        (esp_hal::time::Instant::now() - t0).as_millis());

    // Run user closure
    crate::hw::sound::start_ticking();
    let result = f(unsafe { BOOT_CARD_TYPE });
    crate::hw::sound::stop_ticking();

    // After any SD operation, deselect the card so it releases D0 before
    // the display gets the pins back (see init_sdhost). The RCA is kept so
    // the next session can re-select instead of re-initialising.
    let _ = sdhost_send_cmd(7, 0, CMD_RESP_EXPECT); // CMD7 with RCA=0 → deselect

    // Disconnect SDHOST D0 input before restoring display
    unsafe {
        reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), 0xBC);
    }

    // Restore display
    restore_display_state(&saved);

    if result.is_ok() {
        crate::hw::sound::task_done(delay);
    }

    result
}

// ═══════════════════════════════════════════════════════════════
// FAT32 layer: kassigner-core::fat32, over the BlockDevice trait
// ═══════════════════════════════════════════════════════════════
//
// Until 1.0.7 the FAT32 filesystem, directory, chain and format code lived
// here, as one of two near-identical copies (the other in the M5 driver).
// It is now `kassigner_core::fat32`, once, generic over `BlockDevice`; this
// driver implements that trait for `SdCardType` over its own block I/O and
// re-exports the API, so every `sdcard::mount_fat32(ct)` and
// `sdcard::DirEntry` path in the firmware is unchanged.

pub use kassigner_core::fat32::{
    BlockDevice, BmpInfo, DirEntry, Fat32Info, FormatGeometry,
    allocate_chain, allocate_cluster, create_file, create_file_progress,
    csd_plausible, csd_sectors, delete_file, derive_geometry, do_format_fat32,
    find_fat32_partition, find_file_in_root, format_83_display, list_root_dir,
    list_root_dir_lfn, mount_fat32, overwrite_file, read_fat_entry, read_file,
    read_file_progress, to_83_name, verify_sector, write_fat_entry,
};

impl BlockDevice for SdCardType {
    fn read_block(self, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
        sd_read_block(self, block, buf)
    }
    fn write_block(self, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
        sd_write_block(self, block, buf)
    }
    fn read_multi(self, block: u32, out: &mut [u8], count: u32) -> Result<(), &'static str> {
        fast_read_multi_block(self, block, out, count)
    }
    fn write_multi(self, block: u32, data: &[u8], count: u32) -> Result<(), &'static str> {
        fast_write_multi_block(self, block, data, count)
    }
    fn card_sectors(self) -> Result<u32, &'static str> {
        read_card_sectors(self)
    }
}

// ═══════════════════════════════════════════════════════════════
// FAT32 Format — uses with_sd_card, so it stays with the transport
// ═══════════════════════════════════════════════════════════════

/// Format the SD card as FAT32 (superfloppy layout).
/// Uses with_sd_card internally — handles power-cycle + restore.
pub fn format_fat32<I2C: embedded_hal::i2c::I2c>(
    _card_type: SdCardType,
    i2c: &mut I2C,
    delay: &mut Delay,
) -> bool {
    log!("[SD-FMT] Formatting card as FAT32...");

    match with_sd_card(i2c, delay, |ct| {
        do_format_fat32(ct)
    }) {
        Ok(()) => {
            log!("[SD-FMT] Format complete!");
            true
        }
        Err(e) => {
            log!("[SD-FMT] Format failed: {}", e);
            false
        }
    }
}

/// Sector count for the card, read from its CSD during init.
///
/// See `CARD_SECTORS`: CMD9 is only answered in stand-by state, so the value
/// is captured there rather than asked for here. Without it the format is
/// refused: guessing a capacity is what produced a filesystem larger than the
/// FAT behind it, and probing for the card's end by reading past it leaves the
/// card in an error state where writes are acknowledged and discarded.
fn read_card_sectors(card_type: SdCardType) -> Result<u32, &'static str> {
    let _ = card_type;
    let sectors = CARD_SECTORS.load(core::sync::atomic::Ordering::Relaxed);
    if !csd_plausible(sectors) {
        return Err("Card capacity unknown");
    }
    Ok(sectors)
}
