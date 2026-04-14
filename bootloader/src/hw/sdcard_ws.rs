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

#[cfg(not(feature = "silent"))]
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
static mut CARD_RCA: u16 = 0;

/// Card type detected at boot
pub static mut BOOT_CARD_TYPE: SdCardType = SdCardType::None;

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
    unsafe { CARD_RCA = rca; }

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

    // Enable SDHOST peripheral (configures clock source in CLK_DIV_EDGE)
    sdhost_enable_peripheral();

    // Route GPIOs to SDHOST BEFORE reset/init — CIU needs clock path
    route_pins_to_sdhost();

    // Initialize card
    let result = sdhost_init_card(delay);

    // Restore display GPIO routing
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

    // Try fast re-select via CMD13 + CMD7
    let rca = unsafe { CARD_RCA };
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

    // Run user closure
    crate::hw::sound::start_ticking();
    let result = f(unsafe { BOOT_CARD_TYPE });
    crate::hw::sound::stop_ticking();

    // After any SD operation, deselect card and force full re-init next time.
    // This prevents stale card state after writes (programming not yet flushed).
    let _ = sdhost_send_cmd(7, 0, CMD_RESP_EXPECT); // CMD7 with RCA=0 → deselect
    unsafe { CARD_RCA = 0; }

    // Restore display
    restore_display_state(&saved);

    if result.is_ok() {
        crate::hw::sound::task_done(delay);
    }

    result
}

// ═══════════════════════════════════════════════════════════════
// Legacy API compatibility — these names are used by FAT32 layer
// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// FAT32 Filesystem Structures
// ═══════════════════════════════════════════════════════════════

/// FAT32 Boot Sector / BPB (BIOS Parameter Block)
#[derive(Debug, Clone)]
pub struct Fat32Info {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub fat_size_32: u32,
    pub root_cluster: u32,
    pub total_sectors: u32,
    pub fat_start_sector: u32,
    pub data_start_sector: u32,
}

impl Fat32Info {
    /// Parse FAT32 BPB from boot sector
    pub fn from_boot_sector(sector: &[u8; 512]) -> Result<Self, &'static str> {
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return Err("Invalid boot sector signature");
        }
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        if bytes_per_sector != 512 {
            return Err("Only 512-byte sectors supported");
        }
        let sectors_per_cluster = sector[13];
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err("Invalid sectors per cluster");
        }
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];
        if num_fats == 0 || num_fats > 2 {
            return Err("Invalid number of FATs");
        }
        let fat_size_32 = u32::from_le_bytes([sector[36], sector[37], sector[38], sector[39]]);
        let root_cluster = u32::from_le_bytes([sector[44], sector[45], sector[46], sector[47]]);
        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
        let total_sectors = if total_sectors_16 != 0 { total_sectors_16 as u32 } else { total_sectors_32 };
        let fat_start_sector = reserved_sectors as u32;
        let data_start_sector = fat_start_sector + (num_fats as u32 * fat_size_32);

        log!("[FAT32] spc={} reserved={} fats={} fat_sz={} root_cl={} data_start={}",
            sectors_per_cluster, reserved_sectors, num_fats, fat_size_32, root_cluster, data_start_sector);

        Ok(Self {
            bytes_per_sector, sectors_per_cluster, reserved_sectors, num_fats,
            fat_size_32, root_cluster, total_sectors, fat_start_sector, data_start_sector,
        })
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        if cluster < 2 { return self.data_start_sector; } // guard: cluster 0,1 = invalid
        self.data_start_sector.saturating_add(
            (cluster - 2).saturating_mul(self.sectors_per_cluster as u32)
        )
    }

    pub fn fat_sector_for_cluster(&self, cluster: u32) -> (u32, usize) {
        let fat_offset = cluster.saturating_mul(4);
        let sector = self.fat_start_sector.saturating_add(fat_offset / 512);
        let offset = (fat_offset % 512) as usize;
        (sector, offset)
    }

    pub fn cluster_bytes(&self) -> u32 {
        self.sectors_per_cluster as u32 * 512
    }
}

/// FAT32 directory entry (32 bytes)
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub name: [u8; 11],
    pub attr: u8,
    pub cluster_hi: u16,
    pub cluster_lo: u16,
    pub file_size: u32,
}

impl DirEntry {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 32 { return None; }
        if data[0] == 0x00 { return None; }
        if data[0] == 0xE5 { return None; }
        let attr = data[11];
        if attr == 0x0F { return None; }

        let mut name = [0u8; 11];
        name.copy_from_slice(&data[0..11]);
        let cluster_hi = u16::from_le_bytes([data[20], data[21]]);
        let cluster_lo = u16::from_le_bytes([data[26], data[27]]);
        let file_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        Some(Self { name, attr, cluster_hi, cluster_lo, file_size })
    }

    pub fn first_cluster(&self) -> u32 {
        ((self.cluster_hi as u32) << 16) | (self.cluster_lo as u32)
    }

    pub fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }

    pub fn matches(&self, name_83: &[u8; 11]) -> bool {
        for i in 0..11 {
            let a = self.name[i].to_ascii_uppercase();
            let b = name_83[i].to_ascii_uppercase();
            if a != b { return false; }
        }
        true
    }
}

/// Convert filename like "IMAGE.BMP" to 8.3 format
pub fn to_83_name(filename: &[u8]) -> [u8; 11] {
    let mut result = [b' '; 11];
    let dot_pos = filename.iter().position(|&c| c == b'.').unwrap_or(filename.len());
    let base_len = dot_pos.min(8);
    for i in 0..base_len {
        result[i] = filename[i].to_ascii_uppercase();
    }
    if dot_pos < filename.len() {
        let ext = &filename[dot_pos + 1..];
        for i in 0..3.min(ext.len()) {
            result[8 + i] = ext[i].to_ascii_uppercase();
        }
    }
    result
}

// ═══════════════════════════════════════════════════════════════
// FAT32 Cluster Chain Operations
// ═══════════════════════════════════════════════════════════════

pub fn read_fat_entry(card_type: SdCardType, fat32: &Fat32Info, cluster: u32) -> Result<u32, &'static str> {
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    if offset + 3 >= 512 { return Err("FAT offset out of range"); }
    let mut buf = [0u8; 512];
    sd_read_block(card_type, sector, &mut buf)?;
    let entry = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
    Ok(entry & 0x0FFF_FFFF)
}

pub fn write_fat_entry(card_type: SdCardType, fat32: &Fat32Info, cluster: u32, value: u32) -> Result<(), &'static str> {
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    let mut buf = [0u8; 512];

    sd_read_block(card_type, sector, &mut buf)?;
    let existing = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
    let new_val = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let bytes = new_val.to_le_bytes();
    buf[offset] = bytes[0]; buf[offset+1] = bytes[1];
    buf[offset+2] = bytes[2]; buf[offset+3] = bytes[3];
    sd_write_block(card_type, sector, &buf)?;

    if fat32.num_fats > 1 {
        let fat2_sector = sector + fat32.fat_size_32;
        sd_read_block(card_type, fat2_sector, &mut buf)?;
        let existing2 = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
        let new_val2 = (existing2 & 0xF000_0000) | (value & 0x0FFF_FFFF);
        let bytes2 = new_val2.to_le_bytes();
        buf[offset] = bytes2[0]; buf[offset+1] = bytes2[1];
        buf[offset+2] = bytes2[2]; buf[offset+3] = bytes2[3];
        sd_write_block(card_type, fat2_sector, &buf)?;
    }

    Ok(())
}

pub fn allocate_cluster(card_type: SdCardType, fat32: &Fat32Info, start_hint: u32) -> Result<u32, &'static str> {
    let max_cluster = 2 + (fat32.total_sectors - fat32.data_start_sector) / fat32.sectors_per_cluster as u32;
    let mut buf = [0u8; 512];
    let mut last_sector = 0xFFFF_FFFFu32;

    let mut cluster = if (2..max_cluster).contains(&start_hint) { start_hint } else { 2 };
    let start = cluster;
    loop {
        let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
        if sector != last_sector {
            sd_read_block(card_type, sector, &mut buf)?;
            last_sector = sector;
        }
        let entry = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
        if (entry & 0x0FFF_FFFF) == 0 {
            write_fat_entry(card_type, fat32, cluster, 0x0FFF_FFFF)?;
            log!("[FAT32] Allocated cluster {}", cluster);
            return Ok(cluster);
        }
        cluster += 1;
        if cluster >= max_cluster { cluster = 2; }
        if cluster == start { return Err("Disk full"); }
    }
}

pub fn allocate_chain(card_type: SdCardType, fat32: &Fat32Info, count: u32) -> Result<u32, &'static str> {
    if count == 0 { return Err("Zero clusters requested"); }

    let first = allocate_cluster(card_type, fat32, 2)?;
    let mut prev = first;

    for _ in 1..count {
        let next = allocate_cluster(card_type, fat32, prev + 1)?;
        write_fat_entry(card_type, fat32, prev, next)?;
        prev = next;
    }

    Ok(first)
}

// ═══════════════════════════════════════════════════════════════
// FAT32 Directory Operations
// ═══════════════════════════════════════════════════════════════

pub fn mount_fat32(card_type: SdCardType) -> Result<Fat32Info, &'static str> {
    let mut sector = [0u8; 512];
    sd_read_block(card_type, 0, &mut sector)?;

    log!("[FAT32] Sector 0: {:02x} {:02x} {:02x} .. sig={:02x}{:02x}",
        sector[0], sector[1], sector[2], sector[510], sector[511]);

    if (sector[0] == 0xEB || sector[0] == 0xE9) && sector[510] == 0x55 && sector[511] == 0xAA {
        log!("[FAT32] Trying superfloppy (BPB at sector 0)");
        if let Ok(info) = Fat32Info::from_boot_sector(&sector) {
            return Ok(info);
        }
    }

    if sector[510] == 0x55 && sector[511] == 0xAA {
        log!("[FAT32] Trying MBR partition table");
        if let Ok(lba) = find_fat32_partition(&sector) {
            if lba > 0 {
                sd_read_block(card_type, lba, &mut sector)?;
                let mut info = Fat32Info::from_boot_sector(&sector)?;
                info.fat_start_sector += lba;
                info.data_start_sector += lba;
                return Ok(info);
            }
        }
    }

    for &probe_lba in &[2048u32, 8192, 32768, 1] {
        if sd_read_block(card_type, probe_lba, &mut sector).is_ok()
            && (sector[0] == 0xEB || sector[0] == 0xE9) && sector[510] == 0x55 && sector[511] == 0xAA
        {
                log!("[FAT32] Found BPB at sector {}", probe_lba);
                if let Ok(mut info) = Fat32Info::from_boot_sector(&sector) {
                    info.fat_start_sector += probe_lba;
                    info.data_start_sector += probe_lba;
                    return Ok(info);
                }
        }
    }

    Err("No FAT32 filesystem found")
}

pub fn find_file_in_root(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(DirEntry, u32, usize), &'static str> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            sd_read_block(card_type, base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                if buf[off] == 0x00 { return Err("File not found"); }
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    if entry.matches(name_83) {
                        return Ok((entry, base_sector + s, off));
                    }
                }
            }
        }
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 { break; }
        cluster = next;
    }
    Err("File not found")
}

pub fn read_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    read_file_progress(card_type, fat32, entry, out, &mut |_, _| {})
}

/// Read a file with progress callback. Callback receives (bytes_read, total_bytes).
pub fn read_file_progress(
    card_type: SdCardType,
    fat32: &Fat32Info,
    entry: &DirEntry,
    out: &mut [u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<usize, &'static str> {
    let file_size = entry.file_size as usize;
    if out.len() < file_size {
        return Err("Buffer too small");
    }

    let mut cluster = entry.first_cluster();
    let mut remaining = file_size;
    let mut pos = 0usize;
    let spc = fat32.sectors_per_cluster as u32;
    let mut chain_steps = 0u32;
    // Max clusters a file can span: file_size / cluster_bytes + 1, capped at 16384
    // Prevents infinite loop on circular FAT chain
    let max_chain = ((file_size as u32 / fat32.cluster_bytes()).saturating_add(2)).min(16384);

    while remaining > 0 && (2..0x0FFF_FFF8).contains(&cluster) {
        chain_steps += 1;
        if chain_steps > max_chain { return Err("FAT chain too long"); }
        let base_sector = fat32.cluster_to_sector(cluster);
        // How many full sectors do we need from this cluster?
        let sectors_needed = ((remaining + 511) / 512).min(spc as usize) as u32;
        let _bytes_in_cluster = (sectors_needed as usize * 512).min(remaining + 511);

        if sectors_needed > 1 && pos + (sectors_needed as usize * 512) <= out.len() {
            // Multi-block read: all sectors in this cluster at once
            fast_read_multi_block(card_type, base_sector, &mut out[pos..], sectors_needed)?;
            let actual = remaining.min(sectors_needed as usize * 512);
            pos += actual;
            remaining -= actual;
        } else {
            // Fallback: single-block for partial cluster or buffer edge
            let mut sector_buf = [0u8; 512];
            for s in 0..spc {
                if remaining == 0 { break; }
                sd_read_block(card_type, base_sector + s, &mut sector_buf)?;
                let chunk = if remaining >= 512 { 512 } else { remaining };
                out[pos..pos+chunk].copy_from_slice(&sector_buf[..chunk]);
                pos += chunk;
                remaining -= chunk;
            }
        }
        progress(pos, file_size);
        if remaining > 0 {
            cluster = read_fat_entry(card_type, fat32, cluster)?;
        }
    }

    Ok(pos)
}
/// Create a new file in the root directory. Allocates clusters and writes data.
/// Returns the created DirEntry.
pub fn create_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<DirEntry, &'static str> {
    create_file_progress(card_type, fat32, name_83, data, &mut |_, _| {})
}

/// Create a file on SD with progress callback. Callback receives (bytes_written, total_bytes).
pub fn create_file_progress(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
    progress: &mut dyn FnMut(usize, usize),
) -> Result<DirEntry, &'static str> {
    let file_size = data.len() as u32;
    let cluster_bytes = fat32.cluster_bytes();
    let clusters_needed = if file_size == 0 { 0 } else { (file_size + cluster_bytes - 1) / cluster_bytes };

    let first_cluster = if clusters_needed > 0 {
        allocate_chain(card_type, fat32, clusters_needed)?
    } else {
        0
    };

    if clusters_needed > 0 {
        let mut cluster = first_cluster;
        let mut remaining = data.len();
        let mut pos = 0usize;
        let total = data.len();
        let spc = fat32.sectors_per_cluster as u32;

        while remaining > 0 && (2..0x0FFF_FFF8).contains(&cluster) {
            let base_sector = fat32.cluster_to_sector(cluster);
            // How many full sectors can we write from the data?
            let full_sectors = (remaining / 512).min(spc as usize) as u32;

            if full_sectors > 1 {
                // Multi-block write for full sectors
                let write_bytes = full_sectors as usize * 512;
                fast_write_multi_block(card_type, base_sector, &data[pos..pos + write_bytes], full_sectors)?;
                pos += write_bytes;
                remaining -= write_bytes;
            }

            // Handle remaining sectors in this cluster (partial last sector or single sector)
            let sectors_done = full_sectors;
            for s in sectors_done..spc {
                let mut sector_buf = [0u8; 512];
                if remaining == 0 {
                    sd_write_block(card_type, base_sector + s, &sector_buf)?;
                    continue;
                }
                let chunk = if remaining >= 512 { 512 } else { remaining };
                sector_buf[..chunk].copy_from_slice(&data[pos..pos+chunk]);
                sd_write_block(card_type, base_sector + s, &sector_buf)?;
                pos += chunk;
                remaining -= chunk;
            }

            progress(pos, total);
            if remaining > 0 {
                cluster = read_fat_entry(card_type, fat32, cluster)?;
            }
        }
    }

    let entry = DirEntry {
        name: *name_83,
        attr: 0x20,
        cluster_hi: (first_cluster >> 16) as u16,
        cluster_lo: first_cluster as u16,
        file_size,
    };

    write_dir_entry_to_root(card_type, fat32, &entry)?;

    log!("[FAT32] Created file {:?} size={} cluster={}", 
        core::str::from_utf8(name_83).unwrap_or("?"), file_size, first_cluster);

    Ok(entry)
}

/// Write a DirEntry into the first free slot in root directory.
fn write_dir_entry_to_root(
    card_type: SdCardType,
    fat32: &Fat32Info,
    entry: &DirEntry,
) -> Result<(), &'static str> {
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            sd_read_block(card_type, base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                // Free slot: 0x00 (end of dir) or 0xE5 (deleted)
                if buf[off] == 0x00 || buf[off] == 0xE5 {
                    // Write the entry
                    buf[off..off+11].copy_from_slice(&entry.name);
                    buf[off+11] = entry.attr;
                    buf[off+12..off+20].fill(0); // reserved + create time/date
                    let chi = entry.cluster_hi.to_le_bytes();
                    buf[off+20] = chi[0]; buf[off+21] = chi[1];
                    buf[off+22..off+26].fill(0); // modify time/date
                    let clo = entry.cluster_lo.to_le_bytes();
                    buf[off+26] = clo[0]; buf[off+27] = clo[1];
                    let fsz = entry.file_size.to_le_bytes();
                    buf[off+28] = fsz[0]; buf[off+29] = fsz[1];
                    buf[off+30] = fsz[2]; buf[off+31] = fsz[3];

                    // If this was end-of-dir marker, add new end marker after
                    if off + 32 < 512 && buf[off] == 0x00 {
                        // Actually we just overwrote 0x00, so mark next entry as end
                        // (only if within same sector and next slot is also 0x00 already)
                    }

                    sd_write_block(card_type, base_sector + s, &buf)?;
                    return Ok(());
                }
            }
        }
        // Follow cluster chain; allocate new cluster if needed
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 {
            // Allocate new cluster for directory
            let new_cl = allocate_cluster(card_type, fat32, cluster + 1)?;
            write_fat_entry(card_type, fat32, cluster, new_cl)?;
            // Zero out the new cluster
            let zeros = [0u8; 512];
            let new_base = fat32.cluster_to_sector(new_cl);
            for s in 0..fat32.sectors_per_cluster as u32 {
                sd_write_block(card_type, new_base + s, &zeros)?;
            }
            cluster = new_cl;
        } else {
            cluster = next;
        }
    }
}

/// Delete a file from the root directory (marks entry as deleted, frees cluster chain).
pub fn delete_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
) -> Result<(), &'static str> {
    let (entry, sector, offset) = find_file_in_root(card_type, fat32, name_83)?;

    // Free cluster chain
    let mut cluster = entry.first_cluster();
    while (2..0x0FFF_FFF8).contains(&cluster) {
        let next = read_fat_entry(card_type, fat32, cluster)?;
        write_fat_entry(card_type, fat32, cluster, 0)?; // mark free
        cluster = next;
    }

    // Mark directory entry as deleted (0xE5)
    let mut buf = [0u8; 512];
    sd_read_block(card_type, sector, &mut buf)?;
    buf[offset] = 0xE5;
    sd_write_block(card_type, sector, &buf)?;

    log!("[FAT32] Deleted file");
    Ok(())
}

/// Overwrite an existing file's contents. If new data is larger, extends the chain.
/// If smaller, truncates. Updates the directory entry's file_size.
pub fn overwrite_file(
    card_type: SdCardType,
    fat32: &Fat32Info,
    name_83: &[u8; 11],
    data: &[u8],
) -> Result<(), &'static str> {
    let _ = delete_file(card_type, fat32, name_83);
    create_file(card_type, fat32, name_83, data)?;
    Ok(())
}
/// List files in root directory. Calls callback for each entry.
/// Callback returns true to continue, false to stop.
pub fn list_root_dir<F>(
    card_type: SdCardType,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), &'static str>
where
    F: FnMut(&DirEntry) -> bool,
{
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            sd_read_block(card_type, base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                if buf[off] == 0x00 { return Ok(()); } // end of dir
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    // Skip volume label entries
                    if entry.attr & 0x08 != 0 { continue; }
                    if !callback(&entry) { return Ok(()); }
                }
            }
        }
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 { break; }
        cluster = next;
    }
    Ok(())
}

/// List root directory with LFN (Long File Name) support.
/// Callback receives (&DirEntry, &display_name, display_name_len).
/// display_name contains the LFN if available, otherwise the formatted 8.3 name.
pub fn list_root_dir_lfn<F>(
    card_type: SdCardType,
    fat32: &Fat32Info,
    mut callback: F,
) -> Result<(), &'static str>
where
    F: FnMut(&DirEntry, &[u8; 64], usize) -> bool,
{
    let mut cluster = fat32.root_cluster;
    let mut buf = [0u8; 512];
    // LFN accumulator: up to 4 LFN entries = 52 chars max
    let mut lfn_buf = [0u8; 64];
    #[allow(unused_assignments)]
    let mut lfn_len: usize = 0;
    let mut lfn_parts: [([u8; 26], u8); 4] = [([0; 26], 0); 4]; // (utf16_bytes, seq_num)
    let mut lfn_part_count: usize = 0;

    loop {
        let base_sector = fat32.cluster_to_sector(cluster);
        for s in 0..fat32.sectors_per_cluster as u32 {
            sd_read_block(card_type, base_sector + s, &mut buf)?;
            for i in 0..16 {
                let off = i * 32;
                if buf[off] == 0x00 { return Ok(()); }
                if buf[off] == 0xE5 {
                    lfn_part_count = 0;
                    continue;
                }

                let attr = buf[off + 11];
                if attr == 0x0F {
                    // LFN entry: extract sequence number and UTF-16 chars
                    let seq = buf[off] & 0x3F;
                    if (1..=4).contains(&seq) && (lfn_part_count < 4) {
                        let idx = (seq - 1) as usize;
                        // Extract 13 UTF-16LE chars (26 bytes) from specific offsets
                        let mut utf16 = [0u8; 26];
                        // Chars 1-5: offset 1..10
                        utf16[0..10].copy_from_slice(&buf[off+1..off+11]);
                        // Chars 6-11: offset 14..25
                        utf16[10..22].copy_from_slice(&buf[off+14..off+26]);
                        // Chars 12-13: offset 28..31
                        utf16[22..26].copy_from_slice(&buf[off+28..off+32]);
                        lfn_parts[idx] = (utf16, seq);
                        if idx + 1 > lfn_part_count { lfn_part_count = idx + 1; }
                    }
                    continue;
                }

                // Regular entry — check if we have LFN parts
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    if entry.attr & 0x08 != 0 {
                        lfn_part_count = 0;
                        continue;
                    }

                    // Build display name
                    lfn_len = 0;
                    if lfn_part_count > 0 {
                        // Reconstruct LFN from parts (in order: part 1, 2, 3...)
                        for p in 0..lfn_part_count {
                            let (ref utf16, _) = lfn_parts[p];
                            // Convert UTF-16LE to ASCII (13 chars per part)
                            for c in 0..13 {
                                let lo = utf16[c * 2];
                                let hi = utf16[c * 2 + 1];
                                if lo == 0xFF && hi == 0xFF { break; } // padding
                                if lo == 0x00 && hi == 0x00 { break; } // null terminator
                                if lfn_len >= 63 { break; }
                                // ASCII printable range + extended Latin-1 common chars
                                if hi == 0 && (0x20..0x7F).contains(&lo) {
                                    lfn_buf[lfn_len] = lo;
                                    lfn_len += 1;
                                } else if hi == 0 && lo >= 0x80 {
                                    // Extended Latin-1 — map to closest ASCII
                                    let mapped = match lo {
                                        0xC0..=0xC5 => b'A', // À-Å
                                        0xC7 => b'C',        // Ç
                                        0xC8..=0xCB => b'E', // È-Ë
                                        0xCC..=0xCF => b'I', // Ì-Ï
                                        0xD1 => b'N',        // Ñ
                                        0xD2..=0xD6 => b'O', // Ò-Ö
                                        0xD9..=0xDC => b'U', // Ù-Ü
                                        0xE0..=0xE5 => b'a', // à-å
                                        0xE7 => b'c',        // ç
                                        0xE8..=0xEB => b'e', // è-ë
                                        0xEC..=0xEF => b'i', // ì-ï
                                        0xF1 => b'n',        // ñ
                                        0xF2..=0xF6 => b'o', // ò-ö
                                        0xF9..=0xFC => b'u', // ù-ü
                                        0xA0 => b' ',        // non-breaking space
                                        _ => b'_',           // other extended → underscore
                                    };
                                    lfn_buf[lfn_len] = mapped;
                                    lfn_len += 1;
                                } else if hi > 0 {
                                    // True Unicode (hi byte set) — replace with underscore
                                    lfn_buf[lfn_len] = b'_';
                                    lfn_len += 1;
                                }
                            }
                        }
                    }

                    if lfn_len == 0 {
                        // No LFN — format 8.3 name
                        let mut disp = [0u8; 13];
                        let dlen = crate::hw::sd_backup::format_83_display(&entry.name, &mut disp);
                        lfn_buf[..dlen].copy_from_slice(&disp[..dlen]);
                        lfn_len = dlen;
                    }

                    lfn_part_count = 0;
                    if !callback(&entry, &lfn_buf, lfn_len) { return Ok(()); }
                } else {
                    lfn_part_count = 0;
                }
            }
        }
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 { break; }
        cluster = next;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// BMP Image Parser
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
/// Parsed BMP image header information.
pub struct BmpInfo {
    pub width: u32,
    pub height: u32,
    pub bits_per_pixel: u16,
    pub data_offset: u32,
    pub row_stride: u32,
    pub top_down: bool,
}

impl BmpInfo {
}

fn find_fat32_partition(mbr: &[u8; 512]) -> Result<u32, &'static str> {
    for i in 0..4 {
        let base = 0x1BE + i * 16;
        let part_type = mbr[base + 4];
        if part_type == 0x0B || part_type == 0x0C {
            let lba = u32::from_le_bytes([
                mbr[base + 8], mbr[base + 9], mbr[base + 10], mbr[base + 11]
            ]);
            log!("[MBR] FAT32 partition {} at LBA {}", i, lba);
            return Ok(lba);
        }
    }
    if mbr[0] == 0xEB || mbr[0] == 0xE9 {
        log!("[MBR] No partition table, trying superfloppy");
        return Ok(0);
    }
    Err("No FAT32 partition found")
}

// ═══════════════════════════════════════════════════════════════
// FAT32 Format
// ═══════════════════════════════════════════════════════════════

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

fn do_format_fat32(card_type: SdCardType) -> Result<(), &'static str> {
    let mut test = [0u8; 512];
    sd_read_block(card_type, 0, &mut test)?;
    log!("[SD-FMT] MBR read OK sig={:02x}{:02x}", test[510], test[511]);

    let sectors_per_cluster: u8 = 64;
    let reserved_sectors: u16 = 32;
    let num_fats: u8 = 2;
    let fat_size: u32 = 1024;
    let root_cluster: u32 = 2;
    let total_sectors: u32 = 0x00F00000;

    let mut bpb = [0u8; 512];
    bpb[0] = 0xEB; bpb[1] = 0x58; bpb[2] = 0x90;
    bpb[3..11].copy_from_slice(b"MSDOS5.0");
    bpb[11] = 0x00; bpb[12] = 0x02;
    bpb[13] = sectors_per_cluster;
    bpb[14] = reserved_sectors as u8; bpb[15] = (reserved_sectors >> 8) as u8;
    bpb[16] = num_fats;
    bpb[21] = 0xF8;
    bpb[24] = 0x3F; bpb[26] = 0xFF;
    bpb[32] = total_sectors as u8; bpb[33] = (total_sectors >> 8) as u8;
    bpb[34] = (total_sectors >> 16) as u8; bpb[35] = (total_sectors >> 24) as u8;
    bpb[36] = fat_size as u8; bpb[37] = (fat_size >> 8) as u8;
    bpb[38] = (fat_size >> 16) as u8; bpb[39] = (fat_size >> 24) as u8;
    bpb[44] = root_cluster as u8; bpb[45] = (root_cluster >> 8) as u8;
    bpb[48] = 1; bpb[50] = 6;
    bpb[66] = 0x29;
    bpb[67] = 0x4B; bpb[68] = 0x53; bpb[69] = 0x53; bpb[70] = 0x00;
    bpb[71..82].copy_from_slice(b"KASSIGNER  ");
    bpb[82..90].copy_from_slice(b"FAT32   ");
    bpb[510] = 0x55; bpb[511] = 0xAA;

    sd_write_block(card_type, 0, &bpb)?;
    sd_write_block(card_type, 6, &bpb)?;

    let mut fsinfo = [0u8; 512];
    fsinfo[0] = 0x52; fsinfo[1] = 0x52; fsinfo[2] = 0x61; fsinfo[3] = 0x41;
    fsinfo[484] = 0x72; fsinfo[485] = 0x72; fsinfo[486] = 0x41; fsinfo[487] = 0x61;
    fsinfo[488] = 0xFF; fsinfo[489] = 0xFF; fsinfo[490] = 0xFF; fsinfo[491] = 0xFF;
    fsinfo[492] = 0x03;
    fsinfo[510] = 0x55; fsinfo[511] = 0xAA;
    sd_write_block(card_type, 1, &fsinfo)?;

    let zeros = [0u8; 512];
    for s in 2..reserved_sectors as u32 {
        if s == 6 { continue; }
        let _ = sd_write_block(card_type, s, &zeros);
    }

    let mut fat_first = [0u8; 512];
    fat_first[0] = 0xF8; fat_first[1] = 0xFF; fat_first[2] = 0xFF; fat_first[3] = 0x0F;
    fat_first[4] = 0xFF; fat_first[5] = 0xFF; fat_first[6] = 0xFF; fat_first[7] = 0x0F;
    fat_first[8] = 0xFF; fat_first[9] = 0xFF; fat_first[10] = 0xFF; fat_first[11] = 0x0F;
    let fat1_start = reserved_sectors as u32;
    let fat2_start = fat1_start + fat_size;
    sd_write_block(card_type, fat1_start, &fat_first)?;
    sd_write_block(card_type, fat2_start, &fat_first)?;
    for i in 1..32u32.min(fat_size) {
        let _ = sd_write_block(card_type, fat1_start + i, &zeros);
        let _ = sd_write_block(card_type, fat2_start + i, &zeros);
    }

    let data_start = reserved_sectors as u32 + num_fats as u32 * fat_size;
    for i in 0..sectors_per_cluster as u32 {
        let _ = sd_write_block(card_type, data_start + i, &zeros);
    }

    Ok(())
}
