// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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


// hw/sdcard.rs — MicroSD card driver (bitbang SPI + FAT32 + LFN)
// 100% Rust, no-std, no-alloc
//
// Hardware: MicroSD slot (SPI mode) sharing SPI bus with ILI9342C LCD
//   - SPI_SCK  = GPIO36 (shared with LCD)
//   - SPI_MOSI = GPIO37 (shared with LCD)
//   - SPI_MISO = GPIO35 (shared with LCD DC! — mux switching required)
//   - SD_CS    = GPIO4
//   - LCD_CS   = GPIO3
//   - TF_SW    = card detect (active low, 10K pullup)
//
// Architecture: `with_sd_card` pattern
//   All post-boot SD access goes through with_sd_card(), which:
//   1. Saves SPI2 peripheral + IO_MUX state
//   2. Reclaims GPIOs from SPI peripheral for bitbang
//   3. Power-cycles SD via ALDO4 (AXP2101)
//   4. Re-inits SD card via bitbang
//   5. Runs the user's closure with active card
//   6. Restores SPI2 + IO_MUX so LCD works again
//
// SD Card Protocol (SPI mode):
//   CMD0  → GO_IDLE_STATE (reset, enter SPI mode)
//   CMD8  → SEND_IF_COND  (voltage check, SDv2 detection)
//   CMD58 → READ_OCR      (voltage window)
//   CMD55 + ACMD41 → SD_SEND_OP_COND (initialize card)
//   CMD16 → SET_BLOCKLEN  (512 bytes)
//   CMD17 → READ_SINGLE_BLOCK
//   CMD24 → WRITE_BLOCK

#![allow(dead_code)]
#![allow(static_mut_refs)]
#[cfg(not(feature = "silent"))]

use crate::log;
use esp_hal::delay::Delay;

// ═══════════════════════════════════════════════════════════════
// ESP32-S3 Register Addresses
// ═══════════════════════════════════════════════════════════════

// GPIO registers
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

// GPIO FUNC_OUT_SEL base
const GPIO_FUNC_OUT_SEL_BASE: u32 = 0x6000_4554;

// IO_MUX base
const IO_MUX_BASE: u32 = 0x6000_9004;

// SPI2 registers (needed for LCD state save/restore AND hardware SD transfers)
const SPI2_CLOCK_REG: u32 = 0x6002_400C;
const SPI2_USER_REG: u32  = 0x6002_4010;
const SPI2_CMD_REG: u32   = 0x6002_4000;
const SPI2_CTRL_REG: u32  = 0x6002_4008;
const SPI2_MS_DLEN_REG: u32 = 0x6002_401C;
const SPI2_MISC_REG: u32  = 0x6002_4020;
const SPI2_W0_REG: u32    = 0x6002_4098;  // data buffer start (confirmed writable)

// GPIO FUNC_IN_SEL for FSPIQ (SPI2 MISO input) — signal 102
const GPIO_FUNC_IN_SEL_BASE: u32 = 0x6000_4154;
const FSPIQ_IN_SIGNAL: u32 = 102;

// SPI2 output signals
const FSPICLK_OUT_SIGNAL: u32 = 63;
const FSPID_OUT_SIGNAL: u32   = 64;

/// Whether to use SPI2 hardware for block transfers (set after spi2_sd_init)
static mut USE_HW_SPI2: bool = false;

// GPIO pin numbers
const PIN_LCD_CS: u8  = 3;   // GPIO3  — LCD chip select
const PIN_SD_CS: u8   = 4;   // GPIO4  — SD card chip select
const PIN_MISO: u8    = 35;  // GPIO35 — shared with LCD DC
const PIN_SCK: u8     = 36;  // GPIO36 — SPI clock
const PIN_MOSI: u8    = 37;  // GPIO37 — SPI data out

// SD Card commands (SPI mode)
const CMD0: u8   = 0;   // GO_IDLE_STATE
const CMD8: u8   = 8;   // SEND_IF_COND
const CMD12: u8  = 12;  // STOP_TRANSMISSION (multi-block stop)
const CMD16: u8  = 16;  // SET_BLOCKLEN
const CMD17: u8  = 17;  // READ_SINGLE_BLOCK
const CMD18: u8  = 18;  // READ_MULTIPLE_BLOCK
const CMD24: u8  = 24;  // WRITE_BLOCK
const CMD25: u8  = 25;  // WRITE_MULTIPLE_BLOCK
const CMD55: u8  = 55;  // APP_CMD
const CMD58: u8  = 58;  // READ_OCR
const ACMD41: u8 = 41;  // SD_SEND_OP_COND

/// Whether to use fast (no-delay) bitbang for block I/O.
/// Set to true inside with_sd_card after successful init.
static mut USE_FAST_SPI: bool = false;

/// Internal dispatch: read block using SPI2 hardware, fast bitbang, or slow bitbang
pub fn sd_read_block(card_type: SdCardType, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
    if unsafe { USE_HW_SPI2 } {
        spi2_read_block(card_type, block, buf)
    } else if unsafe { USE_FAST_SPI } {
        fast_read_block(card_type, block, buf)
    } else {
        bb_read_block(card_type, block, buf)
    }
}

/// Internal dispatch: write block using SPI2 hardware, fast bitbang, or slow bitbang
fn sd_write_block(card_type: SdCardType, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
    if unsafe { USE_HW_SPI2 } {
        spi2_write_block(card_type, block, buf)
    } else if unsafe { USE_FAST_SPI } {
        fast_write_block(card_type, block, buf)
    } else {
        bb_write_block(card_type, block, buf)
    }
}

/// SD card type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SdCardType {
    None,
    SdV1,    // SD v1 (byte addressing)
    SdV2Sc,  // SD v2 Standard Capacity (byte addressing)
    SdV2Hc,  // SD v2 High/Extended Capacity (block addressing)
}

// ═══════════════════════════════════════════════════════════════
// Low-level GPIO helpers
// ═══════════════════════════════════════════════════════════════

#[inline(always)]
fn gpio_set(pin: u8) {
    unsafe {
        if pin < 32 {
            core::ptr::write_volatile(GPIO_OUT_W1TS as *mut u32, 1u32 << pin);
        } else {
            core::ptr::write_volatile(GPIO_OUT1_W1TS as *mut u32, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
fn gpio_clear(pin: u8) {
    unsafe {
        if pin < 32 {
            core::ptr::write_volatile(GPIO_OUT_W1TC as *mut u32, 1u32 << pin);
        } else {
            core::ptr::write_volatile(GPIO_OUT1_W1TC as *mut u32, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
fn gpio_read(pin: u8) -> bool {
    unsafe {
        if pin < 32 {
            (core::ptr::read_volatile(GPIO_IN_REG as *const u32) >> pin) & 1 != 0
        } else {
            (core::ptr::read_volatile(GPIO_IN1_REG as *const u32) >> (pin - 32)) & 1 != 0
        }
    }
}

#[inline(always)]
fn gpio_enable_output(pin: u8) {
    unsafe {
        if pin < 32 {
            core::ptr::write_volatile(GPIO_ENABLE_W1TS as *mut u32, 1u32 << pin);
        } else {
            core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, 1u32 << (pin - 32));
        }
    }
}

#[inline(always)]
fn gpio_disable_output(pin: u8) {
    unsafe {
        if pin < 32 {
            core::ptr::write_volatile(GPIO_ENABLE_W1TC as *mut u32, 1u32 << pin);
        } else {
            core::ptr::write_volatile(GPIO_ENABLE1_W1TC as *mut u32, 1u32 << (pin - 32));
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

// ═══════════════════════════════════════════════════════════════
// Bitbang SPI — used for all SD card access
// ═══════════════════════════════════════════════════════════════

/// ~5µs delay for ~100kHz bitbang clock
#[inline(always)]
fn bb_delay() {
    for _ in 0..300u32 {
        unsafe { core::ptr::read_volatile(0x6000_403Cu32 as *const u32); }
    }
}

/// Bitbang: transfer one byte (full-duplex, SPI Mode 0)
fn bb_transfer(tx: u8) -> u8 {
    let mut rx = 0u8;
    for bit in (0..8).rev() {
        if (tx >> bit) & 1 == 1 { gpio_set(PIN_MOSI); } else { gpio_clear(PIN_MOSI); }
        gpio_clear(PIN_SCK);
        bb_delay();
        gpio_set(PIN_SCK);
        bb_delay();
        if gpio_read(PIN_MISO) { rx |= 1 << bit; }
    }
    rx
}

fn sd_crc7(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            let msb = (crc >> 6) & 1;
            crc = (crc << 1) | bit;
            if msb ^ ((crc >> 7) & 1) != 0 {
                crc ^= 0x09;
            }
        }
    }
    (crc << 1) | 1
}

/// Bitbang: send SD command, return R1 response
fn bb_sd_cmd(cmd: u8, arg: u32) -> u8 {
    let frame = [
        0x40 | cmd,
        (arg >> 24) as u8,
        (arg >> 16) as u8,
        (arg >> 8) as u8,
        arg as u8,
    ];
    let crc = if cmd == CMD0 { 0x95 }
              else if cmd == CMD8 { 0x87 }
              else { sd_crc7(&frame) };

    bb_transfer(0xFF);
    for &b in &frame { bb_transfer(b); }
    bb_transfer(crc);

    for _ in 0..64 {
        let r = bb_transfer(0xFF);
        if r & 0x80 == 0 { return r; }
    }
    0xFF
}

/// Bitbang: send ACMD (CMD55 + cmd)
fn bb_sd_acmd(cmd: u8, arg: u32) -> u8 {
    bb_sd_cmd(CMD55, 0);
    bb_sd_cmd(cmd, arg)
}

// ═══════════════════════════════════════════════════════════════
// GPIO init / reclaim / release for bitbang
// ═══════════════════════════════════════════════════════════════

/// Configure GPIOs for bitbang SPI (call before esp-hal takes SPI2 pins)
pub fn bb_gpio_init() {
    unsafe {
        // GPIO4 = SD_CS output, HIGH
        let iomux4 = iomux_addr(4) as *mut u32;
        let v = core::ptr::read_volatile(iomux4);
        core::ptr::write_volatile(iomux4, (v & !0x7000) | 0x1000);
        core::ptr::write_volatile(func_out_sel_addr(4) as *mut u32, 256);
        core::ptr::write_volatile(GPIO_ENABLE_W1TS as *mut u32, 1u32 << 4);
        core::ptr::write_volatile(GPIO_OUT_W1TS as *mut u32, 1u32 << 4);

        // GPIO36 = SCK output, LOW idle
        let iomux36 = iomux_addr(36) as *mut u32;
        let v = core::ptr::read_volatile(iomux36);
        core::ptr::write_volatile(iomux36, (v & !0x7000) | 0x1000);
        core::ptr::write_volatile(func_out_sel_addr(36) as *mut u32, 256);
        core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, 1u32 << 4);
        core::ptr::write_volatile(GPIO_OUT1_W1TC as *mut u32, 1u32 << 4);

        // GPIO37 = MOSI output, HIGH idle
        let iomux37 = iomux_addr(37) as *mut u32;
        let v = core::ptr::read_volatile(iomux37);
        core::ptr::write_volatile(iomux37, (v & !0x7000) | 0x1000);
        core::ptr::write_volatile(func_out_sel_addr(37) as *mut u32, 256);
        core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, 1u32 << 5);
        core::ptr::write_volatile(GPIO_OUT1_W1TS as *mut u32, 1u32 << 5);

        // GPIO35 = MISO input
        core::ptr::write_volatile(GPIO_ENABLE1_W1TC as *mut u32, 1u32 << 3);
        let iomux35 = iomux_addr(35) as *mut u32;
        let v = core::ptr::read_volatile(iomux35);
        core::ptr::write_volatile(iomux35, (v | (1u32 << 9)) & !0x7000 | 0x1000);
    }
}

/// Saved SPI2 + IO_MUX state for restore after bitbang
pub struct SavedSpiState {
    func_out_36: u32,
    func_out_37: u32,
    func_out_35: u32,
    func_in_fspiq: u32, // MISO input signal routing
    spi2_clock: u32,
    spi2_user: u32,
    iomux_35: u32,
    iomux_36: u32,
    iomux_37: u32,
}

/// Save all SPI2 peripheral and IO_MUX state, then reclaim GPIOs for bitbang.
fn save_and_reclaim() -> SavedSpiState {
    unsafe {
        let state = SavedSpiState {
            func_out_36: core::ptr::read_volatile(func_out_sel_addr(36) as *const u32),
            func_out_37: core::ptr::read_volatile(func_out_sel_addr(37) as *const u32),
            func_out_35: core::ptr::read_volatile(func_out_sel_addr(35) as *const u32),
            func_in_fspiq: core::ptr::read_volatile((GPIO_FUNC_IN_SEL_BASE + FSPIQ_IN_SIGNAL * 4) as *const u32),
            spi2_clock: core::ptr::read_volatile(SPI2_CLOCK_REG as *const u32),
            spi2_user: core::ptr::read_volatile(SPI2_USER_REG as *const u32),
            iomux_35: core::ptr::read_volatile(iomux_addr(35) as *const u32),
            iomux_36: core::ptr::read_volatile(iomux_addr(36) as *const u32),
            iomux_37: core::ptr::read_volatile(iomux_addr(37) as *const u32),
        };

        // Reclaim: override FUNC_OUT_SEL to 256 (GPIO) for SCK/MOSI/MISO
        // GPIO36 (SCK) = output, LOW idle
        let iomux36 = iomux_addr(36) as *mut u32;
        let v = core::ptr::read_volatile(iomux36);
        core::ptr::write_volatile(iomux36, (v & !0x7000) | 0x1000);
        core::ptr::write_volatile(func_out_sel_addr(36) as *mut u32, 256);
        core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, 1u32 << 4);
        core::ptr::write_volatile(GPIO_OUT1_W1TC as *mut u32, 1u32 << 4);

        // GPIO37 (MOSI) = output, HIGH idle
        let iomux37 = iomux_addr(37) as *mut u32;
        let v = core::ptr::read_volatile(iomux37);
        core::ptr::write_volatile(iomux37, (v & !0x7000) | 0x1000);
        core::ptr::write_volatile(func_out_sel_addr(37) as *mut u32, 256);
        core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, 1u32 << 5);
        core::ptr::write_volatile(GPIO_OUT1_W1TS as *mut u32, 1u32 << 5);

        // GPIO35 (MISO) = input
        core::ptr::write_volatile(GPIO_ENABLE1_W1TC as *mut u32, 1u32 << 3);
        core::ptr::write_volatile(func_out_sel_addr(35) as *mut u32, 256);
        let iomux35 = iomux_addr(35) as *mut u32;
        let v = core::ptr::read_volatile(iomux35);
        core::ptr::write_volatile(iomux35, (v | (1u32 << 9)) & !0x7000 | 0x1000);

        // SD CS output HIGH, LCD CS HIGH
        core::ptr::write_volatile(GPIO_OUT_W1TS as *mut u32, 1u32 << 4);
        core::ptr::write_volatile(GPIO_OUT_W1TS as *mut u32, 1u32 << 3);

        state
    }
}

/// Restore SPI2 peripheral and IO_MUX state so LCD works again.
fn restore_spi_state(state: &SavedSpiState) {
    unsafe {
        // Restore FUNC_OUT_SEL (reconnects SPI peripheral to pins)
        core::ptr::write_volatile(func_out_sel_addr(36) as *mut u32, state.func_out_36);
        core::ptr::write_volatile(func_out_sel_addr(37) as *mut u32, state.func_out_37);
        core::ptr::write_volatile(func_out_sel_addr(35) as *mut u32, state.func_out_35);
        // Restore FSPIQ_IN signal routing (MISO input)
        core::ptr::write_volatile((GPIO_FUNC_IN_SEL_BASE + FSPIQ_IN_SIGNAL * 4) as *mut u32, state.func_in_fspiq);
        // Re-enable GPIO35 as output (LCD DC)
        core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, 1u32 << 3);
        // Restore SPI2 clock and user regs
        core::ptr::write_volatile(SPI2_CLOCK_REG as *mut u32, state.spi2_clock);
        core::ptr::write_volatile(SPI2_USER_REG as *mut u32, state.spi2_user);
        // Restore IO_MUX
        core::ptr::write_volatile(iomux_addr(35) as *mut u32, state.iomux_35);
        core::ptr::write_volatile(iomux_addr(36) as *mut u32, state.iomux_36);
        core::ptr::write_volatile(iomux_addr(37) as *mut u32, state.iomux_37);
    }
}
// ═══════════════════════════════════════════════════════════════
// SD Card Init
// ═══════════════════════════════════════════════════════════════

/// Full SD card init via bitbang — call BEFORE Spi::new() or inside with_sd_card
pub fn bitbang_init(delay: &mut Delay) -> Result<SdCardType, &'static str> {
    log!("[SD-BB] Starting bitbang SD init...");

    bb_gpio_init();

    // Power-up: CS HIGH, MOSI HIGH, 100+ clock pulses
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    for _ in 0..100 {
        gpio_clear(PIN_SCK); bb_delay();
        gpio_set(PIN_SCK);   bb_delay();
    }

    // Select card
    gpio_clear(PIN_SD_CS);
    bb_delay(); bb_delay();

    // CMD0: GO_IDLE_STATE
    let mut r1 = 0xFFu8;
    for attempt in 0..10 {
        r1 = bb_sd_cmd(CMD0, 0);
        if r1 == 0x01 { break; }
        delay.delay_millis(10);
        if attempt < 3 { log!("[SD-BB] CMD0 attempt {}: R1=0x{:02x}", attempt, r1); }
    }
    if r1 != 0x01 {
        gpio_set(PIN_SD_CS);
        return Err("CMD0 failed");
    }
    log!("[SD-BB] CMD0 OK (idle)");

    // CMD8: SEND_IF_COND — SDv2 detection
    let r1 = bb_sd_cmd(CMD8, 0x000001AA);
    let sd_v2 = if r1 == 0x01 {
        let mut r7 = [0u8; 4];
        for b in r7.iter_mut() { *b = bb_transfer(0xFF); }
        if r7[2] != 0x01 || r7[3] != 0xAA {
            gpio_set(PIN_SD_CS);
            return Err("CMD8 voltage mismatch");
        }
        log!("[SD-BB] CMD8 OK — SDv2");
        true
    } else {
        log!("[SD-BB] CMD8 rejected — SDv1");
        false
    };

    // ACMD41: Initialize card
    let hcs = if sd_v2 { 1u32 << 30 } else { 0 };
    let mut ready = false;
    for i in 0..1000 {
        let r = bb_sd_acmd(ACMD41, hcs);
        if r == 0x00 { ready = true; log!("[SD-BB] ACMD41 OK after {} attempts", i+1); break; }
        if r != 0x01 { log!("[SD-BB] ACMD41 err: 0x{:02x}", r); break; }
        delay.delay_millis(1);
    }
    if !ready {
        gpio_set(PIN_SD_CS);
        return Err("ACMD41 timeout");
    }

    // Determine card type
    let card_type = if sd_v2 {
        let r = bb_sd_cmd(CMD58, 0);
        if r != 0x00 { gpio_set(PIN_SD_CS); return Err("CMD58 failed"); }
        let mut ocr = [0u8; 4];
        for b in ocr.iter_mut() { *b = bb_transfer(0xFF); }
        let ccs = (ocr[0] >> 6) & 1;
        log!("[SD-BB] OCR: {:02x}{:02x}{:02x}{:02x} CCS={}", ocr[0], ocr[1], ocr[2], ocr[3], ccs);
        if ccs == 1 { SdCardType::SdV2Hc } else { SdCardType::SdV2Sc }
    } else {
        SdCardType::SdV1
    };

    // CMD16: Set block length to 512
    if card_type != SdCardType::SdV2Hc {
        let r = bb_sd_cmd(CMD16, 512);
        if r != 0x00 { log!("[SD-BB] CMD16 warning: 0x{:02x}", r); }
    }

    // Deselect
    gpio_set(PIN_SD_CS);
    for _ in 0..8 { gpio_clear(PIN_SCK); bb_delay(); gpio_set(PIN_SCK); bb_delay(); }

    log!("[SD-BB] Card initialized: {:?}", card_type);
    Ok(card_type)
}

// ═══════════════════════════════════════════════════════════════
// Block I/O
// ═══════════════════════════════════════════════════════════════

/// Convert block number to address based on card type
fn bb_block_to_addr(card_type: SdCardType, block: u32) -> u32 {
    match card_type {
        SdCardType::SdV2Hc => block,
        _ => block * 512,
    }
}

/// Bitbang: read a single 512-byte block
pub fn bb_read_block(card_type: SdCardType, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
    gpio_clear(PIN_SD_CS);
    bb_delay();

    let addr = bb_block_to_addr(card_type, block);
    let r = bb_sd_cmd(CMD17, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("CMD17 failed");
    }

    // Wait for data token (0xFE)
    let mut found = false;
    for _ in 0..10000u32 {
        let token = bb_transfer(0xFF);
        if token == 0xFE { found = true; break; }
        if token != 0xFF { gpio_set(PIN_SD_CS); return Err("Read error token"); }
    }
    if !found { gpio_set(PIN_SD_CS); return Err("Read timeout"); }

    for b in buf.iter_mut() {
        *b = bb_transfer(0xFF);
    }

    // Discard 2-byte CRC
    bb_transfer(0xFF);
    bb_transfer(0xFF);

    gpio_set(PIN_SD_CS);
    bb_transfer(0xFF);
    Ok(())
}

/// Bitbang: write a single 512-byte block
pub fn bb_write_block(card_type: SdCardType, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
    gpio_clear(PIN_SD_CS);
    bb_delay();

    let addr = bb_block_to_addr(card_type, block);
    let r = bb_sd_cmd(CMD24, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("CMD24 failed");
    }

    bb_transfer(0xFF);
    bb_transfer(0xFE); // data token

    for &b in buf.iter() {
        bb_transfer(b);
    }

    // Dummy CRC
    bb_transfer(0xFF);
    bb_transfer(0xFF);

    // Check data response
    let resp = bb_transfer(0xFF);
    if (resp & 0x1F) != 0x05 {
        gpio_set(PIN_SD_CS);
        return Err("Write rejected");
    }

    // Wait for busy
    for _ in 0..500_000u32 {
        if bb_transfer(0xFF) != 0x00 {
            gpio_set(PIN_SD_CS);
            bb_transfer(0xFF);
            return Ok(());
        }
    }

    gpio_set(PIN_SD_CS);
    Err("Write busy timeout")
}

/// Fast bitbang: read 512 bytes at maximum GPIO toggle speed (no delays).
/// At 240MHz CPU, each bit takes ~4 clock cycles → ~30MHz effective SPI clock.
/// Much faster than bb_transfer() which uses 300-iteration delay loops.
fn fast_bb_read_512(buf: &mut [u8; 512]) {
    // Pre-compute register addresses
    let sck_set = GPIO_OUT1_W1TS as *mut u32;   // SCK HIGH (bit 4)
    let sck_clr = GPIO_OUT1_W1TC as *mut u32;   // SCK LOW  (bit 4)
    let sck_bit = 1u32 << 4; // GPIO36 = bit 4 of GPIO_OUT1
    let miso_in = GPIO_IN1_REG as *const u32;   // Read GPIO35 (bit 3)
    let miso_bit = 1u32 << 3; // GPIO35 = bit 3 of GPIO_IN1

    for byte_idx in 0..512 {
        let mut rx = 0u8;
        // Unrolled 8-bit SPI Mode 0 read: clock low, then clock high + sample
        // MOSI stays high (0xFF) — already set
        unsafe {
            // Bit 7 (MSB)
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x80; }
            // Bit 6
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x40; }
            // Bit 5
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x20; }
            // Bit 4
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x10; }
            // Bit 3
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x08; }
            // Bit 2
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x04; }
            // Bit 1
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x02; }
            // Bit 0 (LSB)
            core::ptr::write_volatile(sck_clr, sck_bit);
            core::ptr::write_volatile(sck_set, sck_bit);
            if core::ptr::read_volatile(miso_in) & miso_bit != 0 { rx |= 0x01; }
        }
        buf[byte_idx] = rx;
    }
}

/// Fast bitbang: write 512 bytes at maximum GPIO toggle speed.
fn fast_bb_write_512(buf: &[u8; 512]) {
    let sck_set = GPIO_OUT1_W1TS as *mut u32;
    let sck_clr = GPIO_OUT1_W1TC as *mut u32;
    let sck_bit = 1u32 << 4;
    let mosi_set = GPIO_OUT1_W1TS as *mut u32;
    let mosi_clr = GPIO_OUT1_W1TC as *mut u32;
    let mosi_bit = 1u32 << 5; // GPIO37 = bit 5 of GPIO_OUT1

    for byte_idx in 0..512 {
        let tx = buf[byte_idx];
        unsafe {
            for bit in (0..8).rev() {
                if (tx >> bit) & 1 == 1 {
                    core::ptr::write_volatile(mosi_set, mosi_bit);
                } else {
                    core::ptr::write_volatile(mosi_clr, mosi_bit);
                }
                core::ptr::write_volatile(sck_clr, sck_bit);
                core::ptr::write_volatile(sck_set, sck_bit);
            }
        }
    }
    // Leave MOSI high
    unsafe { core::ptr::write_volatile(mosi_set, mosi_bit); }
}

/// Fast read: CMD17 via bitbang, 512-byte payload via fast unrolled bitbang.
/// No SPI2 peripheral — pure GPIO at ~30MHz effective clock.
pub fn fast_read_block(card_type: SdCardType, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
    gpio_clear(PIN_SD_CS);
    bb_delay();

    let addr = bb_block_to_addr(card_type, block);
    let r = bb_sd_cmd(CMD17, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("CMD17 failed");
    }

    // Wait for data token (0xFE) via bitbang
    let mut found = false;
    for _ in 0..10000u32 {
        let token = bb_transfer(0xFF);
        if token == 0xFE { found = true; break; }
        if token != 0xFF { gpio_set(PIN_SD_CS); return Err("Read error token"); }
    }
    if !found { gpio_set(PIN_SD_CS); return Err("Read timeout"); }

    // Fast unrolled bitbang for 512-byte payload
    fast_bb_read_512(buf);

    // Discard 2-byte CRC
    bb_transfer(0xFF);
    bb_transfer(0xFF);

    gpio_set(PIN_SD_CS);
    bb_transfer(0xFF);
    Ok(())
}

/// Fast write: CMD24 via bitbang, 512-byte payload via fast unrolled bitbang.
pub fn fast_write_block(card_type: SdCardType, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
    gpio_clear(PIN_SD_CS);
    bb_delay();

    let addr = bb_block_to_addr(card_type, block);
    let r = bb_sd_cmd(CMD24, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("CMD24 failed");
    }

    // Send gap + data token via bitbang
    bb_transfer(0xFF);
    bb_transfer(0xFE);

    // Fast unrolled bitbang for 512-byte payload
    fast_bb_write_512(buf);

    // Dummy CRC
    bb_transfer(0xFF);
    bb_transfer(0xFF);

    // Check data response
    let resp = bb_transfer(0xFF);
    if (resp & 0x1F) != 0x05 {
        gpio_set(PIN_SD_CS);
        return Err("Write rejected");
    }

    // Wait for busy
    for _ in 0..500_000u32 {
        if bb_transfer(0xFF) != 0x00 {
            gpio_set(PIN_SD_CS);
            bb_transfer(0xFF);
            return Ok(());
        }
    }

    gpio_set(PIN_SD_CS);
    Err("Write busy timeout")
}

/// Multi-block read: CMD18 reads N consecutive sectors starting at `block`.
/// Much faster than N × CMD17 because command overhead is paid only once.
/// Data is written directly into `out` buffer (must be at least count * 512 bytes).
pub fn fast_read_multi_block(
    card_type: SdCardType,
    block: u32,
    out: &mut [u8],
    count: u32,
) -> Result<(), &'static str> {
    if count == 0 { return Ok(()); }
    if count == 1 {
        let buf: &mut [u8; 512] = (&mut out[..512]).try_into().map_err(|_| "buf align")?;
        return fast_read_block(card_type, block, buf);
    }

    gpio_clear(PIN_SD_CS);
    bb_delay();

    let addr = bb_block_to_addr(card_type, block);
    let r = bb_sd_cmd(CMD18, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("CMD18 failed");
    }

    for i in 0..count {
        // Wait for data token (0xFE)
        let mut found = false;
        for _ in 0..10000u32 {
            let token = bb_transfer(0xFF);
            if token == 0xFE { found = true; break; }
            if token != 0xFF {
                // Send CMD12 to stop
                bb_sd_cmd(CMD12, 0);
                bb_transfer(0xFF);
                gpio_set(PIN_SD_CS);
                return Err("Multi-read error token");
            }
        }
        if !found {
            bb_sd_cmd(CMD12, 0);
            bb_transfer(0xFF);
            gpio_set(PIN_SD_CS);
            return Err("Multi-read timeout");
        }

        // Read 512 bytes into the output buffer at the correct offset
        let offset = (i as usize) * 512;
        let sector_slice: &mut [u8; 512] = (&mut out[offset..offset + 512]).try_into().map_err(|_| "slice align")?;
        fast_bb_read_512(sector_slice);

        // Discard 2-byte CRC
        bb_transfer(0xFF);
        bb_transfer(0xFF);
    }

    // Stop transmission: CMD12
    bb_sd_cmd(CMD12, 0);
    // Discard stuff byte + wait for not-busy
    bb_transfer(0xFF);
    for _ in 0..10000u32 {
        if bb_transfer(0xFF) != 0x00 { break; }
    }

    gpio_set(PIN_SD_CS);
    bb_transfer(0xFF);
    Ok(())
}

/// Multi-block write: CMD25 writes N consecutive sectors starting at `block`.
/// Much faster than N × CMD24 because command overhead is paid only once.
pub fn fast_write_multi_block(
    card_type: SdCardType,
    block: u32,
    data: &[u8],
    count: u32,
) -> Result<(), &'static str> {
    if count == 0 { return Ok(()); }
    if count == 1 {
        let buf: &[u8; 512] = (&data[..512]).try_into().map_err(|_| "buf align")?;
        return fast_write_block(card_type, block, buf);
    }

    gpio_clear(PIN_SD_CS);
    bb_delay();

    let addr = bb_block_to_addr(card_type, block);
    let r = bb_sd_cmd(CMD25, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("CMD25 failed");
    }

    for i in 0..count {
        // Data token for multi-write is 0xFC (not 0xFE)
        bb_transfer(0xFF);
        bb_transfer(0xFC);

        let offset = (i as usize) * 512;
        let sector_slice: &[u8; 512] = (&data[offset..offset + 512]).try_into().map_err(|_| "slice align")?;
        fast_bb_write_512(sector_slice);

        // Dummy CRC
        bb_transfer(0xFF);
        bb_transfer(0xFF);

        // Check data response
        let resp = bb_transfer(0xFF);
        if (resp & 0x1F) != 0x05 {
            // Stop token
            bb_transfer(0xFF);
            bb_transfer(0xFD);
            bb_transfer(0xFF);
            gpio_set(PIN_SD_CS);
            return Err("Multi-write rejected");
        }

        // Wait for busy (card programming)
        for _ in 0..500_000u32 {
            if bb_transfer(0xFF) != 0x00 { break; }
        }
    }

    // Stop token: 0xFD
    bb_transfer(0xFF);
    bb_transfer(0xFD);
    bb_transfer(0xFF);

    // Wait for card not busy
    for _ in 0..500_000u32 {
        if bb_transfer(0xFF) != 0x00 { break; }
    }

    gpio_set(PIN_SD_CS);
    bb_transfer(0xFF);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// SPI2 Hardware Mode for SD Card (Option 4)
// ═══════════════════════════════════════════════════════════════
//
// After bitbang init (card is in SPI mode), reconfigure SPI2 peripheral
// for SD card transfers instead of display. 20MHz full-duplex, 64-byte FIFO.
// ~3-4x faster than bitbang for bulk data.

/// Mark SPI2 hardware mode as available. Actual SPI2 register config
/// happens in pins_to_spi2() right before each data burst.
fn spi2_sd_init() -> bool {
    unsafe {
        USE_HW_SPI2 = true;
    }
    log!("[SD] SPI2 hardware mode enabled (1MHz debug)");
    true
}

/// Disable SPI2 hardware mode (before restoring display)
fn spi2_sd_deinit() {
    unsafe { USE_HW_SPI2 = false; }
}

/// Transfer `len` bytes full-duplex via SPI2 hardware FIFO.
/// Sends `tx` data on MOSI, receives MISO data into `rx`.
/// Both buffers must be exactly `len` bytes. Max 64 bytes per call.
fn spi2_transfer(tx: &[u8], rx: &mut [u8], len: usize) {
    debug_assert!(len <= 64 && len > 0);
    unsafe {
        // Load TX data into SPI2 W0..W15
        let w0 = SPI2_W0_REG as *mut u32;
        let words = (len + 3) / 4;
        for i in 0..words {
            let mut word = 0u32;
            for j in 0..4 {
                let idx = i * 4 + j;
                if idx < len {
                    word |= (tx[idx] as u32) << (j * 8);
                } else {
                    word |= 0xFF << (j * 8); // pad with 0xFF (SD idle)
                }
            }
            core::ptr::write_volatile(w0.add(i), word);
        }

        // Set data length: (len * 8 - 1) bits
        core::ptr::write_volatile(SPI2_MS_DLEN_REG as *mut u32, (len as u32 * 8) - 1);

        // Start transfer: set SPI_USR bit (bit 24) in CMD_REG
        core::ptr::write_volatile(SPI2_CMD_REG as *mut u32, 1 << 24);

        // Wait for transfer complete: SPI_USR bit clears when done
        for _ in 0..100_000u32 {
            if core::ptr::read_volatile(SPI2_CMD_REG as *const u32) & (1 << 24) == 0 {
                break;
            }
        }

        // Read RX data from SPI2 W0..W15
        for i in 0..words {
            let word = core::ptr::read_volatile(w0.add(i) as *const u32);
            for j in 0..4 {
                let idx = i * 4 + j;
                if idx < len {
                    rx[idx] = ((word >> (j * 8)) & 0xFF) as u8;
                }
            }
        }
    }
}

/// Send a single byte and receive one byte via SPI2 hardware
fn spi2_transfer_byte(tx: u8) -> u8 {
    let mut rx = [0u8; 1];
    spi2_transfer(&[tx], &mut rx, 1);
    rx[0]
}

/// Read 512 bytes via SPI2 hardware (8 x 64-byte FIFO loads).
/// Sends 0xFF on MOSI (SD idle), captures MISO into buf.
fn spi2_read_512(buf: &mut [u8; 512]) {
    let tx_ff = [0xFFu8; 64];
    for chunk in 0..8 {
        let offset = chunk * 64;
        spi2_transfer(&tx_ff, &mut buf[offset..offset + 64], 64);
    }
}

/// Write 512 bytes via SPI2 hardware (8 x 64-byte FIFO loads).
/// Sends data on MOSI, ignores MISO.
fn spi2_write_512(buf: &[u8; 512]) {
    let mut rx_discard = [0u8; 64];
    for chunk in 0..8 {
        let offset = chunk * 64;
        spi2_transfer(&buf[offset..offset + 64], &mut rx_discard, 64);
    }
}

/// Send an SD command via SPI2 hardware and get R1 response.
fn spi2_sd_cmd(cmd: u8, arg: u32) -> u8 {
    let frame = [
        0x40 | cmd,
        (arg >> 24) as u8,
        (arg >> 16) as u8,
        (arg >> 8) as u8,
        arg as u8,
        if cmd == CMD0 { 0x95 } else if cmd == CMD8 { 0x87 } else { 0x01 },
    ];
    let mut rx = [0u8; 6];
    spi2_transfer(&frame, &mut rx, 6);

    // Wait for response (not 0xFF)
    for _ in 0..16 {
        let r = spi2_transfer_byte(0xFF);
        if r != 0xFF { return r; }
    }
    0xFF
}

/// Helper: switch SCK/MOSI pins to GPIO mode for bitbang, set SD idle state
fn pins_to_gpio() {
    unsafe {
        // Disconnect SPI2 from pins — back to GPIO function
        core::ptr::write_volatile(func_out_sel_addr(36) as *mut u32, 256); // SCK
        core::ptr::write_volatile(func_out_sel_addr(37) as *mut u32, 256); // MOSI
        core::ptr::write_volatile(func_out_sel_addr(35) as *mut u32, 256); // MISO
        // Enable SCK/MOSI as output
        core::ptr::write_volatile(GPIO_ENABLE1_W1TS as *mut u32, (1u32 << 4) | (1u32 << 5));
        // GPIO35 as input for bitbang MISO
        core::ptr::write_volatile(GPIO_ENABLE1_W1TC as *mut u32, 1u32 << 3);
        let iomux35 = iomux_addr(35) as *mut u32;
        let v = core::ptr::read_volatile(iomux35);
        core::ptr::write_volatile(iomux35, (v | (1u32 << 9)) & !0x7000 | 0x1000);
        // Set SD SPI idle: SCK LOW, MOSI HIGH
        core::ptr::write_volatile(GPIO_OUT1_W1TC as *mut u32, 1u32 << 4); // SCK LOW
        core::ptr::write_volatile(GPIO_OUT1_W1TS as *mut u32, 1u32 << 5); // MOSI HIGH
    }
}

/// Helper: configure SPI2 and switch SCK/MOSI/MISO pins for hardware transfer
fn pins_to_spi2() {
    unsafe {
        // Ensure master mode — clear slave register
        const SPI2_SLAVE_REG: u32 = 0x6002_4030;
        core::ptr::write_volatile(SPI2_SLAVE_REG as *mut u32, 0);

        // Disable DMA — force CPU FIFO mode
        const SPI2_DMA_CONF_REG: u32 = 0x6002_4018;
        core::ptr::write_volatile(SPI2_DMA_CONF_REG as *mut u32, 0);

        // Configure SPI2 registers for SD: Mode 0, full-duplex, 1MHz (slow for debug)
        // APB = 80MHz, divider = 80: N=79, H=39, L=79
        let clock_val: u32 = (79 << 12) | (39 << 6) | 79; // 80MHz / 80 = 1MHz
        core::ptr::write_volatile(SPI2_CLOCK_REG as *mut u32, clock_val);

        // USER_REG: full-duplex, MISO+MOSI, Mode 0
        // bit 0 = DOUTDIN (full-duplex), bit 6 = USR_MISO, bit 7 = USR_MOSI
        let user_val: u32 = (1 << 0) | (1 << 6) | (1 << 7);
        core::ptr::write_volatile(SPI2_USER_REG as *mut u32, user_val);

        // Clear USER1 (no addr/dummy phases) and USER2 (no command phase)
        const SPI2_USER1_REG: u32 = 0x6002_4014;
        const SPI2_USER2_REG: u32 = 0x6002_4024;
        core::ptr::write_volatile(SPI2_USER1_REG as *mut u32, 0);
        core::ptr::write_volatile(SPI2_USER2_REG as *mut u32, 0);

        core::ptr::write_volatile(SPI2_CTRL_REG as *mut u32, 0);
        core::ptr::write_volatile(SPI2_MISC_REG as *mut u32, 0);

        // Route GPIO36 (SCK) → SPI2 FSPICLK
        core::ptr::write_volatile(func_out_sel_addr(36) as *mut u32, FSPICLK_OUT_SIGNAL);
        // Route GPIO37 (MOSI) → SPI2 FSPID
        core::ptr::write_volatile(func_out_sel_addr(37) as *mut u32, FSPID_OUT_SIGNAL);
        // Route GPIO35 (MISO) → SPI2 FSPIQ_IN input
        core::ptr::write_volatile(GPIO_ENABLE1_W1TC as *mut u32, 1u32 << 3); // input mode
        let iomux35 = iomux_addr(35) as *mut u32;
        let v = core::ptr::read_volatile(iomux35);
        core::ptr::write_volatile(iomux35, (v | (1u32 << 9)) & !0x7000 | 0x1000); // input enable
        let func_in = (GPIO_FUNC_IN_SEL_BASE + FSPIQ_IN_SIGNAL * 4) as *mut u32;
        core::ptr::write_volatile(func_in, 35 | (1 << 7)); // GPIO35 → signal 102
    }
}

/// SPI2 hardware read block: bitbang CMD17, then SPI2 FIFO for 512-byte data
pub fn spi2_read_block(card_type: SdCardType, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
    // Everything via SPI2 — no pin switching mid-transaction
    pins_to_spi2();

    gpio_clear(PIN_SD_CS);

    // Send CMD17 via SPI2
    let addr = bb_block_to_addr(card_type, block);
    let r = spi2_sd_cmd(CMD17, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("HW CMD17 failed");
    }

    // Wait for data token 0xFE via SPI2
    let mut found = false;
    for _ in 0..10000u32 {
        let token = spi2_transfer_byte(0xFF);
        if token == 0xFE { found = true; break; }
        if token != 0xFF { gpio_set(PIN_SD_CS); return Err("HW read error token"); }
    }
    if !found { gpio_set(PIN_SD_CS); return Err("HW read timeout"); }

    // Read 512 bytes via SPI2 hardware FIFO
    spi2_read_512(buf);

    // CRC
    spi2_transfer_byte(0xFF);
    spi2_transfer_byte(0xFF);

    gpio_set(PIN_SD_CS);
    spi2_transfer_byte(0xFF);

    log!("[SD-HW] first4: {:02x} {:02x} {:02x} {:02x}", buf[0], buf[1], buf[2], buf[3]);
    Ok(())
}

/// SPI2 hardware write block: bitbang CMD24, then SPI2 FIFO for 512-byte data
pub fn spi2_write_block(card_type: SdCardType, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
    // Switch pins to GPIO for bitbang command phase
    pins_to_gpio();

    gpio_clear(PIN_SD_CS);
    bb_delay();

    let addr = bb_block_to_addr(card_type, block);
    let r = bb_sd_cmd(CMD24, addr);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        pins_to_spi2();
        return Err("HW CMD24 failed");
    }

    // Gap + data token via bitbang
    bb_transfer(0xFF);
    bb_transfer(0xFE);

    // Switch to SPI2 hardware for 512-byte data burst
    pins_to_spi2();
    spi2_write_512(buf);

    // Switch back to bitbang for CRC + response + busy
    pins_to_gpio();
    bb_transfer(0xFF);
    bb_transfer(0xFF);

    let resp = bb_transfer(0xFF);
    if (resp & 0x1F) != 0x05 {
        gpio_set(PIN_SD_CS);
        pins_to_spi2();
        return Err("HW write rejected");
    }

    for _ in 0..500_000u32 {
        if bb_transfer(0xFF) != 0x00 {
            gpio_set(PIN_SD_CS);
            bb_transfer(0xFF);
            pins_to_spi2();
            return Ok(());
        }
    }

    gpio_set(PIN_SD_CS);
    pins_to_spi2();
    Err("HW write busy timeout")
}

/// Execute a closure with an active SD card connection.
///
/// Handles the full lifecycle:
/// 1. Save SPI2 + IO_MUX state
/// 2. Reclaim GPIOs from SPI peripheral
/// 3. ALDO4 power-cycle (2s off for cap drain)
/// 4. Bitbang SD init
/// 5. Run closure
/// 6. Restore SPI2 + IO_MUX (LCD resumes)
///
/// The closure receives the detected SdCardType and can call
/// sd_read_block / sd_write_block (auto-dispatches to fast SPI2 or bitbang).
pub fn with_sd_card<I2C, F, T>(
    i2c: &mut I2C,
    delay: &mut Delay,
    f: F,
) -> Result<T, &'static str>
where
    I2C: embedded_hal::i2c::I2c,
    F: FnOnce(SdCardType) -> Result<T, &'static str>,
{
    // Step 1: Save SPI2 state and reclaim GPIOs for bitbang
    let saved = save_and_reclaim();

    // Step 2: ALDO4 power-cycle (required — SPI2 display bus noise
    //         corrupts SD card state beyond software recovery)
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    gpio_set(PIN_SCK);
    gpio_disable_output(PIN_SCK);
    gpio_disable_output(PIN_MOSI);
    gpio_disable_output(PIN_SD_CS);

    let mut ldo = [0u8; 1];
    let _ = i2c.write_read(0x34u8, &[0x90u8], &mut ldo);
    let _ = i2c.write(0x34u8, &[0x90u8, ldo[0] & !0x08]); // ALDO4 off
    delay.delay_millis(300); // cap drain (was 2000ms — 300ms sufficient for most cards)
    let _ = i2c.write(0x34u8, &[0x90u8, ldo[0] | 0x08]);  // ALDO4 on
    delay.delay_millis(200); // power stabilize (was 500ms)

    // Step 3: Re-init GPIOs and SD card
    bb_gpio_init();
    let card_type = match bitbang_init(delay) {
        Ok(ct) => ct,
        Err(e) => {
            log!("[SD] with_sd_card init failed: {}", e);
            restore_spi_state(&saved);
            return Err(e);
        }
    };

    // Step 4: Start tick sound, enable fast bitbang, run the closure
    crate::hw::sound::start_ticking();
    unsafe { USE_FAST_SPI = true; }
    let result = f(card_type);
    unsafe { USE_FAST_SPI = false; }
    crate::hw::sound::stop_ticking();

    // Step 5: Deselect card and restore SPI2 for display
    gpio_set(PIN_SD_CS);
    restore_spi_state(&saved);

    // Step 6: Play success chirp if SD operation succeeded
    if result.is_ok() {
        crate::hw::sound::task_done(delay);
    }

    result
}

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

    /// Convert cluster number to first sector number
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.data_start_sector + (cluster - 2) * self.sectors_per_cluster as u32
    }

    /// Get FAT sector and byte offset for a cluster entry
    pub fn fat_sector_for_cluster(&self, cluster: u32) -> (u32, usize) {
        let fat_offset = cluster * 4;
        let sector = self.fat_start_sector + fat_offset / 512;
        let offset = (fat_offset % 512) as usize;
        (sector, offset)
    }

    /// Bytes per cluster
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
        /// Parse a FAT32 directory entry from 32 raw bytes.
pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 32 { return None; }
        if data[0] == 0x00 { return None; } // end of dir
        if data[0] == 0xE5 { return None; } // deleted
        let attr = data[11];
        if attr == 0x0F { return None; } // LFN

        let mut name = [0u8; 11];
        name.copy_from_slice(&data[0..11]);
        let cluster_hi = u16::from_le_bytes([data[20], data[21]]);
        let cluster_lo = u16::from_le_bytes([data[26], data[27]]);
        let file_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        Some(Self { name, attr, cluster_hi, cluster_lo, file_size })
    }

        /// Get the starting cluster number of this entry.
pub fn first_cluster(&self) -> u32 {
        ((self.cluster_hi as u32) << 16) | (self.cluster_lo as u32)
    }

        /// Returns true if this entry is a directory.
pub fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }

    /// Match against 8.3 name (case-insensitive)
    pub fn matches(&self, name_83: &[u8; 11]) -> bool {
        for i in 0..11 {
            let a = if self.name[i] >= b'a' && self.name[i] <= b'z' { self.name[i] - 32 } else { self.name[i] };
            let b = if name_83[i] >= b'a' && name_83[i] <= b'z' { name_83[i] - 32 } else { name_83[i] };
            if a != b { return false; }
        }
        true
    }
}

/// Convert filename like "IMAGE.BMP" to 8.3 format (11 bytes, space-padded)
pub fn to_83_name(filename: &[u8]) -> [u8; 11] {
    let mut result = [b' '; 11];
    let mut dot_pos = filename.len();
    for i in 0..filename.len() {
        if filename[i] == b'.' { dot_pos = i; break; }
    }
    let base_len = if dot_pos < 8 { dot_pos } else { 8 };
    for i in 0..base_len {
        result[i] = if filename[i] >= b'a' && filename[i] <= b'z' { filename[i] - 32 } else { filename[i] };
    }
    if dot_pos < filename.len() {
        let ext_start = dot_pos + 1;
        for i in 0..3 {
            if ext_start + i < filename.len() {
                result[8 + i] = if filename[ext_start + i] >= b'a' && filename[ext_start + i] <= b'z' {
                    filename[ext_start + i] - 32
                } else {
                    filename[ext_start + i]
                };
            }
        }
    }
    result
}

// ═══════════════════════════════════════════════════════════════
// FAT32 Cluster Chain Operations
// ═══════════════════════════════════════════════════════════════

/// Read a FAT entry for the given cluster. Returns the next cluster or EOC marker.
pub fn read_fat_entry(card_type: SdCardType, fat32: &Fat32Info, cluster: u32) -> Result<u32, &'static str> {
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    let mut buf = [0u8; 512];
    sd_read_block(card_type, sector, &mut buf)?;
    let entry = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
    Ok(entry & 0x0FFF_FFFF) // mask upper 4 bits (reserved)
}

/// Write a FAT entry. Writes to both FAT1 and FAT2.
pub fn write_fat_entry(card_type: SdCardType, fat32: &Fat32Info, cluster: u32, value: u32) -> Result<(), &'static str> {
    let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
    let mut buf = [0u8; 512];

    // Write FAT1
    sd_read_block(card_type, sector, &mut buf)?;
    let existing = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
    let new_val = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let bytes = new_val.to_le_bytes();
    buf[offset] = bytes[0]; buf[offset+1] = bytes[1];
    buf[offset+2] = bytes[2]; buf[offset+3] = bytes[3];
    sd_write_block(card_type, sector, &buf)?;

    // Write FAT2
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

/// Allocate a free cluster. Scans FAT from `start_hint` and marks it as EOC.
/// Returns the allocated cluster number.
pub fn allocate_cluster(card_type: SdCardType, fat32: &Fat32Info, start_hint: u32) -> Result<u32, &'static str> {
    let max_cluster = 2 + (fat32.total_sectors - fat32.data_start_sector) / fat32.sectors_per_cluster as u32;
    let mut buf = [0u8; 512];
    let mut last_sector = 0xFFFF_FFFFu32;

    // Scan from hint, then wrap around
    let mut cluster = if start_hint >= 2 && start_hint < max_cluster { start_hint } else { 2 };
    let start = cluster;
    loop {
        let (sector, offset) = fat32.fat_sector_for_cluster(cluster);
        if sector != last_sector {
            sd_read_block(card_type, sector, &mut buf)?;
            last_sector = sector;
        }
        let entry = u32::from_le_bytes([buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]]);
        if (entry & 0x0FFF_FFFF) == 0 {
            // Free cluster found — mark as EOC
            write_fat_entry(card_type, fat32, cluster, 0x0FFF_FFFF)?;
            log!("[FAT32] Allocated cluster {}", cluster);
            return Ok(cluster);
        }
        cluster += 1;
        if cluster >= max_cluster { cluster = 2; }
        if cluster == start { return Err("Disk full"); }
    }
}

/// Allocate a chain of `count` clusters. Returns the first cluster.
pub fn allocate_chain(card_type: SdCardType, fat32: &Fat32Info, count: u32) -> Result<u32, &'static str> {
    if count == 0 { return Err("Zero clusters requested"); }

    let first = allocate_cluster(card_type, fat32, 2)?;
    let mut prev = first;

    for _ in 1..count {
        let next = allocate_cluster(card_type, fat32, prev + 1)?;
        // Link prev -> next
        write_fat_entry(card_type, fat32, prev, next)?;
        prev = next;
    }
    // Last cluster already has EOC from allocate_cluster

    Ok(first)
}

// ═══════════════════════════════════════════════════════════════
// FAT32 Directory Operations
// ═══════════════════════════════════════════════════════════════

/// Mount FAT32: read BPB, return Fat32Info. Call inside with_sd_card closure.
/// Handles superfloppy (BPB at sector 0), MBR with FAT32 partition, and
/// cards reformatted by macOS/Windows (which may add a partition table).
pub fn mount_fat32(card_type: SdCardType) -> Result<Fat32Info, &'static str> {
    let mut sector = [0u8; 512];
    sd_read_block(card_type, 0, &mut sector)?;

    log!("[FAT32] Sector 0: {:02x} {:02x} {:02x} .. sig={:02x}{:02x}",
        sector[0], sector[1], sector[2], sector[510], sector[511]);

    // Strategy 1: Sector 0 is a BPB (superfloppy) — jump byte + 0x55AA
    if (sector[0] == 0xEB || sector[0] == 0xE9) && sector[510] == 0x55 && sector[511] == 0xAA {
        log!("[FAT32] Trying superfloppy (BPB at sector 0)");
        if let Ok(info) = Fat32Info::from_boot_sector(&sector) {
            return Ok(info);
        }
    }

    // Strategy 2: Sector 0 is an MBR — find FAT32 partition
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
            // lba == 0 means superfloppy fallback — already tried above
        }
    }

    // Strategy 3: Maybe sector 0 is a protective MBR (GPT) or unknown layout.
    // Try common partition offsets: sector 1, 2048 (common for macOS/Windows)
    for &probe_lba in &[2048u32, 8192, 32768, 1] {
        if sd_read_block(card_type, probe_lba, &mut sector).is_ok() {
            if (sector[0] == 0xEB || sector[0] == 0xE9) && sector[510] == 0x55 && sector[511] == 0xAA {
                log!("[FAT32] Found BPB at sector {}", probe_lba);
                if let Ok(mut info) = Fat32Info::from_boot_sector(&sector) {
                    info.fat_start_sector += probe_lba;
                    info.data_start_sector += probe_lba;
                    return Ok(info);
                }
            }
        }
    }

    Err("No FAT32 filesystem found")
}

/// Find a file in the root directory by 8.3 name.
/// Returns (DirEntry, sector_of_entry, offset_in_sector) so we can update it.
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
            for i in 0..16 { // 16 entries per 512-byte sector
                let off = i * 32;
                if buf[off] == 0x00 { return Err("File not found"); } // end of dir
                if let Some(entry) = DirEntry::from_bytes(&buf[off..off+32]) {
                    if entry.matches(name_83) {
                        return Ok((entry, base_sector + s, off));
                    }
                }
            }
        }
        // Follow cluster chain
        let next = read_fat_entry(card_type, fat32, cluster)?;
        if next >= 0x0FFF_FFF8 { break; } // EOC
        cluster = next;
    }
    Err("File not found")
}

/// Read a file's contents into the provided buffer. Returns bytes read.
/// Buffer must be large enough for the file (file_size bytes).
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

    while remaining > 0 && cluster >= 2 && cluster < 0x0FFF_FFF8 {
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

        while remaining > 0 && cluster >= 2 && cluster < 0x0FFF_FFF8 {
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
    while cluster >= 2 && cluster < 0x0FFF_FFF8 {
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
                    if seq >= 1 && seq <= 4 && (lfn_part_count < 4) {
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
                                if hi == 0 && lo >= 0x20 && lo < 0x7F {
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

// ═══════════════════════════════════════════════════════════════
// MBR / Partition Table
// ═══════════════════════════════════════════════════════════════

/// Find the first FAT32 partition in an MBR. Returns the LBA offset.
pub fn find_fat32_partition(mbr: &[u8; 512]) -> Result<u32, &'static str> {
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err("Invalid MBR signature");
    }
    for i in 0..4 {
        let base = 446 + i * 16;
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
// FAT32 Format — uses with_sd_card internally
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

/// Internal format logic — runs inside with_sd_card closure.
fn do_format_fat32(card_type: SdCardType) -> Result<(), &'static str> {
    // Verify card is accessible
    let mut test = [0u8; 512];
    sd_read_block(card_type, 0, &mut test)?;
    log!("[SD-FMT] MBR read OK sig={:02x}{:02x}", test[510], test[511]);

    let sectors_per_cluster: u8 = 64;  // 32KB clusters
    let reserved_sectors: u16 = 32;
    let num_fats: u8 = 2;
    let fat_size: u32 = 1024;
    let root_cluster: u32 = 2;
    let total_sectors: u32 = 0x00F00000;

    // Build BPB
    let mut bpb = [0u8; 512];
    bpb[0] = 0xEB; bpb[1] = 0x58; bpb[2] = 0x90;
    bpb[3..11].copy_from_slice(b"MSDOS5.0");
    bpb[11] = 0x00; bpb[12] = 0x02; // 512 bytes/sector
    bpb[13] = sectors_per_cluster;
    bpb[14] = reserved_sectors as u8; bpb[15] = (reserved_sectors >> 8) as u8;
    bpb[16] = num_fats;
    bpb[21] = 0xF8; // media type
    bpb[24] = 0x3F; bpb[26] = 0xFF; // sectors per track / heads
    bpb[32] = total_sectors as u8; bpb[33] = (total_sectors >> 8) as u8;
    bpb[34] = (total_sectors >> 16) as u8; bpb[35] = (total_sectors >> 24) as u8;
    bpb[36] = fat_size as u8; bpb[37] = (fat_size >> 8) as u8;
    bpb[38] = (fat_size >> 16) as u8; bpb[39] = (fat_size >> 24) as u8;
    bpb[44] = root_cluster as u8; bpb[45] = (root_cluster >> 8) as u8;
    bpb[48] = 1; bpb[50] = 6; // FSInfo=1, backup BPB=6
    bpb[66] = 0x29; // extended boot sig
    bpb[67] = 0x4B; bpb[68] = 0x53; bpb[69] = 0x53; bpb[70] = 0x00; // serial
    bpb[71..82].copy_from_slice(b"KASSIGNER  ");
    bpb[82..90].copy_from_slice(b"FAT32   ");
    bpb[510] = 0x55; bpb[511] = 0xAA;

    sd_write_block(card_type, 0, &bpb)?;
    sd_write_block(card_type, 6, &bpb)?; // backup

    // FSInfo sector
    let mut fsinfo = [0u8; 512];
    fsinfo[0] = 0x52; fsinfo[1] = 0x52; fsinfo[2] = 0x61; fsinfo[3] = 0x41;
    fsinfo[484] = 0x72; fsinfo[485] = 0x72; fsinfo[486] = 0x41; fsinfo[487] = 0x61;
    fsinfo[488] = 0xFF; fsinfo[489] = 0xFF; fsinfo[490] = 0xFF; fsinfo[491] = 0xFF;
    fsinfo[492] = 0x03;
    fsinfo[510] = 0x55; fsinfo[511] = 0xAA;
    sd_write_block(card_type, 1, &fsinfo)?;

    // Clear reserved sectors
    let zeros = [0u8; 512];
    for s in 2..reserved_sectors as u32 {
        if s == 6 { continue; } // backup BPB already written
        let _ = sd_write_block(card_type, s, &zeros);
    }

    // FAT tables — first sector has media byte + EOC markers for clusters 0,1,2
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

    // Clear root directory cluster
    let data_start = reserved_sectors as u32 + num_fats as u32 * fat_size;
    for i in 0..sectors_per_cluster as u32 {
        let _ = sd_write_block(card_type, data_start + i, &zeros);
    }

    Ok(())
}
