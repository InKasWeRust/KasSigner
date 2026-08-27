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

// GPIO FUNC_IN_SEL for FSPIQ (SPI2 MISO input) — signal 102.
// FSPIQ_IN_SIGNAL and SPI2_CLOCK/USER_REG are still read and restored by
// save_and_reclaim/restore_spi_state, the display-bus save/restore bracket.
const GPIO_FUNC_IN_SEL_BASE: u32 = 0x6000_4154;
const FSPIQ_IN_SIGNAL: u32 = 102;

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
const CMD9: u8   = 9;   // SEND_CSD
const CMD58: u8  = 58;  // READ_OCR
const ACMD41: u8 = 41;  // SD_SEND_OP_COND

/// Whether to use fast (no-delay) bitbang for block I/O.
/// Set to true inside with_sd_card after successful init.
static USE_FAST_SPI: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Internal dispatch: fast (no-delay) bitbang inside a `with_sd_card`
/// bracket, plain bitbang otherwise.
///
/// A third arm once dispatched to an SPI2-hardware path. That path was a
/// 1 MHz debug stub that flipped the pin mux twice per sector and was never
/// wired in (`spi2_sd_init` had no caller, `USE_HW_SPI2` was never set), so
/// it was removed in 1.0.7. The CoreS3 microSD (`U11`, MicroSD-SPI) is a
/// 4-wire SPI socket on the bus shared with the ILI9342C display, with no
/// DAT1..3 routed, so neither 4-bit SDMMC nor a private-bus SPI master is
/// available; a genuine SPI2 speedup would drive these same shared pins
/// through the S3 SPI master and is a separate piece of work, bounded by
/// 1-bit SPI and the display-bus hand-off discipline. See STATE.md.
pub fn sd_read_block(card_type: SdCardType, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
    if USE_FAST_SPI.load(core::sync::atomic::Ordering::Relaxed) {
        fast_read_block(card_type, block, buf)
    } else {
        bb_read_block(card_type, block, buf)
    }
}

/// Internal dispatch: fast bitbang inside `with_sd_card`, plain bitbang otherwise.
fn sd_write_block(card_type: SdCardType, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
    if USE_FAST_SPI.load(core::sync::atomic::Ordering::Relaxed) {
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
    USE_FAST_SPI.store(true, core::sync::atomic::Ordering::Relaxed);
    let result = f(card_type);
    USE_FAST_SPI.store(false, core::sync::atomic::Ordering::Relaxed);
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
// FAT32 layer: kassigner-core::fat32, over the BlockDevice trait
// ═══════════════════════════════════════════════════════════════
//
// Until 1.0.7 the FAT32 filesystem, directory, chain and format code lived
// here, as one of two near-identical copies (the other in the Waveshare driver).
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

/// Read the card's sector count from its CSD (CMD9).
///
/// The card is asked how large it is rather than being probed for its end.
/// An earlier version of this function searched for the last readable sector
/// by reading past it; those out-of-range reads leave the card in an error
/// state, after which writes are acknowledged and discarded and reads return
/// all ones. A format built on that reported success over an untouched card.
fn read_card_sectors(card_type: SdCardType) -> Result<u32, &'static str> {
    let _ = card_type; // CMD9 takes no address argument in SPI mode.
    gpio_clear(PIN_SD_CS);
    bb_delay();

    let r = bb_sd_cmd(CMD9, 0);
    if r != 0x00 {
        gpio_set(PIN_SD_CS);
        return Err("CMD9 failed");
    }

    let mut found = false;
    for _ in 0..10000u32 {
        let token = bb_transfer(0xFF);
        if token == 0xFE { found = true; break; }
        if token != 0xFF {
            gpio_set(PIN_SD_CS);
            return Err("CSD error token");
        }
    }
    if !found {
        gpio_set(PIN_SD_CS);
        return Err("CSD timeout");
    }

    let mut csd = [0u8; 16];
    for b in csd.iter_mut() {
        *b = bb_transfer(0xFF);
    }
    bb_transfer(0xFF); // CRC
    bb_transfer(0xFF);
    gpio_set(PIN_SD_CS);
    bb_transfer(0xFF);

    log!("[SD-FMT] CSD {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}",
        csd[0], csd[1], csd[2], csd[3], csd[4], csd[5], csd[6], csd[7],
        csd[8], csd[9], csd[10], csd[11], csd[12], csd[13], csd[14], csd[15]);

    let sectors = csd_sectors(&csd)?;
    if !csd_plausible(sectors) {
        return Err("CSD capacity implausible");
    }
    Ok(sectors)
}
