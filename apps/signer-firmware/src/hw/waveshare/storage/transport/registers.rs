use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU8, Ordering};

use super::SdCardType;
use signer_firmware_core::storage::card::decode_card_type_code;
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Waveshare SDHOST register map and platform state.

// ═══════════════════════════════════════════════════════════════
// SDHOST Controller Registers (base 0x60028000, TRM Ch.34)
// ═══════════════════════════════════════════════════════════════

pub(super) const SDHOST_BASE: u32 = 0x6002_8000;

pub(super) const SDHOST_CTRL:       u32 = SDHOST_BASE + 0x000;
pub(super) const SDHOST_CLKDIV:     u32 = SDHOST_BASE + 0x008;
pub(super) const SDHOST_CLKSRC:     u32 = SDHOST_BASE + 0x00C;
pub(super) const SDHOST_CLKENA:     u32 = SDHOST_BASE + 0x010;
pub(super) const SDHOST_TMOUT:      u32 = SDHOST_BASE + 0x014;
pub(super) const SDHOST_CTYPE:      u32 = SDHOST_BASE + 0x018;
pub(super) const SDHOST_BLKSIZ:     u32 = SDHOST_BASE + 0x01C;
pub(super) const SDHOST_BYTCNT:     u32 = SDHOST_BASE + 0x020;
pub(super) const SDHOST_INTMASK:    u32 = SDHOST_BASE + 0x024;
pub(super) const SDHOST_CMDARG:     u32 = SDHOST_BASE + 0x028;
pub(super) const SDHOST_CMD:        u32 = SDHOST_BASE + 0x02C;
pub(super) const SDHOST_RESP0:      u32 = SDHOST_BASE + 0x030;
pub(super) const SDHOST_RESP1:      u32 = SDHOST_BASE + 0x034;
pub(super) const SDHOST_RESP2:      u32 = SDHOST_BASE + 0x038;
pub(super) const SDHOST_RESP3:      u32 = SDHOST_BASE + 0x03C;
pub(super) const SDHOST_RINTSTS:    u32 = SDHOST_BASE + 0x044;
pub(super) const SDHOST_STATUS:     u32 = SDHOST_BASE + 0x048;
pub(super) const SDHOST_FIFOTH:     u32 = SDHOST_BASE + 0x04C;
pub(super) const SDHOST_DEBNCE:     u32 = SDHOST_BASE + 0x064;
pub(super) const SDHOST_VERID:      u32 = SDHOST_BASE + 0x06C;
pub(super) const SDHOST_RST_N:      u32 = SDHOST_BASE + 0x078;
pub(super) const SDHOST_BUFFIFO:    u32 = SDHOST_BASE + 0x200;
pub(super) const SDHOST_CLK_EDGE:   u32 = SDHOST_BASE + 0x800;

// CMD register bits (TRM 34.13, Register 34.11)
pub(super) const CMD_START:              u32 = 1 << 31;
pub(super) const CMD_USE_HOLE:           u32 = 1 << 29; // use hold register (default=1)
pub(super) const CMD_UPDATE_CLK_ONLY:    u32 = 1 << 21;
pub(super) const CMD_SEND_INIT:          u32 = 1 << 15;
pub(super) const CMD_WAIT_PRVDATA:       u32 = 1 << 13;
pub(super) const CMD_SEND_AUTO_STOP:     u32 = 1 << 12;
pub(super) const CMD_WRITE:              u32 = 1 << 10;
pub(super) const CMD_DATA_EXPECTED:      u32 = 1 << 9;
pub(super) const CMD_CHECK_RESP_CRC:     u32 = 1 << 8;
pub(super) const CMD_RESP_LONG:          u32 = 1 << 7;
pub(super) const CMD_RESP_EXPECT:        u32 = 1 << 6;

// CTRL register bits
pub(super) const CTRL_FIFO_RESET:        u32 = 1 << 1;
pub(super) const CTRL_CONTROLLER_RESET:  u32 = 1 << 0;
pub(super) const CTRL_INT_ENABLE:        u32 = 1 << 4;

// RINTSTS interrupt bits
pub(super) const INT_CD:    u32 = 1 << 2;  // Command Done
pub(super) const INT_DTO:   u32 = 1 << 3;  // Data Transfer Over
pub(super) const INT_RCRC:  u32 = 1 << 6;  // Response CRC Error
pub(super) const INT_DCRC:  u32 = 1 << 7;  // Data CRC Error
pub(super) const INT_RTO:   u32 = 1 << 8;  // Response Timeout
pub(super) const INT_DRTO:  u32 = 1 << 9;  // Data Read Timeout
pub(super) const INT_HTO:   u32 = 1 << 10; // Data Starvation by Host Timeout
pub(super) const INT_FRUN:  u32 = 1 << 11; // FIFO underrun/overrun
pub(super) const INT_HLE:   u32 = 1 << 12; // Hardware Locked write Error
pub(super) const INT_SBE:   u32 = 1 << 13; // Start Bit Error
pub(super) const INT_EBE:   u32 = 1 << 15; // End Bit Error

pub(super) const INT_ALL_ERRORS: u32 = INT_RCRC | INT_DCRC | INT_RTO | INT_DRTO
    | INT_HTO | INT_FRUN | INT_HLE | INT_SBE | INT_EBE;

// STATUS register bits
pub(super) const STATUS_FIFO_FULL:  u32 = 1 << 3;
pub(super) const STATUS_FIFO_EMPTY: u32 = 1 << 2;
pub(super) const STATUS_DATA_BUSY:  u32 = 1 << 9;

// ═══════════════════════════════════════════════════════════════
// GPIO Matrix Signal Numbers for SDHOST Card1 (TRM Table 6-2)
// ═══════════════════════════════════════════════════════════════

pub(super) const SDHOST_CCLK_OUT_1:    u32 = 172;  // output: clock
pub(super) const SDHOST_CCMD_IN_1:     u32 = 178;  // input: command response
pub(super) const SDHOST_CCMD_OUT_1:    u32 = 178;  // output: command (same signal, bidirectional)
pub(super) const SDHOST_CDATA_IN_10:   u32 = 180;  // input: data[0] from card
pub(super) const SDHOST_CDATA_OUT_10:  u32 = 180;  // output: data[0] to card
pub(super) const SDHOST_CARD_DETECT_1: u32 = 194;  // input: card detect (active low)

// ═══════════════════════════════════════════════════════════════
// GPIO / IO_MUX / System Registers
// ═══════════════════════════════════════════════════════════════

pub(super) const GPIO_OUT_W1TS: u32 = 0x6000_4008;
pub(super) const GPIO_OUT_W1TC: u32 = 0x6000_400C;
pub(super) const GPIO_ENABLE_W1TS: u32 = 0x6000_4024;
pub(super) const GPIO_FUNC_IN_SEL_BASE: u32 = 0x6000_4154;
pub(super) const IO_MUX_BASE: u32 = 0x6000_9004;
pub(super) const FSPIQ_IN_SIGNAL: u32 = 102;

pub(super) use crate::hw::shared::registers::esp32s3::{
    GPIO_ENABLE1_W1TS, GPIO_FUNC_OUT_SEL_BASE, GPIO_OUT1_W1TC,
    GPIO_OUT1_W1TS,
};

// System peripheral clock/reset
pub(super) const SYSTEM_PERIP_CLK_EN1: u32  = 0x600C_001C;
pub(super) const SYSTEM_PERIP_RST_EN1: u32  = 0x600C_0024;

// SDHOST clock is bit 7 of CLK_EN1/RST_EN1
pub(super) const SDHOST_CLK_EN_BIT: u32 = 1 << 7;

// GPIO pin numbers (Waveshare ESP32-S3-Touch-LCD-2)
pub(super) const PIN_LCD_CS: u8  = 45;
pub(super) const PIN_SD_CS: u8   = 41;  // D3 in SD mode — used as card-select by SDHOST
pub(super) const PIN_MISO: u8    = 40;  // D0 in SD mode
pub(super) const PIN_SCK: u8     = 39;  // CLK in SD mode
pub(super) const PIN_MOSI: u8    = 38;  // CMD in SD mode

// ═══════════════════════════════════════════════════════════════
// SD Card Type
// ═══════════════════════════════════════════════════════════════

static CARD_RCA: AtomicU16 = AtomicU16::new(0);
static CARD_SECTOR_COUNT: AtomicU32 = AtomicU32::new(0);
static BOOT_CARD_TYPE: AtomicU8 = AtomicU8::new(0);

#[inline]
pub(super) fn card_rca() -> u16 {
    CARD_RCA.load(Ordering::Relaxed)
}

#[inline]
pub(super) fn set_card_rca(value: u16) {
    CARD_RCA.store(value, Ordering::Relaxed);
}

#[inline]
pub(super) fn cached_card_sector_count() -> Option<u32> {
    let sectors = CARD_SECTOR_COUNT.load(Ordering::Relaxed);
    if sectors == 0 { None } else { Some(sectors) }
}

#[inline]
pub(super) fn set_card_sector_count(value: u32) {
    CARD_SECTOR_COUNT.store(value, Ordering::Relaxed);
}

#[inline]
pub fn boot_card_type() -> Option<SdCardType> {
    decode_card_type_code(
        BOOT_CARD_TYPE.load(Ordering::Relaxed),
        SdCardType::SdV1,
        SdCardType::SdV2Sc,
        SdCardType::SdV2Hc,
    )
}

#[inline]
pub(super) fn set_boot_card_type(value: SdCardType) {
    BOOT_CARD_TYPE.store(value as u8, Ordering::Relaxed);
}

// Shared low-level register primitives are re-exported for the transport leaves.
pub(super) use crate::hw::shared::mmio::{
    clear_bits as reg_clear_bits,
    read as reg_read,
    set_bits as reg_set_bits,
    write as reg_write,
};
