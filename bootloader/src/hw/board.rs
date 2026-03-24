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

// hw/board.rs — Waveshare ESP32-S3-Touch-LCD-2 pin definitions
// 100% Rust, no-std, no-alloc
//
// This file centralizes ALL GPIO assignments for the Waveshare board.
// When porting to another board, only this file needs to change.
//
// Reference: ESP32-S3-Touch-LCD-2 schematic (Waveshare)
// Board: ESP32-S3R8 (8MB PSRAM, 16MB Flash)

// ═══════════════════════════════════════════════════════════════
// Display — ST7789T3 (SPI)
// ═══════════════════════════════════════════════════════════════
// Resolution: 240×320, IPS, 262K color
// Driver: ST7789T3 (compatible with ST7789V series)
// Interface: SPI (MOSI + SCLK, no MISO needed)

/// SPI MOSI pin for display (shared with SD card)
pub const LCD_MOSI: u8 = 38;
/// SPI SCLK pin for display (shared with SD card)
pub const LCD_SCLK: u8 = 39;
/// Chip select for display
pub const LCD_CS: u8 = 45;
/// Data/Command select for display
pub const LCD_DC: u8 = 42;
/// Hardware reset for display (directly wired, no IO expander)
pub const LCD_RST: u8 = 0;
/// Backlight control (GPIO → transistor, active HIGH)
pub const LCD_BL: u8 = 1;

// ═══════════════════════════════════════════════════════════════
// Touch — CST816D (I2C)
// ═══════════════════════════════════════════════════════════════
// Single-point capacitive touch, I2C address 0x15
// Shares I2C bus with QMI8658 IMU (we don't use the IMU)

/// Touch I2C SDA (shared bus with IMU)
pub const TP_SDA: u8 = 48;
/// Touch I2C SCL (shared bus with IMU)
pub const TP_SCL: u8 = 47;
/// Touch interrupt pin (active LOW)
pub const TP_INT: u8 = 46;

// ═══════════════════════════════════════════════════════════════
// Camera — OV5640 (DVP parallel)
// ═══════════════════════════════════════════════════════════════
// 5MP camera (OV5640), SCCB (I2C) control, 8-bit DVP data
// SCCB is on a SEPARATE I2C bus from touch

/// Camera SCCB SDA (dedicated I2C bus)
pub const CAM_SDA: u8 = 21;
/// Camera SCCB SCL (dedicated I2C bus)
pub const CAM_SCL: u8 = 16;
/// Camera master clock output (XCLK)
pub const CAM_XCLK: u8 = 8;
/// Camera pixel clock input (PCLK)
pub const CAM_PCLK: u8 = 9;
/// Camera vertical sync
pub const CAM_VSYNC: u8 = 6;
/// Camera horizontal reference
pub const CAM_HREF: u8 = 4;
/// Camera power down (active HIGH)
pub const CAM_PWDN: u8 = 17;
/// Camera data bus D0-D7
pub const CAM_D0: u8 = 12; // Y2
pub const CAM_D1: u8 = 13; // Y3
pub const CAM_D2: u8 = 15; // Y4
pub const CAM_D3: u8 = 11; // Y5
pub const CAM_D4: u8 = 14; // Y6
pub const CAM_D5: u8 = 10; // Y7
pub const CAM_D6: u8 = 7;  // Y8
pub const CAM_D7: u8 = 2;  // Y9

// ═══════════════════════════════════════════════════════════════
// SD Card (SDHOST native mode — shared GPIO with display SPI)
// ═══════════════════════════════════════════════════════════════

/// SD card CMD line (shared with LCD_MOSI via GPIO matrix switching)
pub const SD_CMD: u8 = 38;
/// SD card CLK line (shared with LCD_SCLK via GPIO matrix switching)
pub const SD_CLK: u8 = 39;
/// SD card D0 line (dedicated — display doesn't use this pin)
pub const SD_D0: u8 = 40;
/// SD card D3/CS line (directly wired to card slot)
pub const SD_D3: u8 = 41;

// ═══════════════════════════════════════════════════════════════
// Battery — simple voltage divider on ADC
// ═══════════════════════════════════════════════════════════════
// No PMU on Waveshare. Battery voltage read via resistor divider.
// Divider: R19=200K / R20=100K → ADC reads Vbat/3

/// Battery ADC pin
pub const BAT_ADC: u8 = 5;

// ═══════════════════════════════════════════════════════════════
// UART (for debug logging)
// ═══════════════════════════════════════════════════════════════

pub const UART_TX: u8 = 43;
pub const UART_RX: u8 = 44;

// ═══════════════════════════════════════════════════════════════
// USB
// ═══════════════════════════════════════════════════════════════

pub const USB_DN: u8 = 19;
pub const USB_DP: u8 = 20;

// ═══════════════════════════════════════════════════════════════
// I2C device addresses
// ═══════════════════════════════════════════════════════════════

/// CST816D touch controller I2C address
pub const CST816D_ADDR: u8 = 0x15;
/// OV5640 camera SCCB address (7-bit)
pub const OV5640_ADDR: u8 = 0x3C;
/// QMI8658 IMU I2C address (not used by KasSigner)
pub const QMI8658_ADDR: u8 = 0x6B;

// ═══════════════════════════════════════════════════════════════
// Board capabilities
// ═══════════════════════════════════════════════════════════════

/// This board has no speaker/audio hardware
pub const HAS_SPEAKER: bool = false;
/// This board has no PMU (AXP2101) — direct power
pub const HAS_PMU: bool = false;
/// This board has a battery with ADC monitoring
pub const HAS_BATTERY: bool = true;
/// Camera and touch use SEPARATE I2C buses
pub const SEPARATE_I2C_BUSES: bool = true;
