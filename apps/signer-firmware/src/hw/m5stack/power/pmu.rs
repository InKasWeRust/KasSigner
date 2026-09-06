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


// hw/power/pmu_m5.rs — AXP2101 PMU and AW9523B IO expander initialization

use esp_hal::delay::Delay;
use esp_hal::i2c::master::I2c;
use signer_firmware_core::power::sequencing::{RegisterWriteStep, run_register_writes};

// ═══════════════════════════════════════════════════════════════
// I2C Device Addresses
// ═══════════════════════════════════════════════════════════════

/// AXP2101 PMU I2C address
pub(crate) const AXP2101_ADDR: u8 = 0x34;
/// AW9523B IO Expander I2C address
pub(crate) const AW9523B_ADDR: u8 = 0x58;

// ═══════════════════════════════════════════════════════════════
// AXP2101 Register Definitions
// ═══════════════════════════════════════════════════════════════

/// DLDO1 voltage register — Voltage = 500mV + (value * 100mV)
const AXP_REG_DLDO1_VOLT: u8 = 0x99;
/// LDO enable control register 1 (bit 7 = DLDO1 enable)
pub(crate) const AXP_REG_LDO_EN1: u8 = 0x90;

// ═══════════════════════════════════════════════════════════════
// AW9523B Register Definitions
// ═══════════════════════════════════════════════════════════════

/// Port 1 output register (pins P10-P17)
const AW_REG_OUTPUT_P1: u8 = 0x03;
/// Port 0 output register (pins P00-P07)
const AW_REG_OUTPUT_P0: u8 = 0x02;
/// Port 1 direction register (0=output, 1=input)
const AW_REG_CONFIG_P1: u8 = 0x05;
/// Port 0 direction register
const AW_REG_CONFIG_P0: u8 = 0x04;
/// LED mode switch register for Port 1
const AW_REG_LEDMODE_P1: u8 = 0x13;
/// LED mode switch register for Port 0
const AW_REG_LEDMODE_P0: u8 = 0x12;
/// Global Control Register (GCR) — bit4: P0 push-pull mode
const AW_REG_GCR: u8 = 0x11;
/// Software reset register
const AW_REG_RESET: u8 = 0x7F;

const AXP2101_INIT_STEPS: &[RegisterWriteStep] = &[
    RegisterWriteStep::new(AXP_REG_DLDO1_VOLT, 0x1C, 0, "AXP2101: failed to set DLDO1 voltage"),
    RegisterWriteStep::new(0x92, 0x0D, 0, "AXP2101: ALDO1 voltage"),
    RegisterWriteStep::new(0x93, 0x1C, 0, "AXP2101: ALDO2 voltage"),
    RegisterWriteStep::new(0x96, 0x17, 0, "AXP2101: BLDO1 voltage"),
    RegisterWriteStep::new(0x97, 0x0A, 0, "AXP2101: BLDO2 voltage"),
    RegisterWriteStep::new(0x94, 0x1C, 0, "AXP2101: ALDO3 voltage"),
    RegisterWriteStep::new(0x95, 0x1C, 0, "AXP2101: ALDO4 voltage"),
    RegisterWriteStep::new(0x27, 0x00, 0, "AXP2101: PowerKey config"),
    RegisterWriteStep::new(0x69, 0x11, 0, "AXP2101: CHGLED"),
    RegisterWriteStep::new(0x10, 0x30, 0, "AXP2101: PMU config"),
    RegisterWriteStep::new(0x30, 0x0F, 10, "AXP2101: ADC enable"),
    RegisterWriteStep::new(AXP_REG_LDO_EN1, 0xBF, 50, "AXP2101: failed to enable LDOs"),
];

const AW9523B_INIT_STEPS: &[RegisterWriteStep] = &[
    RegisterWriteStep::new(AW_REG_RESET, 0x00, 20, "AW9523B: reset failed"),
    RegisterWriteStep::new(AW_REG_GCR, 0x10, 0, "AW9523B: GCR push-pull failed"),
    RegisterWriteStep::new(AW_REG_LEDMODE_P1, 0xFF, 0, "AW9523B: P1 LED mode failed"),
    RegisterWriteStep::new(AW_REG_CONFIG_P1, 0x00, 0, "AW9523B: P1 config failed"),
    RegisterWriteStep::new(AW_REG_LEDMODE_P0, 0xFF, 0, "AW9523B: P0 LED mode failed"),
    RegisterWriteStep::new(AW_REG_CONFIG_P0, 0x00, 0, "AW9523B: P0 config failed"),
    RegisterWriteStep::new(AW_REG_OUTPUT_P1, 0x00, 20, "AW9523B: P1 output low failed"),
    RegisterWriteStep::new(AW_REG_OUTPUT_P1, 0x82, 50, "AW9523B: P1 output high failed"),
    RegisterWriteStep::new(AW_REG_OUTPUT_P1, 0xFF, 10, "AW9523B: P1 all-high failed"),
    RegisterWriteStep::new(AW_REG_OUTPUT_P0, 0x00, 20, "AW9523B: P0 output low failed"),
    RegisterWriteStep::new(AW_REG_OUTPUT_P0, 0x15, 100, "AW9523B: P0 output failed"),
    RegisterWriteStep::new(AW_REG_OUTPUT_P0, 0x05, 20, "AW9523B: P0 cam pwdn deassert failed"),
];

pub fn init_axp2101(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
) -> Result<(), &'static str> {
    run_register_writes(
        AXP2101_ADDR,
        AXP2101_INIT_STEPS,
        |address, register, value| i2c.write(address, &[register, value]).is_ok(),
        |milliseconds| delay.delay_millis(milliseconds),
    )
}

/// Initialize AW9523B IO Expander and sequence LCD, touch, speaker, and camera power.
pub fn init_aw9523b(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    delay: &mut Delay,
) -> Result<(), &'static str> {
    run_register_writes(
        AW9523B_ADDR,
        AW9523B_INIT_STEPS,
        |address, register, value| i2c.write(address, &[register, value]).is_ok(),
        |milliseconds| delay.delay_millis(milliseconds),
    )
}

/// Set LCD backlight brightness via AXP2101 DLDO1 voltage.
/// brightness: 0-255 maps to ~2.4V-3.3V (visible range only).
/// The backlight goes dark below ~2.4V (reg 0x13), so we start there.
pub fn set_brightness_value(i2c: &mut I2c<'_, esp_hal::Blocking>, brightness: u8) {
    // DLDO1: voltage = 500mV + reg * 100mV
    // Visible range: 0x11 (2.2V) to 0x1C (3.3V) = 11 steps
    const REG_MIN: u8 = 0x11; // ~2.2V — dimmest visible
    const REG_MAX: u8 = 0x1C; // ~3.3V — full brightness
    const RANGE: u8 = REG_MAX - REG_MIN; // 11 steps
    let reg_val = if brightness <= 1 {
        REG_MIN
    } else {
        let step = (brightness as u16 * RANGE as u16 / 255) as u8;
        REG_MIN + step.min(RANGE)
    };
    let _ = i2c.write(AXP2101_ADDR, &[AXP_REG_DLDO1_VOLT, reg_val]);
}

macro_rules! set_brightness {
    ($i2c:expr, $brightness:expr) => {
        $crate::hw::pmu::set_brightness_value($i2c, $brightness)
    };
}
pub(crate) use set_brightness;
