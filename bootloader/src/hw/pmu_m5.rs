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


// hw/pmu.rs — AXP2101 PMU and AW9523B IO expander initialization

#![allow(dead_code)]
use esp_hal::delay::Delay;
use esp_hal::i2c::master::I2c;

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

pub fn init_axp2101(i2c: &mut I2c<'_, esp_hal::Blocking>, delay: &mut Delay) -> Result<(), &'static str> {
    // Set DLDO1 voltage to 3.3V (LCD backlight)
    // Register 0x99: voltage = 500mV + val*100mV → 0x1C = 3300mV
    i2c.write(AXP2101_ADDR, &[AXP_REG_DLDO1_VOLT, 0x1C])
        .map_err(|_| "AXP2101: failed to set DLDO1 voltage")?;

    // Set ALDO1 = 1800mV (reg 0x92, val = (1800-500)/100 = 13 = 0x0D)
    i2c.write(AXP2101_ADDR, &[0x92, 0x0D])
        .map_err(|_| "AXP2101: ALDO1 voltage")?;

    // Set ALDO2 = 3300mV (reg 0x93, val = (3300-500)/100 = 28 = 0x1C)
    i2c.write(AXP2101_ADDR, &[0x93, 0x1C])
        .map_err(|_| "AXP2101: ALDO2 voltage")?;

    // Set BLDO1 = 2800mV (reg 0x96, val = (2800-500)/100 = 23 = 0x17)
    i2c.write(AXP2101_ADDR, &[0x96, 0x17])
        .map_err(|_| "AXP2101: BLDO1 voltage")?;

    // Set BLDO2 = 1500mV (reg 0x97, val = (1500-500)/100 = 10 = 0x0A)
    i2c.write(AXP2101_ADDR, &[0x97, 0x0A])
        .map_err(|_| "AXP2101: BLDO2 voltage")?;

    // Set ALDO3 = 3300mV (reg 0x94, for camera) — matches M5Unified
    i2c.write(AXP2101_ADDR, &[0x94, 0x1C])
        .map_err(|_| "AXP2101: ALDO3 voltage")?;

    // Set ALDO4 = 3300mV (reg 0x95, for TF card) — matches M5Unified
    i2c.write(AXP2101_ADDR, &[0x95, 0x1C])
        .map_err(|_| "AXP2101: ALDO4 voltage")?;

    // PowerKey config (reg 0x27 = 0x00): Hold=1sec / PowerOff=4sec
    // This is critical for battery-powered boot!
    i2c.write(AXP2101_ADDR, &[0x27, 0x00])
        .map_err(|_| "AXP2101: PowerKey config")?;

    // CHGLED setting (reg 0x69 = 0x11)
    i2c.write(AXP2101_ADDR, &[0x69, 0x11])
        .map_err(|_| "AXP2101: CHGLED")?;

    // PMU common config (reg 0x10 = 0x30)
    i2c.write(AXP2101_ADDR, &[0x10, 0x30])
        .map_err(|_| "AXP2101: PMU config")?;

    // ADC enabled for voltage measurement (reg 0x30 = 0x0F)
    i2c.write(AXP2101_ADDR, &[0x30, 0x0F])
        .map_err(|_| "AXP2101: ADC enable")?;

    delay.delay_millis(10);

    // Enable ALL LDOs: 0xBF = same as M5Unified
    // bits: DLDO1(7) + BLDO2(5) + BLDO1(4) + ALDO4(3) + ALDO3(2) + ALDO2(1) + ALDO1(0)
    i2c.write(AXP2101_ADDR, &[AXP_REG_LDO_EN1, 0xBF])
        .map_err(|_| "AXP2101: failed to enable LDOs")?;

    delay.delay_millis(50); // Wait for power rails to stabilize

    Ok(())
}

/// Initialize AW9523B IO Expander — deassert LCD reset (P1.1/pin9) and touch reset (P0.0)
pub fn init_aw9523b(i2c: &mut I2c<'_, esp_hal::Blocking>, delay: &mut Delay) -> Result<(), &'static str> {
    // Software reset
    i2c.write(AW9523B_ADDR, &[AW_REG_RESET, 0x00])
        .map_err(|_| "AW9523B: reset failed")?;
    delay.delay_millis(20);

    // *** CRITICAL: Set P0 port to Push-Pull mode via GCR register ***
    // After reset, P0 is Open-Drain by default. Without push-pull,
    // P0.2 (SPK_EN / AW88298 RSTN) cannot drive HIGH reliably.
    // GCR bit4 = 1 → P0 push-pull mode
    i2c.write(AW9523B_ADDR, &[AW_REG_GCR, 0x10])
        .map_err(|_| "AW9523B: GCR push-pull failed")?;

    // Configure P1 pins as GPIO mode (not LED), all outputs
    // P1.1 = LCD reset (active low, need to deassert = HIGH)
    i2c.write(AW9523B_ADDR, &[AW_REG_LEDMODE_P1, 0xFF])  // All GPIO mode
        .map_err(|_| "AW9523B: P1 LED mode failed")?;
    i2c.write(AW9523B_ADDR, &[AW_REG_CONFIG_P1, 0x00])    // All outputs
        .map_err(|_| "AW9523B: P1 config failed")?;

    // Configure P0 pins as GPIO mode, all outputs
    // P0.0 = Touch reset (active low, need to deassert = HIGH)
    i2c.write(AW9523B_ADDR, &[AW_REG_LEDMODE_P0, 0xFF])
        .map_err(|_| "AW9523B: P0 LED mode failed")?;
    i2c.write(AW9523B_ADDR, &[AW_REG_CONFIG_P0, 0x00])
        .map_err(|_| "AW9523B: P0 config failed")?;

    // === Power-on sequence for AW88298 ===
    // Step 1: Enable boost converter FIRST (P1.7 = SY7088 BOOST_EN → PVDD supply)
    // AW88298 needs PVDD stable before RSTN goes HIGH.
    // Also deassert LCD reset (P1.1).
    i2c.write(AW9523B_ADDR, &[AW_REG_OUTPUT_P1, 0x00])    // All LOW (reset)
        .map_err(|_| "AW9523B: P1 output low failed")?;
    delay.delay_millis(20);
    i2c.write(AW9523B_ADDR, &[AW_REG_OUTPUT_P1, 0x82])    // P1.1 + P1.7 HIGH
        .map_err(|_| "AW9523B: P1 output high failed")?;
    delay.delay_millis(50); // Let boost converter stabilize PVDD

    // ALSO: Set ALL P1 bits to cover any camera reset/power-down pins
    // CoreS3 may have camera PWDN on P1.x — keep everything HIGH (deasserted)
    i2c.write(AW9523B_ADDR, &[AW_REG_OUTPUT_P1, 0xFF])
        .map_err(|_| "AW9523B: P1 all-high failed")?;
    delay.delay_millis(10);

    // Step 2: Assert RSTN LOW first to ensure clean reset of AW88298
    i2c.write(AW9523B_ADDR, &[AW_REG_OUTPUT_P0, 0x00])    // All LOW (SPK_EN=LOW → reset AW88298)
        .map_err(|_| "AW9523B: P0 output low failed")?;
    delay.delay_millis(20); // Hold reset for 20ms

    // Step 3: Deassert RSTN (P0.2 = HIGH) with PVDD already stable
    // Also deassert touch reset (P0.0)
    // AW88298 transitions: Power-Down → Standby (I2C accessible!)
    //
    // P0 pin map (from schematic):
    //   P0.0 = TOUCH_RST   (active low, deassert = HIGH)
    //   P0.2 = SPK_EN / AW88298 RSTN (active low, deassert = HIGH)
    //   P0.4 = CAM_PWDN    (GC0308 power-down, HIGH = power down, LOW = active)
    //   P0.5 = USB_OTG_EN
    //
    // Camera PWDN sequence: First assert PWDN HIGH (power down), then
    // deassert LOW (wake up) for clean power-on.
    // Step 3a: P0.4 HIGH = camera in power-down during init
    i2c.write(AW9523B_ADDR, &[AW_REG_OUTPUT_P0, 0x15])    // P0.0 + P0.2 + P0.4 HIGH
        .map_err(|_| "AW9523B: P0 output failed")?;
    delay.delay_millis(100); // AW88298 needs time to reach standby mode

    // Step 3b: Deassert CAM_PWDN (P0.4 = LOW) — camera wakes up
    i2c.write(AW9523B_ADDR, &[AW_REG_OUTPUT_P0, 0x05])    // P0.0 + P0.2 HIGH, P0.4 LOW
        .map_err(|_| "AW9523B: P0 cam pwdn deassert failed")?;
    delay.delay_millis(20); // Camera wake-up time

    Ok(())
}
/// Set LCD backlight brightness via AXP2101 DLDO1 voltage.
/// brightness: 0-255 maps to ~2.4V-3.3V (visible range only).
/// The backlight goes dark below ~2.4V (reg 0x13), so we start there.
pub fn set_brightness(i2c: &mut I2c<'_, esp_hal::Blocking>, brightness: u8) {
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
