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


// hw/battery.rs — Battery monitoring via AXP2101 PMU
// 100% Rust, no-std, no-alloc
//
// Reads battery voltage and charge status from AXP2101 over I2C.
// ADC must be enabled first (reg 0x30 = 0x0F, done in pmu::init_axp2101).
//
// Registers:
//   0x00 bit 3: battery present
//   0x01 bits [7:5]: charge status (1=charging, 2=discharging)
//   0x34: VBAT high (bits [5:0])
//   0x35: VBAT low (bits [7:0])
//   Voltage (mV) = (reg[0x34] & 0x3F) << 8 | reg[0x35]
//
// Li-ion mapping: 3000mV = 0%, 4200mV = 100% (linear approximation)

use esp_hal::i2c::master::I2c;

const AXP2101_ADDR: u8 = 0x34;

/// Battery charge state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChargeState {
    /// Battery is charging from USB/adapter
    Charging,
    /// Battery is discharging (running on battery)
    Discharging,
    /// Charge state unknown or standby
    Unknown,
}

/// Battery status snapshot
#[derive(Debug, Clone, Copy)]
pub struct BatteryStatus {
    /// Battery present flag
    pub present: bool,
    /// Battery voltage in millivolts
    pub voltage_mv: u16,
    /// Estimated battery percentage (0-100)
    pub percentage: u8,
    /// Charging state
    pub state: ChargeState,
}

/// Read a single register from AXP2101
fn read_reg(i2c: &mut I2c<'_, esp_hal::Blocking>, reg: u8) -> Result<u8, ()> {
    let mut buf = [0u8; 1];
    i2c.write_read(AXP2101_ADDR, &[reg], &mut buf).map_err(|_| ())?;
    Ok(buf[0])
}

/// Read battery status from AXP2101.
/// Returns None if I2C communication fails.
pub fn read_battery(i2c: &mut I2c<'_, esp_hal::Blocking>) -> Option<BatteryStatus> {
    // Read battery present (reg 0x00, bit 3)
    let status0 = read_reg(i2c, 0x00).ok()?;
    let present = (status0 & 0x08) != 0;

    // Read charge status (reg 0x01, bits [7:5])
    let status1 = read_reg(i2c, 0x01).ok()?;
    let charge_bits = (status1 >> 5) & 0x03;
    let state = match charge_bits {
        1 => ChargeState::Charging,
        2 => ChargeState::Discharging,
        _ => ChargeState::Unknown,
    };

    // Read VBAT voltage (reg 0x34 high, reg 0x35 low)
    // 14-bit value: (0x34[5:0] << 8) | 0x35[7:0] = millivolts
    let vbat_h = read_reg(i2c, 0x34).ok()?;
    let vbat_l = read_reg(i2c, 0x35).ok()?;
    let voltage_mv = ((vbat_h as u16 & 0x3F) << 8) | (vbat_l as u16);

    // Estimate percentage: AXP2101 charge termination is ~4.1V,
    // and under load VBAT reads ~4120mV when full.
    // Use 3200mV → 0% (safe cutoff), 4120mV → 100% (full charge reading)
    let percentage = if voltage_mv <= 3200 {
        0u8
    } else if voltage_mv >= 4100 {
        100u8
    } else {
        ((voltage_mv - 3200) as u32 * 100 / 900) as u8
    };

    Some(BatteryStatus {
        present,
        voltage_mv,
        percentage,
        state,
    })
}
