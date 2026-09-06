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


// hw/power/battery_m5.rs — Battery monitoring via AXP2101 PMU
// 100% Rust, no-std, no-alloc
//
// Reads battery voltage and charge status from AXP2101 over I2C.
// ADC must be enabled first (reg 0x30 = 0x0F, done in pmu::init_axp2101).
//
// Registers:
//   0x01 bits [7:5]: charge status (1=charging, 2=discharging)
//   0x34: VBAT high (bits [5:0])
//   0x35: VBAT low (bits [7:0])
//   Voltage (mV) = (reg[0x34] & 0x3F) << 8 | reg[0x35]
//
// Li-ion mapping: 3000mV = 0%, 4200mV = 100% (linear approximation)

use core::sync::atomic::{AtomicU32, Ordering};
use esp_hal::i2c::master::I2c;

const AXP2101_ADDR: u8 = 0x34;
const CACHE_VALID: u32 = 1 << 31;
const CACHE_CHARGING: u32 = 1 << 8;
const CACHE_DISCHARGING: u32 = 1 << 9;
static CACHED_BATTERY: AtomicU32 = AtomicU32::new(0);

pub use signer_firmware_core::power::battery::ChargeState;

/// Battery status snapshot
#[derive(Debug, Clone, Copy)]
pub struct BatteryStatus {
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

/// Read battery status from AXP2101. This is a boot-time operation only on
/// CoreS3: Home redraw must never put blocking PMU I2C ahead of touch polling.
fn read_battery_value(i2c: &mut I2c<'_, esp_hal::Blocking>) -> Option<BatteryStatus> {
    let status = read_reg(i2c, 0x01).ok()?;
    let voltage_high = read_reg(i2c, 0x34).ok()?;
    let voltage_low = read_reg(i2c, 0x35).ok()?;
    let reading = signer_firmware_core::power::battery::decode_axp2101_battery(
        status,
        voltage_high,
        voltage_low,
    );
    Some(BatteryStatus { percentage: reading.percentage, state: reading.state })
}

/// Capture one PMU snapshot while the boot power phase already owns the bus.
pub(crate) fn refresh_boot_cache(i2c: &mut I2c<'_, esp_hal::Blocking>) -> Option<BatteryStatus> {
    let status = read_battery_value(i2c)?;
    CACHED_BATTERY.store(encode(status), Ordering::Relaxed);
    Some(status)
}

/// Return the last boot snapshot without touching I2C.
pub(crate) fn cached_battery_value() -> Option<BatteryStatus> {
    let encoded = CACHED_BATTERY.load(Ordering::Relaxed);
    if encoded & CACHE_VALID == 0 { return None; }
    Some(BatteryStatus {
        percentage: (encoded & 0xff) as u8,
        state: decode_state(encoded),
    })
}

fn encode(status: BatteryStatus) -> u32 {
    let state = match status.state {
        ChargeState::Charging => CACHE_CHARGING,
        ChargeState::Discharging => CACHE_DISCHARGING,
        ChargeState::Unknown => 0,
    };
    CACHE_VALID | state | u32::from(status.percentage)
}

fn decode_state(encoded: u32) -> ChargeState {
    if encoded & CACHE_CHARGING != 0 {
        ChargeState::Charging
    } else if encoded & CACHE_DISCHARGING != 0 {
        ChargeState::Discharging
    } else {
        ChargeState::Unknown
    }
}

macro_rules! read_battery {
    ($i2c:expr) => {{
        // Keep one board-neutral redraw call site while proving that CoreS3 Home
        // rendering cannot block on the shared PMU/touch I2C bus.
        let _ = &mut *$i2c;
        $crate::hw::battery::cached_battery_value()
    }};
}
pub(crate) use read_battery;
