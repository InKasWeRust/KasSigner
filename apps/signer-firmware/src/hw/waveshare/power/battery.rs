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

// hw/power/battery_ws.rs — Battery monitoring via ADC for Waveshare ESP32-S3-Touch-LCD-2
// 100% Rust, no-std, no-alloc
//
// Schematic: GPIO5 → R19(200K) → VBAT, GPIO5 → R20(100K) → GND
// Divider ratio: Vadc = Vbat × 100K / (200K + 100K) = Vbat / 3
// C31=100nF + C32=100nF for filtering
//
// Uses RTC SAR ADC1 controller for oneshot conversion (TRM §39.3.6)
// ADC1_CH4 on GPIO5, 12-bit, attenuation 12dB (0~2.5V usable range)
// With divider: max Vbat = 2.5V × 3 = 7.5V (covers Li-ion 3.0-4.2V)

use crate::hw::shared::mmio::{read as reg_read, write as reg_write};

// SENS registers for RTC ADC1 (base 0x60008800, TRM §39)
const SENS_BASE: u32               = 0x6000_8800;
const SENS_SAR_READER1_CTRL: u32   = SENS_BASE + 0x0000;
const SENS_SAR_MEAS1_CTRL2: u32    = SENS_BASE + 0x000C;
const SENS_SAR_MEAS1_MUX: u32      = SENS_BASE + 0x0010;
const SENS_SAR_ATTEN1: u32          = SENS_BASE + 0x0014;
const SENS_SAR_POWER_XPD_SAR: u32   = SENS_BASE + 0x003C;
const SENS_SAR_PERI_CLK_GATE: u32   = SENS_BASE + 0x0104;

// System peripheral clock
const SYSTEM_PERIP_CLK_EN0: u32 = 0x600C_0018;

pub use signer_firmware_core::power::battery::ChargeState;

/// Battery status snapshot
#[derive(Debug, Clone, Copy)]
pub struct BatteryStatus {
    pub voltage_mv: u16,
    pub percentage: u8,
    pub state: ChargeState,
}

/// Initialize ADC1 for battery reading. Call once at startup.
pub fn init_battery_adc() {
    unsafe {
        // Enable SARADC peripheral clock (bit 28 of PERIP_CLK_EN0)
        let clk = reg_read(SYSTEM_PERIP_CLK_EN0);
        reg_write(SYSTEM_PERIP_CLK_EN0, clk | (1u32 << 28));

        // Enable SENS peripheral clock gate
        let gate = reg_read(SENS_SAR_PERI_CLK_GATE);
        reg_write(SENS_SAR_PERI_CLK_GATE, gate | 0x3F); // enable all SENS clocks

        // Disable digital input on GPIO5 for analog use
        let iomux5 = (0x6000_9004u32 + 5 * 4) as *mut u32;
        let v = core::ptr::read_volatile(iomux5);
        core::ptr::write_volatile(iomux5, v & !(1u32 << 9)); // clear FUN_IE

        // Select RTC controller for ADC1 (not DIG controller)
        // SENS_SAR_MEAS1_MUX: bit 31 = SAR1_DIG_FORCE = 0
        let mux = reg_read(SENS_SAR_MEAS1_MUX);
        reg_write(SENS_SAR_MEAS1_MUX, mux & !(1u32 << 31));

        // Set attenuation for channel 4: bits[9:8] = 3 (12dB, 0~2.5V)
        let atten = reg_read(SENS_SAR_ATTEN1);
        reg_write(SENS_SAR_ATTEN1, (atten & !(0x3u32 << 8)) | (0x3u32 << 8));

        // Force SAR ADC power on
        let pwr = reg_read(SENS_SAR_POWER_XPD_SAR);
        reg_write(SENS_SAR_POWER_XPD_SAR, (pwr & !0x3) | 0x3); // XPD_SAR_FORCE + XPD_SAR

        // Configure reader: clock divider=2 (RTCADC_SARCLK ≤ 5MHz from ~17.5MHz RC)
        let reader = reg_read(SENS_SAR_READER1_CTRL);
        reg_write(SENS_SAR_READER1_CTRL, (reader & !0xFF) | 4); // clk_div=4
    }
}

/// Read ADC1 channel 4 (GPIO5) via RTC controller oneshot mode.
/// Returns raw 12-bit value (0-4095).
fn adc1_oneshot_ch4() -> u16 {
    unsafe {
        // SENS_SAR_MEAS1_CTRL2:
        //   bit 31: SAR1_EN_PAD_FORCE = 1 (software controls pad enable)
        //   bits 30:19: SAR1_EN_PAD = channel bitmask (ch4 → bit4 at position 23)
        //   bit 18: MEAS1_START_FORCE = 1 (software trigger)
        //   bit 17: MEAS1_START_SAR = trigger bit (write 1 to start)
        //   bit 16: MEAS1_DONE_SAR (read-only, set when done)
        //   bits 15:0: MEAS1_DATA_SAR (read-only, result)

        let en_pad = 1u32 << (19 + 4); // channel 4 in SAR1_EN_PAD field (bit 23)
        let force_bits = (1u32 << 31) | (1u32 << 18); // EN_PAD_FORCE + START_FORCE

        // Clear start, set up pad selection
        reg_write(SENS_SAR_MEAS1_CTRL2, force_bits | en_pad);

        // Small delay for setup
        for _ in 0..10u32 { reg_read(SENS_SAR_MEAS1_CTRL2); }

        // Trigger conversion: set MEAS1_START_SAR (bit 17)
        reg_write(SENS_SAR_MEAS1_CTRL2, force_bits | en_pad | (1u32 << 17));

        // Wait for MEAS1_DONE_SAR (bit 16) with timeout
        for _ in 0..100_000u32 {
            let ctrl2 = reg_read(SENS_SAR_MEAS1_CTRL2);
            if ctrl2 & (1u32 << 16) != 0 {
                // Read result from bits 15:0
                return (ctrl2 & 0xFFF) as u16;
            }
        }

        // Timeout — return 0
        0
    }
}

use signer_firmware_core::power::battery::{raw_to_voltage_mv, voltage_to_percent};

/// Read battery status via ADC on GPIO5.
pub fn read_battery_value() -> Option<BatteryStatus> {
    // Average 4 readings for stability
    let mut sum = 0u32;
    for _ in 0..4 {
        sum += adc1_oneshot_ch4() as u32;
    }
    let raw = (sum / 4) as u16;

    // If raw is very low, ADC may not be working — return USB default
    if raw < 50 {
        return Some(BatteryStatus {
            voltage_mv: 4200,
            percentage: 100,
            state: ChargeState::Unknown,
        });
    }

    let voltage_mv = raw_to_voltage_mv(raw);
    let percentage = voltage_to_percent(voltage_mv);

    let state = if voltage_mv > 4150 {
        ChargeState::Charging
    } else {
        ChargeState::Discharging
    };

    Some(BatteryStatus {
        voltage_mv,
        percentage,
        state,
    })
}

macro_rules! read_battery {
    ($i2c:expr) => {
        $crate::hw::battery::read_battery_value()
    };
}
pub(crate) use read_battery;
