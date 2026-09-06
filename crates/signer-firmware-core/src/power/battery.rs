//! Pure battery conversion policy shared with the Waveshare adapter.

/// Convert one 12-bit ADC sample into the battery voltage after the 3:1 divider.
pub fn raw_to_voltage_mv(raw: u16) -> u16 {
    let vadc_mv = (u32::from(raw) * 2500) / 4095;
    (vadc_mv * 3) as u16
}

const BATTERY_PERCENT_STEPS: [(u16, u8); 11] = [
    (4150, 100),
    (4050, 90),
    (3950, 80),
    (3850, 70),
    (3780, 60),
    (3720, 50),
    (3680, 40),
    (3620, 30),
    (3560, 20),
    (3490, 10),
    (3300, 5),
];

/// Convert battery voltage to the displayed Li-ion percentage.
pub fn voltage_to_percent(mv: u16) -> u8 {
    BATTERY_PERCENT_STEPS
        .iter()
        .find_map(|&(minimum_mv, percentage)| (mv >= minimum_mv).then_some(percentage))
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChargeState {
    Charging,
    Discharging,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Axp2101BatteryReading {
    pub voltage_mv: u16,
    pub percentage: u8,
    pub state: ChargeState,
}

/// Decode AXP2101 charge status and VBAT registers without performing I/O.
pub const fn decode_axp2101_battery(
    status: u8,
    voltage_high: u8,
    voltage_low: u8,
) -> Axp2101BatteryReading {
    let charge_bits = (status >> 5) & 0x03;
    let state = match charge_bits {
        1 => ChargeState::Charging,
        2 => ChargeState::Discharging,
        _ => ChargeState::Unknown,
    };
    let voltage_mv = ((voltage_high as u16 & 0x3F) << 8) | voltage_low as u16;
    let percentage = axp2101_voltage_to_percent(voltage_mv);
    Axp2101BatteryReading {
        voltage_mv,
        percentage,
        state,
    }
}

/// Map the CoreS3's observed battery range to a bounded percentage.
pub const fn axp2101_voltage_to_percent(voltage_mv: u16) -> u8 {
    if voltage_mv <= 3200 {
        0
    } else if voltage_mv >= 4100 {
        100
    } else {
        ((voltage_mv - 3200) as u32 * 100 / 900) as u8
    }
}
