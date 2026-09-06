use crate::power::battery::{
    axp2101_voltage_to_percent, decode_axp2101_battery, raw_to_voltage_mv, voltage_to_percent,
    ChargeState,
};

#[test]
fn adc_conversion_covers_endpoints_and_midpoint() {
    assert_eq!(raw_to_voltage_mv(0), 0);
    assert_eq!(raw_to_voltage_mv(4095), 7500);
    assert!((3748..=3751).contains(&raw_to_voltage_mv(2048)));
}

#[test]
fn percentage_curve_is_monotonic_and_covers_every_boundary() {
    let cases = [
        (0, 0),
        (3299, 0),
        (3300, 5),
        (3489, 5),
        (3490, 10),
        (3559, 10),
        (3560, 20),
        (3619, 20),
        (3620, 30),
        (3679, 30),
        (3680, 40),
        (3719, 40),
        (3720, 50),
        (3779, 50),
        (3780, 60),
        (3849, 60),
        (3850, 70),
        (3949, 70),
        (3950, 80),
        (4049, 80),
        (4050, 90),
        (4149, 90),
        (4150, 100),
        (u16::MAX, 100),
    ];
    for (millivolts, expected) in cases {
        assert_eq!(voltage_to_percent(millivolts), expected, "{millivolts} mV");
    }
    let mut previous = 0;
    for millivolts in 0..=u16::MAX {
        let current = voltage_to_percent(millivolts);
        assert!(current >= previous);
        previous = current;
    }
}

#[test]
fn axp2101_decoding_covers_charge_states_and_percentage_boundaries() {
    assert_eq!(axp2101_voltage_to_percent(0), 0);
    assert_eq!(axp2101_voltage_to_percent(3200), 0);
    assert_eq!(axp2101_voltage_to_percent(3650), 50);
    assert_eq!(axp2101_voltage_to_percent(4099), 99);
    assert_eq!(axp2101_voltage_to_percent(4100), 100);
    assert_eq!(axp2101_voltage_to_percent(u16::MAX), 100);

    let charging = decode_axp2101_battery(1 << 5, 0x0e, 0x42);
    assert_eq!(charging.voltage_mv, 3650);
    assert_eq!(charging.percentage, 50);
    assert_eq!(charging.state, ChargeState::Charging);
    assert_eq!(
        decode_axp2101_battery(2 << 5, 0, 0).state,
        ChargeState::Discharging
    );
    assert_eq!(decode_axp2101_battery(0, 0, 0).state, ChargeState::Unknown);
    assert_eq!(
        decode_axp2101_battery(3 << 5, 0, 0).state,
        ChargeState::Unknown
    );
    assert_eq!(decode_axp2101_battery(0, 0xff, 0xff).voltage_mv, 0x3fff);
}
