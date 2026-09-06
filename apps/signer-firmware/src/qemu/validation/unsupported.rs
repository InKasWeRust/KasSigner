// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Explicit coverage accounting for devices absent from Espressif QEMU.

use super::report::Report;

pub(crate) fn register(report: &mut Report) {
    report.skipped("external PSRAM", "not modeled by the ESP32-S3 QEMU machine");
    report.skipped("LCD pixel transport", "board SPI/LCD wiring is not modeled");
    report.skipped("physical touch controller", "board I2C/GPIO wiring is not modeled");
    report.skipped("camera sensor and DVP", "camera hardware is not modeled");
    report.skipped("SD card transport", "board SPI/SD wiring is not modeled");
    report.skipped("backlight PWM", "LEDC and board wiring are not modeled");
    report.skipped("battery and power IC", "external power-management IC is not modeled");
    report.skipped("physical entropy quality", "QEMU RNG validates register behavior only");
}
