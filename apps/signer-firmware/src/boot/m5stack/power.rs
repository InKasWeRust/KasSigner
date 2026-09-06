//! CoreS3 PMU and IO-expander initialization phase.

use esp_hal::{
    Blocking, delay::Delay,
    i2c::master::{Config as I2cConfig, I2c, SoftwareTimeout},
    time::{Duration, Rate},
};

pub(crate) fn control_bus_config() -> I2cConfig {
    I2cConfig::default()
        .with_frequency(Rate::from_khz(400))
        .with_software_timeout(SoftwareTimeout::Transaction(Duration::from_millis(100)))
}

pub(crate) fn initialize(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) {
    crate::log!("   BOOT PHASE power BEGIN");
    crate::log!("   AXP2101 PMU init...");
    match crate::hw::pmu::init_axp2101(i2c, delay) {
        Ok(()) => {
            crate::log!("   AXP2101 OK — DLDO1 enabled (3.3V backlight)");
            #[cfg(not(feature = "workflow-test-auto"))]
            match crate::hw::battery::refresh_boot_cache(i2c) {
                Some(battery) => crate::log!(
                    "   Battery boot snapshot: {}% {:?}", battery.percentage, battery.state
                ),
                None => crate::log!("   Battery boot snapshot unavailable"),
            }
            #[cfg(feature = "workflow-test-auto")]
            {
                // Battery telemetry is not part of workflow/GUI E2E evidence. Keep the
                // automated image out of this optional AXP2101 write-read path so a
                // wedged PMU telemetry transaction cannot block all later board phases.
                crate::log!("   Battery boot snapshot: skipped for workflow E2E liveness");
                crate::log!("KASSIGNER_WORKFLOW_TESTS: OPTIONAL BATTERY SNAPSHOT SKIPPED");
            }
        }
        Err(error) => {
            crate::log!("   AXP2101 FAILED: {}", error);
            crate::log!("   Display may not work without backlight power!");
        }
    }

    crate::log!("   AW9523B IO Expander init...");
    match crate::hw::pmu::init_aw9523b(i2c, delay) {
        Ok(()) => crate::log!("   AW9523B OK — LCD and touch reset deasserted"),
        Err(error) => {
            crate::log!("   AW9523B FAILED: {}", error);
            crate::log!("   Display will not initialize without reset release!");
        }
    }
    crate::log!("   BOOT PHASE power DONE");
}
