// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

//! Serial-only fatal fallback when display initialization cannot continue.

pub(crate) fn continue_without_display(delay: &mut esp_hal::delay::Delay) -> ! {
    crate::log!();
    crate::log!("No-display mode — serial output only");
    crate::log!();
    let fw = crate::services::verify::FirmwareInfo::new();
    crate::log!("   Version: {}", fw.version_string().as_str());
    let firmware_start = crate::services::verify::firmware_start_addr();
    crate::log!("   Address: 0x{:08X}", firmware_start);
    match fw.verify_firmware(firmware_start, crate::services::verify::FIRMWARE_MAX_SIZE) {
        crate::services::verify::VerificationResult::Valid => crate::log!("Firmware verified OK"),
        other => {
            crate::log!("CRITICAL: Verification failed: {:?}", other);
            loop { delay.delay_millis(1000); }
        }
    }
    crate::log!("===================================");
    crate::log!("  Boot completed (no display)");
    crate::log!("===================================");
    loop { delay.delay_millis(5000); }
}
