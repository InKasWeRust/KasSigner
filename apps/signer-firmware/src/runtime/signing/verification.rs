// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Firmware integrity and hardware-rooted attestation during boot.

use crate::halt_forever;
use crate::hw::display::BootDisplay;
use crate::services::verify::{
    FIRMWARE_MAX_SIZE, FirmwareInfo, VerificationResult, firmware_start_addr,
};
#[cfg(feature = "production")]
use crate::services::verify::AttestationEvidence;

/// Verify firmware integrity and show an honest trust state on the display.
pub fn run_firmware_verify(
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    log!("Verifying Firmware");
    log!("────────────────────────────────");

    let firmware_info = FirmwareInfo::new();
    let version_str = firmware_info.version_string();
    let code_hash = firmware_info.get_display_hash();
    let code_hash_short = firmware_info.hash_to_hex_short(&code_hash);

    let firmware_start = firmware_start_addr();
    log!("   Version: {}", version_str.as_str());
    log!("   Address: 0x{:08X}", firmware_start);
    log!("   Max verified code segment: {} KB", FIRMWARE_MAX_SIZE / 1024);
    log!("   Code hash: {}", code_hash_short.as_str());

    boot_display.show_logo_screen().ok();
    let verify_result = firmware_info.verify_firmware(firmware_start, FIRMWARE_MAX_SIZE);
    delay.delay_millis(1200);

    match verify_result {
        VerificationResult::Valid => finish_verified_boot(boot_display, delay, &firmware_info),
        VerificationResult::InvalidHash => fail_boot(boot_display, delay, "HASH INVALID"),
        VerificationResult::InvalidSignature => fail_boot(boot_display, delay, "SIGNATURE INVALID"),
        VerificationResult::VersionTooOld => fail_boot(boot_display, delay, "SECURITY VERSION OLD"),
        #[cfg(all(feature = "m5stack", feature = "production"))]
        VerificationResult::AntiRollbackUnprovisioned => {
            fail_boot(boot_display, delay, "ANTI-ROLLBACK NOT PROVISIONED")
        },
        VerificationResult::ReadError => fail_boot(boot_display, delay, "READ ERROR"),
        #[cfg(feature = "production")]
        VerificationResult::FlowViolation => fail_boot(boot_display, delay, "FLOW VIOLATION"),
        VerificationResult::CanaryCorrupt => fail_boot(boot_display, delay, "TAMPER DETECT"),
    }

    log!();
    log!("===================================");
    log!("  Boot sequence completed");
    log!("===================================");
    log!();
}

#[cfg(feature = "production")]
fn finish_verified_boot(
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    firmware_info: &FirmwareInfo,
) {
    let verified_code_hash = firmware_info.get_display_hash();
    match crate::services::verify::verify_running_image(&verified_code_hash) {
        Ok(evidence) => show_attestation(boot_display, delay, firmware_info, &evidence),
        Err(error) => {
            log!("CRITICAL: production attestation failed: {:?}", error);
            fail_boot(boot_display, delay, error.message());
        }
    }
}

#[cfg(not(feature = "production"))]
fn finish_verified_boot(
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    firmware_info: &FirmwareInfo,
) {
    log!(
        "Development firmware v{}: hardware attestation is not claimed",
        firmware_info.version_string().as_str()
    );
    boot_display.show_logo_screen().ok();
    delay.delay_millis(400);
}

#[cfg(feature = "production")]
fn show_attestation(
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    firmware_info: &FirmwareInfo,
    evidence: &AttestationEvidence,
) {
    let version = firmware_info.version_string();
    let full_hash = firmware_info.hash_to_hex_full(&evidence.identity_hash);
    let phrase = attestation_phrase(firmware_info, evidence);
    let commit = short_commit(evidence.build_commit);

    log!("Production attestation OK");
    log!("   Secure Boot v2: {}", if evidence.hardware_secure_boot { "HARDWARE ON" } else { "SOFTWARE VERIFIED" });
    log!("   Flash encryption: {}", if evidence.flash_encryption { "ON" } else { "OFF" });
    log!("   Hash scope: {:?}", evidence.hash_scope);
    log!("   Signed identity SHA-256: {}", full_hash.as_str());
    log!("   Source: {}", commit);
    log!("   {}", phrase.as_str());

    boot_display
        .show_verification_screen(
            version.as_str(),
            commit,
            full_hash.as_str(),
            phrase.as_str(),
            evidence.hardware_secure_boot,
        )
        .ok();
    delay.delay_millis(3500);
}

#[cfg(feature = "production")]
fn attestation_phrase(
    firmware_info: &FirmwareInfo,
    evidence: &AttestationEvidence,
) -> heapless::String<64> {
    use core::fmt::Write;

    let words = firmware_info.attestation_phrase(&evidence.identity_hash);
    let mut text = heapless::String::new();
    write!(
        &mut text,
        "{} {}",
        evidence.hash_scope.phrase_prefix(),
        words.as_str()
    )
    .ok();
    text
}

#[cfg(feature = "production")]
fn short_commit(commit: &'static str) -> &'static str {
    crate::ui::display::truncate_chars(commit, 12)
}

fn fail_boot(
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    reason: &'static str,
) -> ! {
    log!("CRITICAL: firmware verification failed: {}", reason);
    #[cfg(feature = "hardware-tests")]
    log!("KASSIGNER_HARDWARE_TESTS: FAIL");
    boot_display.show_panic_screen(reason).ok();
    halt_forever(delay)
}
