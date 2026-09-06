use super::{
    CANARY_PRE_VERIFY,
    FirmwareInfo,
    Ordering,
    VerificationResult,
    compiler_fence,
    flow,
};
#[cfg(not(feature = "production"))]
use super::{constant_time, embedded_firmware_signed};

#[cfg(feature = "production")]
mod production;

// Firmware verification policy and anti-glitch orchestration.
impl FirmwareInfo {
    /// Verify firmware integrity: hash check + signature validation.
    pub fn verify_firmware(
        &self,
        firmware_start: u32,
        max_size: usize,
    ) -> VerificationResult {
        flow::reset();
        flow::advance(flow::Stage::VerifyStart);
        log!("   Verifying firmware...");
        log!("   Code segment: 0x{:08X}", firmware_start);

        let canary_pre = CANARY_PRE_VERIFY;
        compiler_fence(Ordering::SeqCst);
        if let Err(result) = self.verify_anti_rollback() {
            return result;
        }

        #[cfg(not(feature = "production"))]
        {
            self.verify_development(firmware_start, max_size, canary_pre)
        }
        #[cfg(feature = "production")]
        {
            self.verify_production(firmware_start, max_size, canary_pre)
        }
    }

    fn verify_anti_rollback(&self) -> Result<(), VerificationResult> {
        match super::anti_rollback::verify_device_floor() {
            Ok(floor) => log!(
                "   Security version {} >= device floor {} OK",
                super::anti_rollback::APP_SECURITY_VERSION,
                floor
            ),
            #[cfg(all(feature = "m5stack", feature = "production"))]
            Err(super::anti_rollback::AntiRollbackError::Unprovisioned) => {
                log!("   FAIL: anti-rollback eFuse floor is not provisioned");
                return Err(VerificationResult::AntiRollbackUnprovisioned);
            }
            Err(super::anti_rollback::AntiRollbackError::ImageBelowDeviceFloor) => {
                log!("   FAIL: image security version is below device eFuse floor");
                return Err(VerificationResult::VersionTooOld);
            }
        }
        flow::advance(flow::Stage::AntiRollback);
        Ok(())
    }

    #[cfg(not(feature = "production"))]
    fn verify_development(
        &self,
        firmware_start: u32,
        max_size: usize,
        canary_pre: u32,
    ) -> VerificationResult {
        log!("   [DEV] Test-signed development mode");
        if constant_time::eq(&self.expected_hash, &[0u8; 32]) {
            log!("   [DEV] FAIL: firmware hash is not configured");
            return VerificationResult::InvalidHash;
        }
        let result = self.do_verify_mapped_code(firmware_start, max_size);
        compiler_fence(Ordering::SeqCst);
        if canary_pre != CANARY_PRE_VERIFY {
            log!("   [DEV] ALERT: Canary corrupt!");
            return VerificationResult::CanaryCorrupt;
        }
        if !matches!(result, VerificationResult::Valid) {
            log!("   [DEV] Firmware code-segment hash verification failed: {:?}", result);
            return result;
        }
        if !embedded_firmware_signed() {
            log!("   [DEV] FAIL: development image is not test-signed");
            return VerificationResult::InvalidSignature;
        }
        if !matches!(self.verify_signature(), VerificationResult::Valid) {
            log!("   [DEV] FAIL: development TEST signature is invalid");
            return VerificationResult::InvalidSignature;
        }
        log!("   [DEV] Code segment hash: OK");
        log!("   [DEV] TEST signature: VALID");
        VerificationResult::Valid
    }
}
