use super::super::{
    CANARY_POST_VERIFY,
    FirmwareInfo,
    Ordering,
    VerificationResult,
    compiler_fence,
    constant_time,
    flow,
};
#[cfg(not(any(feature = "owner-firmware", feature = "secure-owner-only")))]
use super::super::embedded_firmware_signed;

impl FirmwareInfo {
    pub(super) fn verify_production(
        &self,
        firmware_start: u32,
        max_size: usize,
        canary_pre: u32,
    ) -> VerificationResult {
        log!("   [PROD] STRICT verification");
        if constant_time::eq(&self.expected_hash, &[0u8; 32]) {
            log!("   CRITICAL: Hash not configured in production!");
            return VerificationResult::InvalidHash;
        }

        let result1 = self.do_verify_mapped_code(firmware_start, max_size);
        compiler_fence(Ordering::SeqCst);
        if canary_pre != super::super::CANARY_PRE_VERIFY {
            log!("   CRITICAL: Canary pre-verify corrupt!");
            return VerificationResult::CanaryCorrupt;
        }
        let canary_mid = CANARY_POST_VERIFY;
        compiler_fence(Ordering::SeqCst);
        let result2 = self.do_verify_mapped_code(firmware_start, max_size);
        compiler_fence(Ordering::SeqCst);

        if let Err(result) = validate_results(canary_mid, result1, result2) {
            return result;
        }
        if !verify_flow() {
            return VerificationResult::FlowViolation;
        }
        self.verify_production_signature()
    }

    #[cfg(not(any(feature = "owner-firmware", feature = "secure-owner-only")))]
    fn verify_production_signature(&self) -> VerificationResult {
        if !embedded_firmware_signed() {
            log!("   CRITICAL: Unsigned build in production mode!");
            return VerificationResult::InvalidSignature;
        }
        if !matches!(self.verify_signature(), VerificationResult::Valid) {
            log!("   CRITICAL: Official release signature INVALID!");
            return VerificationResult::InvalidSignature;
        }
        log!("   Official release signature: VALID");
        VerificationResult::Valid
    }

    #[cfg(feature = "secure-owner-only")]
    fn verify_production_signature(&self) -> VerificationResult {
        if crate::services::verify::boot_security::secure_boot_enabled() {
            log!("   Owner-only authority: hardware Secure Boot enforced");
        } else {
            // Before Pop It there is intentionally no immutable vendor trust
            // root. The hash/flow checks above still catch accidental corruption,
            // while the signed bootloader verifies this exact build against the
            // owner RSA key before that key is burned as the sole hardware root.
            log!("   Owner-only pre-Pop mode: RSA trust root not yet fused");
        }
        VerificationResult::Valid
    }

    #[cfg(feature = "owner-firmware")]
    fn verify_production_signature(&self) -> VerificationResult {
        if !crate::services::verify::boot_security::secure_boot_enabled() {
            log!("   CRITICAL: Owner firmware requires hardware Secure Boot!");
            return VerificationResult::InvalidSignature;
        }
        log!("   Owner authority: hardware Secure Boot enforced");
        VerificationResult::Valid
    }
}

fn validate_results(
    canary_mid: u32,
    result1: VerificationResult,
    result2: VerificationResult,
) -> Result<(), VerificationResult> {
    if canary_mid != CANARY_POST_VERIFY {
        log!("   CRITICAL: Canary mid-verify corrupt!");
        return Err(VerificationResult::CanaryCorrupt);
    }
    if !matches!(result1, VerificationResult::Valid) {
        log!("   FAIL: First pass: {:?}", result1);
        return Err(result1);
    }
    if !matches!(result2, VerificationResult::Valid) {
        log!("   FAIL: Second pass: {:?}", result2);
        return Err(result2);
    }
    if result1 != result2 {
        log!("   CRITICAL: Inconsistent results!");
        return Err(VerificationResult::CanaryCorrupt);
    }
    Ok(())
}

fn verify_flow() -> bool {
    let expected_flow = [
        flow::Stage::VerifyStart,
        flow::Stage::AntiRollback,
        flow::Stage::MapStart,
        flow::Stage::SegmentReady,
        flow::Stage::HashComplete,
        flow::Stage::CompareComplete,
        flow::Stage::MapStart,
        flow::Stage::SegmentReady,
        flow::Stage::HashComplete,
        flow::Stage::CompareComplete,
    ];
    if !flow::verify(&expected_flow) {
        log!("   CRITICAL: ordered flow transcript mismatch");
        return false;
    }
    log!("   Verified: double pass + ordered anti-glitch OK");
    true
}
