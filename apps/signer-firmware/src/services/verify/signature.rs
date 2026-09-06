use super::{FirmwareInfo, VerificationResult, constant_time, embedded_firmware_signature};

impl FirmwareInfo {
    pub(super) fn verify_signature(&self) -> VerificationResult {
        #[cfg(feature = "production")]
        let pubkey = &signer_firmware_core::update::release::PRODUCTION_RELEASE_PUBKEY;
        #[cfg(not(feature = "production"))]
        let pubkey = &signer_firmware_core::update::release::DEV_TEST_PUBKEY;

        if constant_time::eq(pubkey, &[0u8; 32]) {
            log!("   WARNING: firmware signing public key not configured");
            return VerificationResult::InvalidSignature;
        }

        let sig = offline_signer::crypto::schnorr::SchnorrSignature {
            bytes: embedded_firmware_signature(),
        };
        match offline_signer::crypto::schnorr::schnorr_verify(pubkey, &self.expected_hash, &sig) {
            Ok(()) => VerificationResult::Valid,
            Err(_) => {
                log!("   Schnorr signature verification FAILED");
                VerificationResult::InvalidSignature
            }
        }
    }
}
