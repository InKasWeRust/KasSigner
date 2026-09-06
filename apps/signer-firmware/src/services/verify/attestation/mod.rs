//! Hardware-rooted attestation of the currently executing ESP32-S3 firmware.
//!
//! Production attestation distinguishes a signed/software-verified boot from
//! the stronger state where the ESP32-S3 Secure Boot v2 eFuse is enforcing the
//! same signed boot chain. The normal KasSigner Schnorr/code verification must
//! already have succeeded. When flash encryption is disabled we additionally bind
//! the display to the deterministic digest of the Secure-Boot-signed app content. With flash
//! encryption enabled, raw SPI reads are ciphertext, so the attestation uses
//! the already verified Schnorr-signed code digest instead of pretending a raw
//! ciphertext digest is the release-image digest. The normal path displays the
//! deterministic SHA-256 digest of the complete Secure-Boot-signed app content
//! (including v2 secure padding, excluding the appended signature sector).

use esp_hal::efuse::{Efuse, SECURE_BOOT_EN};
#[cfg(all(feature = "m5stack", feature = "production"))]
use esp_hal::efuse::DIS_DOWNLOAD_MANUAL_ENCRYPT;

mod flash;
mod image;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationError {
    #[cfg(all(feature = "m5stack", feature = "production"))]
    FlashEncryptionDisabled,
    #[cfg(all(feature = "m5stack", feature = "production"))]
    FlashEncryptionNotRelease,
    FlashRead,
    ImageLayout,
    AppendedHashMismatch,
    SecureBootDigestMissing,
    SecureBootDigestMismatch,
    BuildIdentityMissing,
}

impl AttestationError {
    pub const fn message(self) -> &'static str {
        match self {
            #[cfg(all(feature = "m5stack", feature = "production"))]
            Self::FlashEncryptionDisabled => "ATTESTATION: FLASH ENCRYPTION OFF",
            #[cfg(all(feature = "m5stack", feature = "production"))]
            Self::FlashEncryptionNotRelease => "ATTESTATION: FLASH ENCRYPTION NOT RELEASE",
            Self::FlashRead => "ATTESTATION: IMAGE READ FAILED",
            Self::ImageLayout => "ATTESTATION: IMAGE FORMAT INVALID",
            Self::AppendedHashMismatch => "ATTESTATION: IMAGE HASH INVALID",
            Self::SecureBootDigestMissing => "ATTESTATION: BOOT SIGNATURE MISSING",
            Self::SecureBootDigestMismatch => "ATTESTATION: BOOT DIGEST INVALID",
            Self::BuildIdentityMissing => "ATTESTATION: BUILD ID MISSING",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationHashScope {
    SignedImage,
    SignedCode,
}

impl AttestationHashScope {
    pub const fn phrase_prefix(self) -> &'static str {
        match self {
            Self::SignedImage => "Image phrase:",
            Self::SignedCode => "Code phrase:",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestationEvidence {
    pub identity_hash: [u8; 32],
    pub hash_scope: AttestationHashScope,
    pub flash_encryption: bool,
    pub hardware_secure_boot: bool,
    pub build_commit: &'static str,
}

pub fn verify_running_image(
    verified_code_hash: &[u8; 32],
) -> Result<AttestationEvidence, AttestationError> {
    let hardware_secure_boot = secure_boot_enabled();
    let build_commit = build_commit()?;

    #[cfg(all(feature = "m5stack", feature = "production"))]
    if hardware_secure_boot {
        require_release_flash_encryption()?;
    }

    if flash_encryption_enabled() {
        return Ok(AttestationEvidence {
            identity_hash: *verified_code_hash,
            hash_scope: AttestationHashScope::SignedCode,
            flash_encryption: true,
            hardware_secure_boot,
            build_commit,
        });
    }

    flash::with_other_core_parked(image::verify_running_image).map(|identity_hash| {
        AttestationEvidence {
            identity_hash,
            hash_scope: AttestationHashScope::SignedImage,
            flash_encryption: false,
            hardware_secure_boot,
            build_commit,
        }
    })
}

pub fn secure_boot_enabled() -> bool {
    Efuse::read_field_le::<u8>(SECURE_BOOT_EN) != 0
}

fn flash_encryption_enabled() -> bool {
    Efuse::flash_encryption()
}

pub fn build_commit() -> Result<&'static str, AttestationError> {
    let commit = env!("KASSIGNER_BUILD_COMMIT");
    if valid_commit(commit) {
        Ok(commit)
    } else {
        Err(AttestationError::BuildIdentityMissing)
    }
}

fn valid_commit(commit: &str) -> bool {
    (7..=40).contains(&commit.len()) && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(all(feature = "m5stack", feature = "production"))]
fn require_release_flash_encryption() -> Result<(), AttestationError> {
    if !flash_encryption_enabled() {
        return Err(AttestationError::FlashEncryptionDisabled);
    }
    if Efuse::read_field_le::<u8>(DIS_DOWNLOAD_MANUAL_ENCRYPT) == 0 {
        return Err(AttestationError::FlashEncryptionNotRelease);
    }
    Ok(())
}
