//! User-facing boot trust classification and Pop It preflight.
//!
//! Secure Boot v2 eFuse programming remains bootloader-owned. The application
//! only records an integrity-checked one-shot UI request after its normal release verifier
//! has completed successfully, then restarts into the signed ESP-IDF
//! bootloader. The bootloader performs Espressif's final signature/eFuse
//! viability checks immediately before any irreversible write.

#[cfg(not(feature = "qemu"))]
use esp_hal::efuse::{Efuse, SECURE_BOOT_EN};
#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "qemu")))]
use esp_hal::efuse::{
    KEY_PURPOSE_0, KEY_PURPOSE_1, KEY_PURPOSE_2, KEY_PURPOSE_3, KEY_PURPOSE_4, KEY_PURPOSE_5,
    SECURE_BOOT_KEY_REVOKE1, SECURE_BOOT_KEY_REVOKE2, WR_DIS,
};
#[cfg(all(
    feature = "provisioning-ui",
    feature = "m5stack",
    not(feature = "qemu"),
    feature = "secure-owner-only"
))]
use esp_hal::efuse::SECURE_BOOT_KEY_REVOKE0;
#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production")))]
use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production")))]
static DEV_POP_IT_INDICATOR_DEMO: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootSecurityLevel {
    None,
    SoftwareVerified,
    HardwareEnforced,
}

#[cfg(feature = "secure-provisioning-core")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PopItPreflightError {
    AlreadyEnabled,
    SecurityVersionInvalid,
    BuildIdentityMissing,
}

#[cfg(feature = "secure-provisioning-core")]
impl PopItPreflightError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::AlreadyEnabled => "Secure Boot v2 is already hardware enabled",
            Self::SecurityVersionInvalid => "Firmware security version is invalid",
            Self::BuildIdentityMissing => "Production build identity is missing",
        }
    }
}

pub fn level() -> BootSecurityLevel {
    if secure_boot_enabled() {
        BootSecurityLevel::HardwareEnforced
    } else if crate::services::verify::software_verification_configured() {
        // Normal UI is reached only after the profile-appropriate signature and
        // code hash have verified. Development uses a repository-public TEST key;
        // production uses the private release identity and may later add ROM eFuse enforcement.
        BootSecurityLevel::SoftwareVerified
    } else {
        BootSecurityLevel::None
    }
}

/// Trust icon state. Development may deliberately preview the teal hardware
/// badge without changing the truthful boot-security classification or touching
/// any eFuse. The preview is volatile and disappears on reset.
pub fn indicator_level() -> BootSecurityLevel {
    #[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production")))]
    if DEV_POP_IT_INDICATOR_DEMO.load(AtomicOrdering::Relaxed) {
        return BootSecurityLevel::HardwareEnforced;
    }
    level()
}

#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production")))]
pub fn enable_dev_pop_it_indicator_demo() {
    DEV_POP_IT_INDICATOR_DEMO.store(true, AtomicOrdering::Relaxed);
}

#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production")))]
pub fn dev_pop_it_indicator_demo_active() -> bool {
    DEV_POP_IT_INDICATOR_DEMO.load(AtomicOrdering::Relaxed)
}

#[cfg(all(
    feature = "provisioning-ui",
    not(all(feature = "m5stack", not(feature = "production")))
))]
pub const fn dev_pop_it_indicator_demo_active() -> bool { false }

#[cfg(feature = "secure-provisioning-core")]
pub fn pop_it_preflight() -> Result<(), PopItPreflightError> {
    if secure_boot_enabled() {
        return Err(PopItPreflightError::AlreadyEnabled);
    }
    if crate::services::verify::anti_rollback::APP_SECURITY_VERSION == 0 {
        return Err(PopItPreflightError::SecurityVersionInvalid);
    }
    crate::services::verify::attestation::build_commit()
        .map_err(|_| PopItPreflightError::BuildIdentityMissing)?;
    Ok(())
}

#[cfg(not(feature = "qemu"))]
pub fn secure_boot_enabled() -> bool {
    Efuse::read_field_le::<u8>(SECURE_BOOT_EN) != 0
}

#[cfg(feature = "qemu")]
pub const fn secure_boot_enabled() -> bool { false }

/// Whether the device has the owner authority required by this provisioning profile.
///
/// Dual-authority builds require a protected, unrevoked owner digest in slot 1
/// and a closed slot 2. Owner-only builds reproduce the original sole-owner
/// policy: the owner digest is slot 0, slots 1 and 2 are revoked, and slot 0's
/// revoke control is write-protected. Key-purpose fields are scanned because
/// ESP-IDF may allocate the digest to any free physical key block.
#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "qemu")))]
pub fn owner_authority_enrolled() -> bool {
    #[cfg(feature = "secure-owner-only")]
    {
        const SECURE_BOOT_DIGEST0_PURPOSE: u8 = 0x09;
        const OWNER_REVOKE_WR_DIS_MASK: u32 = 1 << 5;
        let owner_purpose_present = key_purpose_present(SECURE_BOOT_DIGEST0_PURPOSE);
        let write_disable = Efuse::read_field_le::<u32>(WR_DIS);
        return owner_purpose_present
            && Efuse::read_field_le::<u8>(SECURE_BOOT_KEY_REVOKE0) == 0
            && Efuse::read_field_le::<u8>(SECURE_BOOT_KEY_REVOKE1) != 0
            && Efuse::read_field_le::<u8>(SECURE_BOOT_KEY_REVOKE2) != 0
            && (write_disable & OWNER_REVOKE_WR_DIS_MASK) != 0;
    }

    #[cfg(not(feature = "secure-owner-only"))]
    {
        const SECURE_BOOT_DIGEST1_PURPOSE: u8 = 0x0a;
        const OWNER_REVOKE_WR_DIS_MASK: u32 = 1 << 6;
        let owner_purpose_present = key_purpose_present(SECURE_BOOT_DIGEST1_PURPOSE);
        let write_disable = Efuse::read_field_le::<u32>(WR_DIS);
        owner_purpose_present
            && Efuse::read_field_le::<u8>(SECURE_BOOT_KEY_REVOKE1) == 0
            && (write_disable & OWNER_REVOKE_WR_DIS_MASK) != 0
            && Efuse::read_field_le::<u8>(SECURE_BOOT_KEY_REVOKE2) != 0
    }
}

#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "qemu")))]
fn key_purpose_present(purpose: u8) -> bool {
    Efuse::read_field_le::<u8>(KEY_PURPOSE_0) == purpose
        || Efuse::read_field_le::<u8>(KEY_PURPOSE_1) == purpose
        || Efuse::read_field_le::<u8>(KEY_PURPOSE_2) == purpose
        || Efuse::read_field_le::<u8>(KEY_PURPOSE_3) == purpose
        || Efuse::read_field_le::<u8>(KEY_PURPOSE_4) == purpose
        || Efuse::read_field_le::<u8>(KEY_PURPOSE_5) == purpose
}

#[cfg(all(feature = "provisioning-ui", not(all(feature = "m5stack", not(feature = "qemu")))))]
pub const fn owner_authority_enrolled() -> bool { false }

