// KasSigner — firmware verification façade.

use crate::crypto::{constant_time, flow};
use core::sync::atomic::{compiler_fence, Ordering};
use sha2::{Digest, Sha256};

#[path = "../../firmware_hash.rs"]
mod firmware_hash;

/// Load generated image-identity bytes from their dedicated flash rodata object.
///
/// Volatile reads are intentional: the generated hash/signature must remain data
/// and must never be constant-folded into the executable segment whose SHA-256
/// they authenticate. Their fixed-size rodata objects keep code bytes independent
/// of generated identity contents across convergence passes.
#[inline(never)]
pub(super) fn embedded_expected_hash() -> [u8; 32] {
    // SAFETY: EXPECTED_FIRMWARE_HASH is an immutable, aligned, generated static
    // with process lifetime. read_volatile copies exactly its 32 initialized bytes.
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(firmware_hash::EXPECTED_FIRMWARE_HASH))
    }
}

#[inline(never)]
pub(super) fn embedded_firmware_signature() -> [u8; 64] {
    // SAFETY: FIRMWARE_SIGNATURE is an immutable, aligned, generated static
    // with process lifetime. read_volatile copies exactly its 64 initialized bytes.
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(firmware_hash::FIRMWARE_SIGNATURE))
    }
}

#[inline(never)]
pub(super) fn embedded_firmware_signed() -> bool {
    // SAFETY: generated immutable static with process lifetime.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(firmware_hash::FIRMWARE_SIGNED)) }
}

#[inline(never)]
pub(super) fn embedded_firmware_size() -> usize {
    // SAFETY: generated immutable static with process lifetime.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(firmware_hash::FIRMWARE_SIZE)) }
}

#[inline(never)]
pub(crate) fn firmware_start_addr() -> u32 {
    // SAFETY: generated immutable static with process lifetime.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(firmware_hash::FIRMWARE_IADDR)) }
}

#[cfg(feature = "production")]
mod attestation;
#[cfg(feature = "production")]
pub(crate) use attestation::{AttestationEvidence, verify_running_image};

pub(crate) mod anti_rollback;
pub(crate) mod boot_security;

mod types;
pub use types::{FIRMWARE_MAX_SIZE, FirmwareInfo, VerificationResult};
use types::{CANARY_PRE_VERIFY, DRAM_FLASH_BASE, IRAM_FLASH_BASE};
#[cfg(feature = "production")]
use types::CANARY_POST_VERIFY;

mod mapped_segment;

mod signature;

mod format;

mod policy;

/// True when this image carries a generated firmware signature.
pub(crate) fn software_verification_configured() -> bool { embedded_firmware_signed() }
