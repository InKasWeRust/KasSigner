//! ESP application-image parsing and digest binding for boot attestation.

use signer_firmware_core::update::attestation as layout;

use crate::crypto::constant_time;

use super::{
    flash::{flash_address, hash_flash, read_fixed, APP_FLASH_OFFSET, MAX_APP_IMAGE_SPAN},
    AttestationError,
};

pub(super) fn verify_running_image() -> Result<[u8; 32], AttestationError> {
    let image_end = parse_image_end()?;
    verify_appended_image_hash(image_end)?;
    verify_secure_boot_digest(image_end)
}

fn parse_image_end() -> Result<u32, AttestationError> {
    let header = read_fixed::<{ layout::ESP_IMAGE_HEADER_SIZE }>(APP_FLASH_OFFSET)?;
    let parsed = layout::parse_image_header(&header.0).map_err(|_| AttestationError::ImageLayout)?;
    let mut cursor = layout::ESP_IMAGE_HEADER_SIZE as u32;
    for _ in 0..parsed.segment_count {
        cursor = advance_segment(cursor)?;
        if cursor > MAX_APP_IMAGE_SPAN {
            return Err(AttestationError::ImageLayout);
        }
    }
    let hash_offset = layout::appended_hash_offset(cursor).map_err(|_| AttestationError::ImageLayout)?;
    layout::signed_image_end(hash_offset).map_err(|_| AttestationError::ImageLayout)
}

fn advance_segment(cursor: u32) -> Result<u32, AttestationError> {
    let header = read_fixed::<{ layout::ESP_SEGMENT_HEADER_SIZE }>(flash_address(cursor)?)?;
    let length = layout::segment_data_len(&header.0).map_err(|_| AttestationError::ImageLayout)?;
    layout::advance_segment(cursor, length).map_err(|_| AttestationError::ImageLayout)
}

fn verify_appended_image_hash(image_end: u32) -> Result<(), AttestationError> {
    let hash_offset = image_end.checked_sub(32).ok_or(AttestationError::ImageLayout)?;
    let expected = read_fixed::<32>(flash_address(hash_offset)?)?;
    let actual = hash_flash(APP_FLASH_OFFSET, hash_offset)?;
    if constant_time::eq(&actual, &expected.0) {
        Ok(())
    } else {
        Err(AttestationError::AppendedHashMismatch)
    }
}

fn verify_secure_boot_digest(image_end: u32) -> Result<[u8; 32], AttestationError> {
    let signature_offset = layout::secure_boot_signature_offset(image_end)
        .map_err(|_| AttestationError::ImageLayout)?;
    let prefix = read_fixed::<{ layout::SECURE_BOOT_SIGNATURE_PREFIX_SIZE }>(
        flash_address(signature_offset)?,
    )?;
    let expected = layout::parse_signature_digest(&prefix.0)
        .map_err(|_| AttestationError::SecureBootDigestMissing)?;
    let actual = hash_flash(APP_FLASH_OFFSET, signature_offset)?;
    if constant_time::eq(&actual, &expected) {
        Ok(actual)
    } else {
        Err(AttestationError::SecureBootDigestMismatch)
    }
}
