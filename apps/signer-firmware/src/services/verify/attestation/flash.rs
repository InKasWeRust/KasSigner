//! Raw-image hashing policy for boot attestation.

use sha2::{Digest, Sha256};

use crate::hw::shared::flash as raw_flash;

use super::AttestationError;

pub(super) const APP_FLASH_OFFSET: u32 = 0x0001_0000;
pub(super) const MAX_APP_IMAGE_SPAN: u32 = 8 * 1024 * 1024;
const HASH_CHUNK_SIZE: usize = 1024;

pub(super) fn read_fixed<const N: usize>(
    address: u32,
) -> Result<raw_flash::AlignedBytes<N>, AttestationError> {
    raw_flash::read_fixed(address).map_err(map_read_error)
}

pub(super) fn hash_flash(start: u32, length: u32) -> Result<[u8; 32], AttestationError> {
    if length > MAX_APP_IMAGE_SPAN || length % 4 != 0 {
        return Err(AttestationError::ImageLayout);
    }
    let mut hasher = Sha256::new();
    let mut buffer = raw_flash::AlignedBytes::<HASH_CHUNK_SIZE>::zeroed();
    let mut offset = 0u32;
    while offset < length {
        let take = core::cmp::min((length - offset) as usize, HASH_CHUNK_SIZE);
        let address = start.checked_add(offset).ok_or(AttestationError::ImageLayout)?;
        read_chunk(address, &mut buffer, take)?;
        hasher.update(&buffer.0[..take]);
        offset += take as u32;
    }
    Ok(hasher.finalize().into())
}

pub(super) fn flash_address(relative: u32) -> Result<u32, AttestationError> {
    APP_FLASH_OFFSET
        .checked_add(relative)
        .filter(|address| *address < APP_FLASH_OFFSET + MAX_APP_IMAGE_SPAN)
        .ok_or(AttestationError::ImageLayout)
}

pub(super) fn with_other_core_parked<T>(operation: impl FnOnce() -> T) -> T {
    raw_flash::with_other_core_parked(operation)
}

fn read_chunk(
    address: u32,
    buffer: &mut raw_flash::AlignedBytes<HASH_CHUNK_SIZE>,
    length: usize,
) -> Result<(), AttestationError> {
    if length == 0 || length % 4 != 0 {
        return Err(AttestationError::ImageLayout);
    }
    let mut chunk = raw_flash::AlignedBytes::<HASH_CHUNK_SIZE>::zeroed();
    raw_flash::read_into(address, &mut chunk).map_err(map_read_error)?;
    buffer.0[..length].copy_from_slice(&chunk.0[..length]);
    Ok(())
}

fn map_read_error(error: raw_flash::FlashIoError) -> AttestationError {
    match error {
        raw_flash::FlashIoError::Alignment => AttestationError::ImageLayout,
        _ => AttestationError::FlashRead,
    }
}
