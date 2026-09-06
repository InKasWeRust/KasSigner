//! Shared ESP32-S3 ROM-flash access and multicore coordination.
//!
//! This is the single unsafe boundary for firmware services that must inspect
//! or update raw flash. Services retain policy (addresses, record formats,
//! hashes); this module owns only aligned ROM I/O and core parking.

use esp_hal::{
    interrupt::Priority,
    ram,
    rom::spiflash::{
        esp_rom_spiflash_erase_sector, esp_rom_spiflash_read, esp_rom_spiflash_unlock,
        esp_rom_spiflash_write,
    },
    sync::RawPriorityLimitedMutex,
};

static ROM_FLASH_LOCK: RawPriorityLimitedMutex =
    RawPriorityLimitedMutex::new(Priority::max());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlashIoError {
    Alignment,
    Read,
    Unlock,
    Erase,
    Write,
}

#[repr(align(4))]
pub(crate) struct AlignedBytes<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> AlignedBytes<N> {
    pub(crate) const fn zeroed() -> Self {
        Self([0; N])
    }
}

pub(crate) fn read_into<const N: usize>(
    address: u32,
    out: &mut AlignedBytes<N>,
) -> Result<(), FlashIoError> {
    validate_word_access::<N>(address)?;
    rom_read(address, out.0.as_mut_ptr().cast::<u32>(), N as u32)
}

#[cfg(feature = "production")]
pub(crate) fn read_fixed<const N: usize>(address: u32) -> Result<AlignedBytes<N>, FlashIoError> {
    let mut out = AlignedBytes::<N>::zeroed();
    read_into(address, &mut out)?;
    Ok(out)
}

pub(crate) fn unlock() -> Result<(), FlashIoError> {
    rom_unlock()
}

pub(crate) fn erase_sector(sector: u32) -> Result<(), FlashIoError> {
    rom_erase(sector)
}

pub(crate) fn write<const N: usize>(
    address: u32,
    data: &AlignedBytes<N>,
) -> Result<(), FlashIoError> {
    validate_word_access::<N>(address)?;
    rom_write(address, data.0.as_ptr().cast::<u32>(), N as u32)
}

pub(crate) fn with_other_core_parked<T>(operation: impl FnOnce() -> T) -> T {
    super::core::with_other_core_parked(operation)
}

fn validate_word_access<const N: usize>(address: u32) -> Result<(), FlashIoError> {
    if address % 4 == 0 && N != 0 && N % 4 == 0 {
        Ok(())
    } else {
        Err(FlashIoError::Alignment)
    }
}

#[ram]
fn rom_read(address: u32, data: *const u32, len: u32) -> Result<(), FlashIoError> {
    // SAFETY: safe callers enforce word alignment and provide a live aligned buffer.
    let result = ROM_FLASH_LOCK.lock(|| unsafe { esp_rom_spiflash_read(address, data, len) });
    map_rom_result(result, FlashIoError::Read)
}

#[ram]
fn rom_unlock() -> Result<(), FlashIoError> {
    // SAFETY: no pointer arguments; serialized through the firmware ROM-flash lock.
    let result = ROM_FLASH_LOCK.lock(|| unsafe { esp_rom_spiflash_unlock() });
    map_rom_result(result, FlashIoError::Unlock)
}

#[ram]
fn rom_erase(sector: u32) -> Result<(), FlashIoError> {
    // SAFETY: caller supplies a validated sector index while the peer core is parked.
    let result = ROM_FLASH_LOCK.lock(|| unsafe { esp_rom_spiflash_erase_sector(sector) });
    map_rom_result(result, FlashIoError::Erase)
}

#[ram]
fn rom_write(address: u32, data: *const u32, len: u32) -> Result<(), FlashIoError> {
    // SAFETY: safe callers enforce word alignment and keep the input buffer live.
    let result = ROM_FLASH_LOCK.lock(|| unsafe { esp_rom_spiflash_write(address, data, len) });
    map_rom_result(result, FlashIoError::Write)
}

fn map_rom_result(result: i32, error: FlashIoError) -> Result<(), FlashIoError> {
    if result == 0 {
        Ok(())
    } else {
        Err(error)
    }
}
