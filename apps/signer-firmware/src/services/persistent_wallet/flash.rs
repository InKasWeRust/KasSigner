//! Persistent-wallet flash-region policy and FLASH peripheral ownership.

use esp_hal::peripherals::FLASH;

use crate::hw::shared::flash as raw_flash;
pub(super) use crate::hw::shared::flash::AlignedBytes;

pub(super) const SECTOR_SIZE: u32 = 4096;
const FLASH_SIZE: u32 = 16 * 1024 * 1024;

// The auto-run CoreS3 workflow image owns a dedicated four-sector QA region
// immediately before production state. This lets connected hardware tests run
// the real persistent-wallet save/unlock implementation without reading,
// modifying, or erasing the user's production wallet state.
#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
const STATE_BASE: u32 = FLASH_SIZE - 8 * SECTOR_SIZE;
#[cfg(not(all(feature = "m5stack", feature = "workflow-runtime-auto")))]
const STATE_BASE: u32 = FLASH_SIZE - 4 * SECTOR_SIZE;

pub(super) const CONFIG_A: u32 = STATE_BASE;
pub(super) const CONFIG_B: u32 = STATE_BASE + SECTOR_SIZE;
pub(super) const WALLET_A: u32 = STATE_BASE + 2 * SECTOR_SIZE;
pub(super) const WALLET_B: u32 = STATE_BASE + 3 * SECTOR_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FlashError {
    Alignment,
    Read,
    Unlock,
    Erase,
    Write,
    Verify,
}

pub(super) struct DeviceFlash<'d> {
    _flash: FLASH<'d>,
    unlocked: bool,
}

impl<'d> DeviceFlash<'d> {
    pub fn new(peripheral: FLASH<'d>) -> Self {
        Self {
            _flash: peripheral,
            unlocked: false,
        }
    }

    pub fn read<const N: usize>(
        &mut self,
        address: u32,
        out: &mut AlignedBytes<N>,
    ) -> Result<(), FlashError> {
        raw_flash::read_into(address, out).map_err(map_io_error)
    }

    pub fn erase_sector(&mut self, address: u32) -> Result<(), FlashError> {
        validate_sector_address(address)?;
        raw_flash::with_other_core_parked(|| {
            self.unlock_once()?;
            raw_flash::erase_sector(address / SECTOR_SIZE).map_err(map_io_error)
        })
    }

    // Keep the verification scratch buffer in its own compiled frame. Xtensa
    // LTO otherwise tends to merge the caller's 4 KiB wallet record with the
    // second 4 KiB read-back buffer and can exceed the first-party stack gate.
    #[inline(never)]
    pub fn replace_sector<const N: usize>(
        &mut self,
        address: u32,
        data: &AlignedBytes<N>,
    ) -> Result<(), FlashError> {
        validate_sector_write::<N>(address)?;
        self.erase_sector(address)?;
        self.write_aligned(address, data)?;
        self.verify(address, data)
    }

    fn write_aligned<const N: usize>(
        &mut self,
        address: u32,
        data: &AlignedBytes<N>,
    ) -> Result<(), FlashError> {
        raw_flash::with_other_core_parked(|| {
            self.unlock_once()?;
            raw_flash::write(address, data).map_err(map_io_error)
        })
    }

    #[inline(never)]
    fn verify<const N: usize>(
        &mut self,
        address: u32,
        expected: &AlignedBytes<N>,
    ) -> Result<(), FlashError> {
        let mut actual = AlignedBytes::<N>::zeroed();
        self.read(address, &mut actual)?;
        if actual.0 == expected.0 {
            Ok(())
        } else {
            Err(FlashError::Verify)
        }
    }

    fn unlock_once(&mut self) -> Result<(), FlashError> {
        if self.unlocked {
            return Ok(());
        }
        raw_flash::unlock().map_err(map_io_error)?;
        self.unlocked = true;
        Ok(())
    }
}

fn validate_sector_address(address: u32) -> Result<(), FlashError> {
    if address % SECTOR_SIZE == 0 {
        Ok(())
    } else {
        Err(FlashError::Alignment)
    }
}

fn validate_sector_write<const N: usize>(address: u32) -> Result<(), FlashError> {
    validate_sector_address(address)?;
    if N != 0 && N <= SECTOR_SIZE as usize && N % 4 == 0 {
        Ok(())
    } else {
        Err(FlashError::Alignment)
    }
}

fn map_io_error(error: raw_flash::FlashIoError) -> FlashError {
    match error {
        raw_flash::FlashIoError::Alignment => FlashError::Alignment,
        raw_flash::FlashIoError::Read => FlashError::Read,
        raw_flash::FlashIoError::Unlock => FlashError::Unlock,
        raw_flash::FlashIoError::Erase => FlashError::Erase,
        raw_flash::FlashIoError::Write => FlashError::Write,
    }
}
