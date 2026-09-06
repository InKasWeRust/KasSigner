//! Controller-facing removable-storage service facade.
//!
//! Controllers may request FAT32/SD operations here but may not import a board
//! storage driver directly. Board selection and shared-bus ownership remain in `hw`.

pub(crate) use crate::hw::sdcard::{
    Fat32Info, SdCardType, create_file, delete_file, find_file_in_root, format_83_display,
    format_fat32, list_root_dir, mount_fat32, overwrite_file, read_file, to_83_name, with_sd_card,
};

/// Report whether the currently probed board storage is known to be password-locked.
/// This keeps controller/runtime code behind the storage service boundary.
pub(crate) fn card_is_known_locked() -> bool {
    crate::hw::sdcard::card_is_known_locked()
}

/// Unlock a password-locked SD card for the current powered session. The
/// password is caller-owned and must be zeroized immediately after this call.
pub(crate) fn unlock_locked_card(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    password: &[u8],
) -> Result<(), &'static str> {
    crate::hw::sdcard::unlock_locked_card_session(i2c, delay, password)
}

/// Destructively clear a card password using CMD42 force erase. This destroys
/// all card data and is only invoked after the runtime hold-to-confirm gate.
pub(crate) fn force_erase_locked_card(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
) -> Result<bool, &'static str> {
    crate::hw::sdcard::force_erase_locked_card_session(i2c, delay, liveness)
}

/// HIL-only destructive preparation hook retained for disposable-media workflow
/// qualification. Production Format reaches the same protocol only through the
/// runtime hold-to-confirm destructive service.
#[cfg(all(feature = "workflow-hil-auto", feature = "m5stack"))]
pub(crate) fn workflow_force_erase_locked_card(
    card_type: SdCardType,
    delay: &mut esp_hal::delay::Delay,
) -> Result<bool, &'static str> {
    crate::hw::sdcard::workflow_force_erase_locked_card(card_type, delay)
}

/// HIL-only CoreS3 media-formatting hook. The HIL workflow requires a disposable
/// QA card and may intentionally destroy its contents while verifying real media.
#[cfg(all(feature = "workflow-hil-auto", feature = "m5stack"))]
pub(crate) fn workflow_format_fat32(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    let mut liveness = || {};
    crate::hw::sdcard::format_fat32(i2c, delay, &mut liveness)
}
