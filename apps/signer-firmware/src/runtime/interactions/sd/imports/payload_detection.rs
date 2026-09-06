// Pure format probing for SD imports; execution stays in selected_file.rs.
use super::super::sdcard;

pub(super) use signer_firmware_core::storage::payload::DetectedPayload as DetectedSdPayload;

pub(super) fn detect_payload(buffer: &[u8], original_len: usize) -> DetectedSdPayload {
    signer_firmware_core::storage::payload::detect_payload(buffer, original_len)
}

pub(super) fn load_selected_file(
    ad: &crate::runtime::data::AppData,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    let _ = &mut *i2c;
    sdcard::with_sd_card!(i2c, delay, |card_type| {
        let fat32 = sdcard::mount_fat32(card_type)?;
        let (entry, _, _) = sdcard::find_file_in_root(
            card_type,
            &fat32,
            &ad.storage.browser.selected_file,
        )?;
        if entry.file_size as usize > 1024 {
            return Err("Import file exceeds probe buffer");
        }
        sdcard::read_file(card_type, &fat32, &entry, buffer)
    })
}
