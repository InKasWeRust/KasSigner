use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::{display, AppData, Delay, I2c};
use crate::{
    services::storage_files,
};

pub(super) fn scan_covenant_backups(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut Delay,
    i2c: &mut I2c<'_>,
) {
    const EXTENSIONS: [[u8; 3]; 1] = [*b"COV"];
    boot_display.draw_loading_screen("Scanning SD...");
    ad.storage.browser.file_scroll = 0;
    let result = storage_files::scan_short_name_files(
        &mut ad.storage.browser.file_list,
        &mut ad.storage.browser.file_count,
        &EXTENSIONS,
        1024,
        true,
        delay,
        i2c,
    );
    if matches!(result, Ok(count) if count > 0) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdFileList));
    } else {
        show_rejection(boot_display, delay, "No .COV files on SD", 1_500, ErrorSound::Silent);
    }
}
