//! Configurable SD directory scanner used by import workflows.

use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::super::{AppData, display};
use crate::runtime::data::TextFileKind;

#[derive(Clone, Copy)]
pub(crate) struct ImportScanRule {
    pub extensions: &'static [[u8; 3]],
    pub max_size: u32,
    pub exclude_hidden: bool,
    pub next_state: crate::runtime::navigation::ContinuationRoute,
    pub empty_message: &'static str,
    pub text_import_kind: Option<TextFileKind>,
}

pub(crate) fn scan_by_rule(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    card_present: bool,
    rule: ImportScanRule,
) {
    ad.storage.browser.text_import_kind = rule.text_import_kind;
    if !card_present {
        show_rejection(boot_display, delay, "No SD card detected", 2000, ErrorSound::Silent);
        return;
    }

    boot_display.draw_loading_screen("Scanning SD...");
    ad.storage.browser.file_count = 0;
    ad.storage.browser.file_scroll = 0;
    let result = crate::services::storage_files::scan_short_name_files(
        &mut ad.storage.browser.file_list,
        &mut ad.storage.browser.file_count,
        rule.extensions,
        rule.max_size,
        rule.exclude_hidden,
        delay,
        i2c,
    );

    #[cfg(feature = "waveshare")]
    crate::services::touch_recovery::after_sd_scan(i2c);
    #[cfg(feature = "m5stack")]
    crate::services::touch_recovery::after_sd_scan();

    match result {
        Ok(count) if count > 0 => {
            let _ = crate::runtime::effects::continue_to(ad, rule.next_state);
        }
        Ok(_) => {
            show_rejection(boot_display, delay, rule.empty_message, 2000, ErrorSound::Silent);
        }
        Err(error) => {
            log!("[SD-IMPORT] Scan failed: {}", error);
            show_rejection(boot_display, delay, "SD read error", 2000, ErrorSound::Silent);
        }
    }
}
