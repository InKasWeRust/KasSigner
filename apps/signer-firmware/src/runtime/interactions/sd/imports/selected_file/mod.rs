//! Selected-file interpretation and format-specific import routing.
use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use super::payload_detection;
mod covenant_backup;
mod private_key;
mod xprv;

pub(super) fn import_selected_file(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> bool {
    liveness();
    boot_display.draw_loading_screen("Loading...");
    let Ok(mut buffer) = crate::services::memory::zeroed_bytes(1024) else {
        show_rejection(boot_display, delay, "Not enough memory", 2000, ErrorSound::Silent);
        return false;
    };
    let Ok(bytes_read) = payload_detection::load_selected_file(ad, delay, i2c, &mut buffer) else {
        log!("[SD-IMPORT] Read error");
        show_rejection(boot_display, delay, "Read error", 2000, ErrorSound::Silent);
        return false;
    };

    liveness();
    let detected = payload_detection::detect_payload(&buffer, bytes_read);
    let length = detected.trimmed_len();
    match detected {
        payload_detection::DetectedSdPayload::CovenantBackup { .. } => {
            covenant_backup::present(ad, &buffer[..length]);
            true
        }
        payload_detection::DetectedSdPayload::PlainXprv { .. } => {
            xprv::import(ad, &buffer[..length], boot_display, delay);
            false
        }
        payload_detection::DetectedSdPayload::PlainPrivateKey { .. } => {
            private_key::import(ad, &buffer[..length], boot_display, delay);
            false
        }
        payload_detection::DetectedSdPayload::Unknown { .. } => {
            show_rejection(boot_display, delay, "Unknown file format", 2000, ErrorSound::Silent);
            false
        }
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_import_payload(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    payload: &[u8],
) -> bool {
    let detected = payload_detection::detect_payload(payload, payload.len());
    let length = detected.trimmed_len();
    match detected {
        payload_detection::DetectedSdPayload::CovenantBackup { .. } => {
            covenant_backup::present(ad, &payload[..length]);
            true
        }
        payload_detection::DetectedSdPayload::PlainXprv { .. } => {
            xprv::import(ad, &payload[..length], boot_display, delay);
            false
        }
        payload_detection::DetectedSdPayload::PlainPrivateKey { .. } => {
            private_key::import(ad, &payload[..length], boot_display, delay);
            false
        }
        payload_detection::DetectedSdPayload::Unknown { .. } => {
            show_rejection(boot_display, delay, "Unknown file format", 2000, ErrorSound::Silent);
            false
        }
    }
}
