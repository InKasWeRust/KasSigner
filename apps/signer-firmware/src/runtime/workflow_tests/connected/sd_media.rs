//! CoreS3 SD-media gate for connected workflow testing.
//!
//! Normal `workflow-e2e` validates controller/state-machine behavior without
//! mutating removable media. Destructive lock recovery, FAT32 formatting, and
//! the physical create/read/compare/delete tranche are restricted to the
//! explicit `workflow-hil` profile, which requires a disposable QA card.

use crate::hw::sdcard::SdCardType;
#[cfg(feature = "workflow-hil-auto")]
use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

#[cfg(feature = "workflow-hil-auto")]
const QA_FILE: &[u8; 11] = b"KSE2ETSTBIN";
#[cfg(feature = "workflow-hil-auto")]
const QA_PAYLOAD: &[u8] = b"KasSigner CoreS3 SD E2E v1";

#[cfg(feature = "workflow-hil-auto")]
pub(super) fn prepare_and_verify(
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA PROBE BEGIN");
    prepare_hil_media(i2c, sd, delay)
}

#[cfg(not(feature = "workflow-hil-auto"))]
pub(super) fn prepare_controller_e2e(sd: &Option<SdCardType>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA PROBE BEGIN");
    controller_e2e_media_gate(sd)
}

#[cfg(not(feature = "workflow-hil-auto"))]
fn controller_e2e_media_gate(sd: &Option<SdCardType>) -> bool {
    match sd {
        Some(card_type) => log!(
            "KASSIGNER_WORKFLOW_TESTS: SD MEDIA CARD DETECTED {:?}; PHYSICAL MEDIA MUTATION SKIPPED IN CONTROLLER E2E",
            card_type,
        ),
        None => log!(
            "KASSIGNER_WORKFLOW_TESTS: SD MEDIA UNAVAILABLE - BOOT SD INITIALIZATION RETURNED NONE; SEE BOOT PHASE sd DIAGNOSTICS ABOVE; PHYSICAL MEDIA CHECK SKIPPED IN CONTROLLER E2E"
        ),
    }
    log!(
        "KASSIGNER_WORKFLOW_TESTS: SD MEDIA PHYSICAL TRANCHE DEFERRED TO workflow-hil WITH A DISPOSABLE QA CARD"
    );
    true
}

#[cfg(feature = "workflow-hil-auto")]
fn prepare_hil_media(
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    let Some(card_type) = *sd else {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA HIL FAIL - BOOT SD INITIALIZATION RETURNED NONE; SEE BOOT PHASE sd DIAGNOSTICS ABOVE");
        return false;
    };
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA CARD DETECTED {:?}", card_type);

    if !prepare_lock_state(card_type, i2c, delay) {
        return false;
    }
    let Some(fat32) = mount_or_format_hil(card_type, i2c, delay) else {
        return false;
    };
    verify_round_trip(card_type, &fat32)
}

#[cfg(feature = "workflow-hil-auto")]
fn prepare_lock_state(
    card_type: SdCardType,
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
) -> bool {
    match crate::services::storage_device::workflow_force_erase_locked_card(card_type, delay) {
        Ok(true) => format_after_force_erase(i2c, delay),
        Ok(false) => {
            log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA CARD UNLOCKED");
            true
        }
        Err(error) => {
            log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA LOCK PREPARATION FAIL {}", error);
            false
        }
    }
}

#[cfg(feature = "workflow-hil-auto")]
fn format_after_force_erase(
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA CARD-LOCK FORCE ERASE OK");
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA FORMAT AFTER LOCK ERASE BEGIN - DESTRUCTIVE");
    if !crate::services::storage_device::workflow_format_fat32(i2c, delay) {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA FORMAT AFTER LOCK ERASE FAIL");
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA FORMAT AFTER LOCK ERASE OK");
    true
}

#[cfg(feature = "workflow-hil-auto")]
fn mount_or_format_hil(
    card_type: SdCardType,
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
) -> Option<crate::services::storage_device::Fat32Info> {
    match crate::services::storage_device::mount_fat32(card_type) {
        Ok(info) => {
            log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA FAT32 MOUNT OK");
            Some(info)
        }
        Err("No FAT32 filesystem found") => format_missing_fat32(card_type, i2c, delay),
        Err(error) => {
            log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA MOUNT FAIL {}", error);
            None
        }
    }
}

#[cfg(feature = "workflow-hil-auto")]
fn format_missing_fat32(
    card_type: SdCardType,
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
) -> Option<crate::services::storage_device::Fat32Info> {
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA FAT32 MISSING");
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA AUTO-FORMAT BEGIN - DESTRUCTIVE");
    if !crate::services::storage_device::workflow_format_fat32(i2c, delay) {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA AUTO-FORMAT FAIL");
        return None;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA QA AUTO-FORMAT OK");
    match crate::services::storage_device::mount_fat32(card_type) {
        Ok(info) => {
            log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA REMOUNT AFTER FORMAT OK");
            Some(info)
        }
        Err(_) => {
            log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA REMOUNT AFTER FORMAT FAIL");
            None
        }
    }
}

#[cfg(feature = "workflow-hil-auto")]
fn verify_round_trip(
    card_type: SdCardType,
    fat32: &crate::services::storage_device::Fat32Info,
) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA READ-WRITE-DELETE BEGIN");
    if crate::services::storage_device::find_file_in_root(card_type, fat32, QA_FILE).is_ok()
        && crate::services::storage_device::delete_file(card_type, fat32, QA_FILE).is_err()
    {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA STALE QA FILE DELETE FAIL");
        return false;
    }
    let Ok(entry) = crate::services::storage_device::create_file(
        card_type,
        fat32,
        QA_FILE,
        QA_PAYLOAD,
    ) else {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA CREATE FAIL");
        return false;
    };
    let mut readback = [0u8; 64];
    let Ok(length) = crate::services::storage_device::read_file(
        card_type,
        fat32,
        &entry,
        &mut readback,
    ) else {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA READ FAIL");
        return false;
    };
    if length != QA_PAYLOAD.len() || &readback[..length] != QA_PAYLOAD {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA READBACK MISMATCH");
        return false;
    }
    if crate::services::storage_device::delete_file(card_type, fat32, QA_FILE).is_err() {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA DELETE FAIL");
        return false;
    }
    if crate::services::storage_device::find_file_in_root(card_type, fat32, QA_FILE).is_ok() {
        log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA DELETE VERIFY FAIL");
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SD MEDIA READ-WRITE-DELETE OK");
    log!("KASSIGNER_WORKFLOW_TESTS: SD PHYSICAL SPI/FAT32 READ-WRITE VERIFIED");
    true
}
