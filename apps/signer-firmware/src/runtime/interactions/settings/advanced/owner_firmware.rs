//! Owner-controlled Secure Boot trust-root enrollment and owner-firmware install.

use sha2::{Digest, Sha256};

use crate::{
    hw::display::BootDisplay,
    runtime::{data::AppData, input::AppState},
    runtime::interactions::TouchInput,
    services::{
        persistent_wallet::{PersistError, PersistentWallet},
        storage_device as sdcard,
    },
};

use super::input::{self, EditAction};

const OWNER_KEY_SIZE: usize = 76;
const OWNER_KEY_MAGIC: &[u8; 8] = b"KSOWNR01";
const OWNER_KEY_FILE: [u8; 11] = *b"OWNERKEYKAS";
const OWNER_FW_FILE: [u8; 11] = *b"OWNERFW BIN";
const OWNER_FW_MAX: usize = 0x0020_0000;

#[derive(Clone, Copy)]
enum OwnerOperation {
    Enroll,
    Install,
}

pub(super) fn handle_pure(input_event: TouchInput, ad: &mut AppData) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::OwnerKeyWarning => warning(input_event, ad, OwnerOperation::Enroll),
        AppState::OwnerInstallWarning => warning(input_event, ad, OwnerOperation::Install),
        AppState::OwnerKeyConfirm | AppState::OwnerInstallConfirm => confirm_edit(input_event, ad),
        _ => None,
    }
}

fn warning(input: TouchInput, ad: &mut AppData, operation: OwnerOperation) -> Option<bool> {
    if input.is_back {
        ad.pop_it.error = None;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(OwnerFirmwareMenu));
        return Some(true);
    }
    if !(193..=232).contains(&input.y) {
        return Some(false);
    }
    if (172..=304).contains(&input.x) {
        ad.pop_it.error = None;
        ad.wallet.seeds.pp_input.reset();
        let next = match operation {
            OwnerOperation::Enroll => crate::runtime::navigation::route!(OwnerKeyConfirm),
            OwnerOperation::Install => crate::runtime::navigation::route!(OwnerInstallConfirm),
        };
        crate::runtime::effects::route(ad, next);
        return Some(true);
    }
    if (16..=148).contains(&input.x) {
        ad.pop_it.error = None;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(OwnerFirmwareMenu));
        return Some(true);
    }
    Some(false)
}

fn confirm_edit(input_event: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input_event.is_back {
        ad.wallet.seeds.pp_input.reset();
        ad.pop_it.error = None;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(OwnerFirmwareMenu));
        return Some(true);
    }
    match input::edit(input_event, ad, false) {
        EditAction::Edited => {
            ad.pop_it.error = None;
            Some(true)
        }
        EditAction::None => Some(false),
        EditAction::Submitted => None,
    }
}

pub(super) fn handle(
    input_event: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::OwnerKeyConfirm => execute_enroll(input_event, ad, persistence, display, delay, i2c),
        AppState::OwnerInstallConfirm => execute_install(input_event, ad, persistence, display, delay, i2c),
        _ => None,
    }
}

fn submitted(input_event: TouchInput, ad: &mut AppData, phrase: &[u8]) -> bool {
    if !matches!(input::edit(input_event, ad, false), EditAction::Submitted) {
        return false;
    }
    let actual = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
    normalized_matches(actual, phrase)
}

fn normalized_matches(actual: &[u8], expected: &[u8]) -> bool {
    let mut normalized_actual = [0u8; 16];
    let mut normalized_expected = [0u8; 16];
    let actual_len = normalize_phrase(actual, &mut normalized_actual);
    let expected_len = normalize_phrase(expected, &mut normalized_expected);
    actual_len == expected_len
        && normalized_actual[..actual_len] == normalized_expected[..expected_len]
}

fn normalize_phrase(input: &[u8], output: &mut [u8; 16]) -> usize {
    let mut len = 0usize;
    for byte in input.iter().copied() {
        if matches!(byte, b' ' | b'-' | b'_') {
            continue;
        }
        if len == output.len() {
            return output.len();
        }
        output[len] = byte.to_ascii_lowercase();
        len += 1;
    }
    len
}

fn execute_enroll(
    input_event: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if !submitted(input_event, ad, b"ENROLL OWNER") {
        return Some(false);
    }
    if crate::services::verify::boot_security::secure_boot_enabled() {
        ad.pop_it.error = Some("Pop It already enabled; enrollment is closed");
        return Some(true);
    }

    let mut record = [0u8; OWNER_KEY_SIZE];
    if let Err(error) = sdcard::with_sd_card!(i2c, delay, |card| {
        read_named(card, &OWNER_KEY_FILE, &mut record)
    }) {
        ad.pop_it.error = Some(error);
        return Some(true);
    }
    let Some(digest) = parse_owner_key(&record) else {
        ad.pop_it.error = Some("OWNERKEY.KAS is invalid");
        return Some(true);
    };
    ad.wallet.seeds.pp_input.reset();

    #[cfg(feature = "secure-provisioning-core")]
    {
        if crate::services::verify::boot_security::pop_it_preflight().is_err() {
            ad.pop_it.error = Some("Production security preflight failed");
            return Some(true);
        }
        if persistence.request_owner_enrollment(&digest).is_err() {
            ad.pop_it.error = Some("Could not arm owner enrollment");
            return Some(true);
        }
        display.draw_owner_firmware_applying("Owner key enrollment armed", true);
        esp_hal::system::software_reset();
    }

    #[cfg(not(feature = "secure-provisioning-core"))]
    {
        // Development simulation still validates the complete owner-key record; only the
        // irreversible enrollment handoff is omitted.
        let _ = digest;
        let _ = persistence;
        display.draw_owner_firmware_result("Owner key validated", "DEVELOPMENT SIMULATION", true);
        crate::services::timing::pause(delay, 1_800);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(OwnerFirmwareMenu));
        Some(true)
    }
}

fn execute_install(
    input_event: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if !submitted(input_event, ad, b"INSTALL OWNER") {
        return Some(false);
    }

    let Ok(mut image) = crate::services::memory::psram::PsramAllocation::allocate(OWNER_FW_MAX, 8)
    else {
        ad.pop_it.error = Some("Not enough PSRAM for owner firmware");
        return Some(true);
    };
    let length = match sdcard::with_sd_card!(i2c, delay, |card| {
        read_named(card, &OWNER_FW_FILE, image.as_mut_bytes())
    }) {
        Ok(length) => length,
        Err(error) => {
            ad.pop_it.error = Some(error);
            return Some(true);
        }
    };
    if length == 0 || length > OWNER_FW_MAX {
        ad.pop_it.error = Some(PersistError::OwnerFirmwareInvalid.message());
        return Some(true);
    }
    ad.wallet.seeds.pp_input.reset();

    #[cfg(feature = "secure-provisioning-core")]
    {
        let hash: [u8; 32] = Sha256::digest(&image.as_bytes()[..length]).into();
        if !crate::services::verify::boot_security::secure_boot_enabled() {
            ad.pop_it.error = Some("Pop It must be enabled before owner install");
            return Some(true);
        }
        let staged = match persistence.stage_owner_firmware(&image.as_bytes()[..length]) {
            Ok(value) => value,
            Err(_) => {
                ad.pop_it.error = Some("Could not stage owner firmware");
                return Some(true);
            }
        };
        if staged != hash || persistence.request_owner_install(length as u32, &hash).is_err() {
            ad.pop_it.error = Some("Could not arm owner firmware install");
            return Some(true);
        }
        display.draw_owner_firmware_applying("Owner firmware staged", false);
        esp_hal::system::software_reset();
    }

    #[cfg(not(feature = "secure-provisioning-core"))]
    {
        let _ = persistence;
        display.draw_owner_firmware_result("OWNERFW.BIN validated", "DEVELOPMENT SIMULATION", true);
        crate::services::timing::pause(delay, 1_800);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(OwnerFirmwareMenu));
        Some(true)
    }
}

fn read_named(
    card: sdcard::SdCardType,
    name: &[u8; 11],
    output: &mut [u8],
) -> Result<usize, &'static str> {
    let fat = sdcard::mount_fat32(card)?;
    let (entry, _, _) = sdcard::find_file_in_root(card, &fat, name)?;
    if entry.file_size as usize > output.len() {
        return Err("Owner file is too large");
    }
    sdcard::read_file(card, &fat, &entry, output)
}

fn parse_owner_key(record: &[u8; OWNER_KEY_SIZE]) -> Option<[u8; 32]> {
    if &record[..8] != OWNER_KEY_MAGIC || record[8] != 1 || record[9..12] != [0, 0, 0] {
        return None;
    }
    let checksum: [u8; 32] = Sha256::digest(&record[..44]).into();
    if checksum != record[44..76] {
        return None;
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&record[12..44]);
    if digest == [0u8; 32] || digest == [0xffu8; 32] {
        return None;
    }
    Some(digest)
}
