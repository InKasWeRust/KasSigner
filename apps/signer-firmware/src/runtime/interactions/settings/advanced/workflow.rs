//! Connected workflow adapters for advanced security controllers.
//!
//! These adapters deliberately stop at the persistence/physical-RTC/eFuse
//! boundaries. They reuse production parsers and state transitions while the
//! later HIL tranche owns actual flash, HMAC, RTC and irreversible eFuse I/O.

use crate::{
    runtime::interactions::TouchInput,
    hw::display::BootDisplay,
    runtime::{
        data::{AdvancedAvailability, AppData, DuressActivation, PolicyIntegrity},
    },
    services::persistent_wallet::PersistError,
};
use shared_signer::bytes::zeroize_bytes;
use crate::services::credential_policy::{confirmation_digest, confirmation_matches, validate, CredentialKind};
use signer_firmware_core::advanced_policy::SigningPolicy;

#[cfg(feature = "m5stack")]
use crate::runtime::data::RtcVerification;
#[cfg(feature = "m5stack")]
use signer_firmware_core::advanced_policy::{parse_utc_yyyymmddhhmm, parse_weekly_windows};

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn install_saved_wallet_fixture(ad: &mut AppData, kind: CredentialKind) {
    let advanced = &mut ad.storage.persistence.advanced;
    advanced.saved_wallet = true;
    advanced.outer_device_only = false;
    advanced.availability = AdvancedAvailability::Available;
    advanced.credential_kind = Some(kind);
    advanced.duress = DuressActivation::Disabled;
    advanced.policy = SigningPolicy::disabled();
    advanced.policy_integrity = PolicyIntegrity::Valid;
    #[cfg(feature = "m5stack")]
    { advanced.rtc_verification = RtcVerification::Unverified; }
    advanced.clear_pending();
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn open_card(
    input: TouchInput,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    use crate::ui::screens::device::advanced_security::{ADV_CARD_X, DURESS_Y, RTC_Y, SD_STORAGE_Y, TIME_LOCK_Y, WEEKLY_Y};
    if input.is_back {
        crate::runtime::effects::back(ad);
        return Some(true);
    }
    if !ADV_CARD_X.contains(&input.x) { return None; }
    if !ad.storage.persistence.advanced.availability.is_available()
        || !ad.storage.persistence.advanced.policy_integrity.is_valid()
    {
        return Some(true);
    }
    if DURESS_Y.contains(&input.y) {
        if !ad.storage.persistence.advanced.duress.is_enabled() {
            ad.storage.persistence.advanced.clear_pending();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedDuressWarning));
        }
        return Some(true);
    }
    if TIME_LOCK_Y.contains(&input.y) {
        super::overview::handle_time_lock_card(ad, display, delay);
        return Some(true);
    }
    if WEEKLY_Y.contains(&input.y) {
        super::overview::handle_weekly_card(ad, display, delay);
        return Some(true);
    }
    if SD_STORAGE_Y.contains(&input.y) {
        if !ad.storage.persistence.advanced.persistence_backend.is_sd() {
            ad.storage.persistence.advanced.clear_pending();
            ad.storage.persistence.device_storage_intent = crate::runtime::data::DeviceStorageIntent::EnableSd;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageRecoveryAcknowledgement));
        }
        return Some(true);
    }
    if RTC_Y.contains(&input.y) {
        super::overview::handle_rtc_card(ad, display, delay);
        return Some(true);
    }
    None
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn submit_duress(
    ad: &mut AppData,
    confirming: bool,
    persistence_result: Result<(), PersistError>,
) -> Result<(), &'static str> {
    let kind = ad.storage.persistence.advanced.credential_kind.ok_or("Credential unavailable")?;
    let len = ad.wallet.seeds.pp_input.len;
    let mut secret = [0u8; 128];
    secret[..len].copy_from_slice(&ad.wallet.seeds.pp_input.buf[..len]);
    if let Err(error) = validate(kind, &secret[..len]) {
        zeroize_bytes(&mut secret);
        restart_duress_fixture(ad);
        return Err(PersistError::from(error).message());
    }
    let digest = confirmation_digest(kind, &secret[..len]);
    if !confirming {
        ad.storage.persistence.advanced.pending_confirmation_digest = digest;
        ad.storage.persistence.advanced.confirmation = crate::runtime::data::ConfirmationState::Pending;
        zeroize_bytes(&mut secret);
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedDuressConfirm));
        return Ok(());
    }
    if !ad.storage.persistence.advanced.confirmation.is_pending()
        || !confirmation_matches(&ad.storage.persistence.advanced.pending_confirmation_digest, &digest)
    {
        zeroize_bytes(&mut secret);
        restart_duress_fixture(ad);
        return Err(if kind == CredentialKind::Pin {
            "Duress PINs do not match"
        } else {
            "Duress passwords do not match"
        });
    }
    zeroize_bytes(&mut secret);
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.advanced.clear_pending();
    if let Err(error) = persistence_result {
        restart_duress_fixture(ad);
        return Err(error.message());
    }
    ad.storage.persistence.advanced.duress = DuressActivation::Enabled;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
    Ok(())
}

#[cfg(feature = "workflow-test-auto")]
fn restart_duress_fixture(ad: &mut AppData) {
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.advanced.clear_pending();
    crate::runtime::effects::replace(
        ad,
        crate::runtime::navigation::route!(AdvancedDuressEntry),
    );
}

#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]
pub(crate) fn submit_rtc(ad: &mut AppData) -> Result<u64, &'static str> {
    let raw = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
    let value = parse_utc_yyyymmddhhmm(raw).map_err(|_| "Use valid UTC YYYYMMDDHHMM")?;
    let unix = value.to_unix_seconds().map_err(|_| "Use valid UTC YYYYMMDDHHMM")?;
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.advanced.rtc_verification = RtcVerification::Verified;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
    Ok(unix)
}

#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]
pub(crate) fn rtc_low_voltage(ad: &mut AppData) {
    ad.storage.persistence.advanced.rtc_verification = RtcVerification::Unverified;
    ad.storage.persistence.advanced.clear_pending();
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedRtcEntry));
}

#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]
pub(crate) fn submit_time_lock(ad: &mut AppData, now_unix: u64) -> Result<(), &'static str> {
    let raw = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
    let target = parse_utc_yyyymmddhhmm(raw)
        .and_then(|value| value.to_unix_seconds())
        .map_err(|_| "Use valid UTC YYYYMMDDHHMM")?;
    if target <= now_unix { return Err("Lock date must be in the future"); }
    ad.storage.persistence.advanced.pending_not_before_unix = target;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedTimeLockConfirm));
    Ok(())
}

#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]
pub(crate) fn confirm_time_lock(
    ad: &mut AppData,
    now_unix: u64,
    persistence_result: Result<(), PersistError>,
) -> Result<(), &'static str> {
    persistence_result.map_err(PersistError::message)?;
    let target = ad.storage.persistence.advanced.pending_not_before_unix;
    if target <= now_unix { return Err("Invalid security policy"); }
    let mut policy = ad.storage.persistence.advanced.policy;
    policy.not_before_unix = target;
    policy.rtc_floor_unix = policy.rtc_floor_unix.max(now_unix);
    policy.validate().map_err(|_| "Invalid security policy")?;
    ad.storage.persistence.advanced.policy = policy;
    super::input::return_to_advanced(ad);
    Ok(())
}

#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]
pub(crate) fn submit_weekly(ad: &mut AppData) -> Result<(), &'static str> {
    let raw = &ad.wallet.seeds.pp_input.buf[..ad.wallet.seeds.pp_input.len];
    let (windows, count) = parse_weekly_windows(raw).map_err(|_| "Use DAY HH:MM-HH:MM; max 4")?;
    ad.storage.persistence.advanced.pending_windows = windows;
    ad.storage.persistence.advanced.pending_weekly_count = count;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedWeeklyConfirm));
    Ok(())
}

#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]
pub(crate) fn confirm_weekly(
    ad: &mut AppData,
    now_unix: u64,
    persistence_result: Result<(), PersistError>,
) -> Result<(), &'static str> {
    persistence_result.map_err(PersistError::message)?;
    let mut policy = ad.storage.persistence.advanced.policy;
    policy.weekly_enabled = true;
    policy.weekly_count = ad.storage.persistence.advanced.pending_weekly_count;
    policy.windows = ad.storage.persistence.advanced.pending_windows;
    policy.rtc_floor_unix = policy.rtc_floor_unix.max(now_unix);
    policy.validate().map_err(|_| "Invalid security policy")?;
    ad.storage.persistence.advanced.policy = policy;
    super::input::return_to_advanced(ad);
    Ok(())
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn pop_it_prompt(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    super::pop_it::handle_prompt(input, ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn pop_it_confirmation(
    ad: &mut AppData,
    phrase: &[u8],
    preflight_ok: bool,
    arm_ok: bool,
) -> Result<(), &'static str> {
    if !super::pop_it::confirmation_phrase_valid(phrase) {
        ad.pop_it.error = Some("Enter POP IT, then press OK");
        return Err("Enter POP IT, then press OK");
    }
    if !preflight_ok {
        ad.pop_it.error = Some("Secure Boot preflight failed");
        return Err("Secure Boot preflight failed");
    }
    if !arm_ok {
        ad.pop_it.error = Some("Could not arm Secure Boot request");
        return Err("Could not arm Secure Boot request");
    }
    ad.wallet.seeds.pp_input.reset();
    ad.pop_it.error = None;
    crate::runtime::effects::resume(ad, crate::runtime::navigation::ResumeTarget::PopIt);
    Ok(())
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn enter_pop_it(ad: &mut AppData) {
    ad.pop_it.return_state = crate::runtime::navigation::continuation!(AdvancedMenu);
    ad.pop_it.owner_authority_enrolled = true;
    ad.pop_it.error = None;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PopItPrompt));
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn pop_it_phrase_valid(phrase: &[u8]) -> bool {
    super::pop_it::confirmation_phrase_valid(phrase)
}
