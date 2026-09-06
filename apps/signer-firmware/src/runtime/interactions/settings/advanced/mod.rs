//! Touch handling facade for irreversible advanced security features.

#[cfg(feature = "m5stack")]
mod clock;
mod credential;
mod factory_reset;
mod input;
mod overview;
#[cfg(feature = "provisioning-ui")]
mod owner_firmware;
#[cfg(feature = "provisioning-ui")]
mod pop_it;
#[cfg(feature = "workflow-test-auto")]
pub(crate) mod workflow;
#[cfg(feature = "m5stack")]
mod time;

use crate::{
    runtime::interactions::TouchInput,
    hw::display::BootDisplay,
    runtime::{data::AppData, input::AppState},
    services::persistent_wallet::PersistentWallet,
};


/// Handle Advanced-screen interactions that are purely local navigation/input
/// editing. `None` is reserved for operations that really need persistence,
/// RTC I2C, or blocking error feedback.
pub(crate) fn handle_pure(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    #[cfg(feature = "provisioning-ui")]
    let result = pop_it::handle_pure(input, ad)
        .or_else(|| owner_firmware::handle_pure(input, ad))
        .or_else(|| handle_pure_warning(input, ad))
        .or_else(|| handle_pure_entry(input, ad));
    #[cfg(not(feature = "provisioning-ui"))]
    let result = handle_pure_warning(input, ad).or_else(|| handle_pure_entry(input, ad));
    #[cfg(feature = "m5stack")]
    { result.or_else(|| handle_pure_confirm(input, ad)) }
    #[cfg(not(feature = "m5stack"))]
    { result }
}

fn handle_pure_warning(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::AdvancedFeatures if input.is_back => { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SettingsMenu)); Some(true) }
        AppState::FirmwareUpdateReady if input.is_back => { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu)); Some(true) }
        AppState::FactoryResetWarning => factory_reset::handle_warning(input, ad),
        AppState::AdvancedDuressWarning => overview::handle_warning(input, ad, crate::runtime::navigation::continuation!(AdvancedDuressEntry)),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedTimeLockWarning => overview::handle_warning(input, ad, crate::runtime::navigation::continuation!(AdvancedTimeLockEntry)),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedWeeklyWarning => overview::handle_warning(input, ad, crate::runtime::navigation::continuation!(AdvancedWeeklyEntry)),
        AppState::AdvancedSdStorageWarning => handle_sd_warning_cancel(input, ad),
        _ => None,
    }
}


fn handle_sd_warning_cancel(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    let cancel = input.is_back || (
        crate::ui::screens::device::advanced_security::WARNING_BUTTON_Y.contains(&input.y)
            && crate::ui::screens::device::advanced_security::WARNING_CANCEL_X.contains(&input.x)
    );
    if !cancel { return None; }
    ad.storage.persistence.recovery_words_acknowledged = false;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
    Some(true)
}

fn handle_pure_entry(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::AdvancedDuressEntry | AppState::AdvancedDuressConfirm => {
            handle_duress_edit(input, ad)
        }
        #[cfg(feature = "m5stack")]
        AppState::AdvancedRtcEntry | AppState::AdvancedTimeLockEntry => pure_edit(input, ad, true),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedWeeklyEntry => pure_edit(input, ad, false),
        _ => None,
    }
}

fn handle_duress_edit(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if input.is_back {
        ad.wallet.seeds.pp_input.reset();
        ad.storage.persistence.advanced.clear_pending();
        crate::runtime::effects::replace(ad, crate::runtime::navigation::route!(AdvancedFeatures));
        return Some(true);
    }
    let kind = ad.storage.persistence.advanced.credential_kind?;
    match input::edit(
        input, ad, kind == crate::services::credential_policy::CredentialKind::Pin,
    ) {
        input::EditAction::Edited => Some(true),
        input::EditAction::None => Some(false),
        input::EditAction::Submitted => None,
    }
}

#[cfg(feature = "m5stack")]
fn pure_edit(input: TouchInput, ad: &mut AppData, numeric: bool) -> Option<bool> {
    if input.is_back { return input::return_to_advanced(ad); }
    match input::edit(input, ad, numeric) {
        input::EditAction::Edited => Some(true),
        input::EditAction::None => Some(false),
        input::EditAction::Submitted => None,
    }
}

#[cfg(feature = "m5stack")]
fn handle_pure_confirm(input: TouchInput, ad: &mut AppData) -> Option<bool> {
    if ad.navigation.app.state == AppState::FactoryResetConfirm {
        let cancel = input.is_back || (
            crate::ui::screens::device::advanced_security::WARNING_BUTTON_Y.contains(&input.y)
                && crate::ui::screens::device::advanced_security::WARNING_CANCEL_X.contains(&input.x)
        );
        if cancel {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu));
            return Some(true);
        }
    }
    if matches!(
        ad.navigation.app.state, AppState::AdvancedTimeLockConfirm | AppState::AdvancedWeeklyConfirm
    ) {
        let cancel = input.is_back || (
            crate::ui::screens::device::advanced_security::WARNING_BUTTON_Y.contains(&input.y)
                && crate::ui::screens::device::advanced_security::WARNING_CANCEL_X.contains(&input.x)
        );
        if cancel { return input::return_to_advanced(ad); }
    }
    None
}

pub(crate) fn handle(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    #[cfg(feature = "provisioning-ui")]
    {
        if let Some(result) = pop_it::handle(input, ad, persistence, display) { return Some(result); }
        if let Some(result) = owner_firmware::handle(input, ad, persistence, display, delay, i2c) { return Some(result); }
    }
    match ad.navigation.app.state {
        AppState::FactoryResetWarning => factory_reset::handle_warning(input, ad),
        AppState::FactoryResetConfirm => {
            factory_reset::execute_confirmed_reset(input, ad, persistence, display, delay, i2c)
        }
        AppState::AdvancedFeatures => overview::handle_overview(input, ad, persistence, display, delay),
        AppState::AdvancedDuressWarning => {
            overview::handle_warning(input, ad, crate::runtime::navigation::continuation!(AdvancedDuressEntry))
        }
        AppState::AdvancedDuressEntry => {
            credential::handle_duress_entry(input, ad, persistence, display, delay, i2c, false)
        }
        AppState::AdvancedDuressConfirm => {
            credential::handle_duress_entry(input, ad, persistence, display, delay, i2c, true)
        }
        AppState::AdvancedSdStorageWarning => {
            overview::handle_sd_warning(input, ad, persistence, display, delay, i2c)
        }
        _ => {
            #[cfg(feature = "m5stack")]
            { dispatch_m5stack_state(input, ad, persistence, display, delay, i2c) }
            #[cfg(not(feature = "m5stack"))]
            { None }
        }
    }
}

#[cfg(feature = "m5stack")]
fn dispatch_m5stack_state(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::AdvancedRtcEntry => clock::handle_rtc_entry(input, ad, display, delay, i2c),
        AppState::AdvancedTimeLockWarning => {
            overview::handle_warning(input, ad, crate::runtime::navigation::continuation!(AdvancedTimeLockEntry))
        }
        AppState::AdvancedTimeLockEntry => time::handle_time_lock_entry(input, ad, display, delay, i2c),
        AppState::AdvancedTimeLockConfirm => {
            time::handle_time_lock_confirm(input, ad, persistence, display, delay, i2c)
        }
        AppState::AdvancedWeeklyWarning => {
            overview::handle_warning(input, ad, crate::runtime::navigation::continuation!(AdvancedWeeklyEntry))
        }
        AppState::AdvancedWeeklyEntry => time::handle_weekly_entry(input, ad, display, delay, i2c),
        AppState::AdvancedWeeklyConfirm => {
            time::handle_weekly_confirm(input, ad, persistence, display, delay, i2c)
        }
        _ => None,
    }
}


pub(crate) fn is_advanced_state(state: AppState) -> bool {
    if matches!(
        state,
        AppState::AdvancedFeatures
            | AppState::FirmwareUpdateReady
            | AppState::FactoryResetWarning
            | AppState::FactoryResetConfirm
            | AppState::AdvancedDuressWarning
            | AppState::AdvancedDuressEntry
            | AppState::AdvancedDuressConfirm
            | AppState::AdvancedSdStorageWarning
    ) {
        return true;
    }
    #[cfg(feature = "provisioning-ui")]
    if matches!(state, AppState::PopItPrompt | AppState::PopItExplain | AppState::PopItConfirm
        | AppState::OwnerKeyWarning | AppState::OwnerKeyConfirm
        | AppState::OwnerInstallWarning | AppState::OwnerInstallConfirm) {
        return true;
    }
    #[cfg(feature = "m5stack")]
    {
        return matches!(
            state,
            AppState::AdvancedRtcEntry
                | AppState::AdvancedTimeLockWarning
                | AppState::AdvancedTimeLockEntry
                | AppState::AdvancedTimeLockConfirm
                | AppState::AdvancedWeeklyWarning
                | AppState::AdvancedWeeklyEntry
                | AppState::AdvancedWeeklyConfirm
        );
    }
    #[cfg(not(feature = "m5stack"))]
    false
}

