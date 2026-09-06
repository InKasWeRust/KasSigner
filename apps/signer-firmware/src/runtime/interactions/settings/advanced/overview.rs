use crate::{
    runtime::interactions::{
        feedback::{show_rejection, ErrorSound},
        TouchInput,
    },
    hw::display::BootDisplay,
    runtime::data::{AppData, DeviceStorageIntent},
    services::persistent_wallet::{PersistError, PersistentWallet},
    ui::screens::device::advanced_security::{
        ADV_CARD_X, DURESS_Y, RTC_Y, SD_STORAGE_Y, TIME_LOCK_Y, WARNING_BUTTON_Y, WARNING_CANCEL_X,
        WARNING_ENABLE_X, WEEKLY_Y,
    },
};

pub(super) fn handle_overview(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> Option<bool> {
    if input.is_back {
        crate::runtime::effects::back(ad);
        return Some(true);
    }
    if !ADV_CARD_X.contains(&input.x) {
        return None;
    }

    persistence.refresh_security_mirror(ad);
    if !ad.storage.persistence.advanced.availability.is_available() {
        crate::runtime::presentation::show_recoverable_error(
            ad,
            PersistError::AdvancedRequiresSavedWallet.message(),
            "SEC-AUTH-01",
            0,
        );
        return Some(true);
    }
    if !ad.storage.persistence.advanced.policy_integrity.is_valid() {
        show_rejection(
            display,
            delay,
            PersistError::PolicyIntegrity.message(),
            2000,
            ErrorSound::Beep,
        );
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
        handle_time_lock_card(ad, display, delay);
        return Some(true);
    }
    if WEEKLY_Y.contains(&input.y) {
        handle_weekly_card(ad, display, delay);
        return Some(true);
    }
    if SD_STORAGE_Y.contains(&input.y) {
        if ad.storage.persistence.advanced.outer_device_only {
            show_rejection(
                display,
                delay,
                "SD storage unavailable with per-wallet protection",
                2200,
                ErrorSound::Beep,
            );
            return Some(true);
        }
        if !ad.storage.persistence.advanced.persistence_backend.is_sd() {
            ad.storage.persistence.advanced.clear_pending();
            ad.storage.persistence.device_storage_intent = DeviceStorageIntent::EnableSd;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageRecoveryAcknowledgement));
        }
        return Some(true);
    }
    if RTC_Y.contains(&input.y) {
        handle_rtc_card(ad, display, delay);
        return Some(true);
    }
    None
}

pub(super) fn handle_sd_warning(
    input: TouchInput,
    ad: &mut AppData,
    persistence: &mut PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Option<bool> {
    if input.is_back
        || (WARNING_BUTTON_Y.contains(&input.y) && WARNING_CANCEL_X.contains(&input.x))
    {
        ad.storage.persistence.recovery_words_acknowledged = false;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
        return Some(true);
    }
    if !WARNING_BUTTON_Y.contains(&input.y) || !WARNING_ENABLE_X.contains(&input.x) {
        return None;
    }
    let result = persistence.enable_sd_storage(
        &ad.wallet.seeds.seed_mgr,
        ad.storage.persistence.recovery_words_acknowledged,
        i2c,
        delay,
    );
    persistence.refresh_security_mirror(ad);
    match result {
        Ok(()) => {
            ad.storage.persistence.recovery_words_acknowledged = false;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
        },
        Err(error) => {
            if persistence.is_sd_mode() {
                crate::services::device_wipe::zeroize_volatile(ad);
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSdFailure));
            }
            show_rejection(display, delay, error.message(), 2200, ErrorSound::Beep);
        }
    }
    Some(true)
}

pub(super) fn handle_warning(input: TouchInput, ad: &mut AppData, next: crate::runtime::navigation::ContinuationRoute) -> Option<bool> {
    if input.is_back
        || (WARNING_BUTTON_Y.contains(&input.y) && WARNING_CANCEL_X.contains(&input.x))
    {
        ad.storage.persistence.advanced.clear_pending();
        ad.wallet.seeds.pp_input.reset();
        let _ = crate::runtime::effects::back(ad);
        return Some(true);
    }
    if WARNING_BUTTON_Y.contains(&input.y) && WARNING_ENABLE_X.contains(&input.x) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::continue_to(ad, next);
        return Some(true);
    }
    None
}

pub(super) fn handle_time_lock_card(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    #[cfg(feature = "waveshare")]
    let _ = ad;
    #[cfg(feature = "waveshare")]
    show_rejection(
        display,
        delay,
        "Time lock unavailable: no hardware RTC",
        1900,
        ErrorSound::Beep,
    );

    #[cfg(feature = "m5stack")]
    if ad.storage.persistence.advanced.policy.not_before_unix == 0 {
        if !ad.storage.persistence.advanced.policy.has_time_policy()
            && !ad.storage.persistence.advanced.rtc_verification.is_verified()
        {
            show_rejection(
                display,
                delay,
                "Set/verify hardware RTC first",
                1900,
                ErrorSound::Beep,
            );
        } else {
            ad.storage.persistence.advanced.clear_pending();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedTimeLockWarning));
        }
    }
}

pub(super) fn handle_weekly_card(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    #[cfg(feature = "waveshare")]
    let _ = ad;
    #[cfg(feature = "waveshare")]
    show_rejection(
        display,
        delay,
        "Signing windows unavailable: no hardware RTC",
        1900,
        ErrorSound::Beep,
    );

    #[cfg(feature = "m5stack")]
    if ad.storage.persistence.advanced.policy.weekly_enabled {
        display.draw_weekly_policy_readonly(
            &ad.storage.persistence.advanced.policy.windows,
            ad.storage.persistence.advanced.policy.weekly_count,
        );
        crate::services::timing::pause(delay, 2500);
    } else if !ad.storage.persistence.advanced.policy.has_time_policy()
        && !ad.storage.persistence.advanced.rtc_verification.is_verified()
    {
        show_rejection(
            display,
            delay,
            "Set/verify hardware RTC first",
            1900,
            ErrorSound::Beep,
        );
    } else {
        ad.storage.persistence.advanced.clear_pending();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedWeeklyWarning));
    }
}

pub(super) fn handle_rtc_card(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    #[cfg(feature = "waveshare")]
    let _ = ad;
    #[cfg(feature = "waveshare")]
    show_rejection(
        display,
        delay,
        "This board has no hardware RTC",
        1800,
        ErrorSound::Beep,
    );

    #[cfg(feature = "m5stack")]
    if ad.storage.persistence.advanced.policy.has_time_policy() {
        show_rejection(
            display,
            delay,
            "RTC is locked by permanent signing policy",
            1900,
            ErrorSound::Beep,
        );
    } else {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedRtcEntry));
    }
}
