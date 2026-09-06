// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0-or-later.

//! Display power, wake handling, dim-lock policy, QR scanner brightness, and
//! fatal fallback behavior.

mod no_display;
pub(crate) use no_display::continue_without_display;

const SLEEP_AFTER_DIM_TICKS: u32 = 36_000;
const QR_BRIGHTNESS_STEP: u8 = 32;
const QR_BRIGHTNESS_MIN: u8 = 16;

pub(crate) fn handle_wake(
    ad: &mut crate::runtime::data::AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    tracker: &mut crate::hw::touch::TouchTracker,
    wake_debounce: &mut u32,
    physical_touch: bool,
) -> bool {
    let _ = &mut *i2c;
    #[cfg(feature = "waveshare")]
    let _ = &mut *tracker;
    #[cfg(feature = "waveshare")]
    let _ = &mut *delay;
    if !physical_touch { return false; }

    #[cfg(feature = "m5stack")]
    crate::log!("   TOUCH CoreS3 sleep wake BEGIN");

    #[cfg(feature = "m5stack")]
    {
        crate::hw::sound::click();
        delay.delay_millis(50);
    }

    let brightness = effective_brightness(ad);
    crate::hw::pmu::set_brightness!(i2c, brightness);

    #[cfg(feature = "m5stack")]
    {
        delay.delay_millis(50);
        crate::hw::pmu::set_brightness!(i2c, brightness);
    }

    ad.runtime.display_asleep = false;
    ad.runtime.needs_redraw = true;
    ad.runtime.idle_ticks = 0;

    #[cfg(feature = "m5stack")]
    tracker.require_release();
    #[cfg(feature = "waveshare")]
    { *wake_debounce = 200; }
    #[cfg(feature = "m5stack")]
    {
        *wake_debounce = 0;
        crate::log!("   TOUCH CoreS3 sleep wake DONE — release gate armed");
    }
    true
}

pub(crate) fn handle_idle(
    ad: &mut crate::runtime::data::AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    dim_active: &mut bool,
) {
    let _ = &mut *i2c;
    let Some(dim_ticks) = ad.settings.screen_dim_timeout.ticks() else { return; };

    if ad.runtime.idle_ticks >= dim_ticks && !*dim_active && !ad.runtime.display_asleep {
        if should_require_pin_after_dim(ad) {
            arm_pin_reauthentication(ad);
        }
        crate::hw::pmu::set_brightness!(i2c, 20);
        *dim_active = true;
    }

    let sleep_ticks = dim_ticks.saturating_add(SLEEP_AFTER_DIM_TICKS);
    if ad.runtime.idle_ticks >= sleep_ticks && !ad.runtime.display_asleep {
        #[cfg(feature = "waveshare")]
        crate::hw::pmu::set_brightness!(i2c, 0);
        #[cfg(feature = "m5stack")]
        crate::hw::pmu::set_brightness!(i2c, 1);
        ad.runtime.display_asleep = true;
    }
}

fn should_require_pin_after_dim(ad: &crate::runtime::data::AppData) -> bool {
    ad.settings.require_pin_after_dim()
        && ad.storage.persistence.advanced.availability.is_available()
        && ad.storage.persistence.advanced.credential_kind
            == Some(crate::services::persistent_wallet::CredentialKind::Pin)
        && !matches!(
            ad.navigation.app.state,
            crate::runtime::input::AppState::StorageUnlockPin
                | crate::runtime::input::AppState::StorageUnlockPassword
        )
}

fn arm_pin_reauthentication(ad: &mut crate::runtime::data::AppData) {
    let return_to = ad.navigation.committed_state;
    let return_route = crate::runtime::navigation::continuation_from_state(return_to);
    if !ad.runtime.begin_pin_reauth(return_route) { return; }
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.unlock_feedback = crate::runtime::data::UnlockFeedback::None;
    ad.storage.persistence.unlock_retry_after_ms = 0;
    if crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageUnlockPin)) {
        crate::log!("   DISPLAY dim PIN re-auth armed return={:?}", return_to);
    } else {
        let _ = ad.runtime.take_pin_reauth_return();
    }
}

pub(crate) fn qr_brightness_tap(
    ad: &mut crate::runtime::data::AppData,
    x: u16,
    y: u16,
) -> Option<bool> {
    if !ad.navigation.app.state.shows_scannable_qr() { return None; }
    let minus = crate::ui::screens::QR_BRIGHTNESS_MINUS_ZONE.contains(x, y);
    let plus = crate::ui::screens::QR_BRIGHTNESS_PLUS_ZONE.contains(x, y);
    if !minus && !plus { return None; }
    Some(adjust_qr_brightness(ad, plus))
}

fn adjust_qr_brightness(
    ad: &mut crate::runtime::data::AppData,
    increase: bool,
) -> bool {
    if !ad.navigation.app.state.shows_scannable_qr() { return false; }
    let current = ad.runtime.qr_brightness_override.unwrap_or(ad.settings.brightness);
    let next = if increase {
        current.saturating_add(QR_BRIGHTNESS_STEP)
    } else {
        current.saturating_sub(QR_BRIGHTNESS_STEP).max(QR_BRIGHTNESS_MIN)
    };
    if next == current { return false; }
    ad.runtime.qr_brightness_override = Some(next);
    crate::log!("   QR brightness temporary value={}", next);
    true
}

pub(crate) fn effective_brightness(ad: &crate::runtime::data::AppData) -> u8 {
    if ad.navigation.app.state.shows_scannable_qr() {
        ad.runtime.qr_brightness_override.unwrap_or(ad.settings.brightness)
    } else {
        ad.settings.brightness
    }
}

#[inline(never)]
pub(crate) fn apply_requested_brightness(
    ad: &mut crate::runtime::data::AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    applied: &mut u8,
) {
    if !ad.navigation.app.state.shows_scannable_qr() {
        ad.runtime.qr_brightness_override = None;
    }
    let requested = effective_brightness(ad);
    if *applied == requested { return; }
    // Waveshare brightness is PWM-backed; its board macro intentionally ignores I2C.
    #[cfg(feature = "waveshare")]
    let _ = &mut *i2c;
    #[cfg(feature = "m5stack")]
    crate::log!("   DISPLAY CoreS3 brightness apply BEGIN value={}", requested);
    crate::hw::pmu::set_brightness!(i2c, requested);
    *applied = requested;
    #[cfg(feature = "m5stack")]
    crate::log!("   DISPLAY CoreS3 brightness apply DONE value={}", requested);
}

pub fn halt_forever(delay: &mut esp_hal::delay::Delay) -> ! {
    delay.delay_millis(5000);
    loop { delay.delay_millis(1000); }
}
