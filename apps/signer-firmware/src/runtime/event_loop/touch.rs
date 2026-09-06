// KasSigner — Air-gapped offline signing device for Kaspa
//! Touch polling, wake confirmation, dim suppression, and idle policy.
#[cfg(not(feature = "workflow-test-auto"))] macro_rules! prepare_iteration {
    ($touch_state:ident, $action:ident, $ad:ident, $delay:ident, $i2c:ident, $touch_configured:ident,
     $tracker:ident, $wake_confirm_count:ident, $wake_debounce:ident, $dim_active:ident, $watchdog_feed:ident) => {
        #[cfg(feature = "mirror")]
        $crate::hw::screenshot::pump_rows();

        #[cfg(feature = "waveshare")]
        let ($touch_state, $action) = {
            let (ts, gesture) = $crate::runtime::touch_service::read_full(&mut $i2c, &mut $touch_configured);
            let act = $tracker.update(ts, gesture);
            (ts, act)
        };
        #[cfg(feature = "m5stack")]
        let ($touch_state, $action) = {
            let state = $ad.navigation.app.state;
            let release_was_required = $tracker.release_required();
            match $crate::runtime::touch_service::read_checked(&mut $i2c) {
                Ok(ts) => {
                    let act = $tracker.update(ts);
                    if release_was_required && !$tracker.release_required() {
                        $crate::log!("   TOUCH CoreS3 release barrier cleared: {:?}", state);
                    }
                    // Raw Contact/held PressDown samples are intentionally silent.
                    // The contact gate already collapses a physical hold into one
                    // logical action, so log only the action-producing sample.
                    if !matches!(act, $crate::hw::touch::TouchAction::None) {
                        $crate::log!("   TOUCH CoreS3 {:?} sample {:?} -> {:?}", state, ts, act);
                    }
                    (ts, act)
                }
                Err(()) => {
                    // A transport failure is not a physical finger release.
                    // Preserve the contact gate exactly as-is and fail this
                    // poll closed instead of feeding it a synthetic NoTouch.
                    $crate::log!("   TOUCH CoreS3 {:?} I2C read failed — gate preserved", state);
                    ($crate::hw::touch::TouchState::NoTouch, $crate::hw::touch::TouchAction::None)
                }
            }
        };

        $ad.runtime.idle_ticks = $ad.runtime.idle_ticks.saturating_add(1);
        let is_touch = !matches!($action, $crate::hw::touch::TouchAction::None);
        let raw_touch = !matches!($touch_state, $crate::hw::touch::TouchState::NoTouch);

        if $ad.runtime.display_asleep {
            // Waveshare rejects single-frame wake ghosts using consecutive samples.
            #[cfg(feature = "waveshare")]
            {
                let raw_touch = !matches!($touch_state, $crate::hw::touch::TouchState::NoTouch);
                // Dim-first-touch suppression: the first physical contact after dim is wake-only.
        if raw_touch || is_touch {
                    $wake_confirm_count = $wake_confirm_count.saturating_add(1);
                } else {
                    $wake_confirm_count = 0;
                }
                if $wake_confirm_count >= $crate::runtime::event_loop::WAKE_CONFIRM_REQUIRED {
                    $wake_confirm_count = 0;
                    if $crate::runtime::power_state::handle_wake($ad, &mut $i2c, &mut $delay, &mut $tracker,
                                   &mut $wake_debounce, raw_touch || is_touch) {
                        $dim_active = false; $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
                        continue;
                    }
                }
                $delay.delay_millis(100);
                $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
                continue;
            }
            #[cfg(feature = "m5stack")]
            {
                if $crate::runtime::power_state::handle_wake($ad, &mut $i2c, &mut $delay, &mut $tracker,
                               &mut $wake_debounce, raw_touch || is_touch) {
                    $dim_active = false; $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
                    continue;
                }
                $delay.delay_millis(100);
                $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
                continue;
            }
        }
        #[cfg(feature = "waveshare")]
        { $wake_confirm_count = 0; }

        // Movement gating and domain separation live inside the entropy service;
        // this observation is supplemental and never bypasses the checked TRNG.
        if let $crate::hw::touch::TouchState::One(point) = $touch_state {
            $crate::services::entropy::stage_ambient_touch(point.x, point.y);
        }
        if raw_touch || is_touch {
            $ad.runtime.idle_ticks = 0;
            if $dim_active {
                #[cfg(feature = "m5stack")]
                $crate::log!("   TOUCH CoreS3 dim wake BEGIN");
                let wake_brightness = $crate::runtime::power_state::effective_brightness($ad);
                $crate::hw::pmu::set_brightness!(&mut $i2c, wake_brightness);
                $dim_active = false;
                #[cfg(feature = "m5stack")]
                if !matches!(
                    $ad.navigation.app.state,
                    $crate::runtime::input::AppState::ScanQR
                        | $crate::runtime::input::AppState::DecryptSecretScan
                        | $crate::runtime::input::AppState::SignMsgScan
                )
                {
                    $crate::hw::sound::click();
                }
                // The current physical contact is wake-only. Keep the same
                // contact gate and require its release instead of resetting
                // the tracker and adding a time-based debounce that can eat
                // the user's next intentional tap.
                #[cfg(feature = "m5stack")]
                $tracker.require_release();
                #[cfg(feature = "m5stack")]
                {
                    $wake_debounce = 0;
                    $crate::log!("   TOUCH CoreS3 dim wake DONE — release gate armed");
                }
                #[cfg(feature = "waveshare")]
                { $wake_debounce = 100; }
                $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
                continue;
            }
            // Do not rewrite PMU brightness for every ordinary touch. On CoreS3
            // that added a second I2C transaction between a successfully decoded
            // FT6336U Tap and Home dispatch. Brightness restoration belongs only
            // to the dim/wake branches above; an undimmed tap must remain a pure
            // input-routing path.
        }

        // Idle dimming / sleep
        $crate::runtime::power_state::handle_idle($ad, &mut $i2c, &mut $dim_active);
    };
}

#[cfg(not(feature = "workflow-test-auto"))]
pub(crate) use prepare_iteration;
