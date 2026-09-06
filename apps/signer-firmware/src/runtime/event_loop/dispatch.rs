// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//! Main-loop tap, swipe, and drag dispatch.
#[cfg(not(feature = "workflow-test-auto"))] macro_rules! handle_action {
    ($action:ident, $ad:ident, $persistent_wallet:ident, $boot_display:ident, $delay:ident, $i2c:ident,
     $sd_card_type:ident, $dvp_camera_opt:ident, $cam_dma_buf_opt:ident,
     $tracker:ident, $runtime_audio:ident, $watchdog_feed:ident, $grid_zones:ident, $list_zones:ident,
     $page_up_zone:ident, $page_down_zone:ident, $wake_debounce:ident) => {
        // ─── Touch dispatch ──────────────────────────────────────
        if $wake_debounce > 0 {
            $wake_debounce -= 1;
        } else if let $crate::hw::touch::TouchAction::Tap { x, y } = $action {
            // Exit only this dispatch block when a tap is consumed. Never
            // `continue` the application loop from here: the shared frame,
            // camera, persistence, and audio-tail stages must still run.
            'tap_dispatch: {
            if let Some(changed) = $crate::runtime::power_state::qr_brightness_tap($ad, x, y) {
                if changed { $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio); }
                break 'tap_dispatch;
            }

            #[cfg(feature = "m5stack")]
            if $crate::ui::layout::audio_toggle_zone($ad.navigation.app.state)
                .is_some_and(|zone| zone.contains(x, y))
            {
                let new_volume = $crate::runtime::event_loop::audio::toggle_global_mute($ad);
                $crate::services::audio::set_volume(new_volume);
                if $persistent_wallet.persistent_preferences_available() {
                    if let Err(error) = $persistent_wallet.set_audio_muted($ad.settings.audio_muted()) {
                        $crate::log!("   AUDIO mute preference save failed: {:?}", error);
                    }
                }
                $crate::log!(
                    "   AUDIO CoreS3 global mute toggle -> muted={} volume={}",
                    $ad.settings.audio_muted(), new_volume
                );
                break 'tap_dispatch;
            }

            if $crate::runtime::navigation::home_shortcut_visible($ad)
                && $crate::ui::layout::HOME_SHORTCUT_ZONE.contains(x, y)
            {
                $crate::runtime::navigation::home($ad);
                $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                break 'tap_dispatch;
            }

            // Home uses a closed pure root transition.
            if $ad.navigation.app.state == $crate::runtime::input::AppState::MainMenu {
                #[cfg(feature = "m5stack")]
                $crate::log!("   TOUCH CoreS3 MainMenu pure dispatch BEGIN");
                let handled = $crate::runtime::interactions::menu::handle_root_touch($ad, x, y);
                #[cfg(feature = "m5stack")]
                $crate::log!("   TOUCH CoreS3 MainMenu pure dispatch DONE handled={}", handled);
                if handled {
                    $ad.runtime.needs_redraw = true;
                    $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                }
                break 'tap_dispatch;
            }
            if !$crate::runtime::navigation::reconcile($ad) {
                break 'tap_dispatch;
            }
            let is_back = $crate::ui::layout::is_back_tap(x, y);
            if is_back && $crate::runtime::navigation::handle_back($ad) {
                $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                break 'tap_dispatch;
            }
            if let Some(redraw) = $crate::runtime::event_loop::settings_dispatch::handle(
                $ad, &$list_zones, &$page_up_zone, &$page_down_zone, x, y,
            ) {
                $crate::runtime::event_loop::settings_dispatch::persist_device_preferences($ad, &mut $persistent_wallet);
                $ad.runtime.needs_redraw = redraw;
                if redraw {
                    $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                }
                break 'tap_dispatch;
            }
            if $crate::runtime::interactions::settings::advanced::is_advanced_state($ad.navigation.app.state) {
                let input = $crate::runtime::touch_dispatch::physical_touch_input(x, y);
                if let Some(redraw) = $crate::runtime::interactions::settings::advanced::handle(
                    input,
                    $ad,
                    &mut $persistent_wallet,
                    &mut $boot_display,
                    &mut $delay,
                    &mut $i2c,
                ) {
                    $ad.runtime.needs_redraw = redraw;
                    $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                }
                let _ = $crate::runtime::navigation::reconcile($ad);
                break 'tap_dispatch;
            }
            #[cfg(feature = "m5stack")]
            if matches!($ad.navigation.app.state, $crate::runtime::input::AppState::SdCardSettings | $crate::runtime::input::AppState::SdCardUnlockPassword) {
                let input = $crate::runtime::touch_dispatch::physical_touch_input(x, y);
                let result = $crate::runtime::interactions::settings::handle_settings_touch(
                    $crate::runtime::interactions::settings::SettingsTouchContext {
                        ad: $ad,
                        boot_display: &mut $boot_display,
                        delay: &mut $delay,
                        i2c: &mut $i2c,
                        sd_card_type: &$sd_card_type,
                        input,
                    },
                );
                if let Some(redraw) = result {
                    $ad.runtime.needs_redraw = redraw;
                    $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                }
                let _ = $crate::runtime::navigation::reconcile($ad);
                break 'tap_dispatch;
            }
            let input = $crate::runtime::touch_dispatch::physical_touch_input(x, y);
            // Camera scan screens are silent except Back and fault Retry.
            let is_scan_cam = $crate::runtime::event_loop::camera::is_scan_state(
                $ad.navigation.app.state,
            );
            let click_after_route = (!is_scan_cam || is_back)
                && $crate::runtime::navigation::tap_uses_router_click($ad.navigation.app.state);
            if is_scan_cam && is_back {
                $crate::runtime::interactions::camera_loop::route_camera_back($ad);
                $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                break 'tap_dispatch;
            }
            if is_scan_cam && !is_back {
                // Healthy camera scan screens ignore non-back taps.
                break 'tap_dispatch;
            }
            if let Some(redraw) = $crate::runtime::event_loop::navigation_dispatch::handle_narrow_hardware(
                $ad, &mut $persistent_wallet, &mut $boot_display, &mut $delay, &mut $watchdog_feed, &$list_zones, input,
            ) {
                $ad.runtime.needs_redraw = redraw;
                let _ = $crate::runtime::navigation::reconcile($ad);
                if click_after_route && redraw {
                    $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                }
                break 'tap_dispatch;
            }
            if let Some(redraw) = $crate::runtime::event_loop::navigation_dispatch::handle_pure(
                $ad, &$grid_zones, &$list_zones, &$page_up_zone, &$page_down_zone, input,
            ) {
                $ad.runtime.needs_redraw = redraw;
                let _ = $crate::runtime::navigation::reconcile($ad);
                $crate::runtime::event_loop::settings_dispatch::persist_device_preferences($ad, &mut $persistent_wallet);
                if click_after_route && redraw {
                    $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                }
                break 'tap_dispatch;
            }
            #[cfg(feature = "workflow-tests")]
            if let Some(redraw) = $crate::runtime::event_loop::navigation_dispatch::handle_workflow_tests(
                $ad, &$list_zones, &$page_up_zone, &$page_down_zone, &mut $watchdog_feed, input,
            ) {
                $ad.runtime.needs_redraw = redraw;
                let _ = $crate::runtime::navigation::reconcile($ad);
                if click_after_route && redraw {
                    $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
                }
                break 'tap_dispatch;
            }
            let word_count_ack = matches!(
                $ad.navigation.app.state,
                $crate::runtime::input::AppState::ChooseWordCount { .. }
                    | $crate::runtime::input::AppState::StorageSeedWordCountChoice { .. }
            ) && (is_back || $crate::ui::screens::word_count_choice_at(x, y).is_some());
            if word_count_ack {
                $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
            }
            let entropy_recovery_ack = matches!(
                $ad.navigation.app.state,
                $crate::runtime::input::AppState::SeedEntropyUnavailable { .. }
            ) && (is_back || $crate::ui::screens::entropy_recovery_choice_at(x, y).is_some());
            if entropy_recovery_ack {
                $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
            }

            let result = $crate::runtime::event_loop::touch_routes::route_touch!(
                false, input, $ad, $persistent_wallet, $boot_display, $delay, $watchdog_feed, $i2c, $sd_card_type,
                $dvp_camera_opt, $cam_dma_buf_opt, $grid_zones, $list_zones,
                $page_up_zone, $page_down_zone
            );
            let handled = result.is_some();
            if let Some(r) = result {
                $ad.runtime.needs_redraw = r;
            }
            let _ = $crate::runtime::navigation::reconcile($ad);
            if click_after_route && handled {
                $crate::runtime::event_loop::audio::click($ad, &mut $runtime_audio);
            }

            // Waveshare cooldown suppresses residual ghost taps outside cam-tune.
            #[cfg(feature = "waveshare")]
            if !$ad.camera.cam_tune_active {
                $delay.delay_millis(150);
                // Drain any queued touch event so $tracker starts clean
                let (ts, gest) = $crate::runtime::touch_service::read_with_gesture(&mut $i2c);
                $tracker.update(ts, gest);
            }
            }
        }
        // ─── Waveshare: swipe gestures + drag ────────────────────
        #[cfg(feature = "waveshare")]
        {
            if $action == $crate::hw::touch::TouchAction::SwipeLeft && !$ad.camera.cam_tune_active {
                $crate::hw::sound::click();
                if matches!($ad.navigation.app.state, $crate::runtime::input::AppState::MultisigPickSeed { .. }) {
                    let loaded_count = $ad.wallet.seeds.seed_mgr.slots.iter().enumerate().filter(|(i, _)| $ad.wallet.seeds.seed_mgr.slot_visible(*i)).count() as u8;
                    if $ad.signing.multisig.scroll + 3 < loaded_count { $ad.signing.multisig.scroll += 3; $ad.runtime.needs_redraw = true; }
                } else {
                    let fake_x = 300u16;
                    let fake_y = 138u16;
                    let input = $crate::runtime::interactions::TouchInput::new(fake_x, fake_y, false);
                    let result = $crate::runtime::event_loop::touch_routes::route_touch!(
                        true, input, $ad, $persistent_wallet, $boot_display, $delay, $watchdog_feed, $i2c, $sd_card_type,
                        $dvp_camera_opt, $cam_dma_buf_opt, $grid_zones, $list_zones,
                        $page_up_zone, $page_down_zone
                    );
                    if let Some(r) = result { $ad.runtime.needs_redraw = r; }
                    let _ = $crate::runtime::navigation::reconcile($ad);
                }
            } else if $action == $crate::hw::touch::TouchAction::SwipeRight && !$ad.camera.cam_tune_active {
                $crate::hw::sound::click();
                if matches!($ad.navigation.app.state, $crate::runtime::input::AppState::MultisigPickSeed { .. }) {
                    if $ad.signing.multisig.scroll >= 3 { $ad.signing.multisig.scroll -= 3; $ad.runtime.needs_redraw = true; }
                } else {
                    let fake_x = 20u16;
                    let fake_y = 138u16;
                    let input = $crate::runtime::interactions::TouchInput::new(fake_x, fake_y, false);
                    let result = $crate::runtime::event_loop::touch_routes::route_touch!(
                        true, input, $ad, $persistent_wallet, $boot_display, $delay, $watchdog_feed, $i2c, $sd_card_type,
                        $dvp_camera_opt, $cam_dma_buf_opt, $grid_zones, $list_zones,
                        $page_up_zone, $page_down_zone
                    );
                    if let Some(r) = result { $ad.runtime.needs_redraw = r; }
                    let _ = $crate::runtime::navigation::reconcile($ad);
                }
            } else if let $crate::hw::touch::TouchAction::Drag { x, y, .. } = $action {
                let _ = $crate::runtime::event_loop::settings_dispatch::handle_display_drag(
                    $ad, &mut $boot_display, &mut $i2c, x, y,
                );
                // Drag on cam-tune slider
                if $ad.navigation.app.state == $crate::runtime::input::AppState::ScanQR && $ad.camera.cam_tune_active && y >= 198 {
                    let p = $ad.camera.cam_tune_param as usize;
                    if (52..=268).contains(&x) {
                        let clamped = (x as i32 - 56).max(0).min(208) as u32;
                        $ad.camera.cam_tune_vals[p] = ((clamped * 255) / 208) as u8;
                        $ad.camera.cam_tune_dirty = true;
                        $boot_display.update_cam_tune_slider($ad.camera.cam_tune_param, &$ad.camera.cam_tune_vals);
                    }
                }
            }
        }
    };
}

#[cfg(not(feature = "workflow-test-auto"))]
pub(crate) use handle_action;
