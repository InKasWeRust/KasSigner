// KasSigner — Air-gapped offline signing device for Kaspa — GPL-3.0
//! Firmware application-loop orchestration.
#[cfg(feature = "waveshare")] pub(crate) const IMU_RESTAGE_TICKS: u32 = 512;
#[cfg(feature = "waveshare")] pub(crate) const INITIAL_WAKE_DEBOUNCE: u32 = 200;
#[cfg(feature = "m5stack")] pub(crate) const INITIAL_WAKE_DEBOUNCE: u32 = 0;
#[cfg(feature = "waveshare")] pub(crate) const WAKE_CONFIRM_REQUIRED: u8 = 2;
pub(crate) mod audio; pub(crate) mod camera; pub(crate) mod dispatch; pub(crate) mod frame; pub(crate) mod operation_engine; pub(crate) mod persistence;
pub(crate) mod settings_dispatch; pub(crate) mod navigation_dispatch;
#[cfg(not(feature = "hardware-tests"))]
pub(crate) mod runner;
pub(crate) mod touch; pub(crate) mod touch_entropy; pub(crate) mod touch_routes;
#[cfg(not(feature = "workflow-test-auto"))]
macro_rules! run {
    ($ad:ident, $persistent_wallet:ident, $boot_display:ident, $delay:ident, $i2c:ident, $cam_i2c:ident,
     $touch_configured:ident, $sensor_is_ov2640:ident, $sd_card_type:ident, $dvp_camera_opt:ident,
     $cam_dma_buf_opt:ident, $cam_status:ident, $tracker:ident, $runtime_audio:ident,
     $watchdog_feed:ident, $grid_zones:ident, $list_zones:ident, $page_up_zone:ident, $page_down_zone:ident) => {
        let mut wake_debounce: u32 = $crate::runtime::event_loop::INITIAL_WAKE_DEBOUNCE;
        let mut dim_active = false;
        let mut applied_brightness = 102u8;
        #[cfg(feature = "waveshare")]
        let mut camera_session = $crate::runtime::interactions::camera_loop::CameraSessionState::new($sensor_is_ov2640);
        #[cfg(feature = "m5stack")]
        let mut camera_session = $crate::runtime::interactions::camera_loop::CameraSessionState::new();
        #[cfg(feature = "waveshare")]
        let mut wake_confirm_count: u8 = 0;
        let mut operation_engine = $crate::runtime::event_loop::operation_engine::OperationEngineState::new();
        loop {
            // Foreground-exclusive heavy work owns this frame; peripheral ownership stays isolated without hard-stalling a peer core.
            if $crate::runtime::event_loop::operation_engine::owns_exclusive_frame(&operation_engine) {
                $crate::runtime::event_loop::operation_engine::service(&mut operation_engine, $ad, &mut $persistent_wallet, &mut $boot_display, &mut $delay, &mut $i2c, &mut $watchdog_feed);
                #[cfg(feature = "m5stack")]
                $crate::runtime::event_loop::runner::acknowledge_runtime($ad, &mut $watchdog_feed);
                #[cfg(feature = "waveshare")]
                $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
                $delay.delay_millis(1);
                continue;
            }

            $crate::runtime::event_loop::audio::service(&mut $runtime_audio);
            $crate::runtime::event_loop::touch::prepare_iteration!(touch_state, action, $ad, $delay, $i2c, $touch_configured, $tracker, wake_confirm_count, wake_debounce, dim_active, $watchdog_feed);
            #[cfg(feature = "waveshare")]
            $crate::runtime::event_loop::runner::restage_imu(action, $ad, &mut $i2c, &mut $delay);
            let destructive_modal = $crate::runtime::destructive::service_step(touch_state, $ad, &mut $boot_display, &mut $delay, &mut $i2c, &mut $watchdog_feed);
            let action = if destructive_modal {
                $crate::hw::touch::TouchAction::None
            } else {
                action
            };
            let mut action = $crate::runtime::presentation::filter_action($ad, action);
            #[cfg(feature = "m5stack")]
            $crate::runtime::event_loop::navigation_dispatch::log_main_tap_boundary($ad, action, "dispatch boundary reached");
            if $crate::runtime::event_loop::touch_entropy::process_step(touch_state, $ad, &mut $boot_display, &mut $delay) {
                action = $crate::hw::touch::TouchAction::None;
            }
            #[cfg(feature = "m5stack")]
            $crate::runtime::event_loop::navigation_dispatch::log_main_tap_boundary($ad, action, "dispatch BEGIN");
            $crate::runtime::event_loop::dispatch::handle_action!(action, $ad, $persistent_wallet, $boot_display, $delay, $i2c, $sd_card_type, $dvp_camera_opt, $cam_dma_buf_opt, $tracker, $runtime_audio, $watchdog_feed, $grid_zones, $list_zones, $page_up_zone, $page_down_zone, wake_debounce);
            #[cfg(feature = "m5stack")]
            $crate::runtime::event_loop::navigation_dispatch::render_priority_operation($ad, &mut $boot_display, &mut $i2c, &$sd_card_type, &mut $tracker, &mut $watchdog_feed);
            #[cfg(feature = "argon2-bench")]
            $crate::runtime::event_loop::runner::service_navigation_request($ad, &mut $boot_display, &mut $delay, &mut $watchdog_feed);
            #[cfg(not(feature = "argon2-bench"))]
            $crate::runtime::event_loop::runner::service_navigation_request($ad, &mut $watchdog_feed);
            $crate::runtime::power_state::apply_requested_brightness($ad, &mut $i2c, &mut applied_brightness);
            $crate::runtime::event_loop::frame::finish_frame!($ad, $persistent_wallet, $boot_display, $delay, $i2c, $sd_card_type, $tracker, $watchdog_feed, $list_zones, $page_up_zone, $page_down_zone);
            $crate::runtime::event_loop::operation_engine::service(&mut operation_engine, $ad, &mut $persistent_wallet, &mut $boot_display, &mut $delay, &mut $i2c, &mut $watchdog_feed);
            $crate::runtime::event_loop::runner::service_deferred($ad);
            $crate::runtime::event_loop::camera::run_step!($ad, $boot_display, $delay, $i2c, $cam_i2c, camera_session, $dvp_camera_opt, $cam_dma_buf_opt, $cam_status, $watchdog_feed);
            $crate::runtime::event_loop::persistence::sync!($ad, $persistent_wallet, $boot_display, $delay, $i2c);
            $crate::runtime::signing::cycle_signed_qr($ad, &mut $boot_display);
            $crate::runtime::event_loop::audio::service(&mut $runtime_audio);
            #[cfg(feature = "m5stack")]
            $crate::runtime::event_loop::runner::acknowledge_runtime($ad, &mut $watchdog_feed);
            #[cfg(feature = "waveshare")]
            $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
            #[cfg(feature = "m5stack")]
            if $ad.navigation.app.state == $crate::runtime::input::AppState::MainMenu && $ad.runtime.idle_ticks == 0 {
                $crate::log!("   NAV MainMenu loop tail complete — next operation is touch poll");
            }
            $delay.delay_millis(1);
        }
    };
}
#[cfg(not(feature = "workflow-test-auto"))]
pub(crate) use run;
