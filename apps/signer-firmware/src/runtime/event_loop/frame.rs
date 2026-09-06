// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Post-input signing, backup persistence, redraw, and automatic stego work.



#[cfg(not(feature = "workflow-test-auto"))]
macro_rules! finish_frame {
    ($ad:ident, $persistent_wallet:ident, $boot_display:ident, $delay:ident, $i2c:ident, $sd_card_type:ident,
     $tracker:ident, $watchdog_feed:ident, $list_zones:ident, $page_up_zone:ident, $page_down_zone:ident) => {
        // ─── Redraw, camera, post-frame effects ──────────────────
        // Stage-3 long-running signing is serviced only after its operation
        // surface has been rendered by this frame.

        // COVB: if camera detected covenant backup, save to SD
        if $ad.qr.outgoing.covenant_backup_length > 0
            && $ad.qr.outgoing.covenant_backup_length <= $ad.qr.outgoing.buffer.len()
            && matches!($ad.navigation.app.state, $crate::runtime::input::AppState::MainMenu)
            && $ad.storage.browser.file_list[0][0] != b' '
            && $ad.storage.browser.file_list[0][0] != 0
        {
            let n = $ad.qr.outgoing.covenant_backup_length;
            // Filename presence is the explicit user-submission token set by
            // CovBackupName. Never infer a save request from payload length alone.
            let fname = $ad.storage.browser.file_list[0];
            $boot_display.draw_saving_screen("Saving covenant...");
            match $crate::runtime::interactions::sd::write_file_to_sd(&mut $i2c, &mut $delay, &fname, &$ad.qr.outgoing.buffer[..n]) {
                Ok(()) => {
                    $crate::log!("   COVB saved ({} bytes)", n);
                    $boot_display.draw_success_screen("Covenant saved to SD");
                }
                Err(e) => {
                    $crate::log!("   COVB save failed: {}", e);
                    $crate::runtime::presentation::show_error_spec(
                        $ad, $crate::runtime::presentation::SD_WRITE,
                    );
                }
            }
            $ad.qr.outgoing.covenant_backup_length = 0;
            $ad.storage.browser.file_list[0] = [b' '; 11]; // clear filename
            $delay.delay_millis(1500);
            $ad.runtime.needs_redraw = true;
        }

        if $ad.runtime.needs_redraw {
            $ad.runtime.idle_ticks = 0;
            $ad.runtime.needs_redraw = false;
            // Reset sub-menu scroll positions on MainMenu
            if $ad.navigation.app.state == $crate::runtime::input::AppState::MainMenu {
                $ad.navigation.export_menu.scroll = 0;
                $ad.navigation.qr_export_menu.scroll = 0;
                $ad.navigation.settings_menu.scroll = 0;
                #[cfg(feature = "waveshare")]
                { $ad.signing.multisig.scroll = 0; }
            }
            #[cfg(feature = "m5stack")]
            {
                // Give every synchronous redraw a fresh watchdog epoch, but do
                // not feed from inside the renderer. A blocked display path must
                // still fail closed through the 30-second hardware watchdog.
                $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
                $crate::log!("   NAV redraw BEGIN: {:?}", $ad.navigation.app.state);
            }
            $crate::ui::redraw::redraw_screen($ad, &mut $boot_display, &mut $i2c, &$sd_card_type);
            #[cfg(feature = "m5stack")]
            {
                $crate::log!("   NAV redraw DONE: {:?}", $ad.navigation.app.state);
                $crate::runtime::event_loop::runner::acknowledge(&mut $watchdog_feed);
            }
            #[cfg(feature = "m5stack")]
            {
                // Most redrawn screens start a fresh input epoch. TouchEntropy
                // is intentionally continuous: the gesture that selected it may
                // flow directly into the entropy canvas without an artificial
                // release/re-tap delay.
                if $ad.navigation.app.state != $crate::runtime::input::AppState::TouchEntropy {
                    $crate::runtime::event_loop::navigation_dispatch::arm_release_for_state(
                        &mut $tracker, $ad.navigation.app.state,
                    );
                    $crate::log!("   NAV frame input release barrier armed: {:?}", $ad.navigation.app.state);
                } else {
                    $crate::log!("   NAV frame continuous touch enabled: TouchEntropy");
                }
            }
            // Mirror mode: request non-blocking frame dump
            #[cfg(feature = "mirror")]
            $crate::hw::screenshot::request_frame();
            // Waveshare: read touch after redraw to feed $tracker
            #[cfg(feature = "waveshare")]
            {
                let (ts, gest) = $crate::runtime::touch_service::read_with_gesture(&mut $i2c);
                $tracker.update(ts, gest);
            }
        }

        // Auto-trigger: stego JPEG scan
        if $ad.stego.session.auto_scan && $ad.navigation.app.state == $crate::runtime::input::AppState::StegoModeSelect {
            $ad.stego.session.auto_scan = false;
            let result = $crate::runtime::interactions::stego::handle_stego_touch(
                $crate::runtime::interactions::stego::StegoTouchContext {
                    ad: $ad,
                    boot_display: &mut $boot_display,
                    delay: &mut $delay,
                    liveness: &mut $watchdog_feed,
                    i2c: &mut $i2c,
                    sd_card_type: &$sd_card_type,
                    backup_device: &mut $persistent_wallet,
                    list_zones: &$list_zones,
                    page_up_zone: &$page_up_zone,
                    page_down_zone: &$page_down_zone,
                    input: $crate::runtime::interactions::TouchInput::new(160, 120, false),
                },
            );
            if let Some(r) = result { $ad.runtime.needs_redraw = r; }
        }
    };
}

#[cfg(not(feature = "workflow-test-auto"))]
pub(crate) use finish_frame;

