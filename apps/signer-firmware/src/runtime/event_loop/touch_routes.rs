// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Controller routing for touch input emitted by the application loop.

/// Route one normalized touch event. Page gestures deliberately target only
/// page-aware controller groups; direct taps route to every controller group.
#[cfg(not(feature = "workflow-test-auto"))]
macro_rules! route_touch {
    ($page_only:expr, $input:expr, $ad:ident, $persistent_wallet:ident, $boot_display:ident, $delay:ident,
     $watchdog_feed:ident, $i2c:ident, $sd_card_type:ident, $dvp_camera_opt:ident, $cam_dma_buf_opt:ident,
     $grid_zones:ident, $list_zones:ident, $page_up_zone:ident, $page_down_zone:ident) => {{
        let input = $input;
        if $crate::runtime::navigation::is_onboarding($ad) {
            $crate::runtime::interactions::onboarding::handle_onboarding_touch(
                $crate::runtime::interactions::onboarding::OnboardingTouchContext {
                    ad: $ad,
                    persistent_wallet: &mut $persistent_wallet,
                    boot_display: &mut $boot_display,
                    delay: &mut $delay,
                    liveness: &mut $watchdog_feed,
                    i2c: &mut $i2c,
                    sd_card_type: &$sd_card_type,
                    dvp_camera_opt: &mut $dvp_camera_opt,
                    cam_dma_buf_opt: &mut $cam_dma_buf_opt,
                    list_zones: &$list_zones,
                    page_up_zone: &$page_up_zone,
                    page_down_zone: &$page_down_zone,
                    input,
                },
            )
        } else {
        match $crate::controllers::classify($ad.navigation.app.state) {
            $crate::controllers::InteractionDomain::Menu => {
                if let Some(result) = $crate::runtime::interactions::menu::handle_navigation_touch(
                    $ad, &$grid_zones, &$list_zones, &$page_up_zone, &$page_down_zone, input,
                ) {
                    Some(result)
                } else {
                    $crate::runtime::interactions::menu::handle_menu_touch(
                        $crate::runtime::interactions::menu::MenuTouchContext {
                            ad: $ad,
                            boot_display: &mut $boot_display,
                            delay: &mut $delay,
                            liveness: &mut $watchdog_feed,
                            i2c: &mut $i2c,
                            sd_card_type: &$sd_card_type,
                            dvp_camera_opt: &mut $dvp_camera_opt,
                            cam_dma_buf_opt: &mut $cam_dma_buf_opt,
                            list_zones: &$list_zones,
                            page_up_zone: &$page_up_zone,
                            page_down_zone: &$page_down_zone,
                            input,
                        },
                    )
                }
            }
            $crate::controllers::InteractionDomain::Stego => {
                $crate::runtime::interactions::stego::handle_stego_touch(
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
                        input,
                    },
                )
            }
            $crate::controllers::InteractionDomain::Storage if !$page_only => {
                $crate::runtime::interactions::sd::handle_sd_touch(
                    $crate::runtime::interactions::sd::SdTouchContext {
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
                        input,
                    },
                )
            }
            $crate::controllers::InteractionDomain::Seed if !$page_only => {
                $crate::runtime::interactions::seed::handle_seed_touch(
                    $ad,
                    &mut $boot_display,
                    &mut $delay,
                    &mut $watchdog_feed,
                    input,
                )
            }
            $crate::controllers::InteractionDomain::Export => {
                $crate::runtime::interactions::export::handle_export_touch(
                    $crate::runtime::interactions::export::ExportTouchContext {
                        ad: $ad,
                        boot_display: &mut $boot_display,
                        delay: &mut $delay,
                        liveness: &mut $watchdog_feed,
                        i2c: &mut $i2c,
                        sd_card_type: &$sd_card_type,
                        list_zones: &$list_zones,
                        page_up_zone: &$page_up_zone,
                        page_down_zone: &$page_down_zone,
                        input,
                    },
                )
            }
            $crate::controllers::InteractionDomain::Persistence if !$page_only => {
                $crate::runtime::interactions::persistence::handle(
                    input,
                    $ad,
                    &mut $persistent_wallet,
                    &mut $boot_display,
                    &mut $delay,
                )
            }
            #[cfg(feature = "waveshare")]
            $crate::controllers::InteractionDomain::Settings => {
                $crate::runtime::interactions::settings::handle_settings_touch(
                    $crate::runtime::interactions::settings::SettingsTouchContext {
                        ad: $ad,
                        boot_display: &mut $boot_display,
                        delay: &mut $delay,
                        i2c: &mut $i2c,
                        sd_card_type: &$sd_card_type,
                        input,
                    },
                )
            }
            #[cfg(feature = "workflow-tests")]
            $crate::controllers::InteractionDomain::WorkflowTests => {
                $crate::runtime::interactions::workflow_tests::handle(
                    $ad, &$list_zones, &$page_up_zone, &$page_down_zone,
                    &mut $watchdog_feed, input,
                )
            }
            $crate::controllers::InteractionDomain::Signing if !$page_only => {
                $crate::runtime::interactions::tx::handle_tx_touch(
                    $crate::runtime::interactions::tx::TxTouchContext {
                        ad: $ad,
                        boot_display: &mut $boot_display,
                        delay: &mut $delay,
                        i2c: &mut $i2c,
                        sd_card_type: &$sd_card_type,
                        liveness: &mut $watchdog_feed,
                        list_zones: &$list_zones,
                        input,
                    },
                )
            }
            _ => None,
        }
        }
    }};
}

#[cfg(not(feature = "workflow-test-auto"))]
pub(crate) use route_touch;
