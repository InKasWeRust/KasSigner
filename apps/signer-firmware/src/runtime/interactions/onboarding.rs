//! Authoritative first-wallet onboarding touch facade.
//!
//! A screen owned by `NavigationOwner::Onboarding` is routed only through this
//! facade. This keeps rendered onboarding state and input ownership coupled;
//! generic Menu/Seed/Export routing can no longer silently steal an onboarding
//! tap just because a visual component is shared with another workflow.

use crate::{
    runtime::interactions::TouchInput,
    hw::display,
    services::storage_device as sdcard,
    runtime::data::AppData,
    services::persistent_wallet::PersistentWallet,
};
use esp_hal::{dma::DmaRxBuf, lcd_cam::cam::Camera as DvpCamera};

pub struct OnboardingTouchContext<'ctx, 'display, 'hal, 'camera, 'wallet> {
    pub ad: &'ctx mut AppData,
    pub persistent_wallet: &'ctx mut PersistentWallet<'wallet>,
    pub boot_display: &'ctx mut display::BootDisplay<'display>,
    pub delay: &'ctx mut esp_hal::delay::Delay,
    pub liveness: &'ctx mut dyn FnMut(),
    pub i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub sd_card_type: &'ctx Option<sdcard::SdCardType>,
    pub dvp_camera_opt: &'ctx mut Option<DvpCamera<'camera>>,
    pub cam_dma_buf_opt: &'ctx mut Option<DmaRxBuf>,
    pub list_zones: &'ctx [crate::hw::touch::TouchZone; 4],
    pub page_up_zone: &'ctx crate::hw::touch::TouchZone,
    pub page_down_zone: &'ctx crate::hw::touch::TouchZone,
    pub input: TouchInput,
}

/// Route one touch through the single first-wallet workflow facade.
#[inline(never)]
pub fn handle_onboarding_touch(
    context: OnboardingTouchContext<'_, '_, '_, '_, '_>,
) -> Option<bool> {
    let OnboardingTouchContext {
        ad,
        persistent_wallet,
        boot_display,
        delay,
        liveness,
        i2c,
        sd_card_type,
        dvp_camera_opt,
        cam_dma_buf_opt,
        list_zones,
        page_up_zone,
        page_down_zone,
        input,
    } = context;
    let TouchInput { x, y, is_back } = input;

    match crate::runtime::navigation::onboarding_route(ad) {
        Some(crate::runtime::navigation::OnboardingRoute::Persistence) => {
            crate::runtime::interactions::persistence::handle(
                input, ad, persistent_wallet, boot_display, delay,
            )
        }
        Some(crate::runtime::navigation::OnboardingRoute::Generation) => {
            crate::runtime::interactions::menu::seed_generation::handle(
                ad,
                boot_display,
                delay,
                liveness,
                i2c,
                sd_card_type,
                dvp_camera_opt,
                cam_dma_buf_opt,
                x,
                y,
                is_back,
            )
        }
        Some(crate::runtime::navigation::OnboardingRoute::Dice) => Some(
            crate::runtime::interactions::menu::seed_tools::handle_onboarding_dice(
                ad, boot_display, x, y, is_back,
            ),
        ),
        Some(crate::runtime::navigation::OnboardingRoute::SeedEntry) => {
            crate::runtime::interactions::seed::handle_seed_touch(
                ad, boot_display, delay, liveness, input,
            )
        }
        Some(crate::runtime::navigation::OnboardingRoute::RecoveryWords) => {
            crate::runtime::interactions::export::seed_backup::handle(ad, is_back)
        }
        Some(crate::runtime::navigation::OnboardingRoute::Scan) => Some(false),
        Some(crate::runtime::navigation::OnboardingRoute::Sd) => {
            crate::runtime::interactions::sd::handle_sd_touch(crate::runtime::interactions::sd::SdTouchContext {
                ad, boot_display, delay, liveness, i2c, sd_card_type, backup_device: persistent_wallet,
                list_zones, page_up_zone, page_down_zone, input,
            })
        }
        Some(crate::runtime::navigation::OnboardingRoute::Stego) => {
            crate::runtime::interactions::stego::handle_stego_touch(crate::runtime::interactions::stego::StegoTouchContext {
                ad, boot_display, delay, liveness, i2c, sd_card_type, backup_device: persistent_wallet,
                list_zones, page_up_zone, page_down_zone, input,
            })
        }
        None => {
            log!(
                "   NAV invariant: onboarding owner has unroutable state {:?}",
                ad.navigation.app.state
            );
            crate::runtime::effects::recover_onboarding(ad);
            Some(true)
        }
    }
}
