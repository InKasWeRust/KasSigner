// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Hardware-ownership boundary for the application event loop; focused touch,
//! dispatch, frame, and camera stages remain owned by their dedicated modules.

mod deferred; mod idle; mod liveness;
#[cfg(feature = "workflow-test-auto")] mod workflow_auto;
#[cfg(feature = "m5stack")] mod startup_audio;
mod startup_ui;
#[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))] pub(super) use idle::restage_imu;
#[cfg(not(feature = "workflow-test-auto"))]
pub(super) use deferred::service as service_deferred;
#[cfg(not(feature = "workflow-test-auto"))]
pub(super) use deferred::service_request as service_navigation_request;

pub(super) use deferred::service_operation as service_kpub_operation;
pub(super) use deferred::cancel_operation as cancel_kpub_operation;
#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(crate) use deferred::{workflow_drive_address_cache, workflow_drive_connect_kassee};
#[cfg(all(any(feature = "m5stack", feature = "waveshare"), feature = "workflow-runtime-auto"))]
pub(crate) use deferred::workflow_drive_multisig_kpub;
#[cfg(not(feature = "workflow-test-auto"))]
pub(super) use liveness::acknowledge;
#[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))] pub(crate) use liveness::acknowledge_runtime;
#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))] pub(crate) use liveness::sync_watchdog_budget;

#[cfg(not(feature = "workflow-test-auto"))]
use crate::{hw::touch::TouchTracker, runtime::touch_dispatch::NavigationZones};

use crate::{
    hw::{camera::CameraStatus, display::BootDisplay, sdcard::SdCardType},
    runtime::data::AppData,
    services::persistent_wallet::PersistentWallet,
};
use esp_hal::{
    Blocking, delay::Delay, dma::DmaRxBuf, i2c::master::I2c,
    lcd_cam::cam::Camera as DvpCamera, peripherals::{FLASH, HMAC},
};

// LINT-JUSTIFICATION: Clippy scores four focused event-loop macro stages after expansion as one function even though touch, dispatch, frame, and camera policy remain separately owned modules.
#[allow(clippy::cognitive_complexity)]
pub(crate) fn run(
    ad: &mut AppData,
    persistent_hmac: HMAC<'_>,
    persistent_flash: FLASH<'_>,
    mut boot_display: BootDisplay<'_>,
    delay: Delay,
    mut i2c: I2c<'_, Blocking>,
    #[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))] mut cam_i2c: I2c<'_, Blocking>,
    #[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))] mut touch_configured: bool,
    #[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))] sensor_is_ov2640: bool,
    sd_card_type: Option<SdCardType>,
    dvp_camera_opt: Option<DvpCamera<'_>>,
    cam_dma_buf_opt: Option<DmaRxBuf>,
    cam_status: CameraStatus,
    #[cfg(not(feature = "workflow-test-auto"))] mut tracker: TouchTracker,
    #[cfg(feature = "m5stack")] mut runtime_audio: Option<crate::hw::sound::RuntimeAudio>,
    #[cfg(feature = "m5stack")] watchdog_feed: impl FnMut(),
    #[cfg(not(feature = "workflow-test-auto"))] zones: NavigationZones,
) -> ! {
    let mut persistent_wallet = PersistentWallet::new(persistent_hmac, persistent_flash);
    #[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))] let mut delay = delay;
    #[cfg(all(feature = "waveshare", not(feature = "workflow-test-auto")))] let mut delay = delay;
    let startup = persistent_wallet.prepare_startup(ad);
    crate::runtime::interactions::persistence::apply_startup_navigation(ad, startup);
    #[cfg(feature = "m5stack")]
    startup_audio::apply_audio_preference(ad, &mut persistent_wallet, &mut runtime_audio);
    startup_ui::render(ad, &mut boot_display, &mut i2c, &sd_card_type);
    // Interactive loop alone owns the mutable watchdog acknowledgement.
    #[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))] let mut watchdog_feed = watchdog_feed;
    #[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))] acknowledge_runtime(ad, &mut watchdog_feed);
    // Waveshare workflow-auto uses the same explicit no-op liveness callback as its event loop.
    #[cfg(all(feature = "waveshare", feature = "workflow-test-auto"))]
    let watchdog_feed = || {};
    #[cfg(feature = "workflow-test-auto")]
    workflow_auto::run(
        ad, boot_display, i2c, sd_card_type, delay, dvp_camera_opt,
        cam_dma_buf_opt, cam_status, persistent_wallet, watchdog_feed,
    );
    #[cfg(not(feature = "workflow-test-auto"))]
    {
        let (mut dvp_camera_opt, mut cam_dma_buf_opt, mut cam_status) = (dvp_camera_opt, cam_dma_buf_opt, cam_status); let (grid_zones, list_zones, page_up_zone, page_down_zone) = zones;
        #[cfg(feature = "waveshare")]
        let mut runtime_audio = ();
        #[cfg(feature = "waveshare")]
        let mut watchdog_feed = || {};
        super::run!(
            ad, persistent_wallet, boot_display, delay, i2c, cam_i2c,
            touch_configured, sensor_is_ov2640, sd_card_type, dvp_camera_opt,
            cam_dma_buf_opt, cam_status, tracker, runtime_audio, watchdog_feed,
            grid_zones, list_zones, page_up_zone, page_down_zone
        );
    }
}
