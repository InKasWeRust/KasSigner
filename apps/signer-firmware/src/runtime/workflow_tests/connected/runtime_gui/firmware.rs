//! Physical runtime-HIL coverage for firmware-update guidance and the production scanner.

use super::{begin, fail, open_advanced, open_root, pass, render};
use crate::{
    hw::{camera::CameraStatus, display::BootDisplay, sdcard::SdCardType},
    runtime::{self, data::AppData, input::AppState},
};
use esp_hal::{Blocking, delay::Delay, dma::DmaRxBuf, i2c::master::I2c, lcd_cam::cam::Camera};

pub(super) fn probe_firmware_update_guidance(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "firmware-update-guidance-render";
    begin(NAME);
    if !open_advanced(ad) {
        return fail(NAME, "production Home -> Settings -> Advanced route rejected");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    if !runtime::interactions::menu::primary::workflow_advanced_select(ad, 0)
        || ad.navigation.app.state != AppState::FirmwareUpdateReady
        || ad.navigation.owner != crate::runtime::navigation::NavigationOwner::Settings
    {
        return fail(NAME, "Firmware Update USB guidance did not retain Settings ownership");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}

pub(super) fn probe_scan_qr_camera(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    camera: &mut Option<Camera<'_>>,
    camera_dma: &mut Option<DmaRxBuf>,
    camera_status: &mut CameraStatus,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "scan-qr-camera";
    begin(NAME);
    if !open_root(ad, 1, AppState::ScanQR)
        || ad.navigation.owner != crate::runtime::navigation::NavigationOwner::Signing
    {
        return fail(NAME, "production Home -> Scan QR route did not retain Signing ownership");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    let mut camera_session = runtime::interactions::camera_loop::CameraSessionState::new();
    watchdog_feed();
    runtime::interactions::camera_loop::run_camera_cycle(
        &mut camera_session, ad, display, delay, i2c, camera, camera_status, camera_dma, watchdog_feed,
    );
    watchdog_feed();
    pass(NAME);
    true
}

