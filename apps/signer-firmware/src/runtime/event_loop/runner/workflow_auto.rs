//! Test-driver boundary injected after authoritative production startup.

use crate::{
    hw::{camera::CameraStatus, display::BootDisplay, sdcard::SdCardType},
    runtime::data::AppData,
    services::persistent_wallet::PersistentWallet,
};
use esp_hal::{
    Blocking, delay::Delay, dma::DmaRxBuf, i2c::master::I2c,
    lcd_cam::cam::Camera,
};

pub(super) fn run(
    ad: &mut AppData,
    mut display: BootDisplay<'_>,
    mut i2c: I2c<'_, Blocking>,
    sd_card_type: Option<SdCardType>,
    mut delay: Delay,
    mut camera: Option<Camera<'_>>,
    mut camera_dma: Option<DmaRxBuf>,
    mut camera_status: CameraStatus,
    mut persistent_wallet: PersistentWallet<'_>,
    mut watchdog_feed: impl FnMut(),
) -> ! {
    crate::runtime::workflow_tests::run_connected_gate(
        ad, &mut display, &mut i2c, &sd_card_type, &mut delay,
        &mut camera, &mut camera_dma, &mut camera_status,
        &mut persistent_wallet, &mut watchdog_feed,
    );
    crate::runtime::workflow_tests::park_after_gate(&mut delay, &mut watchdog_feed);
}
