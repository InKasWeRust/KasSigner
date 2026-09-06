//! Developer-only workflow E2E harness.
//!
//! The declarative catalog validates production transition ownership on the
//! host/developer menu. `workflow-test-auto` separately runs connected CoreS3
//! scenarios through production controllers after board initialization.

mod catalog;
mod command;
#[cfg(feature = "workflow-test-auto")]
mod connected;
mod runner;

pub(crate) use catalog::{
    category_from_menu_index, category_labels, category_menu, workflow_at,
    WorkflowCategory,
};
pub(crate) use command::{execute, WorkflowCommand};
pub(crate) use runner::WorkflowSummary;

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn run_boot_gate() {
    // Never execute workflow/navigation validation before board bring-up.
    log!("KASSIGNER_WORKFLOW_TESTS: BEGIN");
    log!("KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE");
}



#[cfg(feature = "workflow-test-auto")]
#[inline(never)]
pub(crate) fn park_after_gate(
    delay: &mut esp_hal::delay::Delay,
    watchdog_feed: &mut impl FnMut(),
) -> ! {
    log!("KASSIGNER_WORKFLOW_TESTS: HARNESS PARKED");
    loop {
        watchdog_feed();
        delay.delay_millis(1_000);
    }
}

#[cfg(feature = "workflow-test-auto")]
#[inline(never)]
pub(crate) fn run_connected_gate(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::hw::sdcard::SdCardType>,
    delay: &mut esp_hal::delay::Delay,
    dvp_camera_opt: &mut Option<esp_hal::lcd_cam::cam::Camera<'_>>,
    cam_dma_buf_opt: &mut Option<esp_hal::dma::DmaRxBuf>,
    cam_status: &mut crate::hw::camera::CameraStatus,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    watchdog_feed: &mut impl FnMut(),
) {
    log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED GATE BEGIN");
    #[cfg(feature = "workflow-runtime-auto")]
    log!("KASSIGNER_WORKFLOW_TESTS: RUNTIME GUI NAVIGATION BEGIN");
    #[cfg(not(feature = "workflow-runtime-auto"))]
    log!("KASSIGNER_WORKFLOW_TESTS: CONTROLLER NAVIGATION BEGIN");
    if connected::run(
        ad, boot_display, i2c, sd_card_type, delay,
        dvp_camera_opt, cam_dma_buf_opt, cam_status, persistent_wallet, watchdog_feed,
    ) {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED ROOT NAV PASS 4/4");
        log!("KASSIGNER_WORKFLOW_TESTS: PASS ALL");
    } else {
        log!("KASSIGNER_WORKFLOW_TESTS: FAIL CONNECTED-DEVICE-NAV");
    }
}
