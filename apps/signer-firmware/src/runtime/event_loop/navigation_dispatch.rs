//! Narrow navigation dispatch before the capability-rich generic router.

use crate::{controllers::TouchInput, hw::{display, touch}, runtime::data::AppData};

pub(crate) fn handle_pure(
    ad: &mut AppData,
    grid_zones: &[touch::TouchZone; 4],
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    input: TouchInput,
) -> Option<bool> {
    crate::runtime::interactions::seed::handle_navigation_touch(ad, input)
    .or_else(|| crate::runtime::interactions::menu::handle_navigation_touch(
        ad, grid_zones, list_zones, page_up_zone, page_down_zone, input,
    ))
    .or_else(|| crate::runtime::interactions::export::menus::handle_navigation_touch(
        ad, list_zones, page_up_zone, page_down_zone, input,
    ))
}

pub(crate) fn handle_narrow_hardware(
    ad: &mut AppData,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    list_zones: &[touch::TouchZone; 4],
    input: TouchInput,
) -> Option<bool> {
    if matches!(ad.navigation.app.state,
        crate::runtime::input::AppState::StorageUnlockPin | crate::runtime::input::AppState::StorageUnlockPassword
    ) {
        return crate::runtime::interactions::persistence::handle(input, ad, persistent_wallet, boot_display, delay);
    }
    if matches!(ad.navigation.app.state,
        crate::runtime::input::AppState::SeedList
    ) {
        return crate::runtime::interactions::seed::handle_inventory_touch(
            ad, boot_display, delay, liveness, input,
        );
    }
    crate::runtime::interactions::menu::handle_signing_feedback_touch(
        ad, boot_display, delay, liveness, list_zones, input,
    )
}

#[cfg(feature = "m5stack")]
pub(crate) fn log_main_tap_boundary(
    ad: &AppData,
    action: crate::hw::touch::TouchAction,
    marker: &str,
) {
    if ad.navigation.app.state == crate::runtime::input::AppState::MainMenu
        && matches!(action, crate::hw::touch::TouchAction::Tap { .. })
    {
        crate::log!("   TOUCH CoreS3 MainMenu {}", marker);
    }
}

#[cfg(feature = "workflow-tests")]
pub(crate) fn handle_workflow_tests(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    liveness: &mut dyn FnMut(),
    input: TouchInput,
) -> Option<bool> {
    if !matches!(
        ad.navigation.app.state.handler_group(),
        crate::runtime::input::HandlerGroup::WorkflowTests
    ) {
        return None;
    }
    crate::runtime::interactions::workflow_tests::handle(
        ad, list_zones, page_up_zone, page_down_zone, liveness, input,
    )
}


#[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))]
pub(crate) fn render_priority_operation(
    ad: &mut crate::runtime::data::AppData,
    display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::hw::sdcard::SdCardType>,
    tracker: &mut crate::hw::touch::TouchTracker,
    watchdog_feed: &mut dyn FnMut(),
) {
    use crate::runtime::data::OperationPhase;
    if !ad.runtime.needs_redraw
        || crate::runtime::presentation::operation_phase(ad) != OperationPhase::Queued
    {
        return;
    }
    let Some(kind) = crate::runtime::presentation::operation_kind(ad) else { return; };

    // Long-running work must never start while the previous interactive frame is
    // still visible. Flush the operation surface immediately after the input
    // controller queues it, before any deferred service or persistence work.
    crate::runtime::event_loop::runner::acknowledge(watchdog_feed);
    crate::log!("   UI priority operation redraw BEGIN: {:?}", kind);
    crate::ui::redraw::redraw_screen(ad, display, i2c, sd_card_type);
    ad.runtime.needs_redraw = false;
    if kind.is_credential() {
        tracker.require_strict_release();
    } else {
        tracker.require_release();
    }
    crate::log!("   UI priority operation redraw DONE: {:?}", kind);
    crate::runtime::event_loop::runner::acknowledge(watchdog_feed);
}

#[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))]
pub(in crate::runtime::event_loop) fn arm_release_for_state(
    tracker: &mut crate::hw::touch::TouchTracker,
    state: crate::runtime::input::AppState,
) {
    use crate::runtime::input::AppState;
    if matches!(
        state,
        AppState::StoragePinEntry
            | AppState::StoragePinConfirm
            | AppState::StoragePasswordEntry
            | AppState::StoragePasswordConfirm
            | AppState::StorageUnlockPin
            | AppState::StorageUnlockPassword
    ) {
        tracker.require_strict_release();
    } else {
        tracker.require_release();
    }
}
