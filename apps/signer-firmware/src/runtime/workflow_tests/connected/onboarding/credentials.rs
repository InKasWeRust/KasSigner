use crate::runtime::{interactions::TouchInput, input::AppState};
use super::OnboardingContext;

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
use crate::{
    hw::{display::BootDisplay, sdcard::SdCardType},
    runtime::data::AppData,
};
#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
const PIN_KDF_PASSWORD: &[u8] = b"123456";

pub(super) fn secure_storage_routes(ctx: &mut OnboardingContext<'_, '_, '_>) -> bool {
    if ctx.ad.navigation.app.state != AppState::StorageFinalizeChoice {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_finalize_choice(
        TouchInput::new(160, 59, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::StorageProtectionChoice {
        return false;
    }
    ctx.redraw_step();

    // Exercise the exact production protection-choice controller.  The
    // device-only alternative performs real FLASH/HMAC work and stays HIL-only.
    if crate::runtime::interactions::persistence::workflow_handle_protection_choice(
        TouchInput::new(160, 65, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::StorageCredentialType {
        return false;
    }
    ctx.redraw_step();
    if crate::runtime::interactions::persistence::workflow_handle_credential_type(
        TouchInput::new(310, 70, false), ctx.ad,
    ).is_some() || ctx.ad.navigation.app.state != AppState::StorageCredentialType {
        return false;
    }
    if !credential_route(ctx, 65, AppState::StoragePinEntry) {
        return false;
    }
    if !credential_route(ctx, 113, AppState::StoragePasswordEntry) {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_credential_type(
        TouchInput::new(20, 20, true), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::StorageProtectionChoice {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_protection_choice(
        TouchInput::new(20, 20, true), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != AppState::StorageFinalizeChoice {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE PROTECTION CHOICE + PIN/PASSWORD ROUTES OK");
    log!("KASSIGNER_WORKFLOW_TESTS: CREATE DEVICE-ONLY FLASH COMMIT DEFERRED TO HIL");
    true
}

fn credential_route(
    ctx: &mut OnboardingContext<'_, '_, '_>,
    y: u16,
    expected: AppState,
) -> bool {
    if crate::runtime::interactions::persistence::workflow_handle_credential_type(
        TouchInput::new(160, y, false), ctx.ad,
    ) != Some(true) || ctx.ad.navigation.app.state != expected {
        return false;
    }
    ctx.redraw_step();
    crate::runtime::interactions::persistence::workflow_handle_setup_back(
        TouchInput::new(20, 20, true), ctx.ad,
    ) == Some(true) && ctx.ad.navigation.app.state == AppState::StorageCredentialType
}


#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn render_runtime(
    ad: &mut AppData, display: &mut BootDisplay<'_>, i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>, delay: &mut Delay, watchdog_feed: &mut impl FnMut(),
) {
    super::super::redraw_step(ad, display, i2c, sd);
    super::super::show_step(delay);
    watchdog_feed();
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn fail_runtime(name: &str, why: &str) -> bool {
    log!("KASSIGNER_WORKFLOW_RUNTIME: ACTION FAIL {}: {}", name, why);
    false
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn submit_pin_via_controller(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    pin: &[u8],
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    ad.wallet.seeds.pp_input.reset();
    for digit in pin { ad.wallet.seeds.pp_input.push_char(*digit); }
    crate::runtime::event_loop::runner::sync_watchdog_budget(ad);
    watchdog_feed();
    crate::runtime::interactions::persistence::workflow_handle_unlock_touch(
        TouchInput::new(260, 211, false), ad, display,
    ) == Some(true)
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(in crate::runtime::workflow_tests::connected) fn persistent_pin_round_trip(
    ad: &mut AppData,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "persistent-pin-storage-round-trip";
    log!("KASSIGNER_WORKFLOW_RUNTIME: ACTION BEGIN {}", NAME);
    let mut operation_engine = crate::runtime::event_loop::operation_engine::OperationEngineState::new();
    if !prepare_persistent_pin_fixture(ad, persistent_wallet, display, i2c, sd, delay, watchdog_feed) {
        cleanup_qa_storage(persistent_wallet, ad);
        return fail_runtime(NAME, "QA persistent-storage fixture setup failed");
    }
    if !verify_invalid_pin_retry(
        &mut operation_engine, ad, persistent_wallet, display, i2c, sd, delay, watchdog_feed,
    ) {
        cleanup_qa_storage(persistent_wallet, ad);
        return fail_runtime(NAME, "invalid PIN retry path failed");
    }
    if !verify_valid_pin_unlock(
        &mut operation_engine, ad, persistent_wallet, display, i2c, sd, delay, watchdog_feed,
    ) {
        cleanup_qa_storage(persistent_wallet, ad);
        return fail_runtime(NAME, "valid PIN unlock path failed");
    }
    if persistent_wallet.workflow_reset_qa_storage(ad).is_err() {
        return fail_runtime(NAME, "QA persistent-storage cleanup failed");
    }
    log!("KASSIGNER_WORKFLOW_RUNTIME: PERSISTENT PIN QA STORAGE ROUND-TRIP PASS");
    log!("KASSIGNER_WORKFLOW_RUNTIME: ACTION PASS {}", NAME);
    true
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn prepare_persistent_pin_fixture(
    ad: &mut AppData,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    if persistent_wallet.workflow_reset_qa_storage(ad).is_err() { return false; }
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad) { return false; }

    crate::runtime::core_s3::enter_credential_watchdog_budget();
    watchdog_feed();
    let save = persistent_wallet.save_with_credential(
        crate::services::persistent_wallet::CredentialKind::Pin,
        PIN_KDF_PASSWORD,
        &ad.wallet.seeds.seed_mgr,
        true,
        &mut |_| watchdog_feed(),
    );
    crate::runtime::core_s3::leave_credential_watchdog_budget();
    watchdog_feed();
    if save.is_err() { return false; }

    ad.wallet.seeds.seed_mgr.zeroize_all();
    crate::services::wallet_session::clear_active_wallet(ad);
    if !super::super::reset_tranche_to_home(ad) {
        return false;
    }
    if !crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageUnlockPin)) {
        return false;
    }
    render_runtime(ad, display, i2c, sd, delay, watchdog_feed);
    true
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn service_credential_operation(
    operation_engine: &mut crate::runtime::event_loop::operation_engine::OperationEngineState,
    ad: &mut AppData,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    for _ in 0..90_000u32 {
        crate::runtime::event_loop::operation_engine::service(
            operation_engine, ad, persistent_wallet, display, delay, i2c, watchdog_feed,
        );
        if crate::runtime::presentation::operation_kind(ad).is_none() {
            return true;
        }
        watchdog_feed();
        delay.delay_millis(1);
    }
    false
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn verify_invalid_pin_retry(
    operation_engine: &mut crate::runtime::event_loop::operation_engine::OperationEngineState,
    ad: &mut AppData,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    if !submit_pin_via_controller(ad, display, b"654321", watchdog_feed) { return false; }
    if crate::runtime::presentation::take_ready_operation(ad).is_some() { return false; }
    render_runtime(ad, display, i2c, sd, delay, watchdog_feed);
    if !service_credential_operation(
        operation_engine, ad, persistent_wallet, display, i2c, delay, watchdog_feed,
    ) { return false; }
    if ad.navigation.app.state != AppState::StorageUnlockPin { return false; }
    if ad.storage.persistence.unlock_feedback != crate::runtime::data::UnlockFeedback::WrongPin {
        return false;
    }
    if ad.wallet.seeds.seed_loaded { return false; }
    render_runtime(ad, display, i2c, sd, delay, watchdog_feed);
    log!("KASSIGNER_WORKFLOW_RUNTIME: PERSISTENT PIN INVALID RETRY PASS");
    true
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn verify_valid_pin_unlock(
    operation_engine: &mut crate::runtime::event_loop::operation_engine::OperationEngineState,
    ad: &mut AppData,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    delay.delay_millis(2100);
    watchdog_feed();
    if !submit_pin_via_controller(ad, display, PIN_KDF_PASSWORD, watchdog_feed) { return false; }
    if crate::runtime::presentation::take_ready_operation(ad).is_some() { return false; }
    render_runtime(ad, display, i2c, sd, delay, watchdog_feed);
    if !service_credential_operation(
        operation_engine, ad, persistent_wallet, display, i2c, delay, watchdog_feed,
    ) { return false; }
    if ad.navigation.app.state != AppState::MainMenu { return false; }
    if !ad.wallet.seeds.seed_loaded { return false; }
    render_runtime(ad, display, i2c, sd, delay, watchdog_feed);
    true
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
fn cleanup_qa_storage(
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    ad: &mut AppData,
) {
    let _ = persistent_wallet.workflow_reset_qa_storage(ad);
}
