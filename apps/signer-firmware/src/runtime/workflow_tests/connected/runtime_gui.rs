//! Non-destructive CoreS3 runtime-HIL probes for production GUI paths.
//!
//! These probes deliberately render real screens and invoke the production
//! display/camera/derivation/KDF paths that controller-only workflow E2E used to bypass.
//! No SD destructive write and no eFuse operation is performed here. The real
//! production CoreS3 watchdog is armed immediately before these probes.
mod firmware;

use crate::{
    hw::{camera::CameraStatus, display::BootDisplay, sdcard::SdCardType},
    runtime::{self, data::AppData, input::AppState, interactions::TouchInput},
};
use esp_hal::{Blocking, delay::Delay, dma::DmaRxBuf, i2c::master::I2c, lcd_cam::cam::Camera};
const KDF_PASSWORD: &[u8] = b"CorrectHorse9";
const KDF_SALT: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const KDF_EXPECTED: [u8; 32] = [
    0x0d, 0xf6, 0xba, 0x64, 0xd9, 0x61, 0x9f, 0x69,
    0x93, 0x75, 0x18, 0x32, 0x15, 0x13, 0x14, 0xe9,
    0x0c, 0xb1, 0x4a, 0x0d, 0x22, 0x1b, 0xcc, 0x83,
    0x4c, 0x5a, 0x8d, 0x21, 0x12, 0xa1, 0xac, 0x77,
];
const PIN_KDF_PASSWORD: &[u8] = b"123456";
const PIN_KDF_EXPECTED: [u8; 32] = [
    0xd4, 0xa1, 0x6b, 0xc0, 0xef, 0xc4, 0x37, 0x30,
    0x94, 0xaf, 0x96, 0x5d, 0x45, 0x41, 0x2b, 0xd8,
    0x4e, 0x76, 0xf6, 0x10, 0xa5, 0xfa, 0xc9, 0xd4,
    0xed, 0x16, 0x03, 0x1a, 0x24, 0x41, 0x07, 0x1b,
];
fn begin(name: &str) { log!("KASSIGNER_WORKFLOW_RUNTIME: ACTION BEGIN {}", name); }
fn pass(name: &str) { log!("KASSIGNER_WORKFLOW_RUNTIME: ACTION PASS {}", name); }
fn fail(name: &str, why: &str) -> bool {
    log!("KASSIGNER_WORKFLOW_RUNTIME: ACTION FAIL {}: {}", name, why);
    false
}
fn render(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) {
    super::redraw_step(ad, display, i2c, sd);
    super::show_step(delay);
    // Equivalent to a completed production frame: feed only after redraw and
    // its bounded dwell have returned successfully.
    watchdog_feed();
}

fn open_root(ad: &mut AppData, tile: usize, expected: AppState) -> bool {
    crate::runtime::effects::home(ad);
    let Some(zone) = crate::ui::layout::HOME_GRID_ZONES.get(tile) else { return false; };
    runtime::interactions::menu::handle_root_touch(ad, zone.x + zone.w / 2, zone.y + zone.h / 2)
        && ad.navigation.app.state == expected
        && crate::runtime::navigation::reconcile(ad)
}

fn open_view_words(ad: &mut AppData) -> bool {
    open_root(ad, 2, AppState::SeedsMenu)
        && runtime::interactions::menu::primary::workflow_wallet_select(ad, 1)
        && ad.navigation.app.state == AppState::WalletBackupMethodsMenu
        && runtime::interactions::menu::primary::workflow_wallet_backup_methods_select(ad, 0)
        && ad.navigation.app.state == (AppState::SeedBackup { word_idx: 0 })
        && crate::runtime::navigation::reconcile(ad)
}

fn open_advanced(ad: &mut AppData) -> bool {
    if !open_root(ad, 3, AppState::SettingsMenu) { return false; }
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    ad.navigation.settings_menu.reset();
    let page_down = TouchInput::new(down.x + down.w / 2, down.y + down.h / 2, false);
    if runtime::interactions::settings::handle_settings_menu_navigation(ad, &list, &up, &down, page_down) != Some(true)
        || ad.navigation.settings_menu.scroll != 4
    {
        return false;
    }
    let zone = list[0];
    let advanced = TouchInput::new(zone.x + zone.w / 2, zone.y + zone.h / 2, false);
    runtime::interactions::settings::handle_settings_menu_navigation(ad, &list, &up, &down, advanced) == Some(true)
        && ad.navigation.app.state == AppState::AdvancedMenu
        && crate::runtime::navigation::reconcile(ad)
}

fn open_receive(ad: &mut AppData) -> bool {
    open_root(ad, 2, AppState::SeedsMenu)
        && runtime::interactions::menu::primary::workflow_wallet_select(ad, 0)
        && ad.navigation.app.state == AppState::ShowAddress
        && crate::runtime::navigation::reconcile(ad)
}

fn open_multisig(ad: &mut AppData) -> bool {
    open_root(ad, 2, AppState::SeedsMenu)
        && runtime::interactions::menu::primary::workflow_wallet_select(ad, 4)
        && ad.navigation.app.state == AppState::MultisigMenu
        && crate::runtime::navigation::reconcile(ad)
}

fn probe_view_words(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "view-words-render";
    begin(NAME);
    if !open_view_words(ad) {
        return fail(NAME, "production Wallet -> Backup & Recovery -> View Words route rejected");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}


fn probe_pop_it(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "pop-it-prompt-render";
    begin(NAME);
    if !open_advanced(ad) {
        return fail(NAME, "production Home -> Settings -> Advanced route rejected");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    if crate::runtime::navigation::production::pop_it_available() {
        if !runtime::interactions::menu::primary::workflow_advanced_select(ad, 3)
            || ad.navigation.app.state != AppState::PopItPrompt
        {
            return fail(NAME, "Pop It route rejected");
        }
    } else {
        // Render the production warning surface even on an already-fused test
        // device. Never advance to explanation/confirmation or burn eFuses.
        crate::runtime::interactions::settings::advanced::workflow::enter_pop_it(ad);
        if ad.navigation.app.state != AppState::PopItPrompt {
            return fail(NAME, "safe prompt adapter route rejected");
        }
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}

fn probe_receive_change(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "receive-change-real-derivation";
    begin(NAME);
    ad.wallet.addresses.pubkeys_cached = false;
    if !open_receive(ad) {
        return fail(NAME, "production Home -> Receive route rejected");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    if !crate::runtime::event_loop::runner::workflow_drive_address_cache(ad, watchdog_feed) {
        return fail(NAME, "address cache did not complete");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let toggled = runtime::interactions::export::handle_export_touch(
        runtime::interactions::export::ExportTouchContext {
            ad,
            boot_display: display,
            delay,
            liveness: watchdog_feed,
            i2c,
            sd_card_type: sd,
            list_zones: &list,
            page_up_zone: &up,
            page_down_zone: &down,
            input: {
                let (x, y) = crate::ui::layout::zone_center(crate::ui::layout::ADDRESS_CHAIN_ZONE);
                crate::runtime::touch_dispatch::physical_touch_input(x, y)
            },
        },
    );
    if toggled != Some(true) || !ad.wallet.addresses.view_is_change {
        return fail(NAME, "Change toggle rejected");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}

fn probe_connect_kassee(
    ad: &mut AppData, display: &mut BootDisplay<'_>, i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>, delay: &mut Delay, watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "connect-kassee-real-derivation";
    begin(NAME);
    if !open_root(ad, 0, AppState::SeedsMenu) { return fail(NAME, "production Home -> Connect KasSee route rejected"); }
    // One physical loading render is the authoritative Queued -> Presented boundary.
    // Do not redraw the one-shot presentation before the operation engine has
    // advanced it into Running; production input dispatch follows the same order.
    render(ad, display, i2c, sd, delay, watchdog_feed);
    if !crate::runtime::presentation::operation_active(ad, crate::runtime::data::OperationKind::ConnectKasSee)
    { return fail(NAME, "production Connect KasSee request did not enter loading"); }
    if !crate::runtime::event_loop::runner::workflow_drive_connect_kassee(ad, display, delay, watchdog_feed) {
        return fail(NAME, "production Connect KasSee derivation did not complete");
    }
    if ad.navigation.app.state != AppState::ExportKpub || ad.export.kpub_len == 0 {
        return fail(NAME, "Connect KasSee did not commit the account-key export state");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}

fn probe_multisig_kpub(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "multisig-kpub-real-derivation";
    begin(NAME);
    if !open_multisig(ad) {
        return fail(NAME, "production Home -> Wallet -> Multisig route rejected");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    if !runtime::interactions::export::prepare_multisig_kpub_qr(ad, display, delay, watchdog_feed)
        || !crate::runtime::presentation::operation_active(
            ad, crate::runtime::data::OperationKind::DeriveMultisigKpub,
        )
    {
        return fail(NAME, "production request did not enter loading");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    if !crate::runtime::event_loop::runner::workflow_drive_multisig_kpub(
        ad, display, delay, watchdog_feed,
    ) {
        return fail(NAME, "cooperative derivation did not complete");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}

fn probe_pin_unlock_order(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "pin-unlock-loading-order";
    begin(NAME);
    crate::runtime::effects::home(ad);
    if !crate::runtime::effects::route(
        ad, crate::runtime::navigation::route!(StorageUnlockPin),
    ) {
        return fail(NAME, "production persistent-wallet PIN route rejected");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    ad.wallet.seeds.pp_input.reset();
    for digit in PIN_KDF_PASSWORD {
        ad.wallet.seeds.pp_input.push_char(*digit);
    }
    crate::runtime::event_loop::runner::sync_watchdog_budget(ad);
    watchdog_feed();
    if crate::runtime::interactions::persistence::workflow_handle_unlock_touch(
        crate::runtime::interactions::TouchInput::new(260, 211, false), ad, display,
    ) != Some(true) {
        return fail(NAME, "production PIN-pad submit did not commit loading operation");
    }
    if crate::runtime::presentation::take_ready_operation(ad).is_some() {
        return fail(NAME, "credential operation became runnable before loading render");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    let operation = crate::runtime::data::OperationKind::UnlockWalletPin;
    if crate::runtime::presentation::take_ready_operation(ad) != Some(operation) {
        return fail(NAME, "credential operation was not runnable after loading render");
    }
    watchdog_feed();
    let result = crate::services::memory::password_kdf::derive_key_32(
        offline_signer::crypto::password_kdf::PasswordKdfPurpose::PersistentWallet,
        PIN_KDF_PASSWORD,
        &KDF_SALT,
    );
    watchdog_feed();
    let Ok(mut key) = result else {
        return fail(NAME, "production PIN Argon2id KDF failed");
    };
    let kat_ok = key == PIN_KDF_EXPECTED;
    shared_signer::bytes::zeroize_bytes(&mut key);
    if !crate::runtime::presentation::execution_done(ad, operation, kat_ok) || !kat_ok {
        return fail(NAME, "PIN KDF known-answer mismatch");
    }
    ad.wallet.seeds.pp_input.reset();
    if !crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MainMenu)) {
        return fail(NAME, "successful credential result could not commit Home");
    }
    if !crate::runtime::presentation::credential_result_committed(
        ad, operation, "success MainMenu",
    ) {
        return fail(NAME, "credential result commit ordering rejected");
    }
    crate::runtime::presentation::finish_success(ad);
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}

fn probe_recoverable_operation_timeout(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    const NAME: &str = "recoverable-operation-timeout";
    begin(NAME);
    crate::runtime::effects::home(ad);
    let stable = ad.navigation.committed_state;
    let kind = crate::runtime::data::OperationKind::ConnectKasSee;
    if !crate::runtime::presentation::start_operation(ad, kind) {
        return fail(NAME, "could not queue cooperative operation");
    }
    crate::runtime::event_loop::operation_engine::workflow_inject_timeout(ad, kind);
    match ad.presentation.modal {
        crate::runtime::data::ModalState::RecoverableError { code, return_to, .. }
            if code == "OP-TIMEOUT-01" && return_to == stable => {}
        _ => return fail(NAME, "timeout did not install recoverable modal"),
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    let (x, y) = crate::ui::layout::zone_center(crate::ui::layout::ERROR_OK_ZONE);
    if !crate::runtime::presentation::handle_tap(ad, x, y)
        || ad.presentation.modal != crate::runtime::data::ModalState::None
        || ad.navigation.committed_state != stable
    {
        return fail(NAME, "recoverable timeout OK did not return to stable screen");
    }
    render(ad, display, i2c, sd, delay, watchdog_feed);
    pass(NAME);
    true
}

fn probe_argon2(watchdog_feed: &mut impl FnMut()) -> bool {
    const NAME: &str = "argon2-persistent-wallet-kdf";
    begin(NAME);
    watchdog_feed();
    let result = crate::services::memory::password_kdf::derive_key_32(
        offline_signer::crypto::password_kdf::PasswordKdfPurpose::PersistentWallet,
        KDF_PASSWORD,
        &KDF_SALT,
    );
    watchdog_feed();
    let Ok(mut key) = result else {
        return fail(NAME, "production Argon2id KDF failed");
    };
    let kat_ok = key == KDF_EXPECTED;
    shared_signer::bytes::zeroize_bytes(&mut key);
    if !kat_ok {
        return fail(NAME, "known-answer mismatch");
    }
    pass(NAME);
    true
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
    camera: &mut Option<Camera<'_>>,
    camera_dma: &mut Option<DmaRxBuf>,
    camera_status: &mut CameraStatus,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad) {
        return fail("fixture", "mnemonic install failed");
    }

    // First acknowledgement arms the same 30-second TIMG0 production watchdog.
    // From this point onward, a blocked GUI/KDF operation resets the device and
    // the host runner rejects the repeated boot marker instead of accepting PASS.
    watchdog_feed();
    log!("KASSIGNER_WORKFLOW_RUNTIME: PRODUCTION WATCHDOG ARMED");

    if !probe_view_words(ad, display, i2c, sd, delay, watchdog_feed)
        || !firmware::probe_firmware_update_guidance(ad, display, i2c, sd, delay, watchdog_feed)
        || !firmware::probe_scan_qr_camera(
            ad, display, i2c, sd, delay, camera, camera_dma, camera_status, watchdog_feed,
        )
        || !probe_pop_it(ad, display, i2c, sd, delay, watchdog_feed)
        || !probe_receive_change(ad, display, i2c, sd, delay, watchdog_feed)
        || !probe_connect_kassee(ad, display, i2c, sd, delay, watchdog_feed)
        || !probe_multisig_kpub(ad, display, i2c, sd, delay, watchdog_feed)
        || !probe_pin_unlock_order(ad, display, i2c, sd, delay, watchdog_feed)
        || !super::onboarding::persistent_pin_round_trip(
            ad, persistent_wallet, display, i2c, sd, delay, watchdog_feed,
        )
        || !probe_recoverable_operation_timeout(ad, display, i2c, sd, delay, watchdog_feed)
        || !probe_argon2(watchdog_feed)
    {
        return false;
    }

    crate::runtime::effects::home(ad);
    watchdog_feed();
    log!("KASSIGNER_WORKFLOW_RUNTIME: NONDESTRUCTIVE GUI PROBES PASS");
    true
}
