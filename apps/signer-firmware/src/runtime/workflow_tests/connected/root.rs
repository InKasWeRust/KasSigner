use core::sync::atomic::{AtomicU16, Ordering};
use crate::runtime::input::AppState;

pub(super) static FAILURE_MASK: AtomicU16 = AtomicU16::new(0);
pub(super) static WALLET_BACKUP_FAILURE_MASK: AtomicU16 = AtomicU16::new(0);

pub(super) fn exercise(
    ad: &mut crate::runtime::data::AppData,
    display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd: &Option<crate::hw::sdcard::SdCardType>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    FAILURE_MASK.store(0, Ordering::Relaxed);
    WALLET_BACKUP_FAILURE_MASK.store(0, Ordering::Relaxed);
    const EXPECTED: [AppState; 4] = [
        AppState::SeedsMenu,
        AppState::ScanQR,
        AppState::SeedsMenu,
        AppState::SettingsMenu,
    ];

    log!("KASSIGNER_WORKFLOW_TESTS: APP STATE INIT OK (static internal RAM)");
    log!("KASSIGNER_WORKFLOW_TESTS: SCREEN HOME");
    super::redraw_step(ad, display, i2c, sd);
    super::show_step(delay);

    if crate::runtime::interactions::menu::handle_connected_root_probe(ad, 160, 132) {
        log!("KASSIGNER_WORKFLOW_TESTS: HOME OUTSIDE-TILE FAIL");
        return false;
    }
    if ad.navigation.app.state != AppState::MainMenu {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: HOME OUTSIDE-TILE NOOP OK");

    // Home -> Connect KasSee is intentionally guarded by `seed_loaded`. The
    // connected catalog starts from a fresh AppData, so install the same
    // volatile workflow wallet used by later wallet/signing probes before
    // exercising that guarded production root action.
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: ROOT CONNECT WALLET FIXTURE FAIL");
        return false;
    }

    for (index, (zone, expected)) in crate::ui::layout::HOME_GRID_ZONES.iter().zip(EXPECTED).enumerate() {
        log!("KASSIGNER_WORKFLOW_TESTS: ROOT TILE {} BEGIN", index);
        if !crate::runtime::interactions::menu::handle_connected_root_probe(
            ad, zone.x + zone.w / 2, zone.y + zone.h / 2,
        ) {
            return false;
        }
        if ad.navigation.app.state != expected || !crate::runtime::navigation::reconcile(ad) {
            return false;
        }
        log!("KASSIGNER_WORKFLOW_TESTS: ROOT TILE {} ROUTE OK", index);
        super::redraw_step(ad, display, i2c, sd);
        log!("KASSIGNER_WORKFLOW_TESTS: SCREEN {:?}", expected);
        super::show_step(delay);
        log!("KASSIGNER_WORKFLOW_TESTS: ROOT TILE {} DWELL OK", index);

        let returned_home = match index {
            0 => connect_kassee_from_home(ad),
            2 => wallet_and_backup(ad, display, i2c, sd, delay),
            3 => super::settings::exercise(ad, display, i2c, sd, delay),
            _ => return_home(ad),
        };
        if !returned_home { FAILURE_MASK.fetch_or(1u16 << index, Ordering::Relaxed); return false; }

        log!("KASSIGNER_WORKFLOW_TESTS: ROOT TILE {} HOME ROUTE OK", index);
        super::redraw_step(ad, display, i2c, sd);
        log!("KASSIGNER_WORKFLOW_TESTS: SCREEN HOME RETURN {}", index);
        super::show_step(delay);
    }
    log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED HOME/ROOT PASS");
    true
}

fn wallet_and_backup(
    ad: &mut crate::runtime::data::AppData,
    display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd: &Option<crate::hw::sdcard::SdCardType>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    let wallet_ok = super::wallet::exercise(ad, display, i2c, sd, delay);
    if !wallet_ok {
        log!("KASSIGNER_WORKFLOW_TESTS: WALLET MANAGEMENT FAILED; RECOVERING HOME FOR BACKUP VIA AUTHORITATIVE SCENARIO RESET");
    }
    let home_ready = super::reset_tranche_to_home(ad);
    let backup_ok = home_ready && super::backup::exercise(ad, display, i2c, sd, delay);
    let mut failure_mask = 0u16;
    if !wallet_ok { failure_mask |= 1u16 << 0; }
    if !backup_ok { failure_mask |= 1u16 << 1; }
    WALLET_BACKUP_FAILURE_MASK.store(failure_mask, Ordering::Relaxed);
    wallet_ok && backup_ok
}

fn return_home(ad: &mut crate::runtime::data::AppData) -> bool {
    crate::runtime::effects::home(ad);
    home_ok(ad)
}

pub(super) fn home_ok(ad: &mut crate::runtime::data::AppData) -> bool {
    ad.navigation.app.state == AppState::MainMenu && crate::runtime::navigation::reconcile(ad)
}

fn connect_kassee_from_home(ad: &mut crate::runtime::data::AppData) -> bool {
    if ad.navigation.app.state != AppState::SeedsMenu
        || !crate::runtime::presentation::operation_active(ad, crate::runtime::data::OperationKind::ConnectKasSee)
    {
        return false;
    }
    crate::runtime::effects::home(ad);
    home_ok(ad)
        && !crate::runtime::presentation::operation_active(
            ad,
            crate::runtime::data::OperationKind::ConnectKasSee,
        )
}
