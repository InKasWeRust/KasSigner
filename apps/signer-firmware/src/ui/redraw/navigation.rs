// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Screen redraw — root/production navigation states.

mod developer;
mod production;

use super::{battery, display};
use crate::runtime::input::AppState;

pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> bool {
    if production::redraw(ad, boot_display) || developer::redraw(ad, boot_display) { return true; }
    match ad.navigation.app.state {
        AppState::MainMenu => redraw_home(ad, boot_display, i2c),
        AppState::Rejected => boot_display.draw_rejected_screen("TX Cancelled"),
        AppState::About => boot_display.draw_about_screen(),
        #[cfg(feature = "developer-ui")]
        AppState::DiagnosticInfo => boot_display.draw_diagnostic_info(),
        _ => return false,
    }
    true
}

fn redraw_home(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    let _ = &mut *i2c;
    ad.signing.multisig.creating.n = 0;
    let title = match ad.wallet.seeds.seed_mgr.network() {
        crate::wallet::seed_manager::WalletNetwork::Mainnet => "HOME",
        crate::wallet::seed_manager::WalletNetwork::Testnet10 => "Test-10",
        crate::wallet::seed_manager::WalletNetwork::Testnet12 => "Test-12",
    };
    boot_display.draw_home_grid(title);
    if let Some(batt) = battery::read_battery!(i2c) {
        boot_display.draw_battery_icon(batt.percentage, batt.state == battery::ChargeState::Charging);
    }
}
