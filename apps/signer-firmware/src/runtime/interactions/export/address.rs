// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Address display and derivation-index navigation.

use crate::runtime::input::AppState;
use crate::runtime::signing::{derive_change_pubkey_from_acct, derive_pubkey_from_acct};
use crate::{hw::display, runtime::data::AppData};

use super::index_keypad::{self, IndexKey};


pub(super) fn handle_pure(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::ShowAddress => Some(handle_address_view(ad, x, y, is_back)),
        AppState::ShowAddressQR => Some(if is_back { crate::runtime::effects::back(ad) } else { false }),
        _ => None,
    }
}

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let redraw = match ad.navigation.app.state {
        AppState::ShowAddress => handle_address_view(ad, x, y, is_back),
        AppState::ShowAddressQR => if is_back { crate::runtime::effects::back(ad) } else { false },
        AppState::AddrIndexPicker => handle_index_picker(ad, boot_display, x, y, is_back),
        _ => return None,
    };
    Some(redraw)
}


fn handle_address_view(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        ad.qr.scan.address_length = 0;
        ad.wallet.addresses.view_is_change = false;
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::Address);
        return true;
    }

    // Do not let taps race the cooperative key cache. The loading screen stays
    // responsive to Back, while Change/QR/index actions become available only
    // after the real production cache is complete.
    if ad.qr.scan.address_length == 0 && !ad.wallet.addresses.pubkeys_cached {
        return false;
    }

    let is_single_address = matches!(
        ad.wallet.seeds.active_source,
        crate::wallet::seed_manager::WalletSource::RawPrivateKey
    );
    let address_loaded = ad.qr.scan.address_length != 0;
    if !is_single_address && !address_loaded {
        if address_toolbar_tap(ad, x, y) { return true; }
        if address_index_tap(ad, x, y) { return true; }
    }
    if (40..176).contains(&y) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowAddressQR));
        return true;
    }
    false
}

fn address_toolbar_tap(ad: &mut AppData, x: u16, y: u16) -> bool {
    if crate::ui::layout::ADDRESS_CHAIN_ZONE.contains(x, y) {
        ad.wallet.addresses.view_is_change = !ad.wallet.addresses.view_is_change;
        ad.wallet.addresses.current_addr_index = 0;
        refresh_extended_pubkey(ad);
        return true;
    }
    if crate::ui::layout::ADDRESS_QR_ZONE.contains(x, y) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowAddressQR));
        return true;
    }
    false
}

fn address_index_tap(ad: &mut AppData, x: u16, y: u16) -> bool {
    if crate::ui::layout::ADDRESS_PREV_ZONE.contains(x, y) { return step_address_index(ad, -1); }
    if crate::ui::layout::ADDRESS_NEXT_ZONE.contains(x, y) { return step_address_index(ad, 1); }
    if crate::ui::layout::ADDRESS_INDEX_ZONE.contains(x, y) {
        ad.wallet.addresses.input_len = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AddrIndexPicker));
        return true;
    }
    false
}

fn step_address_index(ad: &mut AppData, delta: i32) -> bool {
    let current = ad.wallet.addresses.current_addr_index;
    if delta < 0 && current == 0 {
        return false;
    }
    ad.wallet.addresses.current_addr_index = if delta < 0 {
        current - 1
    } else {
        current.saturating_add(1)
    };
    refresh_extended_pubkey(ad);
    ad.wallet.addresses.partial_redraw = true;
    true
}

fn refresh_extended_pubkey(ad: &mut AppData) {
    let index = ad.wallet.addresses.current_addr_index;
    if ad.wallet.addresses.view_is_change {
        if index >= 5 && ad.wallet.addresses.extra_change_pubkey_index != index {
            if derive_change_pubkey_from_acct(
                &ad.wallet.keys.acct_key_raw,
                index,
                &mut ad.wallet.addresses.extra_change_pubkey,
            ).is_ok() {
                ad.wallet.addresses.extra_change_pubkey_index = index;
            }
        }
    } else if index >= 20 && ad.wallet.addresses.extra_pubkey_index != index {
        if derive_pubkey_from_acct(
            &ad.wallet.keys.acct_key_raw,
            index,
            &mut ad.wallet.addresses.extra_pubkey,
        ).is_ok() {
            ad.wallet.addresses.extra_pubkey_index = index;
        }
    }
}

fn handle_index_picker(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        leave_index_picker(ad);
        return true;
    }
    let Some(key) = index_keypad::hit(x, y) else {
        return false;
    };
    match key {
        IndexKey::Digit(digit) => append_index_digit(ad, boot_display, digit),
        IndexKey::Clear => clear_index_input(ad, boot_display),
        IndexKey::Submit => return confirm_index(ad),
    }
    false
}

fn append_index_digit(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>, digit: u8) {
    if ad.wallet.addresses.input_len < 5 {
        let index = ad.wallet.addresses.input_len as usize;
        ad.wallet.addresses.input_buf[index] = b'0' + digit;
        ad.wallet.addresses.input_len += 1;
    }
    update_index_display(ad, boot_display);
}

fn clear_index_input(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) {
    ad.wallet.addresses.input_len = 0;
    if crate::runtime::interactions::feedback::physical_presentation_enabled() {
        boot_display.update_addr_index_input("");
    }
}

fn update_index_display(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    if !crate::runtime::interactions::feedback::physical_presentation_enabled() {
        return;
    }
    let end = ad.wallet.addresses.input_len as usize;
    let value = core::str::from_utf8(&ad.wallet.addresses.input_buf[..end]).unwrap_or("");
    boot_display.update_addr_index_input(value);
}

fn confirm_index(ad: &mut AppData) -> bool {
    if ad.wallet.addresses.input_len == 0 {
        return false;
    }
    let Some(value) = parse_index_input(ad) else {
        ad.wallet.addresses.input_len = 0;
        return false;
    };
    ad.wallet.addresses.input_len = 0;
    if ad.signing.multisig.picking_key == 255 {
        apply_multisig_index(ad, value);
    } else {
        ad.wallet.addresses.current_addr_index = value;
        refresh_extended_pubkey(ad);
        ad.signing.multisig.picking_key = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowAddress));
    }
    true
}

fn parse_index_input(ad: &AppData) -> Option<u16> {
    ad.wallet.addresses.input_buf[..ad.wallet.addresses.input_len as usize]
        .iter()
        .try_fold(0u16, |value, digit| {
            value
                .checked_mul(10)?
                .checked_add(u16::from(digit.checked_sub(b'0')?))
        })
}

fn apply_multisig_index(ad: &mut AppData, value: u16) {
    ad.signing.multisig.picking_key = 0;
    ad.signing.multisig.creating.addr_index = u32::from(value);
    ad.signing.multisig.creating.build_script();
    crate::runtime::interactions::multisig_config::persist_creating_config(ad);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigShowAddress));
}

fn leave_index_picker(ad: &mut AppData) {
    let returning_to_multisig = ad.signing.multisig.picking_key == 255;
    ad.signing.multisig.picking_key = 0;
    let route = if returning_to_multisig {
        crate::runtime::navigation::route!(MultisigShowAddress)
    } else {
        crate::runtime::navigation::route!(ShowAddress)
    };
    crate::runtime::effects::route(ad, route);
}
