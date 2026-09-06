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
// Screen redraw — export states.
use super::{display, seed_manager};
use signer_firmware_core::presentation::render::{AddressRenderInput, address_render_model};
fn draw_kpub_export(
    ad: &crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    if ad.export.kpub_len == 0 {
        boot_display.draw_tx_error_screen("Account key unavailable", "Wallet key could not be derived");
        return;
    }
    let mut payload = [0u8; offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN];
    if offline_signer::derivation::xpub::decode_kpub_compatible(
        &ad.export.kpub_data[..ad.export.kpub_len],
        &mut payload,
    )
    .is_err()
    {
        boot_display.draw_error_back_screen("Account key format error");
        return;
    }
    let mut envelope = [0u8; 1 + offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN];
    envelope[0] = kassigner_protocol::wire::qr_payload::PAYLOAD_V1_RAW;
    envelope[1..].copy_from_slice(&payload);
    boot_display.draw_kpub_qr_screen(&envelope);
}

fn address_model(ad: &crate::runtime::data::AppData) -> Option<signer_firmware_core::presentation::render::AddressRenderModel> {
    let raw_key = matches!(
        ad.wallet.seeds.active_source,
        crate::wallet::seed_manager::WalletSource::RawPrivateKey
    );
    address_render_model(AddressRenderInput {
        receive_cache: &ad.wallet.addresses.pubkey_cache,
        change_cache: &ad.wallet.addresses.change_pubkey_cache,
        extra_receive: ad.wallet.addresses.extra_pubkey,
        extra_receive_index: ad.wallet.addresses.extra_pubkey_index,
        extra_change: ad.wallet.addresses.extra_change_pubkey,
        extra_change_index: ad.wallet.addresses.extra_change_pubkey_index,
        current_index: ad.wallet.addresses.current_addr_index,
        is_change: ad.wallet.addresses.view_is_change,
        raw_key,
        partial_redraw: ad.wallet.addresses.partial_redraw,
    })
}

fn draw_address(ad: &mut crate::runtime::data::AppData, boot_display: &mut display::BootDisplay<'_>) {
    if ad.qr.scan.address_length == 0 && !ad.wallet.addresses.pubkeys_cached {
        boot_display.draw_saving_screen("Deriving addresses...");
        #[cfg(feature = "m5stack")]
        boot_display.update_progress_bar(ad.wallet.addresses.cache_progress);
        ad.wallet.addresses.partial_redraw = false;
        return;
    }
    if ad.qr.scan.address_length > 0 {
        let addr = core::str::from_utf8(&ad.qr.scan.address[..ad.qr.scan.address_length])
            .unwrap_or("(invalid)");
        boot_display.draw_address_screen(addr, ad.qr.scan.address_valid, None, None, false);
        return;
    }
    let Some(model) = address_model(ad) else {
        boot_display.draw_error_back_screen("Address key unavailable");
        ad.wallet.addresses.partial_redraw = false;
        return;
    };
    let mut address_buffer = [0u8; offline_signer::address::MAX_ADDR_LEN];
    let address = offline_signer::address::encode_address_str_for_network(
        &model.public_key,
        offline_signer::address::AddressType::P2pk,
        ad.wallet.seeds.seed_mgr.network().kaspa_network(),
        &mut address_buffer,
    );
    if model.partial_update {
        boot_display.update_address_content(
            address,
            model.index.unwrap_or(0),
            model.is_change,
        );
        ad.wallet.addresses.partial_redraw = false;
    } else {
        boot_display.draw_address_screen(address, true, model.index, None, model.is_change);
    }
}

fn draw_address_qr(ad: &crate::runtime::data::AppData, boot_display: &mut display::BootDisplay<'_>) {
    if ad.qr.scan.address_length == 0 && !ad.wallet.addresses.pubkeys_cached {
        boot_display.draw_saving_screen("Deriving addresses...");
        #[cfg(feature = "m5stack")]
        boot_display.update_progress_bar(ad.wallet.addresses.cache_progress);
        return;
    }
    let Some(model) = address_model(ad) else {
        boot_display.draw_error_back_screen("Address key unavailable");
        return;
    };
    let mut address_buffer = [0u8; offline_signer::address::MAX_ADDR_LEN];
    let length = offline_signer::address::encode_address_for_network(
        &model.public_key,
        offline_signer::address::AddressType::P2pk,
        ad.wallet.seeds.seed_mgr.network().kaspa_network(),
        &mut address_buffer,
    );
    boot_display.draw_qr_screen(&address_buffer[..length]);
}

mod account_keys;
mod addresses;
mod menus;
mod seed_qr;

pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    seed_qr::redraw(ad, boot_display)
        || menus::redraw(ad, boot_display)
        || account_keys::redraw(ad, boot_display)
        || addresses::redraw(ad, boot_display)
}
