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
// Screen redraw — multisig states.
use super::display;
pub(super) fn redraw(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        crate::runtime::input::AppState::MultisigMenu => {
                    boot_display.update_menu_content("MULTISIG", &ad.navigation.multisig_menu);
                }
// ─── Multisig Creation Redraws ────────────
                crate::runtime::input::AppState::MultisigChooseMN => {
                    boot_display.draw_multisig_choose_mn(ad.signing.multisig.threshold, ad.signing.multisig.participant_count);
                }
        crate::runtime::input::AppState::MultisigAddKey { key_idx } => {
                    let can_choose_wallet = ad.wallet.seeds.seed_mgr.find_free().is_some()
                        || ad.wallet.seeds.seed_mgr.slots.iter().enumerate()
                            .any(|(index, _)| ad.wallet.seeds.seed_mgr.slot_visible(index));
                    boot_display.draw_multisig_add_key(key_idx, ad.signing.multisig.creating.n, can_choose_wallet);
                }
        crate::runtime::input::AppState::MultisigPickSeed { key_idx } => {
                    boot_display.draw_multisig_pick_seed(key_idx, ad.signing.multisig.creating.n, &ad.wallet.seeds.seed_mgr, ad.signing.multisig.scroll);
                }
        crate::runtime::input::AppState::MultisigShowAddress => {
                    let mut label_buf = [0u8; 8];
                    let label_len = ad.signing.multisig.creating.label(&mut label_buf);
                    let label = core::str::from_utf8(&label_buf[..label_len]).unwrap_or("?-of-?");
                    let script_hash = offline_signer::transaction::sighash::blake2b_hash(
                        &ad.signing.multisig.creating.script[..ad.signing.multisig.creating.script_len]);
                    let mut addr_buf = [0u8; offline_signer::address::MAX_ADDR_LEN];
                    let addr = offline_signer::address::encode_address_str_for_network(
                        &script_hash,
                        offline_signer::address::AddressType::P2sh,
                        ad.wallet.seeds.seed_mgr.network().kaspa_network(),
                        &mut addr_buf,
                    );
                    boot_display.draw_multisig_result(label, addr,
                        ad.signing.multisig.creating.addr_index,
                        ad.signing.multisig.creating.v45.then_some((
                            ad.signing.multisig.creating.cosigner_index,
                            ad.signing.multisig.creating.chain,
                        )));
                }
        crate::runtime::input::AppState::MultisigShowAddressQR => {
                    if ad.signing.multisig.creating.active && ad.signing.multisig.creating.script_len > 0 {
                        // Live flow: derive address from ms_creating script
                        let script_hash = offline_signer::transaction::sighash::blake2b_hash(
                            &ad.signing.multisig.creating.script[..ad.signing.multisig.creating.script_len]);
                        let mut addr_buf = [0u8; offline_signer::address::MAX_ADDR_LEN];
                        let addr_len = offline_signer::address::encode_address_for_network(
                            &script_hash,
                            offline_signer::address::AddressType::P2sh,
                            ad.wallet.seeds.seed_mgr.network().kaspa_network(),
                            &mut addr_buf,
                        );
                        boot_display.draw_qr_fullscreen(&addr_buf[..addr_len]);
                    } else if ad.qr.outgoing.length > 0 {
                        // SD-loaded flow: address already in QR outgoing buffer
                        boot_display.draw_qr_fullscreen(
                            &ad.qr.outgoing.buffer[..ad.qr.outgoing.length]);
                    } else {
                        boot_display.draw_error_back_screen("No address to display");
                    }
                }
        crate::runtime::input::AppState::MultisigDescriptor => {
                    let mut label_buf = [0u8; 8];
                    let label_len = ad.signing.multisig.creating.label(&mut label_buf);
                    let label = core::str::from_utf8(&label_buf[..label_len]).unwrap_or("?-of-?");
                    // Build x-only views of each cosigner parent pubkey for the
                    // descriptor screen (which renders them truncated for
                    // fingerprint recognition). Strip the 0x02/0x03 parity
                    // prefix — callers only display visible bytes, not do crypto.
                    let mut xonly = [[0u8; 32]; offline_signer::transaction::model::MAX_MULTISIG_KEYS];
                    for i in 0..ad.signing.multisig.creating.n as usize {
                        xonly[i].copy_from_slice(&ad.signing.multisig.creating.cosigner_pubkeys[i][1..33]);
                    }
                    boot_display.draw_multisig_descriptor(
                        ad.signing.multisig.creating.n,
                        &xonly[..ad.signing.multisig.creating.n as usize],
                        label,
                    );
                }
        crate::runtime::input::AppState::MultisigSaveAddrAsk => {
                    boot_display.draw_yes_no_ask(
                        "SAVE ADDRESS?",
                        "Save the multisig address",
                        "to SD card?",
                    );
                }
        _ => return false,
    }
    true
}
