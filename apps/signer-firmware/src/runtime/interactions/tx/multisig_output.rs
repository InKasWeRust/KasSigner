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
// tx controller — multisig output workflow.
use super::{AppData, RedrawFlag};
use crate::runtime::input::AppState;

fn build_multisig_descriptor(ad: &mut AppData) {
    let config = &ad.signing.multisig.creating;
    let mut pos = 0usize;
    let prefix: &[u8] = if config.v45 { b"multi_hd45(" } else { b"multi_hd(" };
    if prefix.len() >= ad.qr.outgoing.buffer.len() { ad.qr.outgoing.length = 0; return; }
    ad.qr.outgoing.buffer[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    ad.qr.outgoing.buffer[pos] = b'0' + config.m;
    pos += 1;
    for index in 0..config.n as usize {
        if pos >= ad.qr.outgoing.buffer.len() { ad.qr.outgoing.length = 0; return; }
        ad.qr.outgoing.buffer[pos] = b',';
        pos += 1;
        if config.v45 {
            let parts = offline_signer::derivation::xpub::KpubParts {
                depth: config.cosigner_depth[index],
                parent_fp: config.cosigner_parent_fp[index],
                child_num: config.cosigner_child_num[index],
                chain_code: config.cosigner_chain_codes[index],
                pubkey: config.cosigner_pubkeys[index],
            };
            let written = offline_signer::derivation::xpub::serialize_legacy_kpub_parts(
                &parts, &mut ad.qr.outgoing.buffer[pos..],
            );
            if written != offline_signer::derivation::xpub::LEGACY_KPUB_LEN {
                ad.qr.outgoing.length = 0;
                return;
            }
            pos += written;
        } else {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for &byte in config.cosigner_pubkeys[index].iter().chain(config.cosigner_chain_codes[index].iter()) {
                if pos + 1 >= ad.qr.outgoing.buffer.len() { ad.qr.outgoing.length = 0; return; }
                ad.qr.outgoing.buffer[pos] = HEX[(byte >> 4) as usize];
                ad.qr.outgoing.buffer[pos + 1] = HEX[(byte & 0x0f) as usize];
                pos += 2;
            }
        }
    }
    if pos >= ad.qr.outgoing.buffer.len() { ad.qr.outgoing.length = 0; return; }
    ad.qr.outgoing.buffer[pos] = b')';
    ad.qr.outgoing.length = pos + 1;
}


pub(super) fn handle(
    ad: &mut AppData,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    let redraw = match ad.navigation.app.state {
        AppState::MultisigShowAddress => handle_address(ad, x, y, is_back),
        AppState::MultisigShowAddressQR => handle_address_qr(ad),
        AppState::MultisigSaveAddrAsk => handle_save_prompt(ad, i2c, delay, x, y, is_back),
        AppState::MultisigDescriptor => handle_descriptor(ad, i2c, delay, x, y, is_back),
        _ => return None,
    };
    let mut flag = RedrawFlag::default();
    flag.set(redraw);
    Some(flag.value())
}

fn handle_address(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        let route = if ad.signing.multisig.creating.active {
            crate::runtime::navigation::route!(MultisigDescriptor)
        } else {
            crate::runtime::navigation::route!(SdImportMenu)
        };
        crate::runtime::effects::route(ad, route);
        return true;
    }
    if y < 195 {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigShowAddressQR));
        return true;
    }
    if ad.signing.multisig.creating.v45 && (62..=110).contains(&x) {
        let count = ad.signing.multisig.creating.n;
        if count > 0 {
            ad.signing.multisig.creating.cosigner_index =
                (ad.signing.multisig.creating.cosigner_index + 1) % count;
            rebuild_and_persist(ad);
        }
    } else if ad.signing.multisig.creating.v45 && (118..=158).contains(&x) {
        ad.signing.multisig.creating.chain ^= 1;
        rebuild_and_persist(ad);
    } else if ad.signing.multisig.creating.v45 && (166..=250).contains(&x) {
        open_index_picker(ad);
    } else if x <= 90 {
        change_address_index(ad, -1);
    } else if x >= 230 {
        change_address_index(ad, 1);
    } else {
        open_index_picker(ad);
    }
    true
}

fn change_address_index(ad: &mut AppData, direction: i32) {
    let current = ad.signing.multisig.creating.addr_index;
    let next = if direction < 0 {
        current.saturating_sub(1)
    } else {
        current.saturating_add(1).min(u32::from(u16::MAX))
    };
    if next == current {
        return;
    }
    ad.signing.multisig.creating.addr_index = next;
    rebuild_and_persist(ad);
}

fn open_index_picker(ad: &mut AppData) {
    ad.wallet.addresses.input_len = 0;
    ad.signing.multisig.picking_key = 255;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AddrIndexPicker));
}

fn rebuild_and_persist(ad: &mut AppData) {
    ad.signing.multisig.creating.build_script();
    crate::runtime::interactions::multisig_config::persist_creating_config(ad);
}


fn handle_address_qr(ad: &mut AppData) -> bool {
    let route = if ad.signing.multisig.creating.active {
        crate::runtime::navigation::route!(MultisigSaveAddrAsk)
    } else {
        crate::runtime::navigation::route!(SdImportMenu)
    };
    crate::runtime::effects::route(ad, route);
    true
}

fn handle_save_prompt(
    ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigShowAddress));
        return true;
    }
    if (30..=155).contains(&x) && (140..=185).contains(&y) {
        prepare_address_export(ad);
        prepare_filename(ad, i2c, delay, b"MS", crate::runtime::navigation::route!(SdMsAddrFilename));
        return true;
    }
    if (165..=290).contains(&x) && (140..=185).contains(&y) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigDescriptor));
        return true;
    }
    false
}

fn prepare_address_export(ad: &mut AppData) {
    let script = &ad.signing.multisig.creating.script[..ad.signing.multisig.creating.script_len];
    let script_hash = offline_signer::transaction::sighash::blake2b_hash(script);
    let mut address = [0u8; offline_signer::address::MAX_ADDR_LEN];
    let length = offline_signer::address::encode_address_for_network(
        &script_hash,
        offline_signer::address::AddressType::P2sh,
        ad.wallet.seeds.seed_mgr.network().kaspa_network(),
        &mut address,
    );
    ad.export.kpub_data[..length].copy_from_slice(&address[..length]);
    ad.export.kpub_len = length;
}

fn handle_descriptor(
    ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        let route = if ad.signing.multisig.creating.active {
            crate::runtime::navigation::route!(MultisigShowAddress)
        } else {
            crate::runtime::navigation::route!(SdImportMenu)
        };
        crate::runtime::effects::route(ad, route);
        return true;
    }
    if !(190..=230).contains(&y) {
        return false;
    }
    if (170..=310).contains(&x) {
        build_multisig_descriptor(ad);
        prepare_filename(ad, i2c, delay, b"MD", crate::runtime::navigation::route!(SdMsDescFilename));
        return true;
    }
    if (10..=150).contains(&x) {
        build_multisig_descriptor(ad);
        ad.qr.outgoing.frame_count = 0;
        ad.qr.outgoing.frame = 0;
        ad.qr.outgoing.manual_frames = false;
        ad.qr.outgoing.close_state = Some(crate::runtime::navigation::continuation!(MultisigDescriptor));
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQR));
        return true;
    }
    false
}

fn prepare_filename(
    ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    prefix: &[u8; 2],
    next_route: crate::runtime::navigation::UiRoute,
) {
    let next = crate::runtime::interactions::sd::scan_auto_increment(i2c, delay, prefix, b"TXT");
    let name = crate::runtime::interactions::sd::format_auto_name(prefix, next, b"TXT");
    ad.storage.export_file.filename = name;
    ad.wallet.seeds.pp_input.reset();
    for &byte in name.iter().take(8).filter(|byte| **byte != b' ') {
        ad.wallet.seeds.pp_input.push_char(byte);
    }
    crate::runtime::effects::route(ad, next_route);
}
