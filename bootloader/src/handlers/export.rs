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

// handlers/export.rs — Touch handlers for export/display states
//
// Covers: SeedBackup, ShowAddress, ShowAddressQR, AddrIndexPicker,
//         ExportSeedQR, ExportCompactSeedQR, SeedQrGrid,
//         ExportKpub, ExportXprv, ExportChoice, ExportPrivKey

use crate::log;
use crate::{app::data::AppData, hw::display, hw::sdcard, ui::seed_manager, hw::touch, wallet};
use crate::app::signing::derive_pubkey_from_acct;
/// Handle touch events for export/display screens (address, QR, kpub, xprv).
#[inline(never)]
#[allow(unused_assignments)]
pub fn handle_export_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    bb_card_type: &Option<sdcard::SdCardType>,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::SeedBackup { word_idx } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SeedList;
                        } else {
                            let next = word_idx + 1;
                            if next < ad.word_count {
                                ad.app.state = crate::app::input::AppState::SeedBackup { word_idx: next };
                            } else {
                                ad.app.state = crate::app::input::AppState::SeedList;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowAddress => {
                        let is_single_addr = ad.word_count == 1; // raw key = one address only
                        if is_back {
                            ad.scanned_addr_len = 0;
                            ad.app.go_main_menu();
                        } else if !is_single_addr && ad.scanned_addr_len == 0 && (10..=60).contains(&x) && y >= 210 {
                            // Bottom [<] button — previous address index
                            if ad.current_addr_index > 0 {
                                ad.current_addr_index -= 1;
                                if ad.current_addr_index >= 20 && ad.extra_pubkey_index != ad.current_addr_index {
                                    derive_pubkey_from_acct(&ad.acct_key_raw,
                                        ad.current_addr_index, &mut ad.extra_pubkey);
                                    ad.extra_pubkey_index = ad.current_addr_index;
                                }
                            }
                        } else if !is_single_addr && ad.scanned_addr_len == 0 && (260..=310).contains(&x) && y >= 210 {
                            // Bottom [>] button — next address index (no upper limit)
                            ad.current_addr_index += 1;
                            if ad.current_addr_index >= 20 && ad.extra_pubkey_index != ad.current_addr_index {
                                derive_pubkey_from_acct(&ad.acct_key_raw,
                                    ad.current_addr_index, &mut ad.extra_pubkey);
                                ad.extra_pubkey_index = ad.current_addr_index;
                            }
                        } else if !is_single_addr && ad.scanned_addr_len == 0 && (110..=210).contains(&x) && y >= 210 {
                            // Bottom [#N] button — open index picker
                            ad.addr_input_len = 0;
                            ad.app.state = crate::app::input::AppState::AddrIndexPicker;
                        } else if (40..210).contains(&y) {
                            // Tap address area → show QR
                            ad.app.state = crate::app::input::AppState::ShowAddressQR;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowAddressQR => {
                        // Tap → back to text address view
                        ad.app.state = crate::app::input::AppState::ShowAddress;
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::AddrIndexPicker => {
                        if is_back {
                            if ad.ms_picking_key == 255 {
                                // Sentinel: back to multisig wallet address view
                                ad.ms_picking_key = 0;
                                ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                            } else if ad.ms_picking_key > 0 {
                                let ki = ad.ms_picking_key - 1;
                                ad.ms_picking_key = 0;
                                ad.app.state = crate::app::input::AppState::MultisigPickAddr { key_idx: ki };
                            } else {
                                ad.app.state = crate::app::input::AppState::ShowAddress;
                            }
                        } else {
                            // Keypad grid: 3 cols x 4 rows
                            // Col: 55..120, 130..195, 205..270
                            // Row: 76..106, 110..140, 144..174, 178..208
                            let col = if (55..120).contains(&x) { Some(0u8) }
                                else if (130..195).contains(&x) { Some(1) }
                                else if (205..270).contains(&x) { Some(2) }
                                else { None };
                            let row = if (76..106).contains(&y) { Some(0u8) }
                                else if (110..140).contains(&y) { Some(1) }
                                else if (144..174).contains(&y) { Some(2) }
                                else if (178..208).contains(&y) { Some(3) }
                                else { None };
                            if let (Some(c), Some(r)) = (col, row) {
                                let idx = r * 3 + c;
                                match idx {
                                    0..=8 => {
                                        // Digits 1-9
                                        if ad.addr_input_len < 5 {
                                            ad.addr_input_buf[ad.addr_input_len as usize] = b'1' + idx;
                                            ad.addr_input_len += 1;
                                        }
                                    }
                                    10 => {
                                        // Digit 0
                                        if ad.addr_input_len < 5 {
                                            ad.addr_input_buf[ad.addr_input_len as usize] = b'0';
                                            ad.addr_input_len += 1;
                                        }
                                    }
                                    9 => {
                                        // CLR — clear input
                                        ad.addr_input_len = 0;
                                    }
                                    11 => {
                                        // GO — parse and navigate
                                        if ad.addr_input_len > 0 {
                                            let mut val: u16 = 0;
                                            for i in 0..ad.addr_input_len as usize {
                                                val = val * 10 + (ad.addr_input_buf[i] - b'0') as u16;
                                            }
                                            ad.addr_input_len = 0;
                                            // Sentinel: 255 → picker came from
                                            // MultisigShowAddress wanting to
                                            // set ms_creating.addr_index (HD
                                            // multisig per-address derivation).
                                            if ad.ms_picking_key == 255 {
                                                ad.ms_picking_key = 0;
                                                ad.ms_creating.addr_index = val as u32;
                                                ad.ms_creating.build_script();
                                                // Mirror into stored config so
                                                // re-entry shows the same index.
                                                for i in 0..crate::wallet::transaction::MAX_MULTISIG_WALLETS {
                                                    if ad.ms_store.configs[i].active
                                                        && ad.ms_store.configs[i].m == ad.ms_creating.m
                                                        && ad.ms_store.configs[i].n == ad.ms_creating.n
                                                        && ad.ms_store.configs[i].cosigner_pubkeys
                                                            == ad.ms_creating.cosigner_pubkeys
                                                    {
                                                        ad.ms_store.configs[i] = ad.ms_creating.clone();
                                                        break;
                                                    }
                                                }
                                                ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                                            } else {
                                                ad.current_addr_index = val;
                                                if ad.current_addr_index >= 20 && ad.extra_pubkey_index != ad.current_addr_index {
                                                    derive_pubkey_from_acct(&ad.acct_key_raw,
                                                        ad.current_addr_index, &mut ad.extra_pubkey);
                                                    ad.extra_pubkey_index = ad.current_addr_index;
                                                }
                                                if ad.ms_picking_key > 0 {
                                                    let ki = ad.ms_picking_key - 1;
                                                    ad.ms_picking_key = 0;
                                                    ad.app.state = crate::app::input::AppState::MultisigPickAddr { key_idx: ki };
                                                } else {
                                                    ad.app.state = crate::app::input::AppState::ShowAddress;
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportSeedQR => {
                        // Tap → enter zoomed grid view (standard)
                        ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x: 0, pan_y: 0, compact: false };
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportCompactSeedQR => {
                        // Tap → enter zoomed grid view (compact)
                        ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x: 0, pan_y: 0, compact: true };
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SeedQrGrid { pan_x, pan_y, compact } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            // Get actual QR size by encoding
                            let qr_size: u8 = if let Some(slot) = ad.seed_mgr.active_slot() {
                                if compact {
                                    let mut buf = [0u8; 32];
                                    let len = seed_manager::encode_compact_seedqr(
                                        &slot.indices, slot.word_count, &mut buf);
                                    if let Ok(qr) = crate::qr::encoder::encode(&buf[..len]) {
                                        qr.size
                                    } else { 21 }
                                } else {
                                    let mut buf = [0u8; 96];
                                    let len = seed_manager::encode_seedqr(
                                        &slot.indices, slot.word_count, &mut buf);
                                    if let Ok(qr) = crate::qr::encoder::encode(&buf[..len]) {
                                        qr.size
                                    } else { 29 }
                                }
                            } else { 21 };
                            let view_cells: u8 = 7;
                            let max_pan = qr_size.saturating_sub(view_cells);
                            let step: u8 = 1; // pan 1 cell per tap

                            // Left strip — horizontal pan
                            if x < 55 && (50..130).contains(&y) {
                                // Top left triangle = pan left (<)
                                if pan_x >= step {
                                    ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x: pan_x - step, pan_y, compact };
                                } else if pan_x > 0 {
                                    ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x: 0, pan_y, compact };
                                }
                            }
                            else if x < 55 && (130..200).contains(&y) {
                                // Bottom left triangle = pan right (>)
                                let new_x = (pan_x + step).min(max_pan);
                                if new_x != pan_x {
                                    ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x: new_x, pan_y, compact };
                                }
                            }
                            // Right strip — vertical pan
                            else if x > 265 && (50..130).contains(&y) {
                                // Top right triangle = pan up (^)
                                if pan_y >= step {
                                    ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x, pan_y: pan_y - step, compact };
                                } else if pan_y > 0 {
                                    ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x, pan_y: 0, compact };
                                }
                            }
                            else if x > 265 && (130..200).contains(&y) {
                                // Bottom right triangle = pan down (v)
                                let new_y = (pan_y + step).min(max_pan);
                                if new_y != pan_y {
                                    ad.app.state = crate::app::input::AppState::SeedQrGrid { pan_x, pan_y: new_y, compact };
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportKpub => {
                        if is_back {
                            ad.kpub_nframes = 0;
                            ad.kpub_user_nframes = 0;
                            ad.kpub_frame = 0;
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if ad.kpub_user_nframes == 1 {
                            // Single frame: tap anywhere → popup (save/back)
                            ad.app.state = crate::app::input::AppState::ExportKpubPopup;
                        } else if ad.kpub_manual_frames {
                            // Manual: tap anywhere advances, past last → popup
                            if ad.kpub_frame + 1 >= ad.kpub_nframes {
                                ad.kpub_frame = 0;
                                ad.app.state = crate::app::input::AppState::ExportKpubPopup;
                            } else {
                                ad.kpub_frame += 1;
                            }
                        } else {
                            // Auto: tap anywhere → popup
                            ad.kpub_frame = 0;
                            ad.app.state = crate::app::input::AppState::ExportKpubPopup;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportKpubFrameCount => {
                        if is_back {
                            ad.kpub_nframes = 0;
                            ad.kpub_user_nframes = 0;
                            ad.kpub_frame = 0;
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if x < 160 {
                            // Left: Single (1 frame — full kpub in one QR)
                            ad.kpub_user_nframes = 1;
                            ad.app.state = crate::app::input::AppState::ExportKpub;
                        } else {
                            // Right: Multi-frame (4 frames — large modules)
                            ad.kpub_user_nframes = 4;
                            ad.app.state = crate::app::input::AppState::ExportKpub;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportKpubModeChoice => {
                        if is_back {
                            ad.kpub_nframes = 0;
                            ad.kpub_user_nframes = 0;
                            ad.kpub_frame = 0;
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if x < 160 {
                            // Left button: Auto Cycle
                            ad.kpub_manual_frames = false;
                            ad.kpub_frame = 0;
                            ad.app.state = crate::app::input::AppState::ExportKpub;
                        } else {
                            // Right button: Manual
                            ad.kpub_manual_frames = true;
                            ad.kpub_frame = 0;
                            ad.app.state = crate::app::input::AppState::ExportKpub;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::KpubScannedPopup => {
                        if is_back {
                            ad.app.go_main_menu();
                        } else if x < 160 {
                            // Left button: Show QR
                            ad.kpub_frame = 0;
                            ad.kpub_nframes = 0;
                            ad.kpub_user_nframes = 0;
                            ad.app.state = crate::app::input::AppState::ExportKpub;
                        } else {
                            // Right button: Save to SD
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SdKpubFilename;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportKpubPopup => {
                        if is_back {
                            ad.kpub_nframes = 0;
                            ad.kpub_user_nframes = 0;
                            ad.kpub_frame = 0;
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            // "Save to SD" button — left
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                let next = crate::handlers::sd::scan_auto_increment(i2c, delay, b"KP", b"TXT");
                                let name = crate::handlers::sd::format_auto_name(b"KP", next, b"TXT");
                                ad.kspt_filename = name;
                                ad.pp_input.reset();
                                for j in 0..8usize {
                                    if name[j] != b' ' {
                                        ad.pp_input.push_char(name[j]);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::SdKpubFilename;
                            }
                            // "Back to QR" button — right
                            else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                ad.kpub_frame = 0;
                                ad.app.state = crate::app::input::AppState::ExportKpub;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportXprv => {
                        // Tap anywhere to dismiss — zeroize xprv buffer
                        for b in ad.xprv_data.iter_mut() {
                            unsafe { core::ptr::write_volatile(b as *mut u8, 0); }
                        }
                        ad.xprv_len = 0;
                        ad.app.state = crate::app::input::AppState::SeedList;
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportChoice => {
                        if is_back {
                            ad.export_menu.reset();
                            ad.app.state = crate::app::input::AppState::SeedList;
                        } else if page_up_zone.contains(x, y) && ad.export_menu.can_page_up() {
                            ad.export_menu.page_up();
                        } else if page_down_zone.contains(x, y) && ad.export_menu.can_page_down() {
                            ad.export_menu.page_down();
                        } else {
                            // Check list item taps
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.export_menu.visible_to_absolute(slot);
                                    if abs < ad.export_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                match item {
                                    0 => { ad.app.state = crate::app::input::AppState::SeedBackup { word_idx: 0 }; }
                                    1 => {
                                        // QR Export sub-menu
                                        ad.qr_export_menu.reset();
                                        ad.app.state = crate::app::input::AppState::QrExportMenu;
                                    }
                                    2 => {
                                        // JPEG Stego Export
                                        ad.stego_mode_idx = 0;
                                        let active = ad.seed_mgr.active_slot();
                                        let has_seed = matches!(active, Some(s) if !s.is_empty());
                                        if !has_seed {
                                            boot_display.draw_rejected_screen("No seed loaded");
                                            delay.delay_millis(1500);
                                        } else if bb_card_type.is_none() {
                                            boot_display.draw_rejected_screen("No SD card");
                                            delay.delay_millis(1500);
                                        } else {
                                            ad.stego_auto_scan = true;
                                            ad.app.state = crate::app::input::AppState::StegoModeSelect;
                                        }
                                    }
                                    3 => {
                                        // kpub QR (multi-frame)
                                        ad.kpub_nframes = 0;
                            ad.kpub_user_nframes = 0;
                                        ad.kpub_frame = 0;
                                        boot_display.draw_saving_screen("Deriving kpub...");
                                        let pp = ad.seed_mgr.active_slot().map(|s: &seed_manager::SeedSlot| s.passphrase_str()).unwrap_or("");
                                        let seed_bytes = if ad.word_count == 12 {
                                            let m12 = wallet::bip39::Mnemonic12 {
                                                indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&ad.mnemonic_indices[..12]); arr }
                                            };
                                            wallet::bip39::seed_from_mnemonic_12(&m12, pp)
                                        } else {
                                            let m24 = wallet::bip39::Mnemonic24 {
                                                indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&ad.mnemonic_indices[..24]); arr }
                                            };
                                            wallet::bip39::seed_from_mnemonic_24(&m24, pp)
                                        };
                                        let mut kpub_buf = [0u8; wallet::xpub::KPUB_MAX_LEN];
                                        match wallet::xpub::derive_and_serialize_kpub(&seed_bytes.bytes, &mut kpub_buf) {
                                            Ok(len) => {
                                                ad.kpub_len = len;
                                                ad.kpub_data[..len].copy_from_slice(&kpub_buf[..len]);
                                                ad.app.state = crate::app::input::AppState::ExportKpub;
                                            }
                                            Err(_) => {
                                                boot_display.draw_rejected_screen("kpub derivation failed");
                                                delay.delay_millis(2000);
                                            }
                                        }
                                    }
                                    4 => {
                                        // kpub to SD card — derive first, then ask for filename
                                        if bb_card_type.is_none() {
                                            boot_display.draw_rejected_screen("No SD card");
                                            delay.delay_millis(1500);
                                        } else {
                                            boot_display.draw_saving_screen("Deriving kpub...");
                                            let pp = ad.seed_mgr.active_slot().map(|s: &seed_manager::SeedSlot| s.passphrase_str()).unwrap_or("");
                                            let seed_bytes = if ad.word_count == 12 {
                                                let m12 = wallet::bip39::Mnemonic12 {
                                                    indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&ad.mnemonic_indices[..12]); arr }
                                                };
                                                wallet::bip39::seed_from_mnemonic_12(&m12, pp)
                                            } else {
                                                let m24 = wallet::bip39::Mnemonic24 {
                                                    indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&ad.mnemonic_indices[..24]); arr }
                                                };
                                                wallet::bip39::seed_from_mnemonic_24(&m24, pp)
                                            };
                                            let mut kpub_buf = [0u8; wallet::xpub::KPUB_MAX_LEN];
                                            match wallet::xpub::derive_and_serialize_kpub(&seed_bytes.bytes, &mut kpub_buf) {
                                                Ok(len) => {
                                                    ad.kpub_len = len;
                                                    ad.kpub_data[..len].copy_from_slice(&kpub_buf[..len]);
                                                    ad.pp_input.reset();
                                                    ad.app.state = crate::app::input::AppState::SdKpubFilename;
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("kpub derivation failed");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                    }
                                    5 => {
                                        // xprv Account submenu
                                        ad.xprv_export_menu.reset();
                                        ad.app.state = crate::app::input::AppState::XprvExportMenu;
                                    }
                                    6 => {
                                        if bb_card_type.is_some() {
                                            ad.app.state = crate::app::input::AppState::SdBackupWarning;
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card");
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    7 => {
                                        // Private Key — derivation index picker
                                        ad.addr_input_len = 0;
                                        ad.app.state = crate::app::input::AppState::ExportPrivKeyIndex;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::QrExportMenu => {
                        if is_back {
                            ad.qr_export_menu.reset();
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if page_up_zone.contains(x, y) && ad.qr_export_menu.can_page_up() {
                            ad.qr_export_menu.page_up();
                        } else if page_down_zone.contains(x, y) && ad.qr_export_menu.can_page_down() {
                            ad.qr_export_menu.page_down();
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.qr_export_menu.visible_to_absolute(slot);
                                    if abs < ad.qr_export_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                match item {
                                    0 => { ad.app.state = crate::app::input::AppState::ExportCompactSeedQR; }
                                    1 => { ad.app.state = crate::app::input::AppState::ExportSeedQR; }
                                    2 => {
                                        // Plain Words QR — only for 12-word seeds (24w exceeds QR capacity)
                                        if ad.word_count <= 12 {
                                            ad.app.state = crate::app::input::AppState::ExportPlainWordsQR;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::XprvExportMenu => {
                        if is_back {
                            ad.xprv_export_menu.reset();
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if page_up_zone.contains(x, y) && ad.xprv_export_menu.can_page_up() {
                            ad.xprv_export_menu.page_up();
                        } else if page_down_zone.contains(x, y) && ad.xprv_export_menu.can_page_down() {
                            ad.xprv_export_menu.page_down();
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.xprv_export_menu.visible_to_absolute(slot);
                                    if abs < ad.xprv_export_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                match item {
                                    0 => {
                                        // Show as QR
                                        boot_display.draw_saving_screen("Deriving xprv...");
                                        let pp = ad.seed_mgr.active_slot().map(|s: &seed_manager::SeedSlot| s.passphrase_str()).unwrap_or("");
                                        let seed_bytes = if ad.word_count == 12 {
                                            let m12 = wallet::bip39::Mnemonic12 {
                                                indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&ad.mnemonic_indices[..12]); arr }
                                            };
                                            wallet::bip39::seed_from_mnemonic_12(&m12, pp)
                                        } else {
                                            let m24 = wallet::bip39::Mnemonic24 {
                                                indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&ad.mnemonic_indices[..24]); arr }
                                            };
                                            wallet::bip39::seed_from_mnemonic_24(&m24, pp)
                                        };
                                        let mut xprv_buf = [0u8; wallet::xpub::XPRV_MAX_LEN];
                                        match wallet::xpub::derive_and_serialize_xprv(&seed_bytes.bytes, &mut xprv_buf) {
                                            Ok(len) => {
                                                ad.xprv_len = len;
                                                ad.xprv_data[..len].copy_from_slice(&xprv_buf[..len]);
                                                ad.app.state = crate::app::input::AppState::ExportXprv;
                                            }
                                            Err(_) => {
                                                boot_display.draw_rejected_screen("xprv derivation failed");
                                                delay.delay_millis(2000);
                                            }
                                        }
                                    }
                                    1 => {
                                        // Encrypt to SD — filename keyboard first
                                        if bb_card_type.is_some() {
                                            let next = crate::handlers::sd::scan_auto_increment(i2c, delay, b"XP", b"KAS");
                                            let name = crate::handlers::sd::format_auto_name(b"XP", next, b"KAS");
                                            ad.kspt_filename = name;
                                            ad.pp_input.reset();
                                            for j in 0..8usize {
                                                if name[j] != b' ' {
                                                    ad.pp_input.push_char(name[j]);
                                                }
                                            }
                                            ad.app.state = crate::app::input::AppState::SdXprvFilename;
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card");
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportPlainWordsQR => {
                        // Any tap → back to QR export menu
                        if is_back {
                            ad.app.state = crate::app::input::AppState::QrExportMenu;
                        } else {
                            ad.app.state = crate::app::input::AppState::QrExportMenu;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportPrivKeyIndex => {
                        if is_back {
                            ad.addr_input_len = 0;
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            // Same keypad grid as AddrIndexPicker
                            let col = if (55..120).contains(&x) { Some(0u8) }
                                else if (130..195).contains(&x) { Some(1) }
                                else if (205..270).contains(&x) { Some(2) }
                                else { None };
                            let row = if (76..106).contains(&y) { Some(0u8) }
                                else if (110..140).contains(&y) { Some(1) }
                                else if (144..174).contains(&y) { Some(2) }
                                else if (178..208).contains(&y) { Some(3) }
                                else { None };
                            if let (Some(c), Some(r)) = (col, row) {
                                let idx = r * 3 + c;
                                match idx {
                                    0..=8 => {
                                        if ad.addr_input_len < 5 {
                                            ad.addr_input_buf[ad.addr_input_len as usize] = b'1' + idx;
                                            ad.addr_input_len += 1;
                                        }
                                    }
                                    10 => {
                                        if ad.addr_input_len < 5 {
                                            ad.addr_input_buf[ad.addr_input_len as usize] = b'0';
                                            ad.addr_input_len += 1;
                                        }
                                    }
                                    9 => { ad.addr_input_len = 0; } // CLR
                                    11 => {
                                        // GO — derive private key for this address index
                                        if ad.addr_input_len > 0 {
                                            let mut val: u16 = 0;
                                            for i in 0..ad.addr_input_len as usize {
                                                val = val * 10 + (ad.addr_input_buf[i] - b'0') as u16;
                                            }
                                            ad.addr_input_len = 0;
                                            boot_display.draw_saving_screen("Deriving key...");

                                            let pp = ad.seed_mgr.active_slot().map(|s| s.passphrase_str()).unwrap_or("");
                                            let seed_bytes = if ad.word_count == 12 {
                                                let m12 = wallet::bip39::Mnemonic12 {
                                                    indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&ad.mnemonic_indices[..12]); arr }
                                                };
                                                wallet::bip39::seed_from_mnemonic_12(&m12, pp)
                                            } else {
                                                let m24 = wallet::bip39::Mnemonic24 {
                                                    indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&ad.mnemonic_indices[..24]); arr }
                                                };
                                                wallet::bip39::seed_from_mnemonic_24(&m24, pp)
                                            };

                                            match wallet::bip32::derive_account_key(&seed_bytes.bytes) {
                                                Ok(acct) => {
                                                    match wallet::bip32::derive_address_key(&acct, val) {
                                                        Ok(addr_key) => {
                                                            let privkey = addr_key.private_key_bytes();
                                                            const HX: &[u8; 16] = b"0123456789abcdef";
                                                            for i in 0..32 {
                                                                ad.export_key_hex[i * 2] = HX[(privkey[i] >> 4) as usize];
                                                                ad.export_key_hex[i * 2 + 1] = HX[(privkey[i] & 0x0f) as usize];
                                                            }
                                                            ad.app.state = crate::app::input::AppState::ExportPrivKey;
                                                        }
                                                        Err(_) => {
                                                            boot_display.draw_rejected_screen("Key derivation failed");
                                                            delay.delay_millis(2000);
                                                        }
                                                    }
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("Account key failed");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ExportPrivKey => {
                        // Tap or back → zeroize and exit
                        for b in ad.export_key_hex.iter_mut() {
                            unsafe { core::ptr::write_volatile(b as *mut u8, 0); }
                        }
                        ad.app.state = crate::app::input::AppState::ExportChoice;
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}

// ─── Multi-frame kpub QR auto-cycling ───

/// Auto-cycle the kpub QR display frames (same protocol as signed QR).
pub fn cycle_kpub_qr(
    ad: &mut crate::app::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
) {
    if let crate::app::input::AppState::ExportKpub = ad.app.state {
        if ad.kpub_nframes > 1 && !ad.kpub_manual_frames {
            // Only advance frame every ~2000 idle ticks
            if ad.idle_ticks % 2000 != 0 {
                return;
            }
            ad.kpub_frame = (ad.kpub_frame + 1) % ad.kpub_nframes;
            // Balanced split: equal-sized frames
            let n = ad.kpub_nframes as usize;
            let balanced = (ad.kpub_len + n - 1) / n;
            let offset = ad.kpub_frame as usize * balanced;
            let remaining = ad.kpub_len.saturating_sub(offset);
            let frag_len = remaining.min(balanced);
            if frag_len > 0 {
                let mut frame_buf = [0u8; 134];
                frame_buf[0] = ad.kpub_frame;
                frame_buf[1] = ad.kpub_nframes;
                frame_buf[2] = frag_len as u8;
                frame_buf[3..3 + frag_len]
                    .copy_from_slice(&ad.kpub_data[offset..offset + frag_len]);
                let qr_len = if frag_len < 20 { 3 + 20 } else { 3 + frag_len };
                boot_display.draw_qr_screen(&frame_buf[..qr_len]);
                let mut fc_buf: heapless::String<16> = heapless::String::new();
                core::fmt::Write::write_fmt(&mut fc_buf,
                    format_args!("kpub {}/{}", ad.kpub_frame + 1, ad.kpub_nframes)).ok();
                boot_display.draw_frame_counter(&fc_buf);
            }
        }
    }
}
