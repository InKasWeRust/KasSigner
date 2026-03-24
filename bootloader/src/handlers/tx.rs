// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// handlers/tx.rs — Touch handlers for transaction, multisig, and message signing states
//
// Covers: ScanQR, ReviewTx, ConfirmTx, MultisigChooseMN, MultisigAddKey, MultisigShowAddress,
//         SignMsgChoice, SignMsgType, SignMsgFile, SignMsgPreview, SignMsgResult

use crate::{app::data::AppData, hw::display, hw::sdcard, hw::sound, hw::touch, wallet};
use crate::ui::helpers::pp_keyboard_hit;
/// Handle touch events for transaction review, signing, message signing, and multisig screens.
#[inline(never)]
pub fn handle_tx_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    bb_card_type: &Option<sdcard::SdCardType>,
    list_zones: &[touch::TouchZone; 4],
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::SignTxGuide => {
                        if is_back {
                            ad.tools_menu.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else if ad.seed_loaded {
                            // "SCAN PSKT" button: y=194..230, x=60..260
                            if y >= 194 && y <= 230 && x >= 60 && x <= 260 {
                                ad.app.state = crate::app::input::AppState::ScanQR;
                                needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::ScanQR => {
                        // Back button — matches 34x34 icon at (0,0)
                        if x <= 40 && y <= 40 {
                            ad.app.go_main_menu();
                            ad.cam_tune_active = false;
                            needs_redraw = true;
                        } else if ad.cam_tune_active {
                            // Cam-tune screen: buttons y=198..240, slider track y=196..240
                            if y >= 196 && x >= 56 && x <= 264 {
                                // Slider track zone (includes area around thin track)
                                let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                ad.cam_tune_dirty = true;
                                boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                            } else if y >= 196 && x < 54 {
                                // [-] button
                                let p = ad.cam_tune_param as usize;
                                ad.cam_tune_vals[p] = ad.cam_tune_vals[p].saturating_sub(8);
                                ad.cam_tune_dirty = true;
                                boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                            } else if y >= 196 && x > 266 {
                                // [+] button
                                let p = ad.cam_tune_param as usize;
                                ad.cam_tune_vals[p] = ad.cam_tune_vals[p].saturating_add(8);
                                ad.cam_tune_dirty = true;
                                boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                            } else if x >= 200 {
                                // Right panel
                                if y < 34 {
                                    // EXIT → close cam-tune, restore ScanQR chrome
                                    ad.cam_tune_active = false;
                                    // Clear overlay areas and redraw ScanQR chrome directly
                                    // (avoids full redraw_screen cycle which kills touch)
                                    boot_display.clear_screen();
                                    boot_display.draw_camera_screen_chrome();
                                } else if y >= 36 && y < 180 {
                                    // Grid: col split at x=261 (center of 258..262 gap)
                                    let col = if x < 261 { 0u8 } else { 1u8 };
                                    // grid_y0=36, row_step=49 (btn_h=46 + gap=3)
                                    let row = ((y as i32 - 36).max(0) / 49).min(2) as u8;
                                    let idx = row * 2 + col;
                                    if idx < 6 && idx != ad.cam_tune_param {
                                        ad.cam_tune_param = idx;
                                        boot_display.draw_cam_tune_overlay(ad.cam_tune_param, &ad.cam_tune_vals);
                                    }
                                }
                            }
                        } else {
                            // Normal ScanQR — gear icon zone (generous for small target)
                            if x >= 275 && y <= 45 {
                                ad.cam_tune_active = true;
                                // Don't set cam_tune_dirty — values are already applied
                                boot_display.clear_screen();
                                boot_display.draw_cam_tune_overlay(ad.cam_tune_param, &ad.cam_tune_vals);
                            }
                        }
                    }
                    crate::app::input::AppState::ReviewTx { .. } => {
                        if is_back {
                            ad.app.go_main_menu();
                        } else {
                            // Next page
                            let evt = crate::app::input::ButtonEvent::ShortPress;
                            ad.app.handle_boot(evt);
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ConfirmTx => {
                        if is_back {
                            ad.app.go_main_menu();
                        } else {
                            // CONFIRM/SIGN: x=30..290, y=118..170 (covers both layouts)
                            // CANCEL:       x=30..290, y=168..230 (covers both layouts)
                            let in_confirm = x >= 30 && x <= 290 && y >= 118 && y <= 165;
                            let in_cancel  = x >= 30 && x <= 290 && y >= 168 && y <= 230;

                            if in_confirm {
                                ad.app.menu.cursor = 0;
                                let evt = crate::app::input::ButtonEvent::LongPress;
                                ad.app.handle_boot(evt);
                            } else if in_cancel {
                                ad.app.menu.cursor = 1;
                                let evt = crate::app::input::ButtonEvent::LongPress;
                                ad.app.handle_boot(evt);
                            }
                        }
                        needs_redraw = true;
                    }
                    // ─── Multisig Creation Touch Handlers ────────────
                    crate::app::input::AppState::MultisigChooseMN => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            // M-: x=60..110, y=72..110
                            if x >= 60 && x <= 110 && y >= 72 && y <= 110 {
                                if ad.ms_m > 1 { ad.ms_m -= 1; }
                            }
                            // M+: x=210..260, y=72..110
                            else if x >= 210 && x <= 260 && y >= 72 && y <= 110 {
                                if ad.ms_m < 5 { ad.ms_m += 1; }
                            }
                            // N-: x=60..110, y=140..178
                            else if x >= 60 && x <= 110 && y >= 140 && y <= 178 {
                                if ad.ms_n > 1 { ad.ms_n -= 1; }
                            }
                            // N+: x=210..260, y=140..178
                            else if x >= 210 && x <= 260 && y >= 140 && y <= 178 {
                                if ad.ms_n < 5 { ad.ms_n += 1; }
                            }
                            // NEXT: centered, x=80..240, y=190..230
                            else if x >= 80 && x <= 240 && y >= 190 && y <= 230 {
                                if ad.ms_m >= 1 && ad.ms_m <= ad.ms_n && ad.ms_n <= 5 {
                                    ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                    ad.ms_creating.m = ad.ms_m;
                                    ad.ms_creating.n = ad.ms_n;
                                    ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: 0 };
                                }
                            }
                            // Keep M <= N
                            if ad.ms_m > ad.ms_n { ad.ms_m = ad.ms_n; }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigAddKey { key_idx } => {
                        if is_back {
                            if key_idx == 0 {
                                ad.app.state = crate::app::input::AppState::MultisigChooseMN;
                            } else {
                                // Go back one key
                                ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: key_idx - 1 };
                            }
                        } else {
                            // "Scan QR": x=30..290, y=90..135
                            if x >= 30 && x <= 290 && y >= 90 && y <= 135 {
                                // Go to ScanQR state — when a kpub is scanned, it will be
                                // routed back to MultisigAddKey (handled in scan flow below)
                                ad.app.state = crate::app::input::AppState::ScanQR;
                            }
                            // "Use Loaded Seed": x=30..290, y=145..190
                            else if x >= 30 && x <= 290 && y >= 145 && y <= 190 && ad.seed_loaded {
                                ad.ms_scroll = 0;
                                ad.app.state = crate::app::input::AppState::MultisigPickSeed { key_idx };
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigPickSeed { key_idx } => {
                        if is_back {
                            ad.ms_scroll = 0;
                            ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx };
                        } else if x <= 35 {
                            // Left arrow — page up
                            if ad.ms_scroll >= 3 { ad.ms_scroll -= 3; }
                        } else if x >= 285 {
                            // Right arrow — page down
                            let loaded_count = ad.seed_mgr.slots.iter().filter(|s| !s.is_empty()).count() as u8;
                            if ad.ms_scroll + 3 < loaded_count { ad.ms_scroll += 3; }
                        } else {
                            // Seed rows with scroll offset
                            let loaded: heapless::Vec<u8, 16> = ad.seed_mgr.slots.iter().enumerate()
                                .filter(|(_, s)| !s.is_empty())
                                .map(|(i, _)| i as u8)
                                .collect();
                            for vis in 0..3u8 {
                                let list_idx = ad.ms_scroll + vis;
                                let row_y = 46 + vis as u16 * 46;
                                if y >= row_y && y < row_y + 42 && x >= 44 && x <= 276 {
                                    if (list_idx as usize) < loaded.len() {
                                        let slot_idx = loaded[list_idx as usize];
                                        let already_active = (ad.seed_mgr.active == slot_idx)
                                            && ad.pubkeys_cached;

                                        if !already_active {
                                            ad.seed_mgr.activate(slot_idx as usize);
                                            let slot = &ad.seed_mgr.slots[slot_idx as usize];
                                            ad.mnemonic_indices = slot.indices;
                                            ad.word_count = slot.word_count;
                                            ad.seed_loaded = true;
                                            // Derive pubkeys — show progress
                                            boot_display.draw_saving_screen("Deriving addresses...");
                                            boot_display.update_progress_bar(50);
                                            let hw = crate::hw::display::measure_hint("Wait ~30 seconds");
                                            crate::hw::display::draw_lato_hint(
                                                &mut boot_display.display, "Wait ~30 seconds",
                                                (320 - hw) / 2, 170,
                                                crate::hw::display::COLOR_TEXT_DIM);
                                            let pp = slot.passphrase_str();
                                            crate::app::signing::derive_all_pubkeys(
                                                &ad.mnemonic_indices, ad.word_count, pp,
                                                &mut ad.pubkey_cache, &mut ad.acct_key_raw);
                                            ad.pubkeys_cached = true;
                                        }
                                        ad.current_addr_index = 0;
                                        ad.app.state = crate::app::input::AppState::MultisigPickAddr { key_idx };
                                    }
                                    break;
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigPickAddr { key_idx } => {
                        if is_back {
                            ad.ms_scroll = 0;
                            ad.app.state = crate::app::input::AppState::MultisigPickSeed { key_idx };
                        } else if x >= 10 && x <= 60 && y >= 210 {
                            // [<] previous address
                            if ad.current_addr_index > 0 {
                                ad.current_addr_index -= 1;
                                if ad.current_addr_index >= 20 && ad.extra_pubkey_index != ad.current_addr_index {
                                    crate::app::signing::derive_pubkey_from_acct(
                                        &ad.acct_key_raw, ad.current_addr_index, &mut ad.extra_pubkey);
                                    ad.extra_pubkey_index = ad.current_addr_index;
                                }
                            }
                        } else if x >= 260 && x <= 310 && y >= 210 {
                            // [>] next address
                            ad.current_addr_index += 1;
                            if ad.current_addr_index >= 20 && ad.extra_pubkey_index != ad.current_addr_index {
                                crate::app::signing::derive_pubkey_from_acct(
                                    &ad.acct_key_raw, ad.current_addr_index, &mut ad.extra_pubkey);
                                ad.extra_pubkey_index = ad.current_addr_index;
                            }
                        } else if x >= 110 && x <= 210 && y >= 210 {
                            // [#N] — open index picker, then return to MultisigPickAddr
                            ad.addr_input_len = 0;
                            ad.ms_picking_key = key_idx + 1; // +1 so 0 means "not picking"
                            ad.app.state = crate::app::input::AppState::AddrIndexPicker;
                        } else if x >= 95 && x <= 225 && y >= 150 && y < 182 {
                            // SELECT button — store current address pubkey
                            if key_idx < ad.ms_creating.n {
                                let pk = if (ad.current_addr_index as usize) < 20 {
                                    ad.pubkey_cache[ad.current_addr_index as usize]
                                } else if ad.extra_pubkey_index == ad.current_addr_index {
                                    ad.extra_pubkey
                                } else {
                                    [0u8; 32]
                                };
                                ad.ms_creating.pubkeys[key_idx as usize] = pk;
                                let next = key_idx + 1;
                                if next >= ad.ms_creating.n {
                                    ad.ms_creating.build_script();
                                    ad.ms_creating.active = true;
                                    if let Some(ms_slot) = ad.ms_store.find_free() {
                                        ad.ms_store.configs[ms_slot] = ad.ms_creating.clone();
                                    }
                                    ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                                } else {
                                    ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: next };
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigShowAddress => {
                        if is_back {
                            ad.app.go_main_menu();
                        } else {
                            // Tap → show QR
                            ad.app.state = crate::app::input::AppState::MultisigShowAddressQR;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigShowAddressQR => {
                        // Any tap → home
                        ad.app.go_main_menu();
                        needs_redraw = true;
                    }

                    // ─── Sign Message Flow ────────────
                    crate::app::input::AppState::SignMsgChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else if x >= 40 && x < 280 && y >= 68 && y < 112 {
                            // Type manually
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SignMsgType;
                        } else if x >= 40 && x < 280 && y >= 114 && y < 158 {
                            // Load from SD — scan for .TXT files
                            boot_display.draw_loading_screen("Scanning TXT...");
                            boot_display.update_progress_bar(50);
                            delay.delay_millis(50);
                            (ad.txt_file_count) = 0;
                            let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                let fat32 = sdcard::mount_fat32(ct)?;
                                sdcard::list_root_dir_lfn(ct, &fat32, |entry, disp_name, disp_len| {
                                    if !entry.is_dir() && entry.file_size > 0
                                        && entry.file_size <= 1024
                                        && ((ad.txt_file_count) as usize) < 8 {
                                        let ext = &entry.name[8..11];
                                        let first = entry.name[0];
                                        let is_hidden = first == b'.' || first == b'_' || first == 0xE5;
                                        if !is_hidden && (ext == b"TXT" || ext == b"txt") {
                                            let idx = (ad.txt_file_count) as usize;
                                            ad.txt_file_names[idx] = entry.name;
                                            let copy_len = disp_len.min(32);
                                            ad.txt_display_names[idx] = [0u8; 32];
                                            ad.txt_display_names[idx][..copy_len].copy_from_slice(&disp_name[..copy_len]);
                                            ad.txt_display_lens[idx] = copy_len as u8;
                                            (ad.txt_file_count) += 1;
                                        }
                                    }
                                    true
                                })?;
                                Ok(())
                            });
                            if scan_ok.is_err() || (ad.txt_file_count) == 0 {
                                boot_display.draw_rejected_screen("No .TXT files on SD");
                                sound::beep_error(delay);
                                delay.delay_millis(2000);
                            } else {
                                ad.app.state = crate::app::input::AppState::SignMsgFile;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SignMsgType => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); needs_redraw = true; }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "MESSAGE"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "MESSAGE"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "MESSAGE"); }
                                6 => {
                                    // OK — copy text to jpeg_desc_buf (reuse as message buffer)
                                    let msg = ad.pp_input.as_str();
                                    let copy_len = msg.len().min(128);
                                    ad.jpeg_desc_buf[..copy_len].copy_from_slice(&msg.as_bytes()[..copy_len]);
                                    ad.jpeg_desc_len = copy_len;
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::SignMsgPreview;
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SignMsgFile => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                        } else {
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = slot;
                                    if idx < (ad.txt_file_count) {
                                        boot_display.draw_loading_screen("Reading...");
                                        boot_display.update_progress_bar(50);
                                        delay.delay_millis(50);
                                        let fname83 = ad.txt_file_names[idx as usize];
                                        ad.jpeg_desc_len = 0;
                                        let read_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                            let fat32 = sdcard::mount_fat32(ct)?;
                                            let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &fname83)?;
                                            let fsize = entry.file_size as usize;
                                            let cluster = entry.first_cluster();
                                            if cluster < 2 { return Err("Empty file"); }
                                            let sector = fat32.cluster_to_sector(cluster);
                                            let mut sector_buf = [0u8; 512];
                                            sdcard::sd_read_block(ct, sector, &mut sector_buf)?;
                                            let start = if fsize >= 3 && sector_buf[0] == 0xEF && sector_buf[1] == 0xBB && sector_buf[2] == 0xBF { 3 } else { 0 };
                                            let avail = fsize.min(512);
                                            let use_len = (avail - start).min(128);
                                            let mut end = use_len;
                                            while end > 0 && (sector_buf[start + end - 1] == b'\n' || sector_buf[start + end - 1] == b'\r' || sector_buf[start + end - 1] == b' ' || sector_buf[start + end - 1] == 0) {
                                                end -= 1;
                                            }
                                            if end == 0 { return Err("Empty content"); }
                                            ad.jpeg_desc_buf[..end].copy_from_slice(&sector_buf[start..start + end]);
                                            ad.jpeg_desc_len = end;
                                            Ok(())
                                        });
                                        if read_ok.is_ok() && ad.jpeg_desc_len > 0 {
                                            ad.app.state = crate::app::input::AppState::SignMsgPreview;
                                        } else {
                                            boot_display.draw_rejected_screen("Read failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SignMsgPreview => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                        } else if y >= 185 && y <= 225 && x >= 100 && x <= 220 {
                            // SIGN button tapped
                            boot_display.draw_saving_screen("Signing...");
                            boot_display.update_progress_bar(20);
                            delay.delay_millis(50);

                            // SHA256 hash the message
                            let msg = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                            let msg_hash = wallet::hmac::sha256(msg);
                            boot_display.update_progress_bar(40);

                            // Derive private key for active address
                            let pp = ad.seed_mgr.active_slot()
                                .map(|s| s.passphrase_str())
                                .unwrap_or("");
                            let mut privkey = [0u8; 32];
                            crate::app::signing::derive_privkey(
                                &ad.mnemonic_indices, ad.word_count, pp,
                                ad.current_addr_index, &mut privkey);
                            boot_display.update_progress_bar(70);

                            // Schnorr sign
                            match wallet::schnorr::schnorr_sign(&privkey, &msg_hash) {
                                Ok(sig) => {
                                    ad.sign_msg_sig = sig.bytes;
                                    boot_display.update_progress_bar(100);
                                    sound::success(delay);
                                    ad.app.state = crate::app::input::AppState::SignMsgResult;
                                }
                                Err(_) => {
                                    boot_display.draw_rejected_screen("Signing failed");
                                    sound::beep_error(delay);
                                    delay.delay_millis(2000);
                                }
                            }
                            // Zeroize private key
                            wallet::hmac::zeroize_buf(&mut privkey);
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SignMsgResult => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else if y >= 155 && y <= 191 && x >= 60 && x <= 260 {
                            // SAVE button — write signature to SD
                            if bb_card_type.is_some() {
                                boot_display.draw_saving_screen("Saving sig...");
                                boot_display.update_progress_bar(50);
                                delay.delay_millis(50);

                                // Build hex string of signature
                                let hex_chars = b"0123456789abcdef";
                                let mut hex_buf = [0u8; 128];
                                for i in 0..64 {
                                    hex_buf[i * 2] = hex_chars[(ad.sign_msg_sig[i] >> 4) as usize];
                                    hex_buf[i * 2 + 1] = hex_chars[(ad.sign_msg_sig[i] & 0x0f) as usize];
                                }

                                let sd_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                    let fat32 = sdcard::mount_fat32(ct)?;
                                    let fname = *b"SIGNATURESG";
                                    let _ = sdcard::delete_file(ct, &fat32, &fname);
                                    sdcard::create_file(ct, &fat32, &fname, &hex_buf)?;
                                    Ok(())
                                });
                                if sd_result.is_ok() {
                                    boot_display.draw_success_screen("Signature Saved!");
                                    sound::success(delay);
                                    delay.delay_millis(2000);
                                } else {
                                    boot_display.draw_rejected_screen("SD write failed");
                                    sound::beep_error(delay);
                                    delay.delay_millis(1500);
                                }
                            } else {
                                boot_display.draw_rejected_screen("No SD card");
                                sound::beep_error(delay);
                                delay.delay_millis(1500);
                            }
                        } else {
                            // Tap elsewhere → go home
                            ad.app.go_main_menu();
                        }
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
