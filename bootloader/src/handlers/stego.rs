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

// handlers/stego.rs — Touch handlers for steganography states
//
// Extracted from main.rs to reduce monolith size.
// Returns true if a redraw is needed.


use crate::log;
use crate::{app::data::AppData, hw::display, hw::sd_backup, hw::sdcard, hw::sound, ui::seed_manager, features::stego, hw::touch, wallet};
use crate::ui::helpers::pp_keyboard_hit;

#[cfg(not(feature = "silent"))]
use crate::ui::helpers::validate_mnemonic;

/// Shared state for stego touch handlers.
/// Handle touch events for all steganography workflow screens.
#[inline(never)]
#[allow(unused_assignments)]
pub fn handle_stego_touch(
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
                    crate::app::input::AppState::StegoModeSelect => {
                        // Single mode (JPEG EXIF) — back goes to export menu,
                        // any tap starts the JPEG scan flow directly
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                            needs_redraw = true;
                        } else {
                            // Check seed loaded
                            let active = ad.seed_mgr.active_slot();
                            let has_seed = matches!(active, Some(s) if !s.is_empty());
                            if !has_seed {
                                boot_display.draw_rejected_screen("No seed loaded");
                                delay.delay_millis(1500);
                                needs_redraw = true;
                            } else if bb_card_type.is_none() {
                                boot_display.draw_rejected_screen("No SD card");
                                delay.delay_millis(1500);
                                needs_redraw = true;
                            } else {
                                // Start guided JPEG EXIF flow — scan SD for JPG files
                                boot_display.draw_loading_screen("Scanning SD...");
                                boot_display.update_progress_bar(50);
                                delay.delay_millis(50);
                                (ad.jpeg_file_count) = 0;
                                let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                    let fat32 = sdcard::mount_fat32(ct)?;
                                    sdcard::list_root_dir_lfn(ct, &fat32, |entry, disp_name, disp_len| {
                                        if !entry.is_dir() && entry.file_size > 0
                                            && ((ad.jpeg_file_count) as usize) < 8 {
                                            let ext = &entry.name[8..11];
                                            let first = entry.name[0];
                                            let is_hidden = first == b'.' || first == b'_' || first == 0xE5;
                                            if !is_hidden && (ext == b"JPG" || ext == b"jpg"
                                                || ext == b"JPE" || ext == b"jpe") {
                                                let idx = (ad.jpeg_file_count) as usize;
                                                ad.jpeg_file_names[idx] = entry.name;
                                                let cl = disp_len.min(32);
                                                ad.jpeg_display_names[idx] = [0u8; 32];
                                                ad.jpeg_display_names[idx][..cl].copy_from_slice(&disp_name[..cl]);
                                                ad.jpeg_display_lens[idx] = cl as u8;
                                                (ad.jpeg_file_count) += 1;
                                            }
                                        }
                                        true
                                    })?;
                                    Ok(())
                                });
                                if scan_ok.is_err() || (ad.jpeg_file_count) == 0 {
                                    boot_display.draw_rejected_screen("No .JPG files on SD");
                                    sound::beep_error(delay);
                                    delay.delay_millis(2000);
                                    ad.app.state = crate::app::input::AppState::ExportChoice;
                                } else {
                                    (ad.jpeg_selected) = 0;
                                    ad.app.state = crate::app::input::AppState::StegoJpegPick;
                                }
                                needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::StegoEmbed => {
                        // Processing screen — tap back to cancel
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                            needs_redraw = true;
                        } else {
                            // Legacy embed path (unused — JPEG has its own guided flow)
                            let active = ad.seed_mgr.active_slot();
                            if !matches!(active, Some(s) if !s.is_empty()) {
                                boot_display.draw_rejected_screen("No seed loaded");
                                delay.delay_millis(1500);
                                ad.app.state = crate::app::input::AppState::ExportChoice;
                            } else {
                                boot_display.draw_saving_screen("Encoding stego...");
                                // For now: mark result and show confirmation
                                // JPEG EXIF stego path handles encrypt+embed in stego.rs
                                (ad.stego_result_ok) = true;
                                ad.app.state = crate::app::input::AppState::StegoResult;
                            }
                            needs_redraw = true;
                        }
                    }
                    crate::app::input::AppState::StegoResult => {
                        ad.app.go_main_menu();
                        needs_redraw = true;
                    }
                    // ─── JPEG Stego Guided Flow ────────────
                    crate::app::input::AppState::StegoJpegPick => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if page_up_zone.contains(x, y) && (ad.jpeg_selected) >= 4 {
                            (ad.jpeg_selected) = (ad.jpeg_selected).saturating_sub(4);
                        } else if page_down_zone.contains(x, y) && ((ad.jpeg_selected) / 4 + 1) * 4 < (ad.jpeg_file_count) {
                            (ad.jpeg_selected) += 4;
                            if (ad.jpeg_selected) >= (ad.jpeg_file_count) { (ad.jpeg_selected) = (ad.jpeg_file_count) - 1; }
                        } else {
                            let scroll = ((ad.jpeg_selected) / 4) * 4;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = scroll + slot;
                                    if abs < (ad.jpeg_file_count) {
                                        (ad.jpeg_selected) = abs;
                                        ad.jpeg_desc_len = 0;
                                        ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                                    }
                                    break;
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoJpegDescChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegPick;
                        } else if (40..280).contains(&x) && (68..112).contains(&y) {
                            // Type manually (row 0 at y=70)
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoJpegDesc;
                        } else if (40..280).contains(&x) && (114..158).contains(&y) {
                            // Load from SD — scan for .TXT files with LFN
                            boot_display.draw_loading_screen("Scanning TXT...");
                            boot_display.update_progress_bar(50);
                            delay.delay_millis(50);
                            (ad.txt_file_count) = 0;
                            let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                let fat32 = sdcard::mount_fat32(ct)?;
                                sdcard::list_root_dir_lfn(ct, &fat32, |entry, disp_name, disp_len| {
                                    if !entry.is_dir() && entry.file_size > 0
                                        && entry.file_size <= 256
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
                                delay.delay_millis(2000);
                            } else {
                                ad.app.state = crate::app::input::AppState::StegoJpegDescFile;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoJpegDescFile => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                        } else {
                            let scroll = 0u8; // TXT files don't have paging yet (max 8)
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = scroll + slot;
                                    if idx < (ad.txt_file_count) {
                                    // Read .TXT file content into ad.jpeg_desc_buf
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
                                        ad.app.state = crate::app::input::AppState::StegoJpegDescPreview;
                                    } else {
                                        boot_display.draw_rejected_screen("Read failed");
                                        delay.delay_millis(1500);
                                    }
                                    } // close if idx < (ad.txt_file_count)
                                    break;
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoJpegDesc => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); needs_redraw = true; } // PAGE — full redraw
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                6 => {
                                    // OK — grab text and go to preview
                                    let pp_str = ad.pp_input.as_str();
                                    let copy_len = pp_str.len().min(96);
                                    ad.jpeg_desc_buf[..copy_len].copy_from_slice(&pp_str.as_bytes()[..copy_len]);
                                    ad.jpeg_desc_len = copy_len;
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::StegoJpegDescPreview;
                                    needs_redraw = true;
                                }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); } // char key
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::StegoJpegDescPreview => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                        } else if (185..=225).contains(&y) {
                            if (170..=300).contains(&x) {
                                // USE — proceed to hint
                                ad.stego_pp_len = 0;
                                ad.stego_pp_enc_len = 0;
                                ad.app.state = crate::app::input::AppState::StegoJpegPpAsk;
                            } else if (20..=150).contains(&x) {
                                // EDIT — go back to choice
                                ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoJpegPpAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegDescPreview;
                        } else if (175..=215).contains(&y) {
                            if (20..=150).contains(&x) {
                                // NO — skip passphrase, go to confirm
                                ad.stego_pp_len = 0;
                                ad.stego_pp_enc_len = 0;
                                ad.app.state = crate::app::input::AppState::StegoJpegConfirm;
                            } else if (170..=300).contains(&x) {
                                // YES — show info screen
                                ad.app.state = crate::app::input::AppState::StegoJpegPpInfo;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoJpegPpInfo => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegPpAsk;
                        } else {
                            // 4 rows starting at y=68, each 36px step, 30px tall
                            for row in 0..4u8 {
                                let ry = 68 + row as u16 * 36;
                                if y >= ry && y < ry + 30 && (15..=305).contains(&x) {
                                    (ad.hint_selected) = row;
                                    if row == 3 {
                                        // Custom → go to keyboard
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::StegoJpegPpEntry;
                                    } else {
                                        // Preset selected → encrypt hint directly
                                        let hint_text = stego::HINT_PRESETS[row as usize].as_bytes();
                                        let hint_len = hint_text.len();
                                        ad.stego_pp_buf[..hint_len].copy_from_slice(hint_text);
                                        ad.stego_pp_len = hint_len;

                                        // Encrypt hint with descriptor as password
                                        boot_display.draw_loading_screen("Encrypting hint...");
                                        let password = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                                        let mut nonce_src = [0u8; 128];
                                        let ns_len = (ad.stego_pp_len + ad.jpeg_desc_len).min(128);
                                        nonce_src[..(ad.stego_pp_len).min(64)].copy_from_slice(&ad.stego_pp_buf[..(ad.stego_pp_len).min(64)]);
                                        if ad.jpeg_desc_len > 0 && (ad.stego_pp_len) < 128 {
                                            let copy = (ad.jpeg_desc_len).min(128 - (ad.stego_pp_len));
                                            nonce_src[ad.stego_pp_len..(ad.stego_pp_len) + copy].copy_from_slice(&ad.jpeg_desc_buf[..copy]);
                                        }
                                        let hash = wallet::hmac::hmac_sha512(b"stego-pp-nonce", &nonce_src[..ns_len]);
                                        let mut nonce = [0u8; 12];
                                        nonce.copy_from_slice(&hash[..12]);

                                        match sd_backup::encrypt_raw_progress(
                                            &ad.stego_pp_buf, ad.stego_pp_len, password, &nonce,
                                            &mut ad.stego_pp_encrypted,
                                            &mut |cur, total| {
                                                boot_display.update_progress_bar((cur as u64 * 100 / total as u64) as u8);
                                            })
                                        {
                                            Ok(enc_len) => {
                                                ad.stego_pp_enc_len = enc_len;
                                                sound::task_done(delay);
                                            }
                                            Err(_) => {
                                                boot_display.draw_rejected_screen("Hint encrypt failed");
                                                delay.delay_millis(1500);
                                                ad.stego_pp_len = 0;
                                                ad.stego_pp_enc_len = 0;
                                            }
                                        }
                                        wallet::hmac::zeroize_buf(&mut ad.stego_pp_buf);
                                        ad.app.state = crate::app::input::AppState::StegoJpegConfirm;
                                    }
                                    break;
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoJpegPpEntry => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoJpegPpInfo;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); needs_redraw = true; }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "CUSTOM HINT"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "CUSTOM HINT"); }
                                6 => {
                                    let pp_str = ad.pp_input.as_str();
                                    let pp_copy_len = pp_str.len().min(64);
                                    ad.stego_pp_buf[..pp_copy_len].copy_from_slice(&pp_str.as_bytes()[..pp_copy_len]);
                                    ad.stego_pp_len = pp_copy_len;
                                    ad.pp_input.reset();

                                    if ad.stego_pp_len > 0 {
                                        boot_display.draw_loading_screen("Encrypting hint...");
                                        let password = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                                        let mut nonce_src = [0u8; 128];
                                        let ns_len = (ad.stego_pp_len + ad.jpeg_desc_len).min(128);
                                        nonce_src[..(ad.stego_pp_len).min(64)].copy_from_slice(&ad.stego_pp_buf[..(ad.stego_pp_len).min(64)]);
                                        if ad.jpeg_desc_len > 0 && (ad.stego_pp_len) < 128 {
                                            let copy = (ad.jpeg_desc_len).min(128 - (ad.stego_pp_len));
                                            nonce_src[ad.stego_pp_len..(ad.stego_pp_len) + copy].copy_from_slice(&ad.jpeg_desc_buf[..copy]);
                                        }
                                        let hash = wallet::hmac::hmac_sha512(b"stego-pp-nonce", &nonce_src[..ns_len]);
                                        let mut nonce = [0u8; 12];
                                        nonce.copy_from_slice(&hash[..12]);

                                        match sd_backup::encrypt_raw_progress(
                                            &ad.stego_pp_buf, ad.stego_pp_len, password, &nonce,
                                            &mut ad.stego_pp_encrypted,
                                            &mut |cur, total| {
                                                boot_display.update_progress_bar((cur as u64 * 100 / total as u64) as u8);
                                            })
                                        {
                                            Ok(enc_len) => {
                                                ad.stego_pp_enc_len = enc_len;
                                                sound::task_done(delay);
                                            }
                                            Err(_) => {
                                                boot_display.draw_rejected_screen("PP encrypt failed");
                                                delay.delay_millis(1500);
                                                ad.stego_pp_len = 0;
                                                ad.stego_pp_enc_len = 0;
                                            }
                                        }
                                        wallet::hmac::zeroize_buf(&mut ad.stego_pp_buf);
                                    }
                                    ad.app.state = crate::app::input::AppState::StegoJpegConfirm;
                                    needs_redraw = true;
                                }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "CUSTOM HINT"); }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::StegoJpegConfirm => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegPpAsk;
                            needs_redraw = true;
                        } else if (182..=225).contains(&y) {
                            // Bottom area = confirm buttons
                            if (20..=150).contains(&x) {
                                // CANCEL
                                ad.app.state = crate::app::input::AppState::ExportChoice;
                                needs_redraw = true;
                            } else if (170..=300).contains(&x) {
                                // CONFIRM — do the actual JPEG EXIF write
                                let active = ad.seed_mgr.active_slot();
                                if !matches!(active, Some(s) if !s.is_empty()) {
                                    boot_display.draw_rejected_screen("No seed loaded");
                                    delay.delay_millis(1500);
                                    ad.app.state = crate::app::input::AppState::ExportChoice;
                                    needs_redraw = true;
                                } else if let Some(slot) = active {
                                    boot_display.draw_loading_screen("Encrypting...");

                                    // Generate nonce from seed data (deterministic per slot)
                                    let mut nonce = [0u8; 12];
                                    let mut nonce_src = [0u8; 48];
                                    let src_len = (slot.word_count as usize * 2).min(48);
                                    for i in 0..src_len.min(24) {
                                        nonce_src[i * 2] = (slot.indices[i] >> 8) as u8;
                                        nonce_src[i * 2 + 1] = slot.indices[i] as u8;
                                    }
                                    let hash = wallet::hmac::hmac_sha512(b"stego-nonce", &nonce_src[..src_len]);
                                    nonce.copy_from_slice(&hash[..12]);

                                    // Encrypt with progress bar
                                    let pp = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                                    let mut backup = [0u8; sd_backup::MAX_BACKUP_SIZE];
                                    let enc_result = sd_backup::encrypt_backup_progress(
                                        &slot.indices, slot.word_count,
                                        pp, &nonce, &mut backup,
                                        &mut |cur, total| {
                                            let pct = (cur as u64 * 100 / total as u64) as u8;
                                            boot_display.update_progress_bar(pct);
                                        });

                                    if let Ok(enc_len) = enc_result {
                                        sound::task_done(delay);
                                        let mut b64 = [0u8; 128];
                                        let b64_len = stego::base64_encode(
                                            &backup[..enc_len], enc_len, &mut b64);

                                        // If hint was encrypted, base64-encode it and append
                                        // to UserComment with "|" separator:
                                        // UserComment = base64(seed) | base64(hint)
                                        let mut uc_buf = [0u8; 256];
                                        let mut uc_len = b64_len;
                                        uc_buf[..b64_len].copy_from_slice(&b64[..b64_len]);

                                        if ad.stego_pp_enc_len > 0 {
                                            let mut hint_b64 = [0u8; 128];
                                            let hint_b64_len = stego::base64_encode(
                                                &ad.stego_pp_encrypted[..ad.stego_pp_enc_len],
                                                ad.stego_pp_enc_len, &mut hint_b64);
                                            if hint_b64_len > 0 && uc_len + 1 + hint_b64_len < uc_buf.len() {
                                                uc_buf[uc_len] = b'|';
                                                uc_len += 1;
                                                uc_buf[uc_len..uc_len + hint_b64_len].copy_from_slice(&hint_b64[..hint_b64_len]);
                                                uc_len += hint_b64_len;
                                            }
                                        }

                                        // ImageDescription = plain user text (no ZW, no padding)
                                        // UserComment = seed blob [| hint blob]
                                        let mut app1_buf = [0u8; 2048];
                                        let app1_len = stego::build_exif_app1(
                                            &ad.jpeg_desc_buf[..ad.jpeg_desc_len], ad.jpeg_desc_len,
                                            &uc_buf, uc_len,
                                            &mut app1_buf);

                                    if app1_len > 0 {
                                        boot_display.draw_saving_screen("Writing to SD...");
                                        boot_display.update_progress_bar(50);
                                        delay.delay_millis(50);
                                        let fname83 = ad.jpeg_file_names[(ad.jpeg_selected) as usize];
                                        let sd_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                            let fat32 = sdcard::mount_fat32(ct)?;
                                            let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &fname83)?;
                                            let fsize = entry.file_size as usize;
                                            if fsize > 2_000_000 { return Err("JPEG >2MB"); }
                                            let mut jpeg_buf = alloc::vec![0u8; fsize];
                                            let read_len = sdcard::read_file(ct, &fat32, &entry, &mut jpeg_buf)?;
                                            if read_len < 2 || jpeg_buf[0] != 0xFF || jpeg_buf[1] != 0xD8 {
                                                return Err("Not a valid JPEG");
                                            }
                                            let mut out_buf = alloc::vec![0u8; read_len + app1_len + 16];
                                            let out_len = stego::inject_exif_into_jpeg(
                                                &jpeg_buf[..read_len], read_len,
                                                &app1_buf, app1_len,
                                                &mut out_buf);
                                            if out_len == 0 { return Err("EXIF inject failed"); }
                                            sdcard::overwrite_file(ct, &fat32, &fname83, &out_buf[..out_len])?;
                                            Ok(())
                                        });
                                        boot_display.update_progress_bar(100);
                                        if sd_result.is_ok() {
                                            (ad.stego_result_ok) = true;
                                            ad.app.state = crate::app::input::AppState::StegoResult;
                                            sound::success(delay);
                                        } else {
                                            boot_display.draw_rejected_screen("JPEG write failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(1500);
                                            ad.app.state = crate::app::input::AppState::ExportChoice;
                                        }
                                    } else {
                                        boot_display.draw_rejected_screen("EXIF build failed");
                                        delay.delay_millis(1500);
                                        ad.app.state = crate::app::input::AppState::ExportChoice;
                                    }
                                    // Zeroize encrypted passphrase buffer
                                    wallet::hmac::zeroize_buf(&mut ad.stego_pp_encrypted);
                                    ad.stego_pp_enc_len = 0;
                                    } else {
                                        boot_display.draw_rejected_screen("Encryption failed");
                                        delay.delay_millis(1500);
                                        ad.app.state = crate::app::input::AppState::ExportChoice;
                                    }
                                    needs_redraw = true;
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::FwUpdateResult => {
                        ad.app.go_main_menu();
                        needs_redraw = true;
                    }
                    // ─── Stego Import Flow ────────────
                    crate::app::input::AppState::StegoImportPick => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else if page_up_zone.contains(x, y) && (ad.import_jpeg_selected) >= 4 {
                            (ad.import_jpeg_selected) = (ad.import_jpeg_selected).saturating_sub(4);
                            needs_redraw = true;
                        } else if page_down_zone.contains(x, y) && ((ad.import_jpeg_selected) / 4 + 1) * 4 < (ad.import_jpeg_count) {
                            (ad.import_jpeg_selected) += 4;
                            if (ad.import_jpeg_selected) >= (ad.import_jpeg_count) { (ad.import_jpeg_selected) = (ad.import_jpeg_count) - 1; }
                            needs_redraw = true;
                        } else {
                            let scroll = ((ad.import_jpeg_selected) / 4) * 4;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = scroll + slot;
                                    if abs < (ad.import_jpeg_count) {
                                        (ad.import_jpeg_selected) = abs;
                                        // Go straight to descriptor entry — EXIF read deferred to decrypt
                                        ad.import_exif_b64_len = 0;
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::StegoImportDescChoice;
                                    }
                                    break;
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoImportDescChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoImportPick;
                        } else if (40..280).contains(&x) && (68..112).contains(&y) {
                            // Type manually
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoImportPass;
                        } else if (40..280).contains(&x) && (114..158).contains(&y) {
                            // Load from SD — scan for .TXT files
                            boot_display.draw_loading_screen("Scanning TXT...");
                            boot_display.update_progress_bar(50);
                            delay.delay_millis(50);
                            (ad.txt_file_count) = 0;
                            let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                let fat32 = sdcard::mount_fat32(ct)?;
                                sdcard::list_root_dir_lfn(ct, &fat32, |entry, disp_name, disp_len| {
                                    if !entry.is_dir() && entry.file_size > 0
                                        && entry.file_size <= 256
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
                                ad.app.state = crate::app::input::AppState::StegoImportDescFile;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoImportDescFile => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoImportDescChoice;
                        } else {
                            let scroll = 0u8;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = scroll + slot;
                                    if idx < (ad.txt_file_count) {
                                    // Read .TXT file content into pp_input for decrypt
                                    boot_display.draw_loading_screen("Reading...");
                                    boot_display.update_progress_bar(50);
                                    delay.delay_millis(50);
                                    let fname83 = ad.txt_file_names[idx as usize];
                                    ad.pp_input.reset();
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
                                        // Load raw bytes into pp_input — must match export password exactly
                                        for i in 0..end {
                                            ad.pp_input.push_char(sector_buf[start + i]);
                                        }
                                        Ok(())
                                    });
                                    if read_ok.is_ok() && ad.pp_input.len > 0 {
                                        // Auto-decrypt: simulate OK press on keyboard
                                        // Transition to StegoImportPass which will show the keyboard
                                        // with the descriptor pre-filled — user can review and hit OK
                                        ad.app.state = crate::app::input::AppState::StegoImportPass;
                                    } else {
                                        boot_display.draw_rejected_screen("Read failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(1500);
                                    }
                                    } // close if idx < count
                                    break;
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoImportPass => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoImportDescChoice;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); needs_redraw = true; }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                6 => {
                                    boot_display.draw_loading_screen("Decrypting...");
                                    boot_display.update_progress_bar(10);
                                    delay.delay_millis(50); // flush display before SD + PBKDF2

                                    // Step 1: Read EXIF from selected JPEG on SD card
                                    ad.import_exif_b64_len = 0;
                                    let fname83 = ad.import_jpeg_names[(ad.import_jpeg_selected) as usize];
                                    let exif_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &fname83)?;
                                        let fsize = entry.file_size as usize;
                                        if fsize > 2_000_000 { return Err("JPEG >2MB"); }
                                        let mut jpeg_buf = alloc::vec![0u8; fsize];
                                        let read_len = sdcard::read_file(ct, &fat32, &entry, &mut jpeg_buf)?;
                                        if let Some((app1_off, app1_size)) = stego::find_exif_app1(&jpeg_buf[..read_len], read_len) {
                                            let app1_end: usize = app1_off.checked_add(app1_size).unwrap_or(usize::MAX);
                                            if app1_end > read_len { return Err("EXIF overflow"); }
                                            let extracted = stego::extract_user_comment(
                                                &jpeg_buf[app1_off..app1_end],
                                                app1_size,
                                                &mut ad.import_exif_b64);
                                            ad.import_exif_b64_len = extracted;
                                            if extracted == 0 { return Err("no data"); }
                                            Ok(())
                                        } else {
                                            Err("no data")
                                        }
                                    });
                                    boot_display.update_progress_bar(30);

                                    // Step 2: Parse base64 and decrypt — or fail uniformly
                                    let mut seed_b64_len = ad.import_exif_b64_len;
                                    let mut hint_b64_start: usize = 0;
                                    let mut hint_b64_len: usize = 0;

                                    let mut decrypt_ok = false;

                                    if exif_ok.is_ok() && ad.import_exif_b64_len > 0 {
                                        for i in 0..ad.import_exif_b64_len {
                                            if ad.import_exif_b64[i] == b'|' {
                                                seed_b64_len = i;
                                                hint_b64_start = i + 1;
                                                hint_b64_len = ad.import_exif_b64_len - hint_b64_start;
                                                break;
                                            }
                                        }

                                        let mut decoded = [0u8; 128];
                                        let dec_len = stego::base64_decode(
                                            &ad.import_exif_b64, seed_b64_len, &mut decoded);

                                        if dec_len >= 57 {
                                            let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                            let mut import_indices = [0u16; 24];
                                            match sd_backup::decrypt_backup_progress(
                                                &decoded[..dec_len], pp_bytes, &mut import_indices,
                                                &mut |cur, total| {
                                                    boot_display.update_progress_bar(30 + (cur as u64 * 70 / total as u64) as u8);
                                                })
                                            {
                                                Ok(wc) => {
                                                    if validate_mnemonic(&import_indices, wc) {
                                                        (ad.recovered_hint_len) = 0;

                                                        if hint_b64_len > 0 {
                                                            let mut hint_decoded = [0u8; 128];
                                                            let hint_dec_len = stego::base64_decode(
                                                                &ad.import_exif_b64[hint_b64_start..],
                                                                hint_b64_len, &mut hint_decoded);
                                                            if hint_dec_len > 0 {
                                                                if let Ok(h_len) = sd_backup::decrypt_raw_progress(
                                                                    &hint_decoded[..hint_dec_len], pp_bytes, &mut ad.recovered_hint,
                                                                    &mut |cur, total| {
                                                                        boot_display.update_progress_bar((cur as u64 * 100 / total as u64) as u8);
                                                                    })
                                                                {
                                                                    (ad.recovered_hint_len) = h_len.min(sd_backup::MAX_RAW_PAYLOAD);
                                                                    log!("   Recovery hint found: {} bytes", (ad.recovered_hint_len));
                                                                }
                                                            }
                                                        }

                                                        if let Some(slot_idx) = ad.seed_mgr.store(
                                                            &import_indices, wc, &[], 0,
                                                        ) {
                                                            ad.seed_mgr.activate(slot_idx);
                                                            ad.mnemonic_indices = import_indices;
                                                            (ad.word_count) = wc;
                                                            (ad.seed_loaded) = true;
                                                            (ad.pubkeys_cached) = false;
                                                            (ad.current_addr_index) = 0;
                                                            (ad.extra_pubkey_index) = 0xFFFF;
                                                            log!("   Stego import OK: {} words, slot {}", wc, slot_idx);
                                                            ad.pp_input.reset();
                                                            decrypt_ok = true;

                                                            if (ad.recovered_hint_len) > 0 {
                                                                sound::success(delay);
                                                                ad.app.state = crate::app::input::AppState::StegoHintReveal;
                                                            } else {
                                                                boot_display.draw_success_screen("Seed Recovered!");
                                                                sound::success(delay);
                                                                delay.delay_millis(2000);
                                                                ad.app.state = crate::app::input::AppState::SeedList;
                                                            }
                                                            needs_redraw = true;
                                                        } else {
                                                            ad.pp_input.reset();
                                                            boot_display.draw_rejected_screen("All slots full!");
                                                            sound::beep_error(delay);
                                                            delay.delay_millis(2000);
                                                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                                                            needs_redraw = true;
                                                            decrypt_ok = true; // not a password error
                                                        }
                                                    }
                                                }
                                                Err(_) => {}
                                            }
                                        }
                                    }

                                    // Uniform failure: no EXIF, bad data, wrong password — all same error
                                    if !decrypt_ok {
                                        boot_display.draw_rejected_screen("Wrong password");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2500);
                                        needs_redraw = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::StegoHintReveal => {
                        if is_back {
                            // Skip hint, go to seed list
                            (ad.recovered_hint_len) = 0;
                            ad.app.state = crate::app::input::AppState::SeedList;
                        } else {
                            // Tap → go to passphrase entry
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoHintPassphrase;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::StegoHintPassphrase => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SeedList;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); needs_redraw = true; }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "25TH WORD"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "25TH WORD"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "25TH WORD"); }
                                6 => {
                                    let pp_str = ad.pp_input.as_str();
                                    let pp_len = pp_str.len().min(64);
                                    if pp_len > 0 {
                                        if let Some(slot) = ad.seed_mgr.active_slot_mut() {
                                            slot.passphrase[..pp_len].copy_from_slice(&pp_str.as_bytes()[..pp_len]);
                                            slot.passphrase_len = pp_len as u8;
                                            (ad.pubkeys_cached) = false;
                                            (ad.current_addr_index) = 0;
                                            (ad.extra_pubkey_index) = 0xFFFF;
                                            log!("   Passphrase set from hint: {} chars", pp_len);
                                        }
                                    }
                                    ad.pp_input.reset();
                                    (ad.recovered_hint_len) = 0;
                                    boot_display.draw_success_screen("Full Recovery!");
                                    sound::success(delay);
                                    delay.delay_millis(2000);
                                    ad.app.state = crate::app::input::AppState::SeedList;
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
