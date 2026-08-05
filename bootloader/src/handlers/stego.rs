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
                        // Two carriers now. The cards are drawn at y=56 and
                        // y=142, each 76 px tall and 260 px wide from x=30
                        // (see draw_stego_mode_choice); a tap inside one
                        // selects it and continues into the JPEG scan.
                        // These bounds must track that function.
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                            needs_redraw = true;
                        } else {
                            if (30..290).contains(&x) {
                                if (56..132).contains(&y) {
                                    ad.stego_mode_idx = 0;   // Descriptor (EXIF)
                                } else if (142..218).contains(&y) {
                                    ad.stego_mode_idx = 1;   // Picture (DCT)
                                }
                            }
                            // Check seed loaded
                            let active = ad.seed_mgr.active_slot();
                            let has_seed = matches!(active, Some(s) if !s.is_empty());
                            if !has_seed {
                                boot_display.draw_rejected_screen("No seed loaded");
                                delay.delay_millis(1500);
                                ad.app.state = crate::app::input::AppState::ExportChoice;
                                needs_redraw = true;
                            } else if bb_card_type.is_none() {
                                boot_display.draw_rejected_screen("No SD card");
                                delay.delay_millis(1500);
                                ad.app.state = crate::app::input::AppState::ExportChoice;
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
                                            && ((ad.jpeg_file_count) as usize) < crate::app::data::SD_FILE_LIST_MAX {
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
                                    needs_redraw = true;
                                } else {
                                    (ad.jpeg_selected) = 0;
                                    ad.app.state = crate::app::input::AppState::StegoJpegPick;
                                    needs_redraw = true;
                                }
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
                            needs_redraw = true;
                            } else {
                                boot_display.draw_saving_screen("Encoding stego...");
                                // For now: mark result and show confirmation
                                // JPEG EXIF stego path handles encrypt+embed in stego.rs
                                (ad.stego_result_ok) = true;
                                ad.app.state = crate::app::input::AppState::StegoResult;
                            needs_redraw = true;
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
                            needs_redraw = true;
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
                            needs_redraw = true;
                                    }
                                    break;
                                }
                            }
                        }
                        
                    }
                    crate::app::input::AppState::StegoJpegDescChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegPick;
                            needs_redraw = true;
                        } else if (40..280).contains(&x) && (68..112).contains(&y) {
                            // Type manually (row 0 at y=70)
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoJpegDesc;
                            needs_redraw = true;
                        } else if (40..280).contains(&x) && (114..158).contains(&y) {
                            // Load from SD — scan for .TXT files with LFN
                            boot_display.draw_loading_screen("Scanning TXT...");
                            boot_display.update_progress_bar(50);
                            delay.delay_millis(50);
                            (ad.txt_file_count) = 0;
                            ad.txt_file_scroll = 0;
                            let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                let fat32 = sdcard::mount_fat32(ct)?;
                                sdcard::list_root_dir_lfn(ct, &fat32, |entry, disp_name, disp_len| {
                                    if !entry.is_dir() && entry.file_size > 0
                                        && entry.file_size <= 256
                                        && ((ad.txt_file_count) as usize) < crate::app::data::SD_FILE_LIST_MAX {
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
                            needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::StegoJpegDescFile => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                            needs_redraw = true;
                        } else {
                            // Page arrows, matching the triangles that
                            // draw_stego_txt_pick paints at x 5..30 and
                            // 290..315. Same hit thresholds the SD picker
                            // uses. Previously the arrows were drawn but
                            // wired to nothing, so only the first four
                            // files were ever reachable.
                            //
                            // A flag rather than an else-block, so the row
                            // loop below keeps its original nesting.
                            const PAGE: u8 = 4;
                            let mut paged = false;
                            if x < 40 && y >= 42 && ad.txt_file_scroll > 0 {
                                ad.txt_file_scroll = ad.txt_file_scroll.saturating_sub(PAGE);
                                needs_redraw = true;
                                paged = true;
                            } else if x >= 280 && y >= 42
                                && (ad.txt_file_scroll + PAGE) < ad.txt_file_count {
                                ad.txt_file_scroll += PAGE;
                                needs_redraw = true;
                                paged = true;
                            }
                            for slot in 0..4u8 {
                                if !paged && list_zones[slot as usize].contains(x, y) {
                                    let idx = ad.txt_file_scroll + slot;
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
                            needs_redraw = true;
                                    } else {
                                        boot_display.draw_rejected_screen("Read failed");
                                        delay.delay_millis(1500);
                                    }
                                    } // close if idx < (ad.txt_file_count)
                                    break;
                                }
                            }
                        }
                        
                    }
                    crate::app::input::AppState::StegoJpegDesc => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
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
                            needs_redraw = true;
                        } else if (185..=225).contains(&y) {
                            if (170..=300).contains(&x) {
                                // USE — proceed to hint
                                ad.stego_pp_len = 0;
                                ad.stego_pp_enc_len = 0;
                                ad.app.state = crate::app::input::AppState::StegoJpegPpAsk;
                            needs_redraw = true;
                            } else if (20..=150).contains(&x) {
                                // EDIT — go back to choice
                                ad.app.state = crate::app::input::AppState::StegoJpegDescChoice;
                            needs_redraw = true;
                            }
                        }
                        
                    }
                    crate::app::input::AppState::StegoJpegPpAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegDescPreview;
                            needs_redraw = true;
                        } else if (175..=215).contains(&y) {
                            if (20..=150).contains(&x) {
                                // NO — skip passphrase, go to confirm
                                ad.stego_pp_len = 0;
                                ad.stego_pp_enc_len = 0;
                                ad.app.state = crate::app::input::AppState::StegoJpegConfirm;
                            needs_redraw = true;
                            } else if (170..=300).contains(&x) {
                                // YES — show info screen
                                ad.app.state = crate::app::input::AppState::StegoJpegPpInfo;
                            needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::StegoJpegPpInfo => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoJpegPpAsk;
                            needs_redraw = true;
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
                            needs_redraw = true;
                                    } else {
                                        // Preset selected → encrypt hint directly
                                        let hint_text = stego::HINT_PRESETS[row as usize].as_bytes();
                                        let hint_len = hint_text.len();
                                        ad.stego_pp_buf[..hint_len].copy_from_slice(hint_text);
                                        ad.stego_pp_len = hint_len;

                                        // Encrypt hint with descriptor as password
                                        boot_display.draw_loading_screen("Encrypting hint...");
                                        let password = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                                        // Nonce and salt from the TRNG. Both used to be keyed
                                        // hashes over the hint text itself, i.e. a public
                                        // function of the very secret being encrypted (C-02).
                                        let nonce = crate::handlers::sd::generate_trng_nonce();
                                        let salt = crate::handlers::sd::generate_trng_salt();

                                        match sd_backup::encrypt_raw_v3(
                                            &ad.stego_pp_buf, ad.stego_pp_len, password, &salt, &nonce,
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
                            needs_redraw = true;
                                    }
                                    break;
                                }
                            }
                        }
                        
                    }
                    crate::app::input::AppState::StegoJpegPpEntry => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoJpegPpInfo;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
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
                                        // Nonce and salt from the TRNG. Both used to be keyed
                                        // hashes over the hint text itself, i.e. a public
                                        // function of the very secret being encrypted (C-02).
                                        let nonce = crate::handlers::sd::generate_trng_nonce();
                                        let salt = crate::handlers::sd::generate_trng_salt();

                                        match sd_backup::encrypt_raw_v3(
                                            &ad.stego_pp_buf, ad.stego_pp_len, password, &salt, &nonce,
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
                                } else if let Some((mnemonic_indices, mnemonic_wc)) =
                                    active.and_then(|s| s.as_mnemonic())
                                {
                                    // `as_mnemonic`, not `slot.indices`. The guard
                                    // above only checks the slot is non-empty, so a
                                    // raw-key or xprv slot reached here and had its
                                    // packed PRIVATE KEY handed to a seed-backup
                                    // encryptor as if it were word indices. It failed
                                    // safe only because `encrypt_backup_progress`
                                    // rejects a word count that is not 12 or 24, which
                                    // is validation in the wrong place. Now those kinds
                                    // never reach it (H-08).
                                    boot_display.draw_loading_screen("Encrypting...");

                                    // Nonce and salt from the TRNG. The nonce used to be
                                    // hmac_sha512("stego-nonce", mnemonic indices), a public
                                    // keyed hash of the plaintext secret (C-02). Nothing
                                    // recomputes it on the read side: both are stored in the
                                    // container, so determinism bought nothing.
                                    let nonce = crate::handlers::sd::generate_trng_nonce();
                                    let salt = crate::handlers::sd::generate_trng_salt();

                                    // Encrypt with progress bar
                                    let pp = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                                    let mut backup = [0u8; sd_backup::MAX_BACKUP_SIZE];
                                    let enc_result = sd_backup::encrypt_backup_progress(
                                        mnemonic_indices, mnemonic_wc,
                                        pp, &salt, &nonce, &mut backup,
                                        &mut |cur, total| {
                                            let pct = (cur as u64 * 100 / total as u64) as u8;
                                            boot_display.update_progress_bar(pct);
                                        });

                                    if let Ok(enc_len) = enc_result {
                                        sound::task_done(delay);
                                        // Embedded blob format v2 (D-01): raw container bytes
                                        // with the constant 7-byte prefix stripped, seed then
                                        // optional hint, NO separator. See the format notes in
                                        // features/stego.rs.
                                        //
                                        // v1 wrote base64, which put the ASCII "S0FT" at the
                                        // head of every artifact ever exported and made a photo
                                        // dump greppable. Raw bytes are legal here: UserComment
                                        // is EXIF type 7 (UNDEFINED).
                                        //
                                        // Sizes: seed container 100 - 7 = 93, hint container
                                        // 116 - 7 = 109, total 202 into a 384-byte buffer.
                                        let mut uc_buf = [0u8; 384];
                                        let mut uc_len = stego::strip_v3_prefix(
                                            &backup[..enc_len], &mut uc_buf);

                                        if uc_len > 0 && ad.stego_pp_enc_len > 0 {
                                            // Appended with no delimiter. The hint blob carries
                                            // its own leading length byte, which is what the
                                            // reader uses to find the boundary. A '|' separator
                                            // cannot be used once the payload is raw: the byte
                                            // 0x7C occurs inside ciphertext.
                                            let hint_len = stego::strip_v3_prefix(
                                                &ad.stego_pp_encrypted[..ad.stego_pp_enc_len],
                                                &mut uc_buf[uc_len..]);
                                            uc_len += hint_len;
                                        }

                                        // The APP1 is now built INSIDE the SD closure, because
                                        // copy-forward needs the host photo's own EXIF and the
                                        // photo is not in memory until it is read below.
                                        //
                                        // Description copied to a local first: the closure must
                                        // not borrow `ad`.
                                        let mut desc_local = [0u8; 128];
                                        let desc_len = ad.jpeg_desc_len.min(desc_local.len());
                                        desc_local[..desc_len]
                                            .copy_from_slice(&ad.jpeg_desc_buf[..desc_len]);

                                    if uc_len > 0 {
                                        boot_display.draw_saving_screen("Writing to SD...");
                                        boot_display.update_progress_bar(50);
                                        delay.delay_millis(50);
                                        let fname83 = ad.jpeg_file_names[(ad.jpeg_selected) as usize];
                                        // Carrier chosen on the StegoModeSelect
                                        // screen. Copied out before the closure,
                                        // which must not borrow `ad`.
                                        let picture_mode = ad.stego_mode_idx == 1;
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

                                            // Heap, not a 2 KB stack array: a real camera APP1
                                            // with an embedded thumbnail runs tens of KB, and
                                            // copy-forward carries all of it.
                                            // Skipped in Picture mode: that carrier leaves
                                            // metadata untouched, and running this here would
                                            // let an EXIF-side verify failure abort an export
                                            // that never needed EXIF at all.
                                            let host = if picture_mode { None } else {
                                                stego::find_exif_app1(&jpeg_buf[..read_len], read_len)
                                            };
                                            let host_size = host.map_or(0, |(_, sz)| sz);
                                            let cap = core::cmp::max(4096, host_size + 2048);
                                            let mut app1_buf = alloc::vec![0u8; cap];

                                            // Preferred: carry the photo's own EXIF forward, so
                                            // IFD0 keeps Make, Model, DateTime and the Exif
                                            // sub-IFD instead of collapsing to two entries
                                            // (D-01 fingerprint 2).
                                            let mut app1_len = 0usize;
                                            if let Some((ho, hs)) = host {
                                                let hend = ho.saturating_add(hs);
                                                if hend <= read_len {
                                                    app1_len = stego::build_exif_app1_copyforward(
                                                        &jpeg_buf[ho..hend], hs,
                                                        &desc_local[..desc_len],
                                                        &uc_buf[..uc_len],
                                                        &mut app1_buf);
                                                }
                                            }

                                            // Fallback: the photo has no EXIF (screenshot,
                                            // messaging-app download, editor export), an
                                            // unsupported byte order, or the result would not
                                            // fit. Synthesize a software-export-shaped block
                                            // rather than emitting a two-entry IFD0, which is
                                            // the single most identifying feature in the
                                            // Kee/Johnson/Farid signature work.
                                            //
                                            // No Make and no Model: a fabricated camera claim
                                            // can be contradicted by the file's own
                                            // quantization tables. `Software` cannot, because
                                            // re-encoding chains are ordinary.
                                            //
                                            // Both varying fields are drawn per export, so two
                                            // artifacts share no constant. Dimensions come from
                                            // the file's own SOF marker so they always agree
                                            // with the image.
                                            if app1_len == 0 && !picture_mode {
                                                let rnd = crate::handlers::sd::generate_trng_nonce();
                                                let sw = stego::SOFTWARE_TABLE[
                                                    (rnd[6] as usize) % stego::SOFTWARE_TABLE.len()];
                                                let mut dt = [0u8; 19];
                                                stego::format_exif_datetime(&rnd, &mut dt);
                                                let (w, h) = stego::jpeg_dimensions(
                                                    &jpeg_buf[..read_len], read_len)
                                                    .unwrap_or((0, 0));
                                                if w > 0 && h > 0 {
                                                    app1_len = stego::build_exif_app1_template(
                                                        &desc_local[..desc_len],
                                                        &uc_buf[..uc_len],
                                                        w, h, sw.as_bytes(), &dt,
                                                        &mut app1_buf);
                                                }
                                            }

                                            // Last resort: the minimal two-tag block. Reached
                                            // only if the SOF is unreadable, i.e. the file is
                                            // barely a JPEG. Detectable, but readable, which
                                            // beats refusing to back up the seed.
                                            if app1_len == 0 && !picture_mode {
                                                app1_len = stego::build_exif_app1(
                                                    &desc_local[..desc_len], desc_len,
                                                    &uc_buf, uc_len,
                                                    &mut app1_buf);
                                            }
                                            if app1_len == 0 && !picture_mode {
                                                return Err("EXIF build failed");
                                            }

                                            // VERIFY BEFORE WRITING. This is a seed backup: a
                                            // malformed host photo that produced a subtly wrong
                                            // offset would otherwise be discovered on the day
                                            // the user needs to restore. Read our own payload
                                            // back out of the segment we just built, and if it
                                            // does not match byte for byte, drop to the minimal
                                            // builder and verify that too.
                                            let mut vbuf = [0u8; 384];
                                            let mut vlen = if picture_mode { uc_len } else {
                                                stego::extract_user_comment(
                                                    &app1_buf[..app1_len], app1_len, &mut vbuf)
                                            };
                                            if !picture_mode
                                                && (vlen != uc_len || vbuf[..vlen] != uc_buf[..uc_len])
                                            {
                                                app1_len = stego::build_exif_app1(
                                                    &desc_local[..desc_len], desc_len,
                                                    &uc_buf, uc_len,
                                                    &mut app1_buf);
                                                if app1_len == 0 { return Err("EXIF build failed"); }
                                                vlen = stego::extract_user_comment(
                                                    &app1_buf[..app1_len], app1_len, &mut vbuf);
                                                if vlen != uc_len || vbuf[..vlen] != uc_buf[..uc_len] {
                                                    return Err("EXIF verify failed");
                                                }
                                            }

                                            // Carrier: Descriptor writes the
                                            // payload into EXIF; Picture writes
                                            // it into the DCT coefficients and
                                            // leaves metadata untouched.
                                            let out_len;
                                            let mut out_buf;
                                            if picture_mode {
                                                // The speaker's I2S DMA buffer repeats until
                                                // overwritten, so the `task_done` tone above
                                                // would play for the whole embed and make a
                                                // slow run indistinguishable from a hang.
                                                // Silence it before the long part.
                                                sound::silence();

                                                // Coefficient domain. Output can
                                                // be a few hundred bytes either
                                                // side of the input once changed
                                                // coefficients re-encode.
                                                log!("   [dct] jpeg {} B, allocating {} B out + {} B window",
                                                    read_len,
                                                    read_len + 4096,
                                                    crate::features::stego_dct::RANK_WINDOW as usize * 2);
                                                let t_dct = esp_hal::time::Instant::now();
                                                out_buf = alloc::vec![0u8; read_len + 4096];
                                                out_len = crate::features::stego_dct::embed(
                                                    &jpeg_buf[..read_len],
                                                    &uc_buf[..uc_len],
                                                    &desc_local[..desc_len],
                                                    &mut out_buf,
                                                ).map_err(|e| match e {
                                                    crate::features::stego_dct::DctError::NotBaseline =>
                                                        "Progressive JPEG",
                                                    crate::features::stego_dct::DctError::NoCapacity =>
                                                        "Photo too small",
                                                    _ => "Stego encode failed",
                                                })?;
                                                log!("   [dct] embed {} B -> {} B in {} ms",
                                                    read_len, out_len,
                                                    (esp_hal::time::Instant::now() - t_dct).as_millis());
                                            } else {
                                                out_buf = alloc::vec![0u8; read_len + app1_len + 16];
                                                out_len = stego::inject_exif_into_jpeg(
                                                    &jpeg_buf[..read_len], read_len,
                                                    &app1_buf, app1_len,
                                                    &mut out_buf);
                                                if out_len == 0 { return Err("EXIF inject failed"); }
                                            }
                                            sdcard::overwrite_file(ct, &fat32, &fname83, &out_buf[..out_len])?;
                                            Ok(())
                                        });
                                        boot_display.update_progress_bar(100);
                                        if sd_result.is_ok() {
                                            (ad.stego_result_ok) = true;
                                            ad.app.state = crate::app::input::AppState::StegoResult;
                            needs_redraw = true;
                                            sound::success(delay);
                                        } else {
                                            boot_display.draw_rejected_screen("JPEG write failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(1500);
                                            ad.app.state = crate::app::input::AppState::ExportChoice;
                            needs_redraw = true;
                                        }
                                    } else {
                                        boot_display.draw_rejected_screen("EXIF build failed");
                                        delay.delay_millis(1500);
                                        ad.app.state = crate::app::input::AppState::ExportChoice;
                            needs_redraw = true;
                                    }
                                    // Zeroize encrypted passphrase buffer
                                    wallet::hmac::zeroize_buf(&mut ad.stego_pp_encrypted);
                                    ad.stego_pp_enc_len = 0;
                                    } else {
                                        boot_display.draw_rejected_screen("Encryption failed");
                                        delay.delay_millis(1500);
                                        ad.app.state = crate::app::input::AppState::ExportChoice;
                            needs_redraw = true;
                                    }
                                    needs_redraw = true;
                                }
                            }
                        }
                        
                    }
                    // H-03: firmware-update-over-QR was an abandoned design. Nothing ever
                    // installed anything: the flow stopped at a screen showing a verified tick,
                    // and the signature covered only the hash, never the version, so a replayed
                    // signature with any version number displayed as verified. Commented out
                    // rather than deleted so the abandoned design stays visible.
                    // ─── Stego Import Flow ────────────
                    crate::app::input::AppState::StegoImportPick => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ImportMenu;
                            needs_redraw = true;
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
                            needs_redraw = true;
                                    }
                                    break;
                                }
                            }
                        }
                        
                    }
                    crate::app::input::AppState::StegoImportDescChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoImportPick;
                            needs_redraw = true;
                        } else if (40..280).contains(&x) && (68..112).contains(&y) {
                            // Type manually
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoImportPass;
                            needs_redraw = true;
                        } else if (40..280).contains(&x) && (114..158).contains(&y) {
                            // Load from SD — scan for .TXT files
                            boot_display.draw_loading_screen("Scanning TXT...");
                            boot_display.update_progress_bar(50);
                            delay.delay_millis(50);
                            (ad.txt_file_count) = 0;
                            ad.txt_file_scroll = 0;
                            let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                let fat32 = sdcard::mount_fat32(ct)?;
                                sdcard::list_root_dir_lfn(ct, &fat32, |entry, disp_name, disp_len| {
                                    if !entry.is_dir() && entry.file_size > 0
                                        && entry.file_size <= 256
                                        && ((ad.txt_file_count) as usize) < crate::app::data::SD_FILE_LIST_MAX {
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
                            needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::StegoImportDescFile => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoImportDescChoice;
                            needs_redraw = true;
                        } else {
                            // Page arrows, matching the triangles that
                            // draw_stego_txt_pick paints at x 5..30 and
                            // 290..315. Same hit thresholds the SD picker
                            // uses. Previously the arrows were drawn but
                            // wired to nothing, so only the first four
                            // files were ever reachable.
                            //
                            // A flag rather than an else-block, so the row
                            // loop below keeps its original nesting.
                            const PAGE: u8 = 4;
                            let mut paged = false;
                            if x < 40 && y >= 42 && ad.txt_file_scroll > 0 {
                                ad.txt_file_scroll = ad.txt_file_scroll.saturating_sub(PAGE);
                                needs_redraw = true;
                                paged = true;
                            } else if x >= 280 && y >= 42
                                && (ad.txt_file_scroll + PAGE) < ad.txt_file_count {
                                ad.txt_file_scroll += PAGE;
                                needs_redraw = true;
                                paged = true;
                            }
                            for slot in 0..4u8 {
                                if !paged && list_zones[slot as usize].contains(x, y) {
                                    let idx = ad.txt_file_scroll + slot;
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
                            needs_redraw = true;
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
                        
                    }
                    crate::app::input::AppState::StegoImportPass => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::StegoImportDescChoice;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "IMAGE DESCRIPTOR"); }
                                6 => {
                                    boot_display.draw_loading_screen("Decrypting...");
                                    boot_display.update_progress_bar(10);
                                    delay.delay_millis(50); // flush display before SD + PBKDF2

                                    // Step 1: read the payload from the selected
                                    // JPEG on SD, trying both carriers.
                                    ad.import_exif_b64_len = 0;
                                    // The descriptor doubles as the Picture
                                    // carrier's permutation key. Copied out
                                    // before the closure, which cannot borrow
                                    // `ad` while `ad.import_exif_b64` is
                                    // mutably borrowed inside it.
                                    let mut pp_local = [0u8; 128];
                                    let pp_local_len = ad.pp_input.len.min(pp_local.len());
                                    pp_local[..pp_local_len]
                                        .copy_from_slice(&ad.pp_input.buf[..pp_local_len]);
                                    let fname83 = ad.import_jpeg_names[(ad.import_jpeg_selected) as usize];
                                    let exif_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &fname83)?;
                                        let fsize = entry.file_size as usize;
                                        if fsize > 2_000_000 { return Err("JPEG >2MB"); }
                                        let mut jpeg_buf = alloc::vec![0u8; fsize];
                                        let read_len = sdcard::read_file(ct, &fat32, &entry, &mut jpeg_buf)?;
                                        // Carrier order is chosen by one bit of TRNG,
                                        // not fixed.
                                        //
                                        // The user is never asked which carrier they
                                        // used: they should not have to remember, and a
                                        // wrong answer would be indistinguishable from a
                                        // wrong password.
                                        //
                                        // WHY RANDOM RATHER THAN ALWAYS-EXIF-FIRST. A photo
                                        // can hold BOTH payloads — nothing in an export
                                        // removes the other carrier, by design, since
                                        // running both modes in turn is how a user gets
                                        // redundancy against the two opposite risks
                                        // (metadata stripping vs recompression). With a
                                        // fixed order, a photo carrying two different
                                        // backups always returns the same one, silently,
                                        // and the other is unreachable. Randomising the
                                        // order makes both reachable across retries.
                                        //
                                        // This is deliberately asymmetric in the owner's
                                        // favour, which is the whole point of the feature:
                                        // the owner knows the photo carries a backup and
                                        // can simply import again, while an attacker must
                                        // rule out both carriers on every candidate photo
                                        // without the descriptor.
                                        //
                                        // Cost: when only one carrier holds data and the
                                        // coin picks the other first, the import pays one
                                        // wasted coefficient decode (~6 s on a 250 KB
                                        // photo) before falling through.
                                        //
                                        // If the RNG health tests fail, `generate_trng_nonce`
                                        // returns zeros and this degrades to Descriptor
                                        // first, which is the previous behaviour: no worse,
                                        // and it cannot fail closed on an import path whose
                                        // job is to recover a seed.
                                        let picture_first =
                                            (crate::handlers::sd::generate_trng_nonce()[0] & 1) == 1;
                                        let mut extracted = 0usize;
                                        let mut from_picture = false;

                                        for attempt in 0..2u8 {
                                            let try_picture = if attempt == 0 { picture_first } else { !picture_first };
                                            if try_picture {
                                                // The descriptor keys the permutation as
                                                // well as the container, so a wrong
                                                // descriptor yields a different walk and no
                                                // payload — the same uniform failure as a
                                                // wrong password everywhere else.
                                                extracted = crate::features::stego_dct::extract(
                                                    &jpeg_buf[..read_len],
                                                    &pp_local[..pp_local_len],
                                                    &mut ad.import_exif_b64,
                                                ).unwrap_or(0);
                                                if extracted > 0 { from_picture = true; }
                                            } else if let Some((app1_off, app1_size)) =
                                                stego::find_exif_app1(&jpeg_buf[..read_len], read_len)
                                            {
                                                let app1_end: usize =
                                                    app1_off.checked_add(app1_size).unwrap_or(usize::MAX);
                                                if app1_end > read_len { return Err("EXIF overflow"); }
                                                extracted = stego::extract_user_comment(
                                                    &jpeg_buf[app1_off..app1_end],
                                                    app1_size,
                                                    &mut ad.import_exif_b64);
                                            }
                                            if extracted > 0 { break; }
                                        }

                                        ad.import_exif_b64_len = extracted;
                                        if extracted == 0 { return Err("no data"); }
                                        // Which carrier produced the payload. Without this
                                        // line a stale payload from the other carrier looks
                                        // exactly like a correct import, which is how a
                                        // wrong seed reached slot 1 unnoticed.
                                        log!("   [stego] payload from {} ({} B)",
                                            if from_picture { "picture" } else { "descriptor" },
                                            extracted);
                                        Ok(())
                                    });
                                    boot_display.update_progress_bar(30);

                                    // Step 2: reassemble the container(s) and decrypt, or fail
                                    // uniformly.
                                    //
                                    // Two wire formats are accepted, permanently:
                                    //
                                    //   v1  base64(seed) ['|' base64(hint)]. Every artifact ever
                                    //       written begins with the ASCII "S0FT" (base64 of the
                                    //       container magic), which is exactly the fingerprint
                                    //       v2 exists to remove — and exactly what makes the two
                                    //       formats trivial to tell apart.
                                    //   v2  raw seed blob [|| raw hint blob], each stripped of
                                    //       the constant 7-byte container prefix and each
                                    //       beginning with its own payload-length byte.
                                    //
                                    // Export writes v2 only. Discrimination costs no key
                                    // derivation, so a wrong guess cannot be timed.
                                    let mut decrypt_ok = false;

                                    // a v3 seed container is 100 bytes; 128 was exact for the old 81-byte one
                                    let mut decoded = [0u8; 128];
                                    let mut dec_len = 0usize;
                                    // a v3 hint container is 116 bytes; 128 was exact for the old 97-byte one
                                    let mut hint_decoded = [0u8; 160];
                                    let mut hint_dec_len = 0usize;

                                    if exif_ok.is_ok() && ad.import_exif_b64_len > 0 {
                                        let payload_len = ad.import_exif_b64_len;

                                        if stego::is_legacy_b64_payload(&ad.import_exif_b64[..payload_len]) {
                                            let mut seed_b64_len = payload_len;
                                            let mut hint_b64_start: usize = 0;
                                            let mut hint_b64_len: usize = 0;
                                            for i in 0..payload_len {
                                                if ad.import_exif_b64[i] == b'|' {
                                                    seed_b64_len = i;
                                                    hint_b64_start = i + 1;
                                                    hint_b64_len = payload_len - hint_b64_start;
                                                    break;
                                                }
                                            }
                                            dec_len = stego::base64_decode(
                                                &ad.import_exif_b64, seed_b64_len, &mut decoded);
                                            if hint_b64_len > 0 {
                                                hint_dec_len = stego::base64_decode(
                                                    &ad.import_exif_b64[hint_b64_start..],
                                                    hint_b64_len, &mut hint_decoded);
                                            }
                                        } else {
                                            // v2: the seed blob's own length byte gives the
                                            // boundary; whatever follows is the hint blob.
                                            let seed_blob = stego::embedded_blob_len(
                                                &ad.import_exif_b64[..payload_len]);
                                            if seed_blob > 0 && seed_blob <= payload_len {
                                                dec_len = stego::restore_v3_prefix(
                                                    &ad.import_exif_b64[..seed_blob],
                                                    sd_backup::PURPOSE_SEED,
                                                    &mut decoded);
                                                let rest_len = payload_len - seed_blob;
                                                if rest_len > 0 {
                                                    let hint_blob = stego::embedded_blob_len(
                                                        &ad.import_exif_b64[seed_blob..payload_len]);
                                                    if hint_blob > 0 && hint_blob <= rest_len {
                                                        hint_dec_len = stego::restore_v3_prefix(
                                                            &ad.import_exif_b64[seed_blob..seed_blob + hint_blob],
                                                            sd_backup::PURPOSE_RAW,
                                                            &mut hint_decoded);
                                                    }
                                                }
                                            }
                                        }

                                        if dec_len >= 57 {
                                            let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                            let mut import_indices = [0u16; 24];
                                            match sd_backup::decrypt_backup_versioned(
                                                &decoded[..dec_len], pp_bytes, &mut import_indices,
                                                &mut |cur, total| {
                                                    boot_display.update_progress_bar(30 + (cur as u64 * 70 / total as u64) as u8);
                                                })
                                            {
                                                Ok((wc, legacy)) => {
                                                    if validate_mnemonic(&import_indices, wc) {
                                                        (ad.recovered_hint_len) = 0;

                                                        if hint_dec_len > 0 {
                                                            // Container already reassembled above,
                                                            // for whichever wire format this file
                                                            // uses.
                                                            if let Ok((h_len, _)) = sd_backup::decrypt_raw_versioned(
                                                                &hint_decoded[..hint_dec_len], pp_bytes, &mut ad.recovered_hint,
                                                                &mut |cur, total| {
                                                                    boot_display.update_progress_bar((cur as u64 * 100 / total as u64) as u8);
                                                                })
                                                            {
                                                                (ad.recovered_hint_len) = h_len.min(sd_backup::MAX_RAW_PAYLOAD);
                                                                log!("   Recovery hint found: {} bytes", (ad.recovered_hint_len));
                                                            }
                                                        }

                                                        ad.mnemonic_indices = import_indices;
                                                        (ad.word_count) = wc;
                                                        log!("   Stego import OK: {} words, deferring store", wc);
                                                        ad.pp_input.reset();
                                                        decrypt_ok = true;

                                                        // A pre-v3 artifact carries the shared
                                                        // salt, so one precomputed dictionary
                                                        // table attacks every one ever made. The
                                                        // SD restore path already says so; this
                                                        // one discarded the flag, which meant no
                                                        // stego artifact could ever produce the
                                                        // warning. Shown before the hint or the
                                                        // success screen, since both of those
                                                        // move the flow on.
                                                        if legacy {
                                                            log!("   Stego: legacy format, prompting re-export");
                                                            boot_display.draw_notice_screen(
                                                                "Old backup format",
                                                                "Re-export for better security");
                                                            delay.delay_millis(2500);
                                                        }

                                                        if (ad.recovered_hint_len) > 0 {
                                                            // Has hint → show it, then passphrase keyboard
                                                            sound::success(delay);
                                                            ad.app.state = crate::app::input::AppState::StegoHintReveal;
                        needs_redraw = true;
                                                        } else {
                                                            // No hint → store now without passphrase
                                                            if crate::app::signing::load_active_mnemonic(
                                                                ad,
                                                                boot_display,
                                                                crate::app::signing::PassphraseSource::Empty,
                                                            ).is_some() {
                                                                boot_display.draw_success_screen("Seed Recovered!");
                                                                sound::success(delay);
                                                                delay.delay_millis(2000);
                                                            } else {
                                                                boot_display.draw_rejected_screen("All slots full!");
                                                                sound::beep_error(delay);
                                                                delay.delay_millis(2000);
                                                            }
                                                            ad.app.state = crate::app::input::AppState::SeedList;
                        needs_redraw = true;
                                                        }
                                                        needs_redraw = true;
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
                            // Skip passphrase — store without it
                            (ad.recovered_hint_len) = 0;
                            if crate::app::signing::load_active_mnemonic(
                                ad,
                                boot_display,
                                crate::app::signing::PassphraseSource::Empty,
                            ).is_none() {
                                boot_display.draw_rejected_screen("All slots full!");
                                sound::beep_error(delay);
                                delay.delay_millis(2000);
                            }
                            ad.app.state = crate::app::input::AppState::SeedList;
                            needs_redraw = true;
                        } else {
                            // Tap → go to passphrase entry
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::StegoHintPassphrase;
                            needs_redraw = true;
                        }
                        
                    }
                    crate::app::input::AppState::StegoHintPassphrase => {
                        if is_back {
                            // Back from passphrase — store without it
                            if crate::app::signing::load_active_mnemonic(
                                ad,
                                boot_display,
                                crate::app::signing::PassphraseSource::Empty,
                            ).is_none() {
                                boot_display.draw_rejected_screen("All slots full!");
                                sound::beep_error(delay);
                                delay.delay_millis(2000);
                            }
                            ad.app.state = crate::app::input::AppState::SeedList;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "25TH WORD"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "25TH WORD"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "25TH WORD"); }
                                6 => {
                                    // Store with passphrase (or empty if user hit OK without typing)
                                    let stored = crate::app::signing::load_active_mnemonic(
                                        ad,
                                        boot_display,
                                        crate::app::signing::PassphraseSource::PpInput,
                                    );
                                    (ad.recovered_hint_len) = 0;
                                    if stored.is_some() {
                                        boot_display.draw_success_screen("Full Recovery!");
                                        sound::success(delay);
                                        delay.delay_millis(2000);
                                    } else {
                                        boot_display.draw_rejected_screen("All slots full!");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
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
