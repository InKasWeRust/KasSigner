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

// handlers/sd.rs — Touch handlers for SD backup/restore states
//
// Extracted from main.rs to reduce monolith size.
// Covers: SdBackupWarning, SdBackupPassphrase, SdFileList,
//         SdRestorePassphrase, SdXprvExportPassphrase,
//         SdXprvFileList, SdXprvImportPassphrase

use crate::log;
use crate::{app::data::AppData, hw::display, hw::sd_backup, hw::sdcard, hw::sound, hw::touch, wallet};
use crate::ui::helpers::pp_keyboard_hit;

use crate::wallet::hmac::zeroize_buf;

/// Shared state for SD backup/restore touch handlers.
fn hex_nibble(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        b'A'..=b'F' => ch - b'A' + 10,
        _ => 0xFF,
    }
}

/// Handle touch for SD backup/restore states. Returns Some(true) for redraw.
/// Handle touch events for SD card backup/restore screens.
#[inline(never)]
#[allow(unused_assignments)]
pub fn handle_sd_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    _bb_card_type: &Option<sdcard::SdCardType>,
    list_zones: &[touch::TouchZone; 4],
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::SdBackupWarning => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if (85..=235).contains(&x) && y >= 205 {
                            // "I understand" button → proceed to password entry
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SdBackupPassphrase;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdBackupPassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); needs_redraw = false; }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); needs_redraw = false; }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); needs_redraw = false; }
                                6 => { // OK — encrypt and write backup to SD
                                    // Show encrypting screen with progress bar
                                    boot_display.draw_saving_screen("Encrypting seed...");
                                    let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                    // Generate nonce from TRNG
                                    let mut nonce = [0u8; 12];
                                    for i in 0..12 {
                                        nonce[i] = unsafe {
                                            core::ptr::read_volatile(0x6003_5000 as *const u32)
                                        } as u8;
                                    }
                                    let mut backup_buf = [0u8; sd_backup::MAX_BACKUP_SIZE];
                                    match sd_backup::encrypt_backup_progress(
                                        &ad.mnemonic_indices, ad.word_count,
                                        pp_bytes, &nonce, &mut backup_buf,
                                        &mut |done, total| {
                                            let pct = if total > 0 { (done * 50 / total) as u8 } else { 0 };
                                            boot_display.update_progress_bar(pct);
                                        },
                                    ) {
                                        Ok(backup_len) => {
                                            boot_display.update_progress_bar(50);
                                            boot_display.draw_saving_screen("Writing to SD...");
                                            boot_display.update_progress_bar(50);
                                            delay.delay_millis(50); // flush display before SD takes SPI
                                            // Generate filename from seed fingerprint
                                            let fp = ad.seed_mgr.active_slot()
                                                .map(|s| s.fingerprint)
                                                .unwrap_or([0; 4]);
                                            let fname = sd_backup::backup_filename(&fp);
                                            let write_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                let _ = sdcard::delete_file(ct, &fat32, &fname);
                                                sdcard::create_file(ct, &fat32, &fname, &backup_buf[..backup_len])?;
                                                Ok(())
                                            });
                                            sound::stop_ticking();
                                            match write_result {
                                                Ok(()) => {
                                                    boot_display.update_progress_bar(100);
                                                    let mut disp = [0u8; 13];
                                                    let dlen = sd_backup::format_83_display(&fname, &mut disp);
                                                    let name_str = core::str::from_utf8(&disp[..dlen]).unwrap_or("?");
                                                    log!("[SD-BACKUP] Wrote {} bytes as {}", backup_len, name_str);
                                                    boot_display.draw_success_screen("Backup Saved!");
                                                    sound::success(delay);
                                                    delay.delay_millis(3000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-BACKUP] Write failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD write failed");
                                                    sound::beep_error(delay);
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            sound::stop_ticking();
                                            boot_display.draw_rejected_screen("Encryption failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::SeedList;
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            let max_vis: usize = 4;
                            let scroll_off = ad.sd_file_scroll as usize;
                            let can_page_up = scroll_off > 0;
                            let can_page_down = (scroll_off + max_vis) < ad.sd_file_count as usize;

                            // Left arrow — page up
                            if x < 40 && y >= 42 && can_page_up {
                                if ad.sd_file_scroll >= max_vis as u8 {
                                    ad.sd_file_scroll -= max_vis as u8;
                                } else {
                                    ad.sd_file_scroll = 0;
                                }
                            }
                            // Right arrow — page down
                            else if x >= 280 && y >= 42 && can_page_down {
                                ad.sd_file_scroll += max_vis as u8;
                            } else {
                            let mut tapped: Option<usize> = None;
                            let mut tapped_delete = false;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = slot as usize + scroll_off;
                                    if idx < (ad.sd_file_count) as usize {
                                        tapped = Some(idx);
                                        // Right 40px of card = delete zone
                                        tapped_delete = x > 236;
                                    }
                                    break;
                                }
                            }
                            if let Some(i) = tapped {
                                    ad.sd_selected_file = ad.sd_file_list[i];
                                    if tapped_delete {
                                        // Show delete confirmation
                                        ad.app.state = crate::app::input::AppState::SdDeleteConfirm;
                                    } else {
                                    // Read first bytes to auto-detect format
                                    boot_display.draw_saving_screen("Importing...");
                                    let peek_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        let mut buf = [0u8; 1024];
                                        let n = sdcard::read_file(ct, &fat32, &entry, &mut buf)?;
                                        Ok((buf, n))
                                    });
                                    match peek_result {
                                        Ok((buf, n)) => {
                                            // Trim trailing whitespace/newlines
                                            let mut len = n;
                                            while len > 0 && (buf[len-1] == b'\n' || buf[len-1] == b'\r' || buf[len-1] == b' ' || buf[len-1] == 0) {
                                                len -= 1;
                                            }

                                            if len >= 4 && buf[0] == b'K' && buf[1] == b'A' && buf[2] == b'S' && buf[3] == 0x01 {
                                                // Encrypted seed backup (KAS\x01) — use original n, not trimmed
                                                ad.pp_input.reset();
                                                ad.app.state = crate::app::input::AppState::SdRestorePassphrase;
                                            } else if len >= 4 && buf[0] == b'K' && buf[1] == b'A' && buf[2] == b'S' && buf[3] == 0x02 {
                                                // Encrypted xprv backup (KAS\x02)
                                                ad.pp_input.reset();
                                                ad.app.state = crate::app::input::AppState::SdXprvImportPassphrase;
                                            } else if len >= 4 && buf[0] == b'x' && buf[1] == b'p' && buf[2] == b'r' && buf[3] == b'v' {
                                            // Plain text xprv string
                                            match wallet::xpub::import_xprv(&buf[..len]) {
                                                Ok(acct_key) => {
                                                    boot_display.draw_saving_screen("Importing xprv...");
                                                    let raw = acct_key.to_raw();
                                                    ad.acct_key_raw.copy_from_slice(&raw);
                                                    // Derive pubkeys
                                                    let acct = wallet::bip32::ExtendedPrivKey::from_raw(&raw);
                                                    for idx in 0..20u16 {
                                                        if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                            if let Ok(pk) = ak.public_key_x_only() {
                                                                ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                            }
                                                        }
                                                    }
                                                    // Store in slot
                                                    use sha2::{Sha256, Digest};
                                                    let hash = Sha256::digest(acct_key.private_key_bytes());
                                                    let fp = [hash[0], hash[1], hash[2], hash[3]];
                                                    let mut dummy_indices = [0u16; 24];
                                                    for j in 0..16 {
                                                        dummy_indices[j] = u16::from_le_bytes([raw[j*2], raw[j*2+1]]);
                                                    }
                                                    if let Some(slot_idx) = ad.seed_mgr.find_by_fingerprint(&fp).or_else(|| ad.seed_mgr.find_free()) {
                                                        let slot = &mut ad.seed_mgr.slots[slot_idx];
                                                        if slot.is_empty() {
                                                            slot.word_count = 2;
                                                            slot.indices = dummy_indices;
                                                            slot.passphrase[..32].copy_from_slice(&raw[32..64]);
                                                            slot.passphrase[32] = raw[64];
                                                            slot.passphrase_len = 33;
                                                            slot.fingerprint = fp;
                                                        }
                                                        ad.seed_mgr.activate(slot_idx);
                                                        (ad.seed_loaded) = true;
                                                        (ad.pubkeys_cached) = true;
                                                        (ad.current_addr_index) = 0;
                                                        (ad.extra_pubkey_index) = 0xFFFF;
                                                        ad.word_count = 2;
                                                        log!("[SD-IMPORT] Plain xprv imported to slot {}", slot_idx);
                                                        boot_display.draw_saving_screen("XPrv imported!");
                                                        delay.delay_millis(2000);
                                                    } else {
                                                        boot_display.draw_rejected_screen("All 4 slots full!");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("Invalid xprv");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                            } else if len == 64 {
                                                // Possibly plain hex private key (64 chars)
                                                let mut key = [0u8; 32];
                                                let mut valid = true;
                                                for j in 0..32 {
                                                    let hi = hex_nibble(buf[j * 2]);
                                                    let lo = hex_nibble(buf[j * 2 + 1]);
                                                    if hi == 0xFF || lo == 0xFF { valid = false; break; }
                                                    key[j] = (hi << 4) | lo;
                                                }
                                                if valid {
                                                    if let Ok(pk) = wallet::bip32::pubkey_from_raw_key(&key) {
                                                        if let Some(slot_idx) = ad.seed_mgr.store_raw_key(&key) {
                                                            ad.seed_mgr.activate(slot_idx);
                                                            (ad.seed_loaded) = true;
                                                            (ad.current_addr_index) = 0;
                                                            (ad.extra_pubkey_index) = 0xFFFF;
                                                            ad.pubkey_cache[0].copy_from_slice(&pk);
                                                            (ad.pubkeys_cached) = true;
                                                            ad.word_count = 1;
                                                            log!("[SD-IMPORT] Plain hex key imported to slot {}", slot_idx);
                                                            boot_display.draw_saving_screen("Key imported!");
                                                            sound::success(delay);
                                                            delay.delay_millis(1500);
                                                        } else {
                                                            boot_display.draw_rejected_screen("All 4 slots full!");
                                                            delay.delay_millis(2000);
                                                        }
                                                    } else {
                                                        boot_display.draw_rejected_screen("Invalid key");
                                                        delay.delay_millis(2000);
                                                    }
                                                } else {
                                                    boot_display.draw_rejected_screen("Not a valid key file");
                                                    delay.delay_millis(2000);
                                                }
                                                for b in key.iter_mut() {
                                                    unsafe { core::ptr::write_volatile(b, 0); }
                                                }
                                            } else {
                                                boot_display.draw_rejected_screen("Unknown file format");
                                                delay.delay_millis(2000);
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-IMPORT] Read error: {}", e);
                                            boot_display.draw_rejected_screen("Read error");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    } // close else (import path)
                                    }
                        }
                        } // close page-up/down/tap else
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdDeleteConfirm => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SdFileList;
                        } else if (180..=230).contains(&y) {
                            if (30..=150).contains(&x) {
                                // CANCEL
                                ad.app.state = crate::app::input::AppState::SdFileList;
                                sound::click(delay);
                            } else if (170..=290).contains(&x) {
                                // DELETE — hold-to-confirm (4 seconds)
                                // Wait for finger release first
                                loop {
                                    delay.delay_millis(30);
                                    let ts = crate::hw::touch::read_touch(i2c);
                                    match ts {
                                        crate::hw::touch::TouchState::NoTouch => break,
                                        _ => {}
                                    }
                                }
                                delay.delay_millis(100);

                                // Redraw button as "HOLD 4s" prompt
                                {
                                    use embedded_graphics::primitives::{Rectangle, RoundedRectangle, CornerRadii, PrimitiveStyle};
                                    use embedded_graphics::prelude::*;
                                    use crate::hw::display::*;
                                    let btn_corner = CornerRadii::new(Size::new(8, 8));
                                    let del_rect = Rectangle::new(Point::new(170, 185), Size::new(120, 40));
                                    RoundedRectangle::new(del_rect, btn_corner)
                                        .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
                                        .draw(&mut boot_display.display).ok();
                                    let dw = measure_title("HOLD 4s");
                                    draw_lato_title(&mut boot_display.display, "HOLD 4s", 170 + (120 - dw) / 2, 212, COLOR_TEXT);
                                }

                                let mut held_ms: u32 = 0;
                                let mut confirmed = false;
                                let mut waiting_for_press = true;
                                loop {
                                    delay.delay_millis(50);
                                    let ts = crate::hw::touch::read_touch(i2c);
                                    match ts {
                                        crate::hw::touch::TouchState::One(pt) => {
                                            if pt.x <= 40 && pt.y <= 40 { break; } // back = cancel
                                            if pt.x >= 170 && pt.x <= 290 && pt.y >= 180 && pt.y <= 230 {
                                                waiting_for_press = false;
                                                held_ms += 50;
                                                let fill = (held_ms * 120 / 4000).min(120);
                                                if fill > 0 {
                                                    use embedded_graphics::primitives::{Rectangle, PrimitiveStyle};
                                                    use embedded_graphics::prelude::*;
                                                    Rectangle::new(
                                                        embedded_graphics::geometry::Point::new(170, 190),
                                                        embedded_graphics::geometry::Size::new(fill, 30))
                                                        .into_styled(PrimitiveStyle::with_fill(
                                                            embedded_graphics::pixelcolor::Rgb565::new(0b11111, 0, 0)))
                                                        .draw(&mut boot_display.display).ok();
                                                }
                                                if held_ms >= 4000 {
                                                    confirmed = true;
                                                    break;
                                                }
                                            } else if !waiting_for_press {
                                                break; // moved off button = cancel
                                            }
                                        }
                                        _ => {
                                            if !waiting_for_press { break; } // released = cancel
                                        }
                                    }
                                }

                                if confirmed {
                                    boot_display.draw_saving_screen("Deleting...");
                                    let del_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        sdcard::delete_file(ct, &fat32, &ad.sd_selected_file)?;
                                        Ok(())
                                    });
                                    sound::stop_ticking();
                                    match del_result {
                                        Ok(()) => {
                                            let mut disp = [0u8; 13];
                                            let dlen = sd_backup::format_83_display(&ad.sd_selected_file, &mut disp);
                                            let name_str = core::str::from_utf8(&disp[..dlen]).unwrap_or("?");
                                            log!("[SD-DELETE] Deleted {}", name_str);
                                            boot_display.draw_success_screen("Backup deleted");
                                            sound::success(delay);
                                            delay.delay_millis(1500);
                                            // Remove from file list
                                            for j in 0..ad.sd_file_count as usize {
                                                if ad.sd_file_list[j] == ad.sd_selected_file {
                                                    for k in j..7 {
                                                        ad.sd_file_list[k] = ad.sd_file_list[k + 1];
                                                    }
                                                    ad.sd_file_list[7] = [b' '; 11];
                                                    ad.sd_file_count -= 1;
                                                    break;
                                                }
                                            }
                                            if ad.sd_file_scroll > 0 && ad.sd_file_scroll >= ad.sd_file_count {
                                                ad.sd_file_scroll = ad.sd_file_count.saturating_sub(4);
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-DELETE] Failed: {}", e);
                                            boot_display.draw_rejected_screen("Delete failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::SdFileList;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdRestorePassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); }
                                5 => { ad.pp_input.push_char(b' '); }
                                6 => { // OK — read from SD and decrypt
                                    boot_display.draw_saving_screen("Reading from SD...");
                                    let pp_bytes_len = ad.pp_input.len;
                                    let mut pp_copy = [0u8; 64];
                                    pp_copy[..pp_bytes_len].copy_from_slice(&ad.pp_input.buf[..pp_bytes_len]);

                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        let mut file_buf = [0u8; 128];
                                        let bytes_read = sdcard::read_file(ct, &fat32, &entry, &mut file_buf)?;
                                        Ok((file_buf, bytes_read))
                                    });

                                    match read_result {
                                        Ok((file_buf, bytes_read)) => {
                                            boot_display.draw_loading_screen("Decrypting...");
                                            let mut restored_indices = [0u16; 24];
                                            match sd_backup::decrypt_backup_progress(
                                                &file_buf[..bytes_read],
                                                &pp_copy[..pp_bytes_len],
                                                &mut restored_indices,
                                                &mut |done, total| {
                                                    let pct = if total > 0 { (done * 80 / total) as u8 } else { 0 };
                                                    boot_display.update_progress_bar(pct);
                                                },
                                            ) {
                                                Ok(wc) => {
                                                    boot_display.update_progress_bar(90);
                                                    ad.mnemonic_indices = [0u16; 24];
                                                    for i in 0..wc as usize {
                                                        ad.mnemonic_indices[i] = restored_indices[i];
                                                    }
                                                    ad.word_count = wc;
                                                    if let Some(slot_idx) = ad.seed_mgr.store(
                                                        &ad.mnemonic_indices, ad.word_count, b"", 0,
                                                    ) {
                                                        ad.seed_mgr.activate(slot_idx);
                                                        (ad.seed_loaded) = true;
                                                        (ad.pubkeys_cached) = false;
                                                        (ad.current_addr_index) = 0;
                                                        (ad.extra_pubkey_index) = 0xFFFF;
                                                        boot_display.update_progress_bar(100);
                                                        log!("[SD-RESTORE] Restored {}-word seed to slot {}", wc, slot_idx);
                                                        boot_display.draw_saving_screen("Seed restored!");
                                                        sound::success(delay);
                                                        delay.delay_millis(2000);
                                                    } else {
                                                        boot_display.draw_rejected_screen("All 4 slots full!");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                Err(_) => {
                                                    log!("[SD-RESTORE] Decrypt failed (wrong password?)");
                                                    boot_display.draw_rejected_screen("Wrong password");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-RESTORE] Read failed: {}", e);
                                            boot_display.draw_rejected_screen("File not found");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    for b in pp_copy.iter_mut() {
                                        unsafe { core::ptr::write_volatile(b, 0); }
                                    }
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::ToolsMenu;
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdXprvExportPassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); }
                                5 => { ad.pp_input.push_char(b' '); }
                                6 => { // OK — derive xprv, encrypt, write to SD
                                    boot_display.draw_saving_screen("Deriving xprv...");
                                    boot_display.update_progress_bar(15);
                                    let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                    let pp_str = ad.seed_mgr.active_slot().map(|s| s.passphrase_str()).unwrap_or("");
                                    let seed_bytes = if ad.word_count == 12 {
                                        let m12 = wallet::bip39::Mnemonic12 {
                                            indices: { let mut arr = [0u16; 12]; arr.copy_from_slice(&ad.mnemonic_indices[..12]); arr }
                                        };
                                        wallet::bip39::seed_from_mnemonic_12(&m12, pp_str)
                                    } else {
                                        let m24 = wallet::bip39::Mnemonic24 {
                                            indices: { let mut arr = [0u16; 24]; arr.copy_from_slice(&ad.mnemonic_indices[..24]); arr }
                                        };
                                        wallet::bip39::seed_from_mnemonic_24(&m24, pp_str)
                                    };
                                    boot_display.update_progress_bar(33);
                                    let mut xprv_buf = [0u8; wallet::xpub::XPRV_MAX_LEN];
                                    match wallet::xpub::derive_and_serialize_xprv(&seed_bytes.bytes, &mut xprv_buf) {
                                        Ok(xlen) => {
                                            boot_display.update_progress_bar(50);
                                            boot_display.draw_saving_screen("Encrypting...");
                                            boot_display.update_progress_bar(50);
                                            let mut nonce = [0u8; 12];
                                            for i in 0..12 {
                                                nonce[i] = unsafe { core::ptr::read_volatile(0x6003_5000 as *const u32) } as u8;
                                            }
                                            let mut enc_buf = [0u8; sd_backup::MAX_XPRV_BACKUP_SIZE];
                                            match sd_backup::encrypt_xprv_backup(&xprv_buf, xlen, pp_bytes, &nonce, &mut enc_buf) {
                                                Ok(enc_len) => {
                                                    boot_display.update_progress_bar(70);
                                                    boot_display.draw_saving_screen("Writing to SD...");
                                                    boot_display.update_progress_bar(70);
                                                    let fp = ad.seed_mgr.active_slot().map(|s| s.fingerprint).unwrap_or([0;4]);
                                                    let fname = sd_backup::xprv_backup_filename(&fp);
                                                    let write_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                        let fat32 = sdcard::mount_fat32(ct)?;
                                                        let _ = sdcard::delete_file(ct, &fat32, &fname);
                                                        sdcard::create_file(ct, &fat32, &fname, &enc_buf[..enc_len])?;
                                                        Ok(())
                                                    });
                                                    match write_result {
                                                        Ok(()) => {
                                                            log!("[SD-XPRV] Wrote {} bytes", enc_len);
                                                            boot_display.draw_success_screen("xprv Saved!");
                                                            sound::success(delay);
                                                            delay.delay_millis(2500);
                                                        }
                                                        Err(e) => {
                                                            log!("[SD-XPRV] Write failed: {}", e);
                                                            boot_display.draw_rejected_screen("SD write failed");
                                                            delay.delay_millis(2000);
                                                        }
                                                    }
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("Encryption failed");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            boot_display.draw_rejected_screen("xprv derivation failed");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    zeroize_buf(&mut xprv_buf);
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::SeedList;
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdXprvFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            let max_vis: usize = 4;
                            let scroll_off = ad.sd_file_scroll as usize;
                            let can_page_up = scroll_off > 0;
                            let can_page_down = (scroll_off + max_vis) < ad.sd_file_count as usize;

                            if x < 40 && y >= 42 && can_page_up {
                                if ad.sd_file_scroll >= max_vis as u8 {
                                    ad.sd_file_scroll -= max_vis as u8;
                                } else {
                                    ad.sd_file_scroll = 0;
                                }
                            } else if x >= 280 && y >= 42 && can_page_down {
                                ad.sd_file_scroll += max_vis as u8;
                            } else {
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = slot as usize + scroll_off;
                                    if idx < (ad.sd_file_count) as usize {
                                        ad.sd_selected_file = ad.sd_file_list[idx];
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdXprvImportPassphrase;
                                    }
                                    break;
                                }
                            }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdXprvImportPassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); }
                                5 => { ad.pp_input.push_char(b' '); }
                                6 => { // OK — read from SD, decrypt, import xprv
                                    boot_display.draw_saving_screen("Reading from SD...");
                                    let pp_bytes_len = ad.pp_input.len;
                                    let mut pp_copy = [0u8; 64];
                                    pp_copy[..pp_bytes_len].copy_from_slice(&ad.pp_input.buf[..pp_bytes_len]);

                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        let mut file_buf = [0u8; 256];
                                        let bytes_read = sdcard::read_file(ct, &fat32, &entry, &mut file_buf)?;
                                        Ok((file_buf, bytes_read))
                                    });

                                    match read_result {
                                        Ok((file_buf, bytes_read)) => {
                                            boot_display.draw_loading_screen("Decrypting xprv...");
                                            let mut xprv_plain = [0u8; 120];
                                            match sd_backup::decrypt_xprv_backup_progress(
                                                &file_buf[..bytes_read],
                                                &pp_copy[..pp_bytes_len],
                                                &mut xprv_plain,
                                                &mut |done, total| {
                                                    let pct = if total > 0 { (done * 70 / total) as u8 } else { 0 };
                                                    boot_display.update_progress_bar(pct);
                                                },
                                            ) {
                                                Ok(xlen) => {
                                                    match wallet::xpub::import_xprv(&xprv_plain[..xlen]) {
                                                        Ok(acct_key) => {
                                                            boot_display.update_progress_bar(75);
                                                            let raw = acct_key.to_raw();
                                                            ad.acct_key_raw.copy_from_slice(&raw);
                                                            boot_display.draw_loading_screen("Deriving addresses...");
                                                            boot_display.update_progress_bar(75);
                                                            let acct = wallet::bip32::ExtendedPrivKey::from_raw(&raw);
                                                            for idx in 0..20u16 {
                                                                if let Ok(addr_key) = wallet::bip32::derive_address_key(&acct, idx) {
                                                                    if let Ok(xpub) = addr_key.public_key_x_only() {
                                                                        ad.pubkey_cache[idx as usize].copy_from_slice(&xpub);
                                                                    }
                                                                }
                                                                boot_display.update_progress_bar(75 + ((idx as u8 + 1) * 25 / 20));
                                                            }
                                                            let mut dummy_indices = [0u16; 24];
                                                            use sha2::{Sha256, Digest};
                                                            let hash = Sha256::digest(acct_key.private_key_bytes());
                                                            let fp = [hash[0], hash[1], hash[2], hash[3]];
                                                            for i in 0..16 {
                                                                dummy_indices[i] = u16::from_le_bytes([raw[i*2], raw[i*2+1]]);
                                                            }
                                                            if let Some(slot_idx) = ad.seed_mgr.find_free() {
                                                                let slot = &mut ad.seed_mgr.slots[slot_idx];
                                                                slot.word_count = 2;
                                                                slot.indices = dummy_indices;
                                                                slot.passphrase[..32].copy_from_slice(&raw[32..64]);
                                                                slot.passphrase[32] = raw[64];
                                                                slot.passphrase_len = 33;
                                                                slot.fingerprint = fp;
                                                                ad.seed_mgr.activate(slot_idx);
                                                                (ad.seed_loaded) = true;
                                                                (ad.pubkeys_cached) = true;
                                                                (ad.current_addr_index) = 0;
                                                                (ad.extra_pubkey_index) = 0xFFFF;
                                                                log!("[SD-XPRV] Imported xprv to slot {}", slot_idx);
                                                                boot_display.draw_saving_screen("XPrv imported!");
                                                                delay.delay_millis(2000);
                                                            } else {
                                                                boot_display.draw_rejected_screen("All 4 slots full!");
                                                                delay.delay_millis(2000);
                                                            }
                                                        }
                                                        Err(_) => {
                                                            boot_display.draw_rejected_screen("Invalid xprv format");
                                                            delay.delay_millis(2000);
                                                        }
                                                    }
                                                    zeroize_buf(&mut xprv_plain);
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("Wrong password");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-XPRV] Read failed: {}", e);
                                            boot_display.draw_rejected_screen("File not found");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    for b in pp_copy.iter_mut() {
                                        unsafe { core::ptr::write_volatile(b, 0); }
                                    }
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::ToolsMenu;
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
