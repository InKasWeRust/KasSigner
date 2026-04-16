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

/// Parse a multisig descriptor text of the form "multi(M,hex1,hex2,...,hexN)".
/// Returns (m, n, pubkeys) on success. Each hex is exactly 64 chars (32 bytes x-only).
/// Trailing whitespace/newlines are tolerated.
fn parse_descriptor(
    data: &[u8],
) -> Option<(u8, u8, [[u8; 32]; crate::wallet::transaction::MAX_MULTISIG_KEYS])> {
    // Trim trailing whitespace/newlines
    let mut end = data.len();
    while end > 0 && matches!(data[end - 1], b'\n' | b'\r' | b' ' | b'\t') {
        end -= 1;
    }
    let data = &data[..end];

    // Must start with "multi(" and end with ")"
    let prefix = b"multi(";
    if data.len() < prefix.len() + 2 || &data[..prefix.len()] != prefix {
        return None;
    }
    if data[data.len() - 1] != b')' {
        return None;
    }
    let inner = &data[prefix.len()..data.len() - 1]; // between "multi(" and ")"

    // First field: M (single digit 1..=9)
    if inner.is_empty() || inner[0] < b'1' || inner[0] > b'9' {
        return None;
    }
    let m = inner[0] - b'0';
    if inner.len() < 2 || inner[1] != b',' {
        return None;
    }

    // Remaining: comma-separated 64-char hex strings
    let mut pubkeys = [[0u8; 32]; crate::wallet::transaction::MAX_MULTISIG_KEYS];
    let mut n: u8 = 0;
    let mut pos = 2usize;
    while pos < inner.len() {
        if (n as usize) >= crate::wallet::transaction::MAX_MULTISIG_KEYS {
            return None;
        }
        // Expect 64 hex chars
        if pos + 64 > inner.len() {
            return None;
        }
        let hex_slice = &inner[pos..pos + 64];
        for j in 0..32 {
            let hi = hex_nibble(hex_slice[j * 2]);
            let lo = hex_nibble(hex_slice[j * 2 + 1]);
            if hi == 0xFF || lo == 0xFF {
                return None;
            }
            pubkeys[n as usize][j] = (hi << 4) | lo;
        }
        n += 1;
        pos += 64;
        if pos < inner.len() {
            if inner[pos] != b',' {
                return None;
            }
            pos += 1;
        }
    }

    if n == 0 || m > n {
        return None;
    }
    Some((m, n, pubkeys))
}

/// Check if a file with the given 8.3 name exists on the SD card.
/// Returns true if the file exists, false if not found or on SD error.
fn sd_file_exists(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    name_83: &[u8; 11],
) -> bool {
    sdcard::with_sd_card(i2c, delay, |ct| {
        let fat32 = sdcard::mount_fat32(ct)?;
        sdcard::find_file_in_root(ct, &fat32, name_83)?;
        Ok(())
    }).is_ok()
}

/// Build an 8.3 filename from pp_input buffer with given 3-byte extension.
/// Uppercases the name portion for FAT32 compatibility.
pub(crate) fn build_filename_83(pp_buf: &[u8], pp_len: usize, ext: &[u8; 3]) -> [u8; 11] {
    let mut name = [b' '; 11];
    let len = pp_len.min(8);
    for j in 0..len {
        let c = pp_buf[j];
        name[j] = if c >= b'a' && c <= b'z' { c - 32 } else { c };
    }
    name[8] = ext[0];
    name[9] = ext[1];
    name[10] = ext[2];
    name
}

/// Write data to SD card, replacing any existing file with the same name.
pub(crate) fn write_file_to_sd(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    fname: &[u8; 11],
    data: &[u8],
) -> Result<(), &'static str> {
    sdcard::with_sd_card(i2c, delay, |ct| {
        let fat32 = sdcard::mount_fat32(ct)?;
        let _ = sdcard::delete_file(ct, &fat32, fname);
        sdcard::create_file(ct, &fat32, fname, data)?;
        Ok(())
    })
}

/// Generate a 12-byte nonce from the ESP32-S3 hardware TRNG.
pub(crate) fn generate_trng_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    for i in 0..12 {
        nonce[i] = unsafe {
            core::ptr::read_volatile(0x6003_5000 as *const u32)
        } as u8;
    }
    nonce
}

/// Scan SD card for the highest auto-increment number matching a prefix+extension pattern.
/// Returns the next number (max_found + 1). Prefix is 2 bytes (e.g. "SD", "TX", "XP", "KP", "MS").
pub(crate) fn scan_auto_increment(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    prefix: &[u8; 2],
    ext: &[u8; 3],
) -> u32 {
    let mut max_num: u32 = 0;
    let p0 = prefix[0];
    let p1 = prefix[1];
    let e0 = ext[0];
    let e1 = ext[1];
    let e2 = ext[2];
    let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
        let fat32 = sdcard::mount_fat32(ct)?;
        sdcard::list_root_dir(ct, &fat32, |entry| {
            if entry.name[0] == p0 && entry.name[1] == p1
                && entry.name[8] == e0 && entry.name[9] == e1 && entry.name[10] == e2
            {
                let mut n: u32 = 0;
                let mut valid = true;
                for k in 2..8usize {
                    let c = entry.name[k];
                    if c >= b'0' && c <= b'9' {
                        n = n * 10 + (c - b'0') as u32;
                    } else if c == b' ' {
                        break;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && n > max_num { max_num = n; }
            }
            true
        })?;
        Ok(())
    });
    if scan_ok.is_err() { max_num = 0; }
    max_num + 1
}

/// Format an auto-increment number into an 8.3 name: prefix(2) + zero-padded digits(6) + ext(3).
pub(crate) fn format_auto_name(prefix: &[u8; 2], num: u32, ext: &[u8; 3]) -> [u8; 11] {
    let mut name = [b'0'; 11];
    name[0] = prefix[0];
    name[1] = prefix[1];
    let mut val = num;
    for k in (2..8usize).rev() {
        name[k] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    name[8] = ext[0];
    name[9] = ext[1];
    name[10] = ext[2];
    name
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
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::SdBackupWarning => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else if (85..=235).contains(&x) && y >= 205 {
                            // "I understand" button → filename keyboard first
                            let next = scan_auto_increment(i2c, delay, b"SD", b"KAS");
                            let name = format_auto_name(b"SD", next, b"KAS");
                            ad.kspt_filename = name;
                            ad.pp_input.reset();
                            for j in 0..8usize {
                                if name[j] != b' ' {
                                    ad.pp_input.push_char(name[j]);
                                }
                            }
                            ad.app.state = crate::app::input::AppState::SdSeedFilename;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdSeedFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "SEED FILENAME"); needs_redraw = false; }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "SEED FILENAME"); needs_redraw = false; }
                                6 => {
                                    // OK — build 8.3 filename, extension KAS
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"KAS");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdBackupPassphrase;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdSeedFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdBackupPassphrase;
                                    }
                                }
                                _ => {}
                            }
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
                                    let nonce = generate_trng_nonce();
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
                                            // Use user-chosen filename from SdSeedFilename keyboard
                                            let fname = ad.kspt_filename;
                                            let write_result = write_file_to_sd(i2c, delay, &fname, &backup_buf[..backup_len]);
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
                                    boot_display.draw_loading_screen("Loading...");
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
                                                    boot_display.draw_loading_screen("Importing xprv...");
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
                        // Determine return state based on file extension
                        let is_ksp = ad.sd_selected_file[8] == b'K'
                            && ad.sd_selected_file[9] == b'S'
                            && ad.sd_selected_file[10] == b'P';
                        let return_state = if is_ksp {
                            crate::app::input::AppState::SdKsptFileList
                        } else {
                            crate::app::input::AppState::SdFileList
                        };
                        if is_back {
                            ad.app.state = return_state;
                        } else if (180..=230).contains(&y) {
                            if (30..=150).contains(&x) {
                                // CANCEL
                                ad.app.state = return_state;
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
                                            // CANCEL button zone
                                            if pt.x >= 30 && pt.x <= 150 && pt.y >= 180 && pt.y <= 230 { sound::click(delay); break; }
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
                                ad.app.state = return_state;
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
                                    boot_display.draw_loading_screen("Reading from SD...");
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
                                    ad.app.go_main_menu();
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdXprvFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "XPRV FILENAME"); needs_redraw = false; }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "XPRV FILENAME"); needs_redraw = false; }
                                6 => {
                                    // OK — build 8.3 filename, extension KAS
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"KAS");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdXprvExportPassphrase;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdXprvFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdXprvExportPassphrase;
                                    }
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
                                            let nonce = generate_trng_nonce();
                                            let mut enc_buf = [0u8; sd_backup::MAX_XPRV_BACKUP_SIZE];
                                            match sd_backup::encrypt_xprv_backup(&xprv_buf, xlen, pp_bytes, &nonce, &mut enc_buf) {
                                                Ok(enc_len) => {
                                                    boot_display.update_progress_bar(70);
                                                    boot_display.draw_saving_screen("Writing to SD...");
                                                    boot_display.update_progress_bar(70);
                                                    // Use user-chosen filename from SdXprvFilename keyboard
                                                    let fname = ad.kspt_filename;
                                                    let write_result = write_file_to_sd(i2c, delay, &fname, &enc_buf[..enc_len]);
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
                                    boot_display.draw_loading_screen("Reading from SD...");
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
                    crate::app::input::AppState::SdImportMenu => {
                        if is_back {
                            ad.sd_import_menu.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else if page_up_zone.contains(x, y) && ad.sd_import_menu.can_page_up() {
                            ad.sd_import_menu.page_up();
                        } else if page_down_zone.contains(x, y) && ad.sd_import_menu.can_page_down() {
                            ad.sd_import_menu.page_down();
                        } else {
                            // Chip-row list navigation
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.sd_import_menu.visible_to_absolute(slot);
                                    if abs < ad.sd_import_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                match item {
                                    0 => {
                                        // Seed Backup — scan SD for compatible seed/xprv/key files
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                let mut candidates: [[u8; 11]; 16] = [[b' '; 11]; 16];
                                                let mut cand_count = 0u8;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    if !entry.is_dir()
                                                        && entry.file_size > 0
                                                        && entry.file_size <= 1024
                                                        && (cand_count as usize) < 16
                                                    {
                                                        candidates[cand_count as usize] = entry.name;
                                                        cand_count += 1;
                                                    }
                                                    true
                                                })?;
                                                let mut peek_buf = [0u8; 512];
                                                for c in 0..cand_count as usize {
                                                    if ad.sd_file_count >= 8 { break; }
                                                    let name = &candidates[c];
                                                    if let Ok((entry, _, _)) = sdcard::find_file_in_root(ct, &fat32, name) {
                                                        let cluster = entry.first_cluster();
                                                        if cluster >= 2 {
                                                            let sector = fat32.cluster_to_sector(cluster);
                                                            if sdcard::sd_read_block(ct, sector, &mut peek_buf).is_ok() {
                                                                let sz = entry.file_size as usize;
                                                                let is_enc_seed = sz >= 57 && peek_buf[0] == b'K' && peek_buf[1] == b'A' && peek_buf[2] == b'S' && peek_buf[3] == 0x01;
                                                                let is_enc_xprv = sz >= 40 && peek_buf[0] == b'K' && peek_buf[1] == b'A' && peek_buf[2] == b'S' && peek_buf[3] == 0x02;
                                                                let is_plain_xprv = sz >= 100 && peek_buf[0] == b'x' && peek_buf[1] == b'p' && peek_buf[2] == b'r' && peek_buf[3] == b'v';
                                                                let is_plain_hex = (64..=66).contains(&sz) && {
                                                                    let mut ok = true;
                                                                    for b in &peek_buf[..64.min(sz)] {
                                                                        if !((*b >= b'0' && *b <= b'9') || (*b >= b'a' && *b <= b'f') || (*b >= b'A' && *b <= b'F')) {
                                                                            ok = false; break;
                                                                        }
                                                                    }
                                                                    ok
                                                                };
                                                                if is_enc_seed || is_enc_xprv || is_plain_xprv || is_plain_hex {
                                                                    ad.sd_file_list[ad.sd_file_count as usize] = *name;
                                                                    ad.sd_file_count += 1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No compatible files");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-IMPORT] Scan failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    1 => {
                                        // Transaction — scan SD for .KSP files
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    if !entry.is_dir()
                                                        && entry.file_size > 0
                                                        && entry.file_size <= 1024
                                                        && (ad.sd_file_count as usize) < 8
                                                        && entry.name[8] == b'K'
                                                        && entry.name[9] == b'S'
                                                        && entry.name[10] == b'P'
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .KSP files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-KSPT] Scan failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    2 => {
                                        // kpub — scan SD for .TXT files
                                        ad.txt_import_type = 0;
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    if !entry.is_dir()
                                                        && entry.file_size > 0
                                                        && entry.file_size <= 256
                                                        && (ad.sd_file_count as usize) < 8
                                                        && entry.name[8] == b'T'
                                                        && entry.name[9] == b'X'
                                                        && entry.name[10] == b'T'
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdKpubFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .TXT files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-KPUB] Scan failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    3 => {
                                        // Multisig Address — scan SD for .TXT files
                                        ad.txt_import_type = 1;
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    if !entry.is_dir()
                                                        && entry.file_size > 0
                                                        && entry.file_size <= 256
                                                        && (ad.sd_file_count as usize) < 8
                                                        && entry.name[8] == b'T'
                                                        && entry.name[9] == b'X'
                                                        && entry.name[10] == b'T'
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdKpubFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .TXT files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    4 => {
                                        // Multisig Descriptor — scan SD for .TXT files
                                        ad.txt_import_type = 2;
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    if !entry.is_dir()
                                                        && entry.file_size > 0
                                                        && entry.file_size <= 512
                                                        && (ad.sd_file_count as usize) < 8
                                                        && entry.name[8] == b'T'
                                                        && entry.name[9] == b'X'
                                                        && entry.name[10] == b'T'
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdKpubFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .TXT files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKsptFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::SdImportMenu;
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
                                    // Read .KSP file into signed_qr_buf
                                    boot_display.draw_loading_screen("Loading TX...");
                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        let mut buf = [0u8; 1024];
                                        let n = sdcard::read_file(ct, &fat32, &entry, &mut buf)?;
                                        Ok((buf, n))
                                    });
                                    match read_result {
                                        Ok((buf, n)) => {
                                            // Check if encrypted (KAS\x03)
                                            if n >= 4 && buf[0] == b'K' && buf[1] == b'A' && buf[2] == b'S' && buf[3] == 0x03 {
                                                // Encrypted KSPT — need password
                                                // Store raw file in signed_qr_buf temporarily for decryption
                                                ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                ad.signed_qr_len = n;
                                                ad.kspt_filename = [b' '; 11]; // clear so save/load detection works
                                                ad.pp_input.reset();
                                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                                            } else {
                                                // Plain KSPT — load directly
                                                ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                ad.signed_qr_len = n;
                                                ad.signed_qr_frame = 0;
                                                ad.signed_qr_nframes = 0;
                                                ad.signed_qr_large = false;
                                                ad.tx_sigs_present = 0;
                                                ad.tx_sigs_required = 0;
                                                log!("[SD-KSPT] Loaded {} bytes from SD", n);
                                                boot_display.draw_success_screen("TX loaded!");
                                                sound::success(delay);
                                                delay.delay_millis(1000);
                                                ad.app.state = crate::app::input::AppState::ShowQrFrameChoice;
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-KSPT] Read failed: {}", e);
                                            boot_display.draw_rejected_screen("Read error");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    } // close tapped_delete else
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowQrPopup => {
                        if is_back {
                            ad.signed_qr_nframes = 0;
                            ad.app.go_main_menu();
                        } else {
                            // Two buttons: "Save to SD" and "Back to QR"
                            // Save to SD button zone: center-left area
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Save to SD → filename keyboard
                                let next = scan_auto_increment(i2c, delay, b"TX", b"KSP");
                                let name = format_auto_name(b"TX", next, b"KSP");
                                ad.kspt_filename = name;
                                ad.pp_input.reset();
                                for j in 0..8usize {
                                    if name[j] != b' ' {
                                        ad.pp_input.push_char(name[j]);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::SdKsptFilename;
                            }
                            // Back to QR button zone: center-right area
                            else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                ad.app.state = crate::app::input::AppState::ShowQrModeChoice;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKsptFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ShowQrPopup;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "FILENAME"); needs_redraw = false; }
                                5 => { /* no space in filenames — ignore */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "FILENAME"); needs_redraw = false; }
                                6 => {
                                    // OK — build 8.3 filename from input
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"KSP");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdKsptEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdKsptFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdKsptEncryptAsk;
                                    }
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKsptEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ShowQrPopup;
                        } else {
                            // Two buttons: "Yes" (encrypt) and "No" (plain)
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt: go to password keyboard
                                ad.kspt_encrypt = true;
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain KSPT to SD
                                ad.kspt_encrypt = false;
                                boot_display.draw_saving_screen("Saving to SD...");
                                let data = &ad.signed_qr_buf[..ad.signed_qr_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                sound::stop_ticking();
                                match write_result {
                                    Ok(()) => {
                                        let mut disp = [0u8; 13];
                                        let dlen = sd_backup::format_83_display(&fname, &mut disp);
                                        let name_str = core::str::from_utf8(&disp[..dlen]).unwrap_or("?");
                                        log!("[SD-KSPT] Saved {} bytes as {}", ad.signed_qr_len, name_str);
                                        boot_display.draw_success_screen("Saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("[SD-KSPT] Write failed: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.go_main_menu();
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKpubFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::SdImportMenu;
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
                                let mut tapped: Option<usize> = None;
                                for slot in 0..4u8 {
                                    if list_zones[slot as usize].contains(x, y) {
                                        let idx = slot as usize + scroll_off;
                                        if idx < ad.sd_file_count as usize {
                                            tapped = Some(idx);
                                        }
                                        break;
                                    }
                                }
                                if let Some(i) = tapped {
                                    ad.sd_selected_file = ad.sd_file_list[i];
                                    let load_label = match ad.txt_import_type {
                                        0 => "Reading kpub...",
                                        1 => "Reading address...",
                                        2 => "Reading descriptor...",
                                        _ => "Reading file...",
                                    };
                                    boot_display.draw_loading_screen(load_label);
                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        let mut buf = [0u8; 512];
                                        let n = sdcard::read_file(ct, &fat32, &entry, &mut buf)?;
                                        Ok((buf, n))
                                    });
                                    match read_result {
                                        Ok((buf, n)) => {
                                            match ad.txt_import_type {
                                                0 => {
                                                    // kpub — display as multi-frame QR
                                                    if n > 0 && n <= wallet::xpub::KPUB_MAX_LEN {
                                                        ad.kpub_data[..n].copy_from_slice(&buf[..n]);
                                                        ad.kpub_len = n;
                                                        ad.kpub_frame = 0;
                                                        ad.kpub_nframes = 0;
                                                        ad.app.state = crate::app::input::AppState::ExportKpub;
                                                    } else {
                                                        boot_display.draw_rejected_screen("Invalid kpub file");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                1 => {
                                                    // Multisig address — display as fullscreen QR.
                                                    // kpub_data is only 120 bytes; clamp size to the smallest
                                                    // of all destination buffers to prevent overflow if the
                                                    // file on SD is corrupted or unexpectedly large.
                                                    let max_addr_len = wallet::xpub::KPUB_MAX_LEN
                                                        .min(buf.len())
                                                        .min(ad.signed_qr_buf.len());
                                                    if n > 0 && n <= max_addr_len {
                                                        ad.kpub_data[..n].copy_from_slice(&buf[..n]);
                                                        ad.kpub_len = n;
                                                        // Store address in signed_qr_buf for the
                                                        // MultisigShowAddressQR redraw to render.
                                                        // ms_creating.active remains false — signals
                                                        // SD-loaded flow (no save popup, tap=back).
                                                        ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                        ad.signed_qr_len = n;
                                                        ad.signed_qr_frame = 0;
                                                        ad.signed_qr_nframes = 0;
                                                        ad.signed_qr_large = false;
                                                        boot_display.draw_success_screen("Address loaded!");
                                                        sound::success(delay);
                                                        delay.delay_millis(1000);
                                                        ad.app.state = crate::app::input::AppState::MultisigShowAddressQR;
                                                    } else {
                                                        boot_display.draw_rejected_screen("Invalid address file");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                2 => {
                                                    // Multisig descriptor — parse and show participant summary.
                                                    // Note: buf is 512 bytes. Parse directly from buf — descriptor
                                                    // data does not need to be stashed in kpub_data (which is only
                                                    // 120 bytes and would overflow for N≥2 descriptors).
                                                    if n > 0 && n <= 400 && n <= buf.len() {
                                                        let text = core::str::from_utf8(&buf[..n]).unwrap_or("?");
                                                        log!("[SD-DESC] Loaded: {}", text);
                                                        if let Some((m, nn, pubkeys)) = parse_descriptor(&buf[..n]) {
                                                            // Populate ms_creating (view-only: .active stays false)
                                                            ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                                            ad.ms_creating.m = m;
                                                            ad.ms_creating.n = nn;
                                                            ad.ms_creating.pubkeys = pubkeys;
                                                            // Build script so "SHOW QR" and the derived
                                                            // address (if ever computed from this view)
                                                            // match the live flow.
                                                            ad.ms_creating.build_script();
                                                            boot_display.draw_success_screen("Descriptor loaded!");
                                                            sound::success(delay);
                                                            delay.delay_millis(1000);
                                                            ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                                                        } else {
                                                            boot_display.draw_rejected_screen("Bad descriptor format");
                                                            delay.delay_millis(2000);
                                                            // Bailout to main menu on parse failure —
                                                            // prevents re-tapping the same bad file.
                                                            ad.app.go_main_menu();
                                                        }
                                                    } else {
                                                        boot_display.draw_rejected_screen("Invalid descriptor");
                                                        delay.delay_millis(2000);
                                                        ad.app.go_main_menu();
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-TXT] Read failed: {}", e);
                                            boot_display.draw_rejected_screen("SD read error");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKpubFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "KPUB FILENAME"); needs_redraw = false; }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "KPUB FILENAME"); needs_redraw = false; }
                                6 => {
                                    // OK — build 8.3 filename, extension TXT
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"TXT");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdKpubEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdKpubFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdKpubEncryptAsk;
                                    }
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdMsAddrFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "ADDRESS FILENAME"); needs_redraw = false; }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "ADDRESS FILENAME"); needs_redraw = false; }
                                6 => {
                                    // OK — build 8.3 filename, extension TXT
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"TXT");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdMsAddrEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdMsAddrFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdMsAddrEncryptAsk;
                                    }
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdMsAddrEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                        } else {
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt: copy address into signed_qr_buf, reuse KSPT encrypt path
                                let addr_len = ad.kpub_len;
                                ad.signed_qr_buf[..addr_len].copy_from_slice(&ad.kpub_data[..addr_len]);
                                ad.signed_qr_len = addr_len;
                                ad.sd_txt_origin = 0; // multisig address
                                // kspt_filename already has TXT extension — SdKsptEncryptPass
                                // will detect TXT and return to MultisigDescriptor after save
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain address to SD
                                boot_display.draw_saving_screen("Saving address...");
                                let data = &ad.kpub_data[..ad.kpub_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                match write_result {
                                    Ok(()) => {
                                        boot_display.draw_success_screen("Address saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("SD ms-addr write error: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdMsDescFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "DESCRIPTOR FILENAME"); needs_redraw = false; }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "DESCRIPTOR FILENAME"); needs_redraw = false; }
                                6 => {
                                    // OK — build 8.3 filename, extension TXT
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"TXT");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdMsDescEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdMsDescFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdMsDescEncryptAsk;
                                    }
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdMsDescEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                        } else {
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt: descriptor is already staged in signed_qr_buf
                                // by the SD CARD button in tx.rs. Just set origin and go.
                                ad.sd_txt_origin = 2; // multisig descriptor
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain descriptor to SD (from signed_qr_buf)
                                boot_display.draw_saving_screen("Saving descriptor...");
                                let data = &ad.signed_qr_buf[..ad.signed_qr_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                match write_result {
                                    Ok(()) => {
                                        boot_display.draw_success_screen("Descriptor saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("SD ms-desc write error: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKsptEncryptPass => {
                        if is_back {
                            ad.pp_input.reset();
                            // If we came from file list (loading encrypted), go back to file list
                            // If we came from encrypt-ask (saving), go back to popup
                            // Detect by checking kspt_encrypt flag context:
                            // When loading, kspt_filename is still [' '; 11] or irrelevant
                            // Simplest: always go back to import menu when loading, popup when saving
                            if ad.kspt_filename[8] == b'K' && ad.kspt_filename[9] == b'S' && ad.kspt_filename[10] == b'P' {
                                // KSPT save → back to encrypt ask
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptAsk;
                            } else if ad.kspt_filename[8] == b'T' && ad.kspt_filename[9] == b'X' && ad.kspt_filename[10] == b'T' {
                                // TXT encrypt → back to the relevant encrypt-ask
                                if ad.sd_txt_origin == 1 {
                                    ad.app.state = crate::app::input::AppState::SdKpubEncryptAsk;
                                } else if ad.sd_txt_origin == 2 {
                                    ad.app.state = crate::app::input::AppState::SdMsDescEncryptAsk;
                                } else {
                                    ad.app.state = crate::app::input::AppState::SdMsAddrEncryptAsk;
                                }
                            } else {
                                // Loading an encrypted file
                                ad.app.state = crate::app::input::AppState::SdKsptFileList;
                            }
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); needs_redraw = false; }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); needs_redraw = false; }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); needs_redraw = false; }
                                6 => {
                                    // OK — check if we're encrypting (save) or decrypting (load)
                                    let is_ksp = ad.kspt_filename[8] == b'K' && ad.kspt_filename[9] == b'S' && ad.kspt_filename[10] == b'P';
                                    let is_txt = ad.kspt_filename[8] == b'T' && ad.kspt_filename[9] == b'X' && ad.kspt_filename[10] == b'T';
                                    if is_ksp || is_txt {
                                        // SAVING: encrypt signed_qr_buf and write to SD
                                        boot_display.draw_saving_screen("Encrypting...");
                                        let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                        let nonce = generate_trng_nonce();
                                        let data_len = ad.signed_qr_len;
                                        // Encrypt in a temp buffer: KAS\x03 + len(2B LE) + nonce(12) + ciphertext + tag(16)
                                        let enc_size = 4 + 2 + 12 + data_len + 16;
                                        if enc_size <= 1024 {
                                            let mut enc_buf = [0u8; 1024];
                                            enc_buf[0] = b'K'; enc_buf[1] = b'A'; enc_buf[2] = b'S'; enc_buf[3] = 0x03;
                                            enc_buf[4] = (data_len & 0xFF) as u8;
                                            enc_buf[5] = ((data_len >> 8) & 0xFF) as u8;
                                            enc_buf[6..18].copy_from_slice(&nonce);
                                            enc_buf[18..18 + data_len].copy_from_slice(&ad.signed_qr_buf[..data_len]);

                                            // Derive key via PBKDF2
                                            let aes_key = sd_backup::pbkdf2_key_for_kspt(pp_bytes, &mut |done, total| {
                                                let pct = if total > 0 { (done * 50 / total) as u8 } else { 0 };
                                                boot_display.update_progress_bar(pct);
                                            });

                                            use aes_gcm::{Aes256Gcm, aead::{AeadInPlace, KeyInit, generic_array::GenericArray}};
                                            let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
                                            let nonce_ga = GenericArray::from_slice(&nonce);
                                            let aad = [b'K', b'A', b'S', 0x03, enc_buf[4], enc_buf[5]];

                                            match cipher.encrypt_in_place_detached(
                                                nonce_ga, &aad, &mut enc_buf[18..18 + data_len]
                                            ) {
                                                Ok(tag) => {
                                                    enc_buf[18 + data_len..18 + data_len + 16].copy_from_slice(&tag);
                                                    boot_display.update_progress_bar(70);
                                                    boot_display.draw_saving_screen("Writing to SD...");
                                                    let fname = ad.kspt_filename;
                                                    let write_result = write_file_to_sd(i2c, delay, &fname, &enc_buf[..enc_size]);
                                                    sound::stop_ticking();
                                                    match write_result {
                                                        Ok(()) => {
                                                            boot_display.update_progress_bar(100);
                                                            let mut disp_buf = [0u8; 13];
                                                            let dlen = sd_backup::format_83_display(&fname, &mut disp_buf);
                                                            let name_str = core::str::from_utf8(&disp_buf[..dlen]).unwrap_or("?");
                                                            log!("[SD-KSPT] Encrypted {} bytes as {}", data_len, name_str);
                                                            boot_display.draw_success_screen("Saved!");
                                                            sound::success(delay);
                                                            delay.delay_millis(1500);
                                                        }
                                                        Err(e) => {
                                                            log!("[SD-KSPT] Write failed: {}", e);
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
                                            zeroize_buf(&mut enc_buf[..64]);
                                        } else {
                                            boot_display.draw_rejected_screen("TX too large");
                                            delay.delay_millis(2000);
                                        }
                                        ad.pp_input.reset();
                                        if is_txt {
                                            if ad.sd_txt_origin == 1 {
                                                ad.app.state = crate::app::input::AppState::ExportChoice;
                                            } else {
                                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                                            }
                                        } else {
                                            ad.app.go_main_menu();
                                        }
                                    } else {
                                        // LOADING: decrypt encrypted KSPT from signed_qr_buf
                                        boot_display.draw_loading_screen("Decrypting TX...");
                                        let pp_bytes_len = ad.pp_input.len;
                                        let mut pp_copy = [0u8; 64];
                                        pp_copy[..pp_bytes_len].copy_from_slice(&ad.pp_input.buf[..pp_bytes_len]);

                                        let file_len = ad.signed_qr_len;
                                        if file_len >= 4 + 2 + 12 + 1 + 16
                                            && ad.signed_qr_buf[0] == b'K'
                                            && ad.signed_qr_buf[3] == 0x03
                                        {
                                            let data_len = ad.signed_qr_buf[4] as usize
                                                | ((ad.signed_qr_buf[5] as usize) << 8);
                                            let expected = 4 + 2 + 12 + data_len + 16;
                                            if expected <= file_len && data_len <= 1024 - 34 {
                                                let nonce_sl = &ad.signed_qr_buf[6..18];
                                                let ct_start = 18usize;
                                                let tag_start = ct_start + data_len;

                                                let aes_key = sd_backup::pbkdf2_key_for_kspt(
                                                    &pp_copy[..pp_bytes_len],
                                                    &mut |done, total| {
                                                        let pct = if total > 0 { (done * 70 / total) as u8 } else { 0 };
                                                        boot_display.update_progress_bar(pct);
                                                    },
                                                );

                                                use aes_gcm::{Aes256Gcm, aead::{AeadInPlace, KeyInit, generic_array::GenericArray}};
                                                let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
                                                let nonce_ga = GenericArray::from_slice(nonce_sl);
                                                let tag = GenericArray::from_slice(&ad.signed_qr_buf[tag_start..tag_start + 16]);
                                                let aad = [b'K', b'A', b'S', 0x03,
                                                           ad.signed_qr_buf[4], ad.signed_qr_buf[5]];

                                                // Decrypt in-place over the ciphertext area
                                                let mut plain = [0u8; 1024];
                                                plain[..data_len].copy_from_slice(
                                                    &ad.signed_qr_buf[ct_start..ct_start + data_len]);

                                                match cipher.decrypt_in_place_detached(
                                                    nonce_ga, &aad, &mut plain[..data_len], tag
                                                ) {
                                                    Ok(()) => {
                                                        ad.signed_qr_buf[..data_len].copy_from_slice(&plain[..data_len]);
                                                        ad.signed_qr_len = data_len;
                                                        ad.signed_qr_frame = 0;
                                                        ad.signed_qr_nframes = 0;
                                                        ad.signed_qr_large = false;
                                                        ad.tx_sigs_present = 0;
                                                        ad.tx_sigs_required = 0;
                                                        log!("[SD-KSPT] Decrypted {} bytes", data_len);
                                                        boot_display.draw_success_screen("TX loaded!");
                                                        sound::success(delay);
                                                        delay.delay_millis(1000);
                                                        ad.app.state = crate::app::input::AppState::ShowQrFrameChoice;
                                                    }
                                                    Err(_) => {
                                                        boot_display.draw_rejected_screen("Wrong password");
                                                        sound::beep_error(delay);
                                                        delay.delay_millis(2000);
                                                        ad.signed_qr_len = 0;
                                                        ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                                    }
                                                }
                                                zeroize_buf(&mut plain[..64]);
                                            } else {
                                                boot_display.draw_rejected_screen("Invalid file");
                                                delay.delay_millis(2000);
                                                ad.signed_qr_len = 0;
                                                ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("Invalid file");
                                            delay.delay_millis(2000);
                                            ad.signed_qr_len = 0;
                                            ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                        }
                                        for b in pp_copy.iter_mut() {
                                            unsafe { core::ptr::write_volatile(b, 0); }
                                        }
                                        ad.pp_input.reset();
                                    }
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowQrModeChoice => {
                        if is_back {
                            ad.signed_qr_nframes = 0;
                            ad.app.go_main_menu();
                        } else {
                            // "Auto Cycle" button: left
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                ad.qr_manual_frames = false;
                                ad.app.state = crate::app::input::AppState::ShowQR;
                            }
                            // "Manual" button: right
                            else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                ad.qr_manual_frames = true;
                                ad.signed_qr_frame = 0;
                                ad.app.state = crate::app::input::AppState::ShowQR;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdOverwriteWarning => {
                        if is_back {
                            // Return to the filename keyboard that brought us here
                            ad.app.state = ad.sd_overwrite_back;
                        } else {
                            // "Yes" button — left: proceed with overwrite
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                ad.pp_input.reset();
                                ad.app.state = ad.sd_overwrite_next;
                            }
                            // "No" button — right: return to filename keyboard
                            else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                ad.app.state = ad.sd_overwrite_back;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKpubEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ExportChoice;
                        } else {
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt: copy kpub into signed_qr_buf, reuse KSPT encrypt path
                                let kpub_len = ad.kpub_len;
                                ad.signed_qr_buf[..kpub_len].copy_from_slice(&ad.kpub_data[..kpub_len]);
                                ad.signed_qr_len = kpub_len;
                                ad.sd_txt_origin = 1; // kpub
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain kpub to SD
                                boot_display.draw_saving_screen("Saving kpub...");
                                let data = &ad.kpub_data[..ad.kpub_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                match write_result {
                                    Ok(()) => {
                                        boot_display.draw_success_screen("kpub saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("SD kpub write error: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::ExportChoice;
                            }
                        }
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
