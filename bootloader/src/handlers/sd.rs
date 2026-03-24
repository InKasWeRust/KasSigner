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

#[cfg(not(feature = "silent"))]

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
                        } else if x >= 85 && x <= 235 && y >= 205 {
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
                                            let pct = if total > 0 { (done as u32 * 50 / total as u32) as u8 } else { 0 };
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
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            let mut tapped: Option<usize> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = slot as usize;
                                    if idx < (ad.sd_file_count) as usize {
                                        tapped = Some(idx);
                                    }
                                    break;
                                }
                            }
                            if let Some(i) = tapped {
                                    ad.sd_selected_file = ad.sd_file_list[i];
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
                                            boot_display.draw_saving_screen("Decrypting...");
                                            let mut restored_indices = [0u16; 24];
                                            match sd_backup::decrypt_backup(
                                                &file_buf[..bytes_read],
                                                &pp_copy[..pp_bytes_len],
                                                &mut restored_indices,
                                            ) {
                                                Ok(wc) => {
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
                                                    log!("[SD-RESTORE] Decrypt failed (wrong passphrase?)");
                                                    boot_display.draw_rejected_screen("Wrong passphrase");
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
                                    let mut xprv_buf = [0u8; wallet::xpub::XPRV_MAX_LEN];
                                    match wallet::xpub::derive_and_serialize_xprv(&seed_bytes.bytes, &mut xprv_buf) {
                                        Ok(xlen) => {
                                            boot_display.draw_saving_screen("Encrypting...");
                                            let mut nonce = [0u8; 12];
                                            for i in 0..12 {
                                                nonce[i] = unsafe { core::ptr::read_volatile(0x6003_5000 as *const u32) } as u8;
                                            }
                                            let mut enc_buf = [0u8; sd_backup::MAX_XPRV_BACKUP_SIZE];
                                            match sd_backup::encrypt_xprv_backup(&xprv_buf, xlen, pp_bytes, &nonce, &mut enc_buf) {
                                                Ok(enc_len) => {
                                                    boot_display.draw_saving_screen("Writing to SD...");
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
                                                            boot_display.draw_saving_screen("XPrv saved!");
                                                            delay.delay_millis(2000);
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
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = slot as usize;
                                    if idx < (ad.sd_file_count) as usize {
                                        ad.sd_selected_file = ad.sd_file_list[idx];
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdXprvImportPassphrase;
                                    }
                                    break;
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
                                            boot_display.draw_saving_screen("Decrypting...");
                                            let mut xprv_plain = [0u8; 120];
                                            match sd_backup::decrypt_xprv_backup(
                                                &file_buf[..bytes_read],
                                                &pp_copy[..pp_bytes_len],
                                                &mut xprv_plain,
                                            ) {
                                                Ok(xlen) => {
                                                    match wallet::xpub::import_xprv(&xprv_plain[..xlen]) {
                                                        Ok(acct_key) => {
                                                            let raw = acct_key.to_raw();
                                                            ad.acct_key_raw.copy_from_slice(&raw);
                                                            boot_display.draw_saving_screen("Deriving addresses...");
                                                            let acct = wallet::bip32::ExtendedPrivKey::from_raw(&raw);
                                                            for idx in 0..20u16 {
                                                                if let Ok(addr_key) = wallet::bip32::derive_address_key(&acct, idx) {
                                                                    if let Ok(xpub) = addr_key.public_key_x_only() {
                                                                        ad.pubkey_cache[idx as usize].copy_from_slice(&xpub);
                                                                    }
                                                                }
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
                                                    boot_display.draw_rejected_screen("Wrong passphrase");
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
