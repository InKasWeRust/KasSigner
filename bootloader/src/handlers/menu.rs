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

// handlers/menu.rs — Touch handlers for MainMenu, SeedsMenu, ToolsMenu
//                     DiceRoll, ChooseWordCount, ShowQR/Rejected/ViewSeed

use crate::log;
use crate::{app::data::AppData, hw::display, hw::sdcard, hw::sound, ui::setup_wizard, hw::touch, wallet};
use esp_hal::lcd_cam::cam::Camera as DvpCamera;
use esp_hal::dma::DmaRxBuf;

/// Handle touch events for menu screens (MainMenu, SeedsMenu, ToolsMenu, etc.).
#[inline(never)]
pub fn handle_menu_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    _bb_card_type: &Option<sdcard::SdCardType>,
    dvp_camera_opt: &mut Option<DvpCamera<'_>>,
    cam_dma_buf_opt: &mut Option<DmaRxBuf>,
    grid_zones: &[touch::TouchZone; 4],
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::MainMenu => {
                        // Check 2x2 grid zones
                        for (idx, zone) in grid_zones.iter().enumerate() {
                            if zone.contains(x, y) && (idx as u8) < ad.app.menu.count {
                                ad.app.menu.cursor = idx as u8;
                                let evt = crate::app::input::ButtonEvent::LongPress;
                                ad.app.handle_boot(evt);
                                needs_redraw = true;
                                break;
                            }
                        }
                    }
                    // Sub-menus: list touch handling
                    crate::app::input::AppState::SeedsMenu => {
                        if is_back {
                            ad.app.go_main_menu();
                            needs_redraw = true;
                        } else {
                            ad.app.state = crate::app::input::AppState::SeedList;
                            needs_redraw = true;
                        }
                    }
                    crate::app::input::AppState::ToolsMenu => {
                        if is_back {
                            ad.tools_menu.reset();
                            ad.app.go_main_menu();
                            needs_redraw = true;
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.tools_menu.visible_to_absolute(slot);
                                    if abs < ad.tools_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                needs_redraw = true;
                                match item {
                                    0 => {
                                        ad.seed_tools_menu.reset();
                                        ad.app.state = crate::app::input::AppState::SeedToolsMenu;
                                    }
                                    1 => {
                                        ad.app.state = crate::app::input::AppState::ImportExportChoice;
                                    }
                                    2 => {
                                        ad.single_sig_menu.reset();
                                        ad.app.state = crate::app::input::AppState::SingleSigMenu;
                                    }
                                    3 => {
                                        ad.multisig_menu.reset();
                                        ad.app.state = crate::app::input::AppState::MultisigMenu;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::SeedToolsMenu => {
                        if is_back {
                            ad.seed_tools_menu.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else if page_up_zone.contains(x, y) && ad.seed_tools_menu.can_page_up() {
                            ad.seed_tools_menu.page_up();
                            needs_redraw = true;
                        } else if page_down_zone.contains(x, y) && ad.seed_tools_menu.can_page_down() {
                            ad.seed_tools_menu.page_down();
                            needs_redraw = true;
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.seed_tools_menu.visible_to_absolute(slot);
                                    if abs < ad.seed_tools_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                needs_redraw = true;
                                match item {
                                    0 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 0 }; } // New Seed
                                    1 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 1 }; } // Dice Seed
                                    2 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 5 }; } // Touch Seed
                                    3 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 2 }; } // Import Words
                                    4 => { // Address
                                        if ad.seed_loaded {
                                            // Derive pubkeys if not cached
                                            if !ad.pubkeys_cached {
                                                let slot_wc = ad.seed_mgr.active_slot().map(|s| s.word_count).unwrap_or(0);
                                                if slot_wc == 1 {
                                                    // Kind-checked (H-08).
                                                    if let Some(mut key) = ad.seed_mgr.active_slot()
                                                        .and_then(|s| s.as_raw_key())
                                                    {
                                                        if let Ok(xpub) = wallet::bip32::pubkey_from_raw_key(&key) {
                                                            ad.pubkey_cache[0].copy_from_slice(&xpub);
                                                        }
                                                        for b in key.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } }
                                                        ad.pubkeys_cached = true;
                                                    }
                                                } else if slot_wc == 2 {
                                                    boot_display.draw_saving_screen("Deriving addresses...");
                                                    let acct = wallet::bip32::ExtendedPrivKey::from_raw(&ad.acct_key_raw);
                                                    for idx in 0..20u16 {
                                                        if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                            if let Ok(pk) = ak.public_key_x_only() {
                                                                ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                            }
                                                        }
                                                    }
                                                    crate::app::signing::derive_change_pubkeys(
                                                        &ad.acct_key_raw, &mut ad.change_pubkey_cache);
                                                    ad.pubkeys_cached = true;
                                                } else {
                                                    boot_display.draw_saving_screen("Deriving...");
                                                    let pp = ad.seed_mgr.active_slot().map(|s: &crate::ui::seed_manager::SeedSlot| s.passphrase_str()).unwrap_or("");
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
                                                    if let Ok(acct) = wallet::bip32::derive_account_key(&seed_bytes.bytes) {
                                                        ad.acct_key_raw.copy_from_slice(&acct.to_raw());
                                                        for idx in 0..20u16 {
                                                            if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                                if let Ok(pk) = ak.public_key_x_only() {
                                                                    ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                                }
                                                            }
                                                        }
                                                        crate::app::signing::derive_change_pubkeys(
                                                            &ad.acct_key_raw, &mut ad.change_pubkey_cache);
                                                        ad.pubkeys_cached = true;
                                                    }
                                                }
                                            }
                                            ad.scanned_addr_len = 0;
                                            ad.address_return = crate::app::input::AppState::SeedToolsMenu;
                                            ad.app.state = crate::app::input::AppState::ShowAddress;
                                        } else {
                                            boot_display.draw_rejected_screen("Load a seed first");
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    5 => { // BIP85 Child
                                        if ad.seed_loaded {
                                            ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 4 };
                                        } else {
                                            boot_display.draw_rejected_screen("Load a seed first");
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    6 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 3 }; } // Calc Last Word
                                    _ => {}
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::ImportExportChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else if (22..=152).contains(&x) && (100..=155).contains(&y) {
                            // Import button
                            ad.import_menu.reset();
                            ad.app.state = crate::app::input::AppState::ImportMenu;
                            needs_redraw = true;
                        } else if (168..=298).contains(&x) && (100..=155).contains(&y) {
                            // Export button → existing ExportChoice
                            if ad.seed_loaded {
                                ad.export_menu.reset();
                                ad.app.state = crate::app::input::AppState::ExportChoice;
                            } else {
                                boot_display.draw_rejected_screen("Load a seed first");
                                delay.delay_millis(1500);
                            }
                            needs_redraw = true;
                        }
                    }
                    crate::app::input::AppState::ImportMenu => {
                        if is_back {
                            ad.import_menu.reset();
                            ad.app.state = crate::app::input::AppState::ImportExportChoice;
                            needs_redraw = true;
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.import_menu.visible_to_absolute(slot);
                                    if abs < ad.import_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                needs_redraw = true;
                                match item {
                                    0 => { // Import from SD
                                        ad.sd_import_menu.reset();
                                        ad.app.state = crate::app::input::AppState::SdImportMenu;
                                    }
                                    1 => { // Stego Import
                                        boot_display.draw_loading_screen("Scanning SD...");
                                        ad.import_jpeg_count = 0;
                                        let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
                                            let fat32 = sdcard::mount_fat32(ct)?;
                                            sdcard::list_root_dir_lfn(ct, &fat32, |entry, disp_name, disp_len| {
                                                if !entry.is_dir() && entry.file_size > 0
                                                    && (ad.import_jpeg_count as usize) < crate::app::data::SD_FILE_LIST_MAX {
                                                    let ext = &entry.name[8..11];
                                                    let first = entry.name[0];
                                                    let is_hidden = first == b'.' || first == b'_' || first == 0xE5;
                                                    if !is_hidden && (ext == b"JPG" || ext == b"jpg"
                                                        || ext == b"JPE" || ext == b"jpe") {
                                                        let idx = ad.import_jpeg_count as usize;
                                                        ad.import_jpeg_names[idx] = entry.name;
                                                        let cl = disp_len.min(32);
                                                        ad.import_jpeg_display[idx] = [0u8; 32];
                                                        ad.import_jpeg_display[idx][..cl].copy_from_slice(&disp_name[..cl]);
                                                        ad.import_jpeg_disp_lens[idx] = cl as u8;
                                                        ad.import_jpeg_count += 1;
                                                    }
                                                }
                                                true
                                            })?;
                                            Ok(())
                                        });
                                        if scan_ok.is_err() || ad.import_jpeg_count == 0 {
                                            boot_display.draw_rejected_screen("No .JPG files on SD");
                                            delay.delay_millis(2000);
                                        } else {
                                            ad.import_jpeg_selected = 0;
                                            ad.app.state = crate::app::input::AppState::StegoImportPick;
                                        }
                                    }
                                    2 => { // Import Raw Key
                                        ad.hex_input_len = 0;
                                        ad.app.state = crate::app::input::AppState::ImportPrivKey;
                                    }
                                    3 => { // Covenant Restore — scan SD for .COV files
                                        boot_display.draw_loading_screen("Scanning SD...");
                                        ad.sd_file_count = 0;
                                        ad.sd_file_scroll = 0;
                                        let _ = sdcard::with_sd_card(i2c, delay, |ct| {
                                            let fat32 = sdcard::mount_fat32(ct)?;
                                            sdcard::list_root_dir(ct, &fat32, |entry| {
                                                let is_hidden = entry.name[0] == b'.' || entry.name[0] == 0xE5 || entry.name[0] == b'_';
                                                let ext = [entry.name[8], entry.name[9], entry.name[10]];
                                                if !entry.is_dir()
                                                    && !is_hidden
                                                    && entry.file_size > 0
                                                    && entry.file_size <= 1024
                                                    && (ad.sd_file_count as usize) < crate::app::data::SD_FILE_LIST_MAX
                                                    && ext == *b"COV"
                                                {
                                                    ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                    ad.sd_file_count += 1;
                                                }
                                                true
                                            })?;
                                            Ok(())
                                        });
                                        if ad.sd_file_count > 0 {
                                            ad.app.state = crate::app::input::AppState::SdFileList;
                                        } else {
                                            boot_display.draw_rejected_screen("No .COV files on SD");
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::SingleSigMenu => {
                        if is_back {
                            ad.single_sig_menu.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.single_sig_menu.visible_to_absolute(slot);
                                    if abs < ad.single_sig_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                needs_redraw = true;
                                match item {
                                    0 => { // Sign TX
                                        if ad.seed_loaded && !ad.pubkeys_cached {
                                            {
                                                boot_display.display.clear(crate::hw::display::COLOR_BG).ok();
                                                let tw = crate::hw::display::measure_header("DERIVING");
                                                crate::hw::display::draw_oswald_header(&mut boot_display.display, "DERIVING", (320 - tw) / 2, 90, crate::hw::display::KASPA_TEAL);
                                                let mw = crate::hw::display::measure_body("Deriving addresses...");
                                                crate::hw::display::draw_lato_body(&mut boot_display.display, "Deriving addresses...", (320 - mw) / 2, 120, crate::hw::display::COLOR_TEXT_DIM);
                                                use embedded_graphics::primitives::{Rectangle, PrimitiveStyle};
                                                use embedded_graphics::prelude::*;
                                                Rectangle::new(Point::new(40, 145), Size::new(240, 10))
                                                    .into_styled(PrimitiveStyle::with_fill(crate::hw::display::COLOR_CARD))
                                                    .draw(&mut boot_display.display).ok();
                                                Rectangle::new(Point::new(40, 145), Size::new(120, 10))
                                                    .into_styled(PrimitiveStyle::with_fill(crate::hw::display::KASPA_ACCENT))
                                                    .draw(&mut boot_display.display).ok();
                                                let ww = crate::hw::display::measure_body("Deriving...");
                                                crate::hw::display::draw_lato_body(&mut boot_display.display, "Deriving...", (320 - ww) / 2, 172, crate::hw::display::COLOR_TEXT_DIM);
                                            }
                                            // Dispatches on word_count: xprv and
                                            // raw-key slots must not go through
                                            // derive_all_pubkeys, whose packed key
                                            // bytes are not BIP39 word indices.
                                            // Sets pubkeys_cached only on success.
                                            crate::app::signing::fill_display_caches(ad);
                                        }
                                        ad.app.state = crate::app::input::AppState::SignTxGuide;
                                    }
                                    1 => { // Sign Message
                                        let has_seed = ad.seed_loaded;
                                        if !has_seed {
                                            boot_display.draw_rejected_screen("No seed loaded");
                                            sound::beep_error(delay);
                                            delay.delay_millis(1500);
                                        } else {
                                            ad.pp_input.reset();
                                            ad.jpeg_desc_len = 0;
                                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                                        }
                                    }
                                    2 => { // Commit Secret
                                        let has_seed = ad.seed_loaded;
                                        if !has_seed {
                                            boot_display.draw_rejected_screen("No seed loaded");
                                            sound::beep_error(delay);
                                            delay.delay_millis(1500);
                                        } else {
                                            ad.pp_input.reset();
                                            ad.jpeg_desc_len = 0;
                                            ad.cr_ciphertext.clear();
                                            ad.cr_hash = [0u8; 32];
                                            ad.app.state = crate::app::input::AppState::CommitRevealType;
                                        }
                                    }
                                    3 => { // Decrypt Secret
                                        let has_seed = ad.seed_loaded;
                                        if !has_seed {
                                            boot_display.draw_rejected_screen("No seed loaded");
                                            sound::beep_error(delay);
                                            delay.delay_millis(1500);
                                        } else {
                                            ad.cr_ciphertext.clear();
                                            ad.jpeg_desc_len = 0;
                                            ad.app.state = crate::app::input::AppState::DecryptSecretScan;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::MultisigMenu => {
                        if is_back {
                            ad.multisig_menu.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.multisig_menu.visible_to_absolute(slot);
                                    if abs < ad.multisig_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                needs_redraw = true;
                                match item {
                                    0 => { // Create Multisig
                                        ad.ms_m = 2;
                                        ad.ms_n = 3;
                                        ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                        ad.app.state = crate::app::input::AppState::MultisigChooseMN;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    #[cfg(feature = "icon-browser")]
                    crate::app::input::AppState::IconBrowser { page } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            let nav = crate::ui::icon_browser::hit_nav(x, y);
                            if nav < 0 && page > 0 {
                                ad.app.state = crate::app::input::AppState::IconBrowser { page: page - 1 };
                            } else if nav > 0 {
                                let max_page = (crate::ui::icon_browser::ICON_COUNT + 7) / 8;
                                if page + 1 < max_page {
                                    ad.app.state = crate::app::input::AppState::IconBrowser { page: page + 1 };
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::DiceRoll => {
                        if is_back {
                            // Cancel dice roll, go to tools menu
                            ad.dice_collector.count = 0;
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else {
                            // Check dice buttons: Row 1 y=70..135, Row 2 y=135..200
                            let dice_x: [u16; 3] = [10, 110, 210];
                            let dice_y: [u16; 2] = [70, 135];
                            let dw: u16 = 100;
                            let dh: u16 = 65;
                            let mut tapped_die: Option<u8> = None;

                            for val in 1u8..=6 {
                                let row = ((val - 1) / 3) as usize;
                                let col = ((val - 1) % 3) as usize;
                                let dx = dice_x[col];
                                let dy = dice_y[row];
                                if x >= dx && x < dx + dw && y >= dy && y < dy + dh {
                                    tapped_die = Some(val);
                                    break;
                                }
                            }

                            if let Some(val) = tapped_die {
                                ad.dice_collector.add_roll(val);
                                // Progress only, never the value. The die values
                                // ARE the seed entropy: anyone capturing serial
                                // while a user rolls reproduces the wallet.
                                //
                                // Through 1.0.4 this line printed `val`, and
                                // `production` was enabled in no documented
                                // build (P-08), so it reached the wire in every
                                // published binary. Both halves are closed as of
                                // 1.0.5: the value is gone from here, and all six
                                // Dockerfile image stages now build with
                                // `--features production`, which implies `silent`
                                // and compiles `log!` out altogether. The line
                                // below therefore exists only in dev builds.
                                //
                                // Reported externally by `kas-builder` in PR #1
                                // against InKasWeRust/KasSigner, their first
                                // pull request. M-16.
                                log!("   Dice roll entered ({}/{})",
                                    ad.dice_collector.count, ad.dice_collector.target);

                                if ad.dice_collector.is_complete() {
                                    // Generate seed from dice
                                    boot_display.draw_saving_screen("Generating seed...");
                                    let wc = if ad.dice_collector.target >= 198 { 24u8 } else { 12u8 };
                                    let mut wizard = setup_wizard::SetupWizard::new();
                                    wizard.word_count = wc;
                                    wizard.dice = core::mem::replace(
                                        &mut ad.dice_collector,
                                        setup_wizard::DiceCollector::new_12_word(),
                                    );
                                    wizard.generate_from_dice();
                                    ad.mnemonic_indices = wizard.mnemonic;
                                    ad.word_count = wc;
                                    wizard.zeroize();
                                    log!("   Dice seed generated ({} words)", wc);
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                    needs_redraw = true;
                                } else {
                                    boot_display.update_dice_progress(
                                        ad.dice_collector.count, ad.dice_collector.target);
                                }
                            }
                            // Undo button: centered, x=100..220, y=200..240
                            else if (100..=220).contains(&x) && y >= 200 && ad.dice_collector.count > 0 {
                                ad.dice_collector.undo();
                                log!("   Dice undo ({}/{})", ad.dice_collector.count, ad.dice_collector.target);
                                boot_display.update_dice_progress(
                                    ad.dice_collector.count, ad.dice_collector.target);
                            }
                        }
                    }
                    crate::app::input::AppState::ChooseWordCount { action } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SeedToolsMenu;
                            needs_redraw = true;
                        } else {
                            let chose_12 = (30..=290).contains(&x) && (70..=130).contains(&y);
                            let chose_24 = (30..=290).contains(&x) && (150..=210).contains(&y);
                            let wc: u8 = if chose_12 { 12 } else if chose_24 { 24 } else { 0 };
                            if wc > 0 {
                                needs_redraw = true;
                                match action {
                                    0 => {
                                        // === HARDWARE ENTROPY COLLECTION ===
                                        // Sources mixed via SHA-256:
                                        //   1. ESP32-S3 TRNG (thermal noise + RC_FAST_CLK jitter)
                                        //   2. Camera sensor noise (8 frames, full 153KB each)
                                        //   3. Timing jitter (DMA completion, I2C bus, loop iteration)
                                        //   4. ADC noise from battery pin (GPIO5)

                                        // Show progress screen
                                        boot_display.clear_screen();
                                        {
                                            use crate::hw::display::*;
                                            let tw = measure_header("GENERATING");
                                            draw_oswald_header(&mut boot_display.display, "GENERATING", (320 - tw) / 2, 100, KASPA_TEAL);
                                            let sw = measure_body("Collecting entropy...");
                                            draw_lato_body(&mut boot_display.display, "Collecting entropy...", (320 - sw) / 2, 130, COLOR_TEXT_DIM);
                                        }

                                        // Round 0.5: MEMS gyro noise BEFORE the camera is
                                        // powered, as a control.
                                        //
                                        // The IMU is healthy at boot and degrades by seed time,
                                        // and camera power-up is the only thing that differs.
                                        // Collecting on both sides of it turns that inference into
                                        // a measurement: if pre-cam is clean and post-cam is
                                        // frozen, the camera is the cause and this collection
                                        // point is also the fix.
                                        #[cfg(feature = "waveshare")]
                                        let mut imu_pre = [0u8; 96];
                                        #[cfg(feature = "waveshare")]
                                        let imu_pre_n = crate::hw::imu::collect(i2c, delay, &mut imu_pre);

                                        // Power on camera for entropy capture
                                        #[cfg(feature = "waveshare")]
                                        {
                                            // PWDN LOW = active (GPIO17 output clear)
                                            unsafe {
                                                core::ptr::write_volatile(0x6000_400Cu32 as *mut u32, 1u32 << 17);
                                            }
                                            delay.delay_millis(100); // OV5640 wake from PWDN
                                        }

                                        let mut wizard = setup_wizard::SetupWizard::new();
                                        wizard.word_count = wc;
                                        let entropy_bytes = if wc == 12 { 16usize } else { 32usize };
                                        let mut pool = [0u8; 32]; // entropy accumulator
                                        let mut got_entropy = false;
                                        // Bytes of MEMS gyro noise mixed in Round 2.5. The m5stack
                                        // build has no IMU module, so the block that assigns this
                                        // is cfg'd out there and `mut` goes unused: underscore
                                        // silences unused_variables, allow() silences unused_mut.
                                        #[allow(unused_mut)]
                                        let mut _imu_bytes = 0usize;

                                        // Enable BOTH documented RNG noise sources before sampling.
                                        //
                                        // Shared with crypto::entropy so this path cannot drift from
                                        // fill(). enable_rc_fast() sets RTC_CNTL_DIG_CLK8M_EN and then
                                        // waits for the RC oscillator to settle, which the previous
                                        // inline write here did not do: it set the bit and started
                                        // reading immediately.
                                        //
                                        // enable_sar_adc_noise() holds the SAR ADC powered on. TRM 25.3:
                                        // RC_FAST_CLK alone yields true random numbers, but "to ensure
                                        // maximum entropy, it's recommended to always enable an ADC
                                        // source as well". The high-speed ADC needs Wi-Fi or Bluetooth,
                                        // which this device never starts, so the SAR ADC is the only one
                                        // available. It also makes the SAR ADC1 data reads further down
                                        // meaningful; without it that register is static and those reads
                                        // contributed nothing while appearing to.
                                        crate::crypto::entropy::enable_rc_fast();
                                        crate::crypto::entropy::enable_sar_adc_noise();


                                        // Round 1: device identity and timing.
                                        // Was "TRNG seed"; the TRNG is gone, see below.
                                        {
                                            use sha2::{Sha256, Digest};
                                            let mut hasher = Sha256::new();
                                            // NO WDEV HERE.
                                            //
                                            // The named seed methods are single-source by
                                            // design: camera means the camera, dice means the
                                            // dice, touch means the touchscreen. Mixing the
                                            // hardware RNG in masked the failure the method is
                                            // supposed to report: a camera that contributed
                                            // nothing still produced a seed, so "not enough
                                            // light" could not be said honestly.
                                            //
                                            // It also went unreported. The summary line below
                                            // has always listed CAM, IMU, eFuse, SYSTIMER and
                                            // timing, and never the TRNG that was mixed twice.
                                            //
                                            // The RNG keeps its place in `entropy::fill`, which
                                            // is where a mixture belongs: nonces and salts on
                                            // demand, health-gated per call, failing closed.
                                            //
                                            // What stays here is what the log line declares.
                                            // Mix SYSTIMER: latch counter then read full 52-bit value
                                            unsafe {
                                                // SYSTIMER_UNIT0_OP_REG (0x6002_3004): write 1 to bit 30 to latch
                                                core::ptr::write_volatile(0x6002_3004u32 as *mut u32, 1 << 30);
                                                for _ in 0..20u32 { core::hint::spin_loop(); }
                                                let lo = core::ptr::read_volatile(0x6002_3044u32 as *const u32);
                                                let hi = core::ptr::read_volatile(0x6002_3040u32 as *const u32);
                                                hasher.update(lo.to_le_bytes());
                                                hasher.update(hi.to_le_bytes());
                                            }
                                            // Mix eFuse MAC address (unique per chip — 6 bytes at EFUSE_RD_MAC_SPI_SYS_0/1)
                                            unsafe {
                                                let mac0 = core::ptr::read_volatile(0x6000_7044u32 as *const u32);
                                                let mac1 = core::ptr::read_volatile(0x6000_7048u32 as *const u32);
                                                hasher.update(mac0.to_le_bytes());
                                                hasher.update(mac1.to_le_bytes());
                                            }
                                            // Mix idle_ticks (touch/display loop counter — varies with user interaction timing)
                                            hasher.update(ad.idle_ticks.to_le_bytes());
                                            hasher.update([0x01]); // domain separator
                                            let hash = hasher.finalize();
                                            for i in 0..32 { pool[i] ^= hash[i]; }
                                        }

                                        // Round 2: Camera frames (8 frames, full data)
                                        // Waveshare: ensure cam_dma is capturing
                                        #[cfg(feature = "waveshare")]
                                        if dvp_camera_opt.is_none() {
                                            crate::hw::cam_dma::start_capture();
                                            delay.delay_millis(50); // let DMA settle
                                        }

                                        // Camera noise measurement, accumulated across the frame
                                        // loop. The image is a constant across generations; only
                                        // the frame-to-frame delta is entropy.
                                        //
                                        // NOT platform-gated. Both capture paths feed the same
                                        // measurement: the DvpCamera path below hands over full
                                        // frames, the Waveshare cam_dma fallback hands over the
                                        // partial capture. Gating this on `waveshare` is what left
                                        // audit E-07 open on M5Stack.
                                        // E-12: every delta must pass on its own. `cam_meas`
                                        // counts deltas measured; `cam_live` counts those that
                                        // passed. A mean cannot see a sensor that stops partway.
                                        let mut cam_live = 0u32;
                                        let mut cam_meas = 0u32;
                                        let mut cam_changed = 0u32;
                                        let mut cam_mad = 0u32;
                                        let mut cam_sampled = 0u32;
                                        // ACCUMULATED |shift|, not the last frame's. Reporting
                                        // the last frame's shift beside an averaged MAD and AC
                                        // produced lines like "MAD 21.11, shift 0, AC 1.29",
                                        // which is arithmetically impossible for one frame and
                                        // hid the fact that ~94% of that MAD was DC level-step.
                                        let mut cam_shift_abs = 0u32;
                                        let mut cam_ac = 0u32;
                                        // Worst frame, not the last one. distinct and shift were
                                        // being overwritten each pass while changed and MAD were
                                        // averaged, so the line mixed a snapshot with an average.
                                        let mut cam_distinct_min = u32::MAX;
                                        // Bytes actually hashed into the pool. Counted, not
                                        // hardcoded: a literal was wrong by 28x on Waveshare
                                        // (E-09) and wrong again on M5Stack, whose frames are
                                        // 76800 bytes against Waveshare's 8064-byte partials.
                                        let mut cam_bytes = 0u32;
                                        crate::hw::frame_noise::reset_baseline();

                                        for frame_idx in 0..8u8 {
                                            if let Some(cam) = dvp_camera_opt.take() {
                                                if let Some(dma_buf) = cam_dma_buf_opt.take() {
                                                    // Read idle_ticks before DMA as timing entropy
                                                    let t0 = ad.idle_ticks;
                                                    match cam.receive(dma_buf) {
                                                        Ok(transfer) => {
                                                            let (_res, cam_back, buf_back) = transfer.wait();
                                                            let t1 = ad.idle_ticks;
                                                            use sha2::{Sha256, Digest};
                                                            let pixels = buf_back.as_slice();
                                                            let mut hasher = Sha256::new();
                                                            // Hash ALL pixel data (not just first 64K)
                                                            hasher.update(pixels);
                                                            // Mix in frame index + timing jitter
                                                            hasher.update([frame_idx, (t0 & 0xFF) as u8, (t1 & 0xFF) as u8]);
                                                            // Mid-frame TRNG sample removed: camera means camera.
                                                            let hash = hasher.finalize();
                                                            for i in 0..32 { pool[i] ^= hash[i]; }
                                                            got_entropy = true;
                                                            cam_bytes += pixels.len() as u32;
                                                            // Measured here, before buf_back moves
                                                            // back into the Option and the borrow
                                                            // on `pixels` ends.
                                                            if let Some(fm) =
                                                                crate::hw::frame_noise::measure(pixels)
                                                            {
                                                                cam_meas += 1;
                                                                if crate::hw::frame_noise::is_live(&fm) {
                                                                    cam_live += 1;
                                                                }
                                                                cam_changed += fm.changed;
                                                                cam_mad += fm.mad_x100;
                                                                cam_ac += fm.ac_x100;
                                                                cam_distinct_min =
                                                                    cam_distinct_min.min(fm.distinct);
                                                                cam_sampled = fm.sampled;
                                                                cam_shift_abs +=
                                                                    fm.mean_shift_x100.unsigned_abs();
                                                            }
                                                            *cam_dma_buf_opt = Some(buf_back);
                                                            *dvp_camera_opt = Some(cam_back);
                                                        }
                                                        Err((_e, cam_back, buf_back)) => {
                                                            log!("   Entropy capture failed");
                                                            *cam_dma_buf_opt = Some(buf_back);
                                                            *dvp_camera_opt = Some(cam_back);
                                                        }
                                                    }
                                                } else {
                                                    *dvp_camera_opt = Some(cam);
                                                }
                                            }
                                            // Waveshare cam_dma fallback: DvpCamera is None,
                                            // use cam_dma::get_frame_any() for PSRAM pixel entropy
                                            // (partial frames are fine — any pixel data is good randomness)
                                            #[cfg(feature = "waveshare")]
                                            if dvp_camera_opt.is_none() {
                                                // Wait for TWO frame completions so the read buffer has real pixels.
                                                // After start_capture(), first poll_done() fills write buffer,
                                                // second poll_done() swaps and fills the other → read buffer is fresh.
                                                delay.delay_millis(80);
                                                crate::hw::cam_dma::poll_done();
                                                delay.delay_millis(80);
                                                crate::hw::cam_dma::poll_done();
                                                if let Some(pixels) = crate::hw::cam_dma::get_entropy_bytes() {
                                                    let t0 = ad.idle_ticks;
                                                    use sha2::{Sha256, Digest};
                                                    let mut hasher = Sha256::new();
                                                    hasher.update(pixels);
                                                    // Mix SYSTIMER for timing jitter
                                                    let ccount: u32 = unsafe {
                                                        core::ptr::write_volatile(0x6002_3004u32 as *mut u32, 1 << 30);
                                                        core::ptr::read_volatile(0x6002_3044u32 as *const u32)
                                                    };
                                                    hasher.update([frame_idx, (t0 & 0xFF) as u8, 0xCA]);
                                                    hasher.update(ccount.to_le_bytes());
                                                    // Mid-frame TRNG sample removed: camera means camera.
                                                    let hash = hasher.finalize();
                                                    for i in 0..32 { pool[i] ^= hash[i]; }
                                                    got_entropy = true;
                                                    cam_bytes += pixels.len() as u32;
                                                    if let Some(fm) =
                                                        crate::hw::frame_noise::measure(pixels)
                                                    {
                                                        cam_meas += 1;
                                                        if crate::hw::frame_noise::is_live(&fm) {
                                                            cam_live += 1;
                                                        }
                                                        cam_changed += fm.changed;
                                                        cam_mad += fm.mad_x100;
                                                        cam_ac += fm.ac_x100;
                                                        cam_distinct_min =
                                                            cam_distinct_min.min(fm.distinct);
                                                        cam_sampled = fm.sampled;
                                                        cam_shift_abs +=
                                                            fm.mean_shift_x100.unsigned_abs();
                                                    }
                                                }
                                            }
                                            delay.delay_millis(30);
                                        }

                                        // Report the camera the same way the IMU is reported.
                                        // `changed` near zero means the buffer is not refreshing
                                        // and the camera contributes nothing while the summary
                                        // line claims 8 frames.
                                        crate::log!("   Entropy: CAM live {}/{} deltas",
                                            cam_live, cam_meas);
                                        if cam_meas > 0 {
                                            let ch = cam_changed / cam_meas;
                                            let mad = cam_mad / cam_meas;
                                            // mean shift is the DC component. If MAD is entirely
                                            // explained by it, the frame moved as one object and
                                            // contributed nothing per pixel.
                                            let ac = cam_ac / cam_meas;
                                            let sh = cam_shift_abs / cam_meas;
                                            log!(
                                                "   Entropy: CAM noise — {}/{} changed/frame, MAD {}.{:02}, AC {}.{:02}, |shift| {}.{:02} LSB, distinct min {}, over {} deltas",
                                                ch, cam_sampled, mad / 100, mad % 100,
                                                ac / 100, ac % 100, sh / 100, sh % 100,
                                                cam_distinct_min, cam_meas
                                            );
                                        } else {
                                            log!("   Entropy: CAM noise — no frame deltas measured");
                                        }
                                        // Waveshare: stop cam_dma after entropy collection
                                        #[cfg(feature = "waveshare")]
                                        if dvp_camera_opt.is_none() {
                                            crate::hw::cam_dma::stop();
                                        }

                                        // Round 2.5: MEMS gyro noise, both sides of the camera.
                                        //
                                        // The only source in this pool that is not the SoC itself.
                                        // Rounds 1 and 3 are ESP32-S3 registers; round 2 is the
                                        // camera, which contributes nothing with the lens covered
                                        // or in the dark.
                                        //
                                        // ADDITIVE ONLY. Neither collection sets got_entropy: the
                                        // camera stays the fail-closed gate. Bytes are mixed even
                                        // when a collection fails its health check, because
                                        // folding a frozen axis through SHA-256 and XOR cannot
                                        // REMOVE entropy, it just adds none; only the reported
                                        // byte count is gated, so the log never claims a
                                        // contribution that was not made.
                                        #[cfg(feature = "waveshare")]
                                        {
                                            let mut imu_post = [0u8; 96]; // 32 passes x 3 axes
                                            let imu_post_n =
                                                crate::hw::imu::collect(i2c, delay, &mut imu_post);

                                            let sources: [(&str, &[u8], usize); 2] = [
                                                ("pre-cam", &imu_pre[..], imu_pre_n),
                                                ("post-cam", &imu_post[..], imu_post_n),
                                            ];

                                            for (idx, &(label, buf, n)) in sources.iter().enumerate() {
                                                if n == 0 {
                                                    log!("   Entropy: IMU {} unavailable, skipped", label);
                                                    continue;
                                                }
                                                let ax = crate::hw::imu::axis_distinct(&buf[..n]);
                                                let healthy =
                                                    crate::hw::imu::buffer_is_healthy(&buf[..n]);

                                                use sha2::{Sha256, Digest};
                                                let mut hasher = Sha256::new();
                                                hasher.update(&buf[..n]);
                                                // Length and source index are bound in so a short
                                                // collection cannot collide with a full one that
                                                // shares a prefix, and the two sources cannot
                                                // cancel if they ever return identical bytes.
                                                hasher.update((n as u32).to_le_bytes());
                                                hasher.update([0x02, idx as u8]);
                                                let hash = hasher.finalize();
                                                for i in 0..32 { pool[i] ^= hash[i]; }

                                                if healthy {
                                                    _imu_bytes += n;
                                                    log!(
                                                        "   Entropy: IMU {} {} bytes mixed (distinct X{} Y{} Z{} of {})",
                                                        label, n, ax[0], ax[1], ax[2], n / 3
                                                    );
                                                } else {
                                                    // The stuck value names the failure: 0xFF or
                                                    // 0x00 on an axis with distinct 1 is a
                                                    // rail-pinned axis (full-scale clip from
                                                    // handling), anything else is a frozen
                                                    // register or a bus fault.
                                                    let fb = crate::hw::imu::axis_first_byte(&buf[..n]);
                                                    log!(
                                                        "   Entropy: IMU {} DEGRADED — {} bytes but distinct X{} Y{} Z{} of {} (first X{:02X} Y{:02X} Z{:02X}); contributed ~nothing, NOT counted",
                                                        label, n, ax[0], ax[1], ax[2], n / 3,
                                                        fb[0], fb[1], fb[2]
                                                    );
                                                }

                                                #[cfg(feature = "imu-dump")]
                                                {
                                                    log!("   [imu-dump] source: {}", label);
                                                    crate::hw::imu::dump_buffer(&buf[..n]);
                                                }
                                            }

                                            for b in imu_post.iter_mut() {
                                                unsafe { core::ptr::write_volatile(b, 0); }
                                            }
                                            for b in imu_pre.iter_mut() {
                                                unsafe { core::ptr::write_volatile(b, 0); }
                                            }
                                        }

                                        // Round 3: ADC noise whitening.
                                        // Was "Final TRNG + ADC"; the TRNG is gone.
                                        {
                                            use sha2::{Sha256, Digest};
                                            let mut hasher = Sha256::new();
                                            hasher.update(pool);
                                            // 64 TRNG reads removed: camera means camera.
                                            // Battery ADC noise (GPIO5) — even if not calibrated, LSBs are noisy
                                            for _ in 0..16 {
                                                let adc_val = unsafe {
                                                    // SAR ADC1 data register
                                                    core::ptr::read_volatile(0x6004_0868u32 as *const u32)
                                                };
                                                hasher.update(adc_val.to_le_bytes());
                                            }
                                            // SYSTIMER latch for final timing jitter
                                            unsafe {
                                                core::ptr::write_volatile(0x6002_3004u32 as *mut u32, 1 << 30);
                                                for _ in 0..20u32 { core::hint::spin_loop(); }
                                                let lo = core::ptr::read_volatile(0x6002_3044u32 as *const u32);
                                                hasher.update(lo.to_le_bytes());
                                            }
                                            // eFuse unique ID (OPTIONAL_UNIQUE_ID, 128 bits)
                                            unsafe {
                                                for off in [0x005Cu32, 0x0060, 0x0064, 0x0068] {
                                                    let val = core::ptr::read_volatile((0x6000_7000u32 + off) as *const u32);
                                                    hasher.update(val.to_le_bytes());
                                                }
                                            }
                                            // idle_ticks again (changed since round 1 due to camera captures)
                                            hasher.update(ad.idle_ticks.to_le_bytes());
                                            hasher.update([0x03]); // domain separator
                                            let final_hash = hasher.finalize();
                                            // Replace pool with final whitened entropy
                                            pool.copy_from_slice(&final_hash);
                                        }

                                        // ── Entropy gate ─────────────────────────────────
                                        //
                                        // Fail-closed on the property that actually matters: at
                                        // least one source OUTSIDE the SoC contributed measured,
                                        // varying data. Rounds 1 and 3 are ESP32-S3 registers and
                                        // deliberately cannot satisfy this alone, because a
                                        // firmware that believes it has a TRNG and does not is
                                        // the failure this subsystem exists to survive.
                                        //
                                        // Camera OR IMU, not camera alone. The camera-only gate
                                        // predates the IMU and became arbitrary once a second
                                        // independent die with its own point-of-use health check
                                        // was in the pool. Requiring BOTH would make a healthy
                                        // device refuse to generate a seed because one of two
                                        // sources had a bad moment, and in testing both have.
                                        //
                                        // The camera check was previously nominal: got_entropy
                                        // was set because get_entropy_bytes() returned Some, i.e.
                                        // the pointer was non-null. It never verified the data
                                        // varied. Now it does.
                                        //
                                        // One expression, both platforms. The measurement is in
                                        // hw/frame_noise.rs precisely so this does not need a cfg,
                                        // and so `cam_ok` means the same thing on M5Stack as on
                                        // Waveshare.
                                        //
                                        // `cam_meas > 0` IS REQUIRED, not an escape. This used to
                                        // read `cam_meas == 0 || (...)`, which passed a run that
                                        // produced no delta at all. That is reachable: frame_noise
                                        // ::measure returns None on the first capture because
                                        // there is no baseline to compare against, so a loop in
                                        // which capture 0 succeeds and captures 1..8 all take the
                                        // Err branch sets got_entropy, leaves cam_meas at 0, and
                                        // satisfied the gate with zero evidence that the sensor
                                        // produced varying data. On M5Stack, which has no IMU, that
                                        // single unmeasured frame was the whole non-SoC
                                        // justification for the seed.
                                        //
                                        // A gate that exists to fail closed must refuse when it
                                        // cannot measure, not pass. Healthy hardware is unaffected:
                                        // the loop runs 8 captures and every one after the first
                                        // yields a delta, so cam_meas is 7 in the normal case on
                                        // both boards. Waveshare still falls through to imu_ok;
                                        // M5Stack now shows "Need more light" for a capture run
                                        // that produced fewer than two frames, which is the correct
                                        // answer to an unverifiable source.
                                        //
                                        // EVERY DELTA MUST PASS, not the average of them. This
                                        // extends the `cam_meas > 0` requirement above rather
                                        // than replacing it: that fixed a run which measured
                                        // NOTHING, this fixes a run whose mean hides deltas that
                                        // measured nothing.
                                        //
                                        // E-12 measured a capture whose averages cleared every
                                        // threshold while four of its seven deltas were frozen
                                        // (bit-identical frames, `changed` 0, `distinct` 1).
                                        // NIST SP 800-90B `ea_non_iid`, all ten estimators over
                                        // the frame-delta stream, assessed that capture at ZERO
                                        // min-entropy and the device generated a seed from it.
                                        // Three live deltas at the head carried the dead tail.
                                        //
                                        // AC IS OUT OF THE GATE, and the note above about
                                        // `distinct` refusing a flat-but-noisy dark frame is why
                                        // it is `distinct` PER DELTA rather than a spatial
                                        // threshold. `ac_x100` is `MAD - |shift|`, which is not
                                        // the AC component: half the pixels moving 0 and half
                                        // moving +32 gives MAD 16, shift 16, AC 0, while every
                                        // pixel carried an independent bit. Measured, a capture
                                        // assessing at 830 bits had `min AC` 0.01, and the single
                                        // richest delta in the set (4.09 bits/byte) scored 0.06.
                                        // It ranks acceptably and thresholds inverted, so it
                                        // stays in the log line and out of the decision.
                                        //
                                        // `is_live` is `changed >= MIN_CHANGED_FOR_ENTROPY &&
                                        // distinct >= MIN_DISTINCT_FOR_ENTROPY`, applied to each
                                        // delta as it is measured. `cam_meas > 0` is kept: it is
                                        // still the condition that refuses a run producing no
                                        // delta at all.
                                        let cam_ok = got_entropy
                                            && cam_meas > 0
                                            && cam_live == cam_meas;
                                        // _imu_bytes counts only collections that passed the
                                        // per-axis health check, so non-zero means at least one
                                        // substantiated IMU contribution. Always 0 on m5stack,
                                        // which has no IMU module, so the gate there reduces
                                        // exactly to the previous camera-only behaviour.
                                        let imu_ok = _imu_bytes > 0;

                                        if cam_ok || imu_ok {
                                            // "8 frames" overstated by ~28x: a frame is 230400
                                            // bytes and cam_dma delivers 8064 of them. Report the
                                            // bytes actually hashed, as the IMU line does.
                                            log!("   Entropy: CAM({}B){} + IMU({}B){} + ADC + eFuse + SYSTIMER + timing → SHA-256",
                                                cam_bytes,
                                                if cam_ok { "" } else { " DEGRADED" },
                                                _imu_bytes,
                                                if imu_ok { "" } else { " DEGRADED" });
                                            wizard.generate_from_entropy(&pool[..entropy_bytes]);
                                            for b in pool.iter_mut() {
                                                unsafe { core::ptr::write_volatile(b, 0); }
                                            }
                                            ad.mnemonic_indices = wizard.mnemonic;
                                            ad.word_count = wc;
                                            wizard.zeroize();
                                            ad.pp_input.reset();
                                            ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                        } else {
                                            log!("   REFUSED: no non-SoC entropy source healthy (cam {}, imu {})",
                                                if cam_ok { "ok" } else { "FAIL" },
                                                if imu_ok { "ok" } else { "FAIL" });
                                            // Actionable, not just accurate. On both boards the
                                            // fix a user can apply is light: the camera is the
                                            // only non-SoC source on M5Stack, and on Waveshare a
                                            // refusal means the IMU failed too. A user who is
                                            // told only "no entropy source" may go and generate a
                                            // seed somewhere worse.
                                            boot_display.draw_rejected_screen("Need more light");
                                            delay.delay_millis(2000);
                                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                                        }
                                    }
                                    5 => {
                                        // Touch. The canvas is the collection surface: a bare
                                        // screen means a stray tap cannot trigger a menu action,
                                        // and the cadence collected is the one the feature sees.
                                        //
                                        // Word count rides on `ad.word_count` rather than a
                                        // second collector type: the target event count does not
                                        // change with it. 2,048 events give 1,558 bits at the
                                        // measured worst case, six times a 24-word seed's 256.
                                        crate::crypto::entropy::touch_probe_reset();
                                        ad.word_count = wc;
                                        ad.app.state = crate::app::input::AppState::TouchEntropy;
                                    }
                                    1 => {
                                        // Dice
                                        ad.dice_collector = if wc == 24 {
                                            setup_wizard::DiceCollector::new_24_word()
                                        } else {
                                            setup_wizard::DiceCollector::new_12_word()
                                        };
                                        ad.app.state = crate::app::input::AppState::DiceRoll;
                                    }
                                    2 => {
                                        // Import Words
                                        ad.word_input.reset();
                                        ad.app.state = crate::app::input::AppState::ImportWord {
                                            word_idx: 0, word_count: wc,
                                        };
                                    }
                                    3 => {
                                        // Calc Last Word
                                        ad.word_input.reset();
                                        ad.app.state = crate::app::input::AppState::CalcLastWord {
                                            word_idx: 0, word_count: wc,
                                        };
                                    }
                                    4 => {
                                        // BIP85 Child — go to index input
                                        ad.bip85_index = 0;
                                        ad.bip85_child_wc = wc;
                                        ad.app.state = crate::app::input::AppState::Bip85Index { word_count: wc };
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::ShowQrFrameChoice => {
                        if is_back {
                            ad.signed_qr_nframes = 0;
                            ad.signed_qr_large = false;
                            ad.signed_qr_mode = 0;
                            ad.signed_qr_via_density = false;
                            ad.app.go_main_menu();
                        } else if x < 160 {
                            // Left: Phone/KasSee — standard legacy framing
                            // (mode 0 + signed_qr_large=false → 106 B/frame,
                            // single-QR if payload fits 134B else auto-splits
                            // to V6-ish multi). Tuned for general QR readers.
                            ad.signed_qr_large = false;
                            ad.signed_qr_mode = 0;
                            ad.signed_qr_nframes = 0;
                            ad.signed_qr_via_density = false;
                            ad.app.state = crate::app::input::AppState::ShowQR;
                        } else {
                            // Right: KasSigner — open density sub-screen.
                            // Flag remembers that downstream screens
                            // (ShowQrModeChoice, ShowQrPopup) should
                            // return here to density picker on back,
                            // not jump straight to ShowQrFrameChoice.
                            ad.signed_qr_nframes = 0;
                            ad.signed_qr_via_density = true;
                            ad.app.state =
                                crate::app::input::AppState::ShowQrDensityChoice;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowQrDensityChoice => {
                        if is_back {
                            // Back to Phone/KasSigner choice. Clear the
                            // via_density flag — we're exiting that path.
                            ad.signed_qr_nframes = 0;
                            ad.signed_qr_large = false;
                            ad.signed_qr_mode = 0;
                            ad.signed_qr_via_density = false;
                            ad.app.state =
                                crate::app::input::AppState::ShowQrFrameChoice;
                        } else if x < 160 {
                            // Left: Fast — V6 density (mode 0 +
                            // signed_qr_large=false, 106 B/frame). Fewer
                            // QRs per tx but needs a capable receiver
                            // (M5Stack GC0308, future OV5640 AF, OV2640
                            // wide). Same encoding as Phone/KasSee; users
                            // who know their peer has a good camera get
                            // the efficient path without going through
                            // the phone-compatible button name.
                            ad.signed_qr_large = false;
                            ad.signed_qr_mode = 0;
                            ad.signed_qr_nframes = 0;
                            ad.app.state = crate::app::input::AppState::ShowQR;
                        } else {
                            // Right: Safe — V3 density (mode 3,
                            // signed_qr_large=true, 40 B/frame). More
                            // QRs, but decodes on every current camera
                            // including Waveshare OV5640 fixed-focus at
                            // close range. Universal ceiling today.
                            ad.signed_qr_large = true;
                            ad.signed_qr_mode = 3;
                            ad.signed_qr_nframes = 0;
                            ad.app.state = crate::app::input::AppState::ShowQR;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowQR => {
                        // Full-screen QR: any tap (including back zone) goes to popup or advances
                        if ad.signed_qr_len > 0 {
                            if ad.qr_manual_frames && ad.signed_qr_nframes > 1 {
                                // Manual mode: tap advances to next frame, no cycling
                                let next = ad.signed_qr_frame + 1;
                                if next >= ad.signed_qr_nframes {
                                    // Last frame shown → go to save popup
                                    ad.app.state = crate::app::input::AppState::ShowQrPopup;
                                } else {
                                    ad.signed_qr_frame = next;
                                }
                            } else {
                                // Single frame or auto mode: tap → popup
                                ad.app.state = crate::app::input::AppState::ShowQrPopup;
                            }
                        } else {
                            ad.app.go_main_menu();
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::CovBackupName => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.covb_len = 0;
                            ad.app.go_main_menu();
                            needs_redraw = true;
                        } else {
                            match crate::ui::helpers::pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "COV NAME"); }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "COV NAME"); }
                                6 => {
                                    // OK: build filename and trigger save
                                    if ad.pp_input.len == 0 {
                                        let hx = b"0123456789ABCDEF";
                                        for i in 0..5usize {
                                            if i + 4 < ad.covb_len {
                                                ad.pp_input.buf[i] = hx[(ad.signed_qr_buf[4 + i] >> 4) as usize];
                                            }
                                        }
                                        ad.pp_input.len = 5;
                                    }
                                    let name_83 = crate::handlers::sd::build_filename_83(
                                        &ad.pp_input.buf, ad.pp_input.len, b"COV"
                                    );
                                    ad.sd_file_list[0] = name_83;
                                    ad.pp_input.reset();
                                    ad.app.go_main_menu();
                                    ad.needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::Rejected
                    | crate::app::input::AppState::ViewSeed => {
                        // Back button or tap anywhere → main menu
                        ad.app.go_main_menu();
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}


/// Silent duress wipe. Called from main.rs the moment a finger lands in the
/// logo corner on the main menu; returns true only if it stays there for
/// HOLD_MS without lifting or drifting.
///
/// Deliberately silent: no prompt, no progress bar, no confirmation. A quick
/// tap is indistinguishable from doing nothing, and an observer sees no
/// indication that a wipe is in progress. That is the point of a duress
/// control.
///
/// Polls raw `TouchState` rather than `TouchAction`, because `TouchAction`
/// differs per board: CST816D reports Hold from its hardware gesture engine
/// after a real long press, FT6336U reports it on every poll while down.
/// `TouchState::One(TouchPoint)` is identical on both.
///
/// The finger is ALREADY down on entry, so there is no arm-wait state and
/// therefore no way to loop: every poll either extends the hold, completes
/// it, or returns false.
pub(crate) fn wipe_hold_confirm(
    _boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> bool {
    const HOLD_MS: u32 = 4000;
    let mut held_ms: u32 = 0;
    loop {
        delay.delay_millis(50);
        match crate::hw::touch::read_touch(i2c) {
            crate::hw::touch::TouchState::One(pt) if pt.x <= 48 && pt.y <= 48 => {
                held_ms += 50;
                if held_ms >= HOLD_MS { return true; }
            }
            // Lifted, or moved off the corner.
            _ => return false,
        }
    }
}
