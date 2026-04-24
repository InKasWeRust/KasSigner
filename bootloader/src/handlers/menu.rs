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

#[cfg(not(feature = "silent"))]
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
                                    2 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 2 }; } // Import Words
                                    3 => { // Address
                                        if ad.seed_loaded {
                                            // Derive pubkeys if not cached
                                            if !ad.pubkeys_cached {
                                                let slot_wc = ad.seed_mgr.active_slot().map(|s| s.word_count).unwrap_or(0);
                                                if slot_wc == 1 {
                                                    if let Some(slot) = ad.seed_mgr.active_slot() as Option<&crate::ui::seed_manager::SeedSlot> {
                                                        let mut key = [0u8; 32];
                                                        slot.raw_key_bytes(&mut key);
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
                                    4 => { // BIP85 Child
                                        if ad.seed_loaded {
                                            ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 4 };
                                        } else {
                                            boot_display.draw_rejected_screen("Load a seed first");
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    5 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 3 }; } // Calc Last Word
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
                                                    && (ad.import_jpeg_count as usize) < 8 {
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
                                            let pp = ad.seed_mgr.active_slot().map(|s: &crate::ui::seed_manager::SeedSlot| s.passphrase_str()).unwrap_or("");
                                            crate::app::signing::derive_all_pubkeys(
                                                &ad.mnemonic_indices, ad.word_count, pp,
                                                &mut ad.pubkey_cache, &mut ad.acct_key_raw);
                                            crate::app::signing::derive_change_pubkeys(
                                                &ad.acct_key_raw, &mut ad.change_pubkey_cache);
                                            ad.pubkeys_cached = true;
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
                                log!("   Dice: {} ({}/{})", val, ad.dice_collector.count, ad.dice_collector.target);

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

                                        // Enable RC_FAST_CLK for TRNG entropy
                                        // RTC_CNTL_CLK_CONF_REG = 0x6000_8074, bit 10 = DIG_CLK8M_EN
                                        unsafe {
                                            let clk_conf = core::ptr::read_volatile(0x6000_8074u32 as *const u32);
                                            core::ptr::write_volatile(0x6000_8074u32 as *mut u32, clk_conf | (1 << 10));
                                        }


                                        // Round 1: TRNG seed (32 reads at 500kHz max → ~64µs)
                                        {
                                            use sha2::{Sha256, Digest};
                                            let mut hasher = Sha256::new();
                                            let mut trng_buf = [0u8; 128]; // 32 × 4 bytes
                                            for i in 0..32 {
                                                let rng_val = unsafe {
                                                    core::ptr::read_volatile(0x6003_5144u32 as *const u32)
                                                };
                                                if i < 4 {
                                                }
                                                trng_buf[i*4]     = (rng_val & 0xFF) as u8;
                                                trng_buf[i*4 + 1] = ((rng_val >> 8) & 0xFF) as u8;
                                                trng_buf[i*4 + 2] = ((rng_val >> 16) & 0xFF) as u8;
                                                trng_buf[i*4 + 3] = ((rng_val >> 24) & 0xFF) as u8;
                                                // ~2µs delay between reads for max entropy
                                                for _ in 0..160u32 { core::hint::spin_loop(); }
                                            }
                                            hasher.update(trng_buf);
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
                                            hasher.update((ad.idle_ticks as u32).to_le_bytes());
                                            hasher.update([0x01]); // domain separator
                                            let hash = hasher.finalize();
                                            for i in 0..32 { pool[i] ^= hash[i]; }
                                            // Zeroize
                                            for b in trng_buf.iter_mut() {
                                                unsafe { core::ptr::write_volatile(b, 0); }
                                            }
                                        }

                                        // Round 2: Camera frames (8 frames, full data)
                                        // Waveshare: ensure cam_dma is capturing
                                        #[cfg(feature = "waveshare")]
                                        if dvp_camera_opt.is_none() {
                                            crate::hw::cam_dma::start_capture();
                                            delay.delay_millis(50); // let DMA settle
                                        }
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
                                                            // Mix in TRNG sample taken mid-frame
                                                            let rng_mid = unsafe {
                                                                core::ptr::read_volatile(0x6003_5144u32 as *const u32)
                                                            };
                                                            hasher.update(rng_mid.to_le_bytes());
                                                            let hash = hasher.finalize();
                                                            for i in 0..32 { pool[i] ^= hash[i]; }
                                                            got_entropy = true;
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
                                                    if frame_idx == 0 {
                                                    }
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
                                                    let rng_mid = unsafe {
                                                        core::ptr::read_volatile(0x6003_5144u32 as *const u32)
                                                    };
                                                    hasher.update(rng_mid.to_le_bytes());
                                                    let hash = hasher.finalize();
                                                    for i in 0..32 { pool[i] ^= hash[i]; }
                                                    got_entropy = true;
                                                }
                                            }
                                            delay.delay_millis(30);
                                        }
                                        // Waveshare: stop cam_dma after entropy collection
                                        #[cfg(feature = "waveshare")]
                                        if dvp_camera_opt.is_none() {
                                            crate::hw::cam_dma::stop();
                                        }

                                        // Round 3: Final TRNG + ADC noise whitening
                                        {
                                            use sha2::{Sha256, Digest};
                                            let mut hasher = Sha256::new();
                                            hasher.update(pool);
                                            // 64 more TRNG reads
                                            for _ in 0..64 {
                                                let rng_val = unsafe {
                                                    core::ptr::read_volatile(0x6003_5144u32 as *const u32)
                                                };
                                                hasher.update(rng_val.to_le_bytes());
                                                for _ in 0..160u32 { core::hint::spin_loop(); }
                                            }
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
                                            hasher.update((ad.idle_ticks as u32).to_le_bytes());
                                            hasher.update([0x03]); // domain separator
                                            let final_hash = hasher.finalize();
                                            // Replace pool with final whitened entropy
                                            pool.copy_from_slice(&final_hash);
                                        }

                                        if got_entropy {
                                            log!("   Entropy: CAM(8 frames) + eFuse + SYSTIMER + timing → SHA-256");
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
                                            log!("   No camera for entropy!");
                                            boot_display.draw_rejected_screen("Camera not ready");
                                            delay.delay_millis(2000);
                                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                                        }
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
                        if is_back {
                            // Reset per-tx QR state; keep via_density so
                            // we can route back to the right upstream
                            // screen.
                            ad.signed_qr_nframes = 0;
                            ad.signed_qr_large = false;
                            // If we came from a live multisig descriptor, go back there
                            if ad.ms_creating.active {
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            } else if ad.signed_qr_via_density {
                                // Came via KasSigner → Density (Fast/Safe)
                                // — return to the density picker so the
                                // user can flip density without restarting.
                                ad.app.state =
                                    crate::app::input::AppState::ShowQrDensityChoice;
                            } else {
                                // Phone/KasSee direct path → return to the
                                // top-level Phone/KasSigner choice.
                                ad.app.state =
                                    crate::app::input::AppState::ShowQrFrameChoice;
                            }
                        } else if ad.signed_qr_len > 0 {
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
