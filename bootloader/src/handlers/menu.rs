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
    let needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::MainMenu => {
                        // Check 2x2 grid zones
                        for (idx, zone) in grid_zones.iter().enumerate() {
                            if zone.contains(x, y) && (idx as u8) < ad.app.menu.count {
                                ad.app.menu.cursor = idx as u8;
                                let evt = crate::app::input::ButtonEvent::LongPress;
                                ad.app.handle_boot(evt);
                                ad.needs_redraw = true;
                                break;
                            }
                        }
                    }
                    // Sub-menus: list touch handling
                    crate::app::input::AppState::SeedsMenu => {
                        if is_back {
                            ad.app.go_main_menu();
                        } else {
                            // Always go to SeedList
                            ad.app.state = crate::app::input::AppState::SeedList;
                        }
                        ad.needs_redraw = true;
                    }
                    crate::app::input::AppState::ToolsMenu => {
                        if is_back {
                            ad.tools_menu.reset();
                            ad.app.go_main_menu();
                        } else if page_up_zone.contains(x, y) && ad.tools_menu.can_page_up() {
                            ad.tools_menu.page_up();
                        } else if page_down_zone.contains(x, y) && ad.tools_menu.can_page_down() {
                            ad.tools_menu.page_down();
                        } else {
                            // Find which visible slot was tapped
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
                                match item {
                                    0 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 0 }; }
                                    1 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 1 }; }
                                    2 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 2 }; }
                                    3 => { ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 3 }; }
                                    4 => {
                                        if ad.seed_loaded {
                                            ad.app.state = crate::app::input::AppState::ChooseWordCount { action: 4 };
                                        } else {
                                            boot_display.draw_rejected_screen("Load a seed first");
                                            delay.delay_millis(1500);
                                        }
                                    }
                                    5 => {
                                        ad.hex_input_len = 0;
                                        ad.app.state = crate::app::input::AppState::ImportPrivKey;
                                    }
                                    6 => {
                                        // Import from SD → submenu
                                        ad.sd_import_menu.reset();
                                        ad.app.state = crate::app::input::AppState::SdImportMenu;
                                    }
                                    7 => {
                                        // Create Multisig
                                        ad.ms_m = 2;
                                        ad.ms_n = 3;
                                        ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                        ad.app.state = crate::app::input::AppState::MultisigChooseMN;
                                    }
                                    8 => {
                                        // Stego Import — scan SD for JPEG files
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
                                    9 => {
                                        // Sign TX guide — auto-derive addresses if needed
                                        if ad.seed_loaded && !ad.pubkeys_cached {
                                            {
                                                boot_display.display.clear(crate::hw::display::COLOR_BG).ok();
                                                let tw = crate::hw::display::measure_header("DERIVING");
                                                crate::hw::display::draw_oswald_header(&mut boot_display.display, "DERIVING", (320 - tw) / 2, 90, crate::hw::display::KASPA_TEAL);
                                                let mw = crate::hw::display::measure_body("Deriving addresses...");
                                                crate::hw::display::draw_lato_body(&mut boot_display.display, "Deriving addresses...", (320 - mw) / 2, 120, crate::hw::display::COLOR_TEXT_DIM);
                                                // 50% progress bar
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
                                    10 => {
                                        // Sign Message — check seed, go to choice screen
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
                                    #[cfg(feature = "icon-browser")]
                                    11 => {
                                        // Icon browser test
                                        ad.app.state = crate::app::input::AppState::IconBrowser { page: 0 };
                                    }
                                    _ => {}
                                }
                            }
                        }
                        ad.needs_redraw = true;
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
                                    // → passphrase prompt
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                }
                            }
                            // Undo button: centered, x=100..220, y=200..240
                            else if (100..=220).contains(&x) && y >= 200 && ad.dice_collector.count > 0 {
                                ad.dice_collector.undo();
                                log!("   Dice undo ({}/{})", ad.dice_collector.count, ad.dice_collector.target);
                            }
                        }
                        ad.needs_redraw = true;
                    }
                    crate::app::input::AppState::ChooseWordCount { action } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            let chose_12 = (30..=290).contains(&x) && (70..=130).contains(&y);
                            let chose_24 = (30..=290).contains(&x) && (150..=210).contains(&y);
                            let wc: u8 = if chose_12 { 12 } else if chose_24 { 24 } else { 0 };
                            if wc > 0 {
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
                                        // RTC_CNTL_CLK_CONF_REG = 0x6000_8070, bit 10 = DIG_CLK8M_EN
                                        unsafe {
                                            let clk_conf = core::ptr::read_volatile(0x6000_8070u32 as *const u32);
                                            core::ptr::write_volatile(0x6000_8070u32 as *mut u32, clk_conf | (1 << 10));
                                        }

                                        // Round 1: TRNG seed (32 reads at 500kHz max → ~64µs)
                                        {
                                            use sha2::{Sha256, Digest};
                                            let mut hasher = Sha256::new();
                                            let mut trng_buf = [0u8; 128]; // 32 × 4 bytes
                                            for i in 0..32 {
                                                let rng_val = unsafe {
                                                    core::ptr::read_volatile(0x6003_5110u32 as *const u32)
                                                };
                                                trng_buf[i*4]     = (rng_val & 0xFF) as u8;
                                                trng_buf[i*4 + 1] = ((rng_val >> 8) & 0xFF) as u8;
                                                trng_buf[i*4 + 2] = ((rng_val >> 16) & 0xFF) as u8;
                                                trng_buf[i*4 + 3] = ((rng_val >> 24) & 0xFF) as u8;
                                                // ~2µs delay between reads for max entropy
                                                for _ in 0..160u32 { core::hint::spin_loop(); }
                                            }
                                            hasher.update(trng_buf);
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
                                            delay.delay_millis(100); // let a few frames arrive
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
                                                                core::ptr::read_volatile(0x6003_5110u32 as *const u32)
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
                                            // use cam_dma::get_frame() for PSRAM pixel entropy
                                            #[cfg(feature = "waveshare")]
                                            if dvp_camera_opt.is_none() {
                                                // Poll until a frame arrives (max ~50ms per frame at 20fps)
                                                for _ in 0..500u16 {
                                                    if crate::hw::cam_dma::poll_done() { break; }
                                                    delay.delay_millis(1);
                                                }
                                                if let Some(pixels) = crate::hw::cam_dma::get_frame() {
                                                    let t0 = ad.idle_ticks;
                                                    use sha2::{Sha256, Digest};
                                                    let mut hasher = Sha256::new();
                                                    hasher.update(pixels);
                                                    hasher.update([frame_idx, (t0 & 0xFF) as u8, 0xCA]);
                                                    let rng_mid = unsafe {
                                                        core::ptr::read_volatile(0x6003_5110u32 as *const u32)
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
                                                    core::ptr::read_volatile(0x6003_5110u32 as *const u32)
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
                                            hasher.update([0x03]); // domain separator
                                            let final_hash = hasher.finalize();
                                            // Replace pool with final whitened entropy
                                            pool.copy_from_slice(&final_hash);
                                        }

                                        if got_entropy {
                                            log!("   Entropy: TRNG(128B) + CAM(8 frames) + ADC + timing → SHA-256");
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
                        ad.needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowQrFrameChoice => {
                        if is_back {
                            ad.signed_qr_nframes = 0;
                            ad.signed_qr_large = false;
                            ad.signed_qr_mode = 0;
                            ad.app.go_main_menu();
                        } else if x < 160 {
                            // Left: Single — standard frames for KasSee/phone
                            // (legacy 106 B/frame, single-QR if payload fits 134B,
                            // auto-splits to V6-ish if bigger).
                            ad.signed_qr_large = false;
                            ad.signed_qr_mode = 0;
                            ad.signed_qr_nframes = 0;
                            ad.app.state = crate::app::input::AppState::ShowQR;
                        } else {
                            // Right: Multi — V3 mode (40 B/frame, binary KSPT,
                            // proven reliable for device-to-device LCD scanning).
                            ad.signed_qr_large = true;
                            ad.signed_qr_mode = 3;
                            ad.signed_qr_nframes = 0;
                            ad.app.state = crate::app::input::AppState::ShowQR;
                        }
                        ad.needs_redraw = true;
                    }
                    crate::app::input::AppState::ShowQR => {
                        if is_back {
                            // Reset nframes so re-entry shows mode choice again
                            ad.signed_qr_nframes = 0;
                            ad.signed_qr_large = false;
                            // If we came from a live multisig descriptor, go back there
                            if ad.ms_creating.active {
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            } else {
                                ad.app.go_main_menu();
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
                        ad.needs_redraw = true;
                    }
                    crate::app::input::AppState::Rejected
                    | crate::app::input::AppState::ViewSeed => {
                        // Back button or tap anywhere → main menu
                        ad.app.go_main_menu();
                        ad.needs_redraw = true;
                    }
                    _ => { return None; }
                }
    if needs_redraw { Some(true) } else { None }
}
