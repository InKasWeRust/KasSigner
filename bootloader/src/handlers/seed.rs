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

// handlers/seed.rs — Touch handlers for seed management states
//
// Covers: Bip85Index, Bip85ShowWord, Bip85Deriving, ImportPrivKey,
//         ImportWord, CalcLastWord, DiceRoll, ChooseWordCount,
//         PassphraseEntry, SeedList

use crate::log;
use crate::{app::data::AppData, hw::display, ui::seed_manager, hw::sound, wallet};
use crate::ui::helpers::pp_keyboard_hit;

// Helper functions from helpers.rs
use crate::ui::helpers::{suggestion_hit_test, validate_mnemonic, compute_last_word};

#[cfg(not(feature = "silent"))]

fn hex_nibble(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        b'A'..=b'F' => ch - b'A' + 10,
        _ => 0xFF,
    }
}

/// Handle touch events for seed management screens (BIP85, import, passphrase).
#[inline(never)]
pub fn handle_seed_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::Bip85Index { word_count: bwc } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else if x >= 85 && x <= 125 && y >= 98 && y <= 132 {
                            // [-] button (row_x=85, btn_sz=40, row_y=98, btn_h=34)
                            if ad.bip85_index > 0 { ad.bip85_index -= 1; }
                        } else if x >= 195 && x <= 235 && y >= 98 && y <= 132 {
                            // [+] button (plus_x=195, btn_sz=40)
                            if ad.bip85_index < 99 { ad.bip85_index += 1; }
                        } else if x >= 90 && x <= 230 && y >= 150 && y <= 182 {
                            // Derive button (derive_x=90, derive_w=140, derive_y=150, derive_h=32)
                            if ad.seed_loaded {
                                boot_display.draw_bip85_deriving();

                                // Get seed from active slot
                                let pp = ad.seed_mgr.active_slot().map(|s: &seed_manager::SeedSlot| s.passphrase_str()).unwrap_or("");
                                let seed = if ad.word_count == 12 {
                                    let m = wallet::bip39::Mnemonic12 {
                                        indices: {
                                            let mut idx = [0u16; 12];
                                            idx.copy_from_slice(&ad.mnemonic_indices[..12]);
                                            idx
                                        }
                                    };
                                    wallet::bip39::seed_from_mnemonic_12(&m, pp)
                                } else {
                                    let m = wallet::bip39::Mnemonic24 {
                                        indices: ad.mnemonic_indices,
                                    };
                                    wallet::bip39::seed_from_mnemonic_24(&m, pp)
                                };

                                if bwc == 12 {
                                    match wallet::bip85::derive_mnemonic_12(&seed.bytes, ad.bip85_index as u32) {
                                        Ok(child) => {
                                            ad.bip85_child_wc = 12;
                                            for i in 0..12 { ad.bip85_child_indices[i] = child.indices[i]; }
                                            ad.app.state = crate::app::input::AppState::Bip85ShowWord { word_idx: 0, word_count: 12 };
                                        }
                                        Err(_) => {
                                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                                        }
                                    }
                                } else {
                                    match wallet::bip85::derive_mnemonic_24(&seed.bytes, ad.bip85_index as u32) {
                                        Ok(child) => {
                                            ad.bip85_child_wc = 24;
                                            for i in 0..24 { ad.bip85_child_indices[i] = child.indices[i]; }
                                            ad.app.state = crate::app::input::AppState::Bip85ShowWord { word_idx: 0, word_count: 24 };
                                        }
                                        Err(_) => {
                                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                                        }
                                    }
                                }
                            } else {
                                // No seed loaded — show warning
                                boot_display.draw_rejected_screen("Load a seed first");
                                delay.delay_millis(1500);
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::Bip85ShowWord { word_idx, word_count: bwc } => {
                        if is_back {
                            // Zeroize child indices
                            for i in ad.bip85_child_indices.iter_mut() { *i = 0; }
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            let next = word_idx + 1;
                            if next < bwc {
                                ad.app.state = crate::app::input::AppState::Bip85ShowWord { word_idx: next, word_count: bwc };
                            } else {
                                // Done — zeroize and go back
                                for i in ad.bip85_child_indices.iter_mut() { *i = 0; }
                                ad.app.state = crate::app::input::AppState::ToolsMenu;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::Bip85Deriving => {
                        // No interaction during derivation
                    }
                    crate::app::input::AppState::ImportPrivKey => {
                        if is_back {
                            ad.hex_input_len = 0;
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else {
                            use crate::ui::keyboard::{hit_test, KeyboardMode, KeyAction};
                            match hit_test(x, y, KeyboardMode::Hex, 0) {
                                KeyAction::Char(ch) => {
                                    // Normalize to lowercase for internal storage
                                    let ch_lower = if ch >= b'A' && ch <= b'F' { ch + 32 } else { ch };
                                    if ad.hex_input_len < 64 {
                                        ad.hex_input[ad.hex_input_len as usize] = ch_lower;
                                        ad.hex_input_len += 1;
                                    }
                                }
                                KeyAction::Backspace => {
                                    if ad.hex_input_len > 0 { ad.hex_input_len -= 1; }
                                }
                                KeyAction::Ok => {
                                    if ad.hex_input_len == 64 {
                                        // Parse hex to 32 bytes
                                        let mut key = [0u8; 32];
                                        let mut valid = true;
                                        for i in 0..32 {
                                            let hi = hex_nibble(ad.hex_input[i * 2]);
                                            let lo = hex_nibble(ad.hex_input[i * 2 + 1]);
                                            if hi == 0xFF || lo == 0xFF { valid = false; break; }
                                            key[i] = (hi << 4) | lo;
                                        }
                                        if valid {
                                            if let Ok(xpub) = wallet::bip32::pubkey_from_raw_key(&key) {
                                                if let Some(slot_idx) = ad.seed_mgr.store_raw_key(&key) {
                                                    ad.seed_mgr.activate(slot_idx);
                                                    ad.seed_loaded = true;
                                                    ad.current_addr_index = 0;
                                                    ad.extra_pubkey_index = 0xFFFF;
                                                    ad.pubkey_cache[0].copy_from_slice(&xpub);
                                                    ad.pubkeys_cached = true;
                                                    log!("[IMPORT-KEY] Raw key stored in slot {}", slot_idx);
                                                    boot_display.draw_saving_screen("Key imported!");
                                                    sound::success(delay);
                                                    delay.delay_millis(1500);
                                                    ad.app.state = crate::app::input::AppState::SeedsMenu;
                                                } else {
                                                    boot_display.draw_rejected_screen("All 4 slots full!");
                                                    delay.delay_millis(2000);
                                                }
                                            } else {
                                                boot_display.draw_rejected_screen("Invalid key (not on curve)");
                                                delay.delay_millis(2000);
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("Invalid hex characters");
                                            delay.delay_millis(2000);
                                        }
                                        for b in key.iter_mut() {
                                            unsafe { core::ptr::write_volatile(b as *mut u8, 0); }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ImportWord { word_idx, word_count: wc } => {
                        if is_back {
                            ad.word_input.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else if let Some(idx) = suggestion_hit_test(x, y, &ad.word_input) {
                            // Suggestion tap — takes priority over keyboard
                            ad.mnemonic_indices[word_idx as usize] = idx;
                            ad.word_input.reset();
                            let next = word_idx + 1;
                            if next >= wc {
                                if validate_mnemonic(&ad.mnemonic_indices, wc) {
                                    ad.word_count = wc;
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                } else {
                                    ad.app.state = crate::app::input::AppState::ToolsMenu;
                                }
                            } else {
                                ad.app.state = crate::app::input::AppState::ImportWord {
                                    word_idx: next, word_count: wc,
                                };
                            }
                            needs_redraw = true;
                        } else {
                            use crate::ui::keyboard::{hit_test, KeyboardMode, KeyAction};
                            match hit_test(x, y, KeyboardMode::Alpha, 0) {
                                KeyAction::Char(ch) => {
                                    ad.word_input.push_char(ch);
                                    boot_display.draw_import_keyboard(&ad.word_input);
                                }
                                KeyAction::Backspace => {
                                    ad.word_input.backspace();
                                    boot_display.draw_import_keyboard(&ad.word_input);
                                }
                                KeyAction::Ok => {
                                    if let Some(idx) = ad.word_input.matched_index {
                                        log!("   Word {}: {} (idx {})", word_idx + 1,
                                            wallet::bip39::index_to_word(idx), idx);
                                        ad.mnemonic_indices[word_idx as usize] = idx;
                                        ad.word_input.reset();
                                        let next = word_idx + 1;
                                        if next >= wc {
                                            if validate_mnemonic(&ad.mnemonic_indices, wc) {
                                                ad.word_count = wc;
                                                log!("   Import complete — {} words → passphrase", wc);
                                                ad.pp_input.reset();
                                                ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                            } else {
                                                log!("   Import FAILED — bad checksum");
                                                ad.app.state = crate::app::input::AppState::ToolsMenu;
                                            }
                                        } else {
                                            ad.app.state = crate::app::input::AppState::ImportWord {
                                                word_idx: next, word_count: wc,
                                            };
                                        }
                                    }
                                    needs_redraw = true;
                                }
                                KeyAction::Cancel => {
                                    ad.word_input.reset();
                                    ad.app.state = crate::app::input::AppState::ToolsMenu;
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::CalcLastWord { word_idx, word_count: wc } => {
                        let target = if wc == 12 { 11u8 } else { 23u8 };
                        if is_back {
                            ad.word_input.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else if let Some(idx) = suggestion_hit_test(x, y, &ad.word_input) {
                            ad.mnemonic_indices[word_idx as usize] = idx;
                            ad.word_input.reset();
                            let next = word_idx + 1;
                            if next >= target {
                                let last_idx = compute_last_word(&ad.mnemonic_indices, wc);
                                ad.mnemonic_indices[(wc - 1) as usize] = last_idx;
                                ad.word_count = wc;
                                let last_word = wallet::bip39::index_to_word(last_idx);
                                log!("   Last word: #{} = {}", wc, last_word);
                                boot_display.draw_word_screen(wc - 1, wc, last_word);
                                delay.delay_millis(3000);
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::PassphraseEntry;
                            } else {
                                ad.app.state = crate::app::input::AppState::CalcLastWord {
                                    word_idx: next, word_count: wc,
                                };
                            }
                            needs_redraw = true;
                        } else {
                            use crate::ui::keyboard::{hit_test, KeyboardMode, KeyAction};
                            match hit_test(x, y, KeyboardMode::Alpha, 0) {
                                KeyAction::Char(ch) => {
                                    ad.word_input.push_char(ch);
                                    boot_display.draw_import_keyboard(&ad.word_input);
                                }
                                KeyAction::Backspace => {
                                    ad.word_input.backspace();
                                    boot_display.draw_import_keyboard(&ad.word_input);
                                }
                                KeyAction::Ok => {
                                    if let Some(idx) = ad.word_input.matched_index {
                                        ad.mnemonic_indices[word_idx as usize] = idx;
                                        ad.word_input.reset();
                                        let next = word_idx + 1;
                                        if next >= target {
                                            let last_idx = compute_last_word(&ad.mnemonic_indices, wc);
                                            ad.mnemonic_indices[(wc - 1) as usize] = last_idx;
                                            ad.word_count = wc;
                                            let last_word = wallet::bip39::index_to_word(last_idx);
                                            log!("   Last word: #{} = {}", wc, last_word);
                                            boot_display.draw_word_screen(wc - 1, wc, last_word);
                                            delay.delay_millis(3000);
                                            ad.pp_input.reset();
                                            ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                        } else {
                                            ad.app.state = crate::app::input::AppState::CalcLastWord {
                                                word_idx: next, word_count: wc,
                                            };
                                        }
                                    }
                                    needs_redraw = true;
                                }
                                KeyAction::Cancel => {
                                    ad.word_input.reset();
                                    ad.app.state = crate::app::input::AppState::ToolsMenu;
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::PassphraseEntry => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); needs_redraw = true; } // PAGE — full redraw
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); } // char
                                6 => { // OK — store with passphrase
                                    let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                    if let Some(slot_idx) = ad.seed_mgr.store(
                                        &ad.mnemonic_indices, ad.word_count,
                                        pp_bytes, ad.pp_input.len as u8,
                                    ) {
                                        ad.seed_mgr.activate(slot_idx);
                                        ad.seed_loaded = true;
                                        ad.pubkeys_cached = false;
                                        ad.current_addr_index = 0;
                                        ad.extra_pubkey_index = 0xFFFF;
                                        log!("   Seed stored in slot {} (pp={})", slot_idx, ad.pp_input.len);
                                        sound::success(delay);
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SeedBackup { word_idx: 0 };
                                    } else {
                                        ad.pp_input.reset();
                                        boot_display.draw_rejected_screen("All 4 slots full!");
                                        delay.delay_millis(2000);
                                        ad.app.state = crate::app::input::AppState::ToolsMenu;
                                    }
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SeedList => {
                        if is_back {
                            ad.seed_list_scroll = 0;
                            ad.app.go_main_menu();
                        } else {
                            let mut loaded_idx: [usize; 16] = [0; 16];
                            let mut loaded_n: usize = 0;
                            for si in 0..seed_manager::MAX_SLOTS {
                                if !ad.seed_mgr.slots[si].is_empty() {
                                    loaded_idx[loaded_n] = si;
                                    loaded_n += 1;
                                }
                            }
                            let max_vis: usize = 3;
                            // Total visible rows = loaded seeds + 1 empty "add" row (capped at MAX_SLOTS)
                            let visible_total = (loaded_n + 1).min(seed_manager::MAX_SLOTS);
                            // Page-based scroll: always multiples of max_vis
                            let scroll_off = ad.seed_list_scroll as usize;
                            let slot_wc = ad.seed_mgr.active_slot().map(|s| s.word_count).unwrap_or(0);
                            let can_page_up = scroll_off > 0;
                            let can_page_down = (scroll_off + max_vis) < visible_total;

                            // L-strip page up (x < 40, y >= 42)
                            if x < 40 && y >= 42 && can_page_up {
                                if ad.seed_list_scroll >= max_vis as u8 {
                                    ad.seed_list_scroll -= max_vis as u8;
                                } else {
                                    ad.seed_list_scroll = 0;
                                }
                            }
                            // R-strip page down (x >= 280, y >= 42)
                            else if x >= 280 && y >= 42 && can_page_down {
                                ad.seed_list_scroll += max_vis as u8;
                            }
                            // Top buttons (y=42..74) — always 3 buttons
                            else if y >= 42 && y < 74 {
                                // 3 buttons centered, 95px each, 6px gap
                                let btn_w: u16 = 95;
                                let btn_gap: u16 = 6;
                                let active_count: u16 = if ad.seed_loaded && slot_wc == 1 { 2 } else { 3 };
                                let total_btn_w = active_count * btn_w + (active_count - 1) * btn_gap;
                                let btn_start_x = (320 - total_btn_w) / 2;
                                let mut col: Option<u8> = None;
                                for c in 0..active_count {
                                    let bx = btn_start_x + c * (btn_w + btn_gap);
                                    if x >= bx && x < bx + btn_w {
                                        col = Some(c as u8);
                                        break;
                                    }
                                }
                                if let Some(vis_col) = col {
                                    // For raw keys, button layout is ["", "Address", "Export"]
                                    // Visible col 0 = Address (logical col 1), visible col 1 = Export (logical col 2)
                                    let col = if ad.seed_loaded && slot_wc == 1 {
                                        vis_col + 1 // shift: vis 0→1(Address), vis 1→2(Export)
                                    } else {
                                        vis_col
                                    };
                                    if !ad.seed_loaded {
                                        // No seed — show friendly message, then go to Tools
                                        boot_display.draw_rejected_screen("Load a seed first");
                                        delay.delay_millis(1500);
                                        ad.tools_menu.reset();
                                        ad.app.state = crate::app::input::AppState::ToolsMenu;
                                    } else if col == 0 {
                                        // ── Sign TX ──
                                        // Raw keys can't sign Kaspa transactions (no HD derivation)
                                        if slot_wc == 1 {
                                            boot_display.draw_rejected_screen("Raw key: use Address");
                                            delay.delay_millis(1500);
                                        } else {
                                            // Ensure pubkeys are derived before showing guide
                                            if !ad.pubkeys_cached {
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
                                                    let ww = crate::hw::display::measure_body("Wait ~30 seconds");
                                                    crate::hw::display::draw_lato_body(&mut boot_display.display, "Wait ~30 seconds", (320 - ww) / 2, 172, crate::hw::display::COLOR_TEXT_DIM);
                                                }
                                                if slot_wc == 2 {
                                                    let acct = wallet::bip32::ExtendedPrivKey::from_raw(&ad.acct_key_raw);
                                                    for idx in 0..20u16 {
                                                        if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                            if let Ok(pk) = ak.public_key_x_only() {
                                                                ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                            }
                                                        }
                                                    }
                                                } else {
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
                                                    if let Ok(acct) = wallet::bip32::derive_account_key(&seed_bytes.bytes) {
                                                        ad.acct_key_raw.copy_from_slice(&acct.to_raw());
                                                        for idx in 0..20u16 {
                                                            if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                                if let Ok(pk) = ak.public_key_x_only() {
                                                                    ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                ad.pubkeys_cached = true;
                                            }
                                            ad.app.state = crate::app::input::AppState::SignTxGuide;
                                        }
                                    } else if col == 1 {
                                        // ── Address ──
                                        if slot_wc == 1 {
                                            // Raw key — derive pubkey directly
                                            if !ad.pubkeys_cached {
                                                if let Some(slot) = ad.seed_mgr.active_slot() as Option<&seed_manager::SeedSlot> {
                                                    let mut key = [0u8; 32];
                                                    slot.raw_key_bytes(&mut key);
                                                    if let Ok(xpub) = wallet::bip32::pubkey_from_raw_key(&key) {
                                                        ad.pubkey_cache[0].copy_from_slice(&xpub);
                                                    }
                                                    for b in key.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } }
                                                    ad.pubkeys_cached = true;
                                                }
                                            }
                                        } else if slot_wc == 2 {
                                            // xprv — derive from cached account key
                                            if !ad.pubkeys_cached {
                                                boot_display.draw_saving_screen("Deriving addresses...");
                                                let acct = wallet::bip32::ExtendedPrivKey::from_raw(&ad.acct_key_raw);
                                                for idx in 0..20u16 {
                                                    if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                        if let Ok(pk) = ak.public_key_x_only() {
                                                            ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                        }
                                                    }
                                                }
                                                ad.pubkeys_cached = true;
                                            }
                                        } else {
                                            // Normal mnemonic — full PBKDF2 derivation
                                            if !ad.pubkeys_cached {
                                                boot_display.draw_saving_screen("Deriving ~30s...");
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
                                                if let Ok(acct) = wallet::bip32::derive_account_key(&seed_bytes.bytes) {
                                                    ad.acct_key_raw.copy_from_slice(&acct.to_raw());
                                                    for idx in 0..20u16 {
                                                        if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                            if let Ok(pk) = ak.public_key_x_only() {
                                                                ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                            }
                                                        }
                                                    }
                                                    ad.pubkeys_cached = true;
                                                }
                                            }
                                        }
                                        ad.scanned_addr_len = 0;
                                        ad.app.state = crate::app::input::AppState::ShowAddress;
                                    } else if col == 2 {
                                        // ── Export ──
                                        if slot_wc == 1 {
                                            // Raw key → export hex directly
                                            if let Some(slot) = ad.seed_mgr.active_slot() as Option<&seed_manager::SeedSlot> {
                                                let mut key = [0u8; 32];
                                                slot.raw_key_bytes(&mut key);
                                                for i in 0..32 {
                                                    const HX: &[u8; 16] = b"0123456789abcdef";
                                                    ad.export_key_hex[i * 2] = HX[(key[i] >> 4) as usize];
                                                    ad.export_key_hex[i * 2 + 1] = HX[(key[i] & 0x0f) as usize];
                                                }
                                                for b in key.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } }
                                                ad.app.state = crate::app::input::AppState::ExportPrivKey;
                                            }
                                        } else {
                                            // Normal/xprv → export choice menu
                                            ad.app.state = crate::app::input::AppState::ExportChoice;
                                        }
                                    }
                                }
                            }
                            // Card rows in center content (x=40..280, y=78..216)
                            else if x >= 40 && x < 280 && y >= 76 && y < 216 {
                                let card_h: u16 = 42;
                                let card_gap: u16 = 4;
                                let start_y: u16 = 78;
                                for vis in 0..max_vis {
                                    let list_idx = scroll_off + vis;
                                    let row_y_val = start_y + (vis as u16) * (card_h + card_gap);
                                    if y >= row_y_val && y < row_y_val + card_h {
                                        if list_idx >= loaded_n {
                                            // Empty row tapped → go to Tools
                                            ad.tools_menu.reset();
                                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                                            break;
                                        }
                                        let i = loaded_idx[list_idx];
                                        // DEL button: rightmost 38px of card
                                        if x >= 232 && x < 276 {
                                            // Store pending slot and go to confirmation screen
                                            ad.pending_delete_slot = i as u8;
                                            ad.app.state = crate::app::input::AppState::ConfirmDeleteSeed;
                                            break;
                                        }
                                        // Select/activate slot
                                        ad.seed_mgr.activate(i);
                                        ad.mnemonic_indices = ad.seed_mgr.slots[i].indices;
                                        ad.word_count = ad.seed_mgr.slots[i].word_count;
                                        ad.seed_loaded = true;
                                        ad.pubkeys_cached = false;
                                        ad.current_addr_index = 0;
                                        ad.extra_pubkey_index = 0xFFFF;
                                        if ad.word_count == 2 {
                                            let slot = &ad.seed_mgr.slots[i];
                                            for j in 0..16 {
                                                let le = slot.indices[j].to_le_bytes();
                                                ad.acct_key_raw[j * 2] = le[0];
                                                ad.acct_key_raw[j * 2 + 1] = le[1];
                                            }
                                            ad.acct_key_raw[32..64].copy_from_slice(&slot.passphrase[..32]);
                                            ad.acct_key_raw[64] = slot.passphrase[32];
                                        }
                                        sound::success(delay);
                                        break;
                                    }
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::ConfirmDeleteSeed => {
                        if is_back {
                            ad.pending_delete_slot = 0xFF;
                            ad.app.state = crate::app::input::AppState::SeedList;
                        } else if y >= 180 && y <= 230 {
                            // Bottom buttons row
                            if x >= 30 && x <= 150 {
                                // CANCEL — go back to seed list
                                ad.pending_delete_slot = 0xFF;
                                ad.app.state = crate::app::input::AppState::SeedList;
                                sound::click(delay);
                            } else if x >= 170 && x <= 290 {
                                // DELETE — perform the actual deletion
                                let i = ad.pending_delete_slot as usize;
                                if i < ad.seed_mgr.slots.len() {
                                    let was_active = ad.seed_mgr.active == i as u8;
                                    ad.seed_mgr.delete(i);
                                    if was_active {
                                        ad.seed_loaded = false;
                                        ad.pubkeys_cached = false;
                                        ad.current_addr_index = 0;
                                        ad.extra_pubkey_index = 0xFFFF;
                                        for sl in ad.pubkey_cache.iter_mut() { for b in sl.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } } }
                                        for b in ad.acct_key_raw.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } }
                                        for b in ad.extra_pubkey.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } }
                                        for b in ad.our_privkey.iter_mut() { unsafe { core::ptr::write_volatile(b as *mut u8, 0); } }
                                    }
                                }
                                ad.pending_delete_slot = 0xFF;
                                ad.app.state = crate::app::input::AppState::SeedList;
                                sound::warning(delay);
                            }
                        }
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
