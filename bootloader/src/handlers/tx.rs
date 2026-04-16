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

// handlers/tx.rs — Touch handlers for transaction, multisig, and message signing states
//
// Covers: ScanQR, ReviewTx, ConfirmTx, MultisigChooseMN, MultisigAddKey, MultisigShowAddress,
//         SignMsgChoice, SignMsgType, SignMsgFile, SignMsgPreview, SignMsgResult

use crate::{app::data::AppData, hw::display, hw::sdcard, hw::sound, hw::touch, wallet};
use crate::ui::helpers::pp_keyboard_hit;
#[allow(unused_variables, unused_assignments, unused_mut)]
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
                            // "SCAN KSPT" button: drawn at y=194..230, x=60..260
                            if (190..=234).contains(&y) && (55..=265).contains(&x) {
                                ad.app.state = crate::app::input::AppState::ScanQR;
                                needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::ScanQR => {
                        // Back button (top-left) — both platforms
                        if x <= 40 && y <= 40 {
                            #[cfg(feature = "waveshare")]
                            { ad.cam_tune_active = false; }
                            if ad.ms_creating.n > 0 && !ad.ms_creating.active {
                                let mut key_idx: u8 = 0;
                                for i in 0..ad.ms_creating.n {
                                    if ad.ms_creating.slot_empty(i as usize) {
                                        key_idx = i;
                                        break;
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx };
                            } else {
                                ad.app.go_main_menu();
                            }
                            needs_redraw = true;
                        }
                        // M5Stack: top-right = home
                        #[cfg(feature = "m5stack")]
                        if x >= 268 && y <= 40 {
                            ad.app.go_main_menu();
                            needs_redraw = true;
                        }
                        // Waveshare: cam-tune overlay interaction
                        #[cfg(feature = "waveshare")]
                        if x > 40 || y > 40 {
                            if ad.cam_tune_active {
                                // Slider track (y>=200, x=52..268) — padded around track at y=210
                                if y >= 198 && (52..=268).contains(&x) {
                                    let clamped = (x as i32 - 56).max(0).min(208) as u32;
                                    ad.cam_tune_vals[ad.cam_tune_param as usize] = ((clamped * 255) / 208) as u8;
                                    ad.cam_tune_dirty = true;
                                    boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                }
                                // [-] button (visual: x=2..52, y=200..234)
                                else if x <= 52 && y >= 195 {
                                    let p = ad.cam_tune_param as usize;
                                    ad.cam_tune_vals[p] = ad.cam_tune_vals[p].saturating_sub(8);
                                    ad.cam_tune_dirty = true;
                                    boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                }
                                // [+] button (visual: x=268..318, y=200..234)
                                else if x >= 265 && y >= 195 {
                                    let p = ad.cam_tune_param as usize;
                                    ad.cam_tune_vals[p] = ad.cam_tune_vals[p].saturating_add(8);
                                    ad.cam_tune_dirty = true;
                                    boot_display.update_cam_tune_slider(ad.cam_tune_param, &ad.cam_tune_vals);
                                }
                                // Right panel (x>=198)
                                else if x >= 198 {
                                    if y <= 36 {
                                        // EXIT button (visual: 202,2 → 318,34)
                                        ad.cam_tune_active = false;
                                        boot_display.draw_camera_screen("", "");
                                    } else if (36..180).contains(&y) {
                                        // Param grid: col split at x=259, row_step=47
                                        let col = if x < 259 { 0u8 } else { 1u8 };
                                        let row = ((y as i32 - 38).max(0) / 47).min(2) as u8;
                                        let idx = row * 2 + col;
                                        if idx < 6 && idx != ad.cam_tune_param {
                                            ad.cam_tune_param = idx;
                                            boot_display.draw_cam_tune_overlay(ad.cam_tune_param, &ad.cam_tune_vals);
                                        }
                                    }
                                }
                            } else {
                                // Normal ScanQR — gear icon (x>=270, y<=48) → activate cam-tune
                                if x >= 270 && y <= 48 {
                                    ad.cam_tune_active = true;
                                    boot_display.draw_camera_screen("", "");
                                    boot_display.draw_cam_tune_overlay(ad.cam_tune_param, &ad.cam_tune_vals);
                                }
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
                            let in_confirm = (30..=290).contains(&x) && (118..=165).contains(&y);
                            let in_cancel  = (30..=290).contains(&x) && (168..=230).contains(&y);

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
                            // M-: x=60..110, y=65..103
                            if (60..=110).contains(&x) && (65..=103).contains(&y) {
                                if ad.ms_m > 1 { ad.ms_m -= 1; }
                            }
                            // M+: x=210..260, y=65..103
                            else if (210..=260).contains(&x) && (65..=103).contains(&y) {
                                if ad.ms_m < 5 { ad.ms_m += 1; }
                            }
                            // N-: x=60..110, y=125..163
                            else if (60..=110).contains(&x) && (125..=163).contains(&y) {
                                if ad.ms_n > 1 { ad.ms_n -= 1; }
                            }
                            // N+: x=210..260, y=125..163
                            else if (210..=260).contains(&x) && (125..=163).contains(&y) {
                                if ad.ms_n < 5 { ad.ms_n += 1; }
                            }
                            // NEXT: centered, x=80..240, y=190..230
                            else if (80..=240).contains(&x) && (190..=230).contains(&y)
                                && ad.ms_m >= 1 && ad.ms_m <= ad.ms_n && ad.ms_n <= 5
                            {
                                ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                ad.ms_creating.m = ad.ms_m;
                                ad.ms_creating.n = ad.ms_n;
                                ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: 0 };
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
                                ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: key_idx - 1 };
                            }
                        } else {
                            // "Scan QR": x=30..290, y=90..135
                            if (30..=290).contains(&x) && (90..=135).contains(&y) {
                                ad.app.state = crate::app::input::AppState::ScanQR;
                            }
                            // "Use Loaded Seed": x=30..290, y=145..190
                            else if (30..=290).contains(&x) && (145..=190).contains(&y) {
                                if ad.seed_loaded {
                                    ad.app.state = crate::app::input::AppState::MultisigPickSeed { key_idx };
                                } else {
                                    // No seed loaded — show warning
                                    boot_display.draw_rejected_screen("Load a seed first");
                                    delay.delay_millis(1500);
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigPickSeed { key_idx } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx };
                        } else {
                            // Count loaded seeds for scroll bounds
                            let loaded_count = ad.seed_mgr.slots.iter()
                                .filter(|s| !s.is_empty()).count() as u8;

                            // Left arrow (scroll up): x<35, y=46..184
                            if x < 35 && (46..=184).contains(&y) {
                                if ad.ms_scroll >= 3 {
                                    ad.ms_scroll -= 3;
                                }
                            }
                            // Right arrow (scroll down): x>285, y=46..184
                            else if x > 285 && (46..=184).contains(&y) {
                                if ad.ms_scroll + 3 < loaded_count {
                                    ad.ms_scroll += 3;
                                }
                            }
                            // Seed card rows: start_y=46, card_h=42, card_gap=4, max 3 visible
                            else {
                                // Build list of non-empty slot indices
                                let mut loaded: [usize; 16] = [0; 16];
                                let mut lcount: usize = 0;
                                for i in 0..crate::ui::seed_manager::MAX_SLOTS {
                                    if !ad.seed_mgr.slots[i].is_empty() {
                                        loaded[lcount] = i;
                                        lcount += 1;
                                    }
                                }

                                for vis in 0..3u8 {
                                    let row_y = 46 + vis as u16 * 46;
                                    if y >= row_y && y < row_y + 46 && (40..=280).contains(&x) {
                                        let list_idx = ad.ms_scroll as usize + vis as usize;

                                        if list_idx >= lcount {
                                            // Empty slot tapped → go to Tools menu to create/import
                                            ad.tools_menu.reset();
                                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                                            break;
                                        }

                                        let real_slot = loaded[list_idx] as u8;

                                        // Trash button: rightmost 44px of card (start_x=44, card_w=232, so trash at x>=232)
                                        if x >= 232 {
                                            ad.pending_delete_slot = real_slot;
                                            ad.app.state = crate::app::input::AppState::ConfirmDeleteSeed;
                                            break;
                                        }

                                        // Tap seed card → select and derive
                                        let already_active = (ad.seed_mgr.active == real_slot)
                                            && ad.pubkeys_cached;

                                        if !already_active {
                                            ad.seed_mgr.activate(real_slot as usize);
                                            let slot = &ad.seed_mgr.slots[real_slot as usize];
                                            ad.mnemonic_indices = slot.indices;
                                            ad.word_count = slot.word_count;
                                            ad.seed_loaded = true;
                                            boot_display.draw_saving_screen("Deriving addresses...");
                                            boot_display.update_progress_bar(50);
                                            let hw = crate::hw::display::measure_hint("Deriving...");
                                            crate::hw::display::draw_lato_hint(
                                                &mut boot_display.display, "Deriving...",
                                                (320 - hw) / 2, 170,
                                                crate::hw::display::COLOR_TEXT_DIM);
                                            let pp = slot.passphrase_str();
                                            crate::app::signing::derive_all_pubkeys(
                                                &ad.mnemonic_indices, ad.word_count, pp,
                                                &mut ad.pubkey_cache, &mut ad.acct_key_raw);
                                            crate::app::signing::derive_change_pubkeys(
                                                &ad.acct_key_raw, &mut ad.change_pubkey_cache);
                                            ad.pubkeys_cached = true;
                                        }
                                        ad.current_addr_index = 0;
                                        ad.app.state = crate::app::input::AppState::MultisigPickAddr { key_idx };
                                        break;
                                    }
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigPickAddr { key_idx } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigPickSeed { key_idx };
                        } else if (10..=60).contains(&x) && (205..=240).contains(&y) {
                            // [<] previous address
                            if ad.current_addr_index > 0 {
                                ad.current_addr_index -= 1;
                                if ad.current_addr_index >= 20 && ad.extra_pubkey_index != ad.current_addr_index {
                                    crate::app::signing::derive_pubkey_from_acct(
                                        &ad.acct_key_raw, ad.current_addr_index, &mut ad.extra_pubkey);
                                    ad.extra_pubkey_index = ad.current_addr_index;
                                }
                            }
                        } else if (260..=310).contains(&x) && (205..=240).contains(&y) {
                            // [>] next address
                            ad.current_addr_index += 1;
                            if ad.current_addr_index >= 20 && ad.extra_pubkey_index != ad.current_addr_index {
                                crate::app::signing::derive_pubkey_from_acct(
                                    &ad.acct_key_raw, ad.current_addr_index, &mut ad.extra_pubkey);
                                ad.extra_pubkey_index = ad.current_addr_index;
                            }
                        } else if (110..=210).contains(&x) && (205..=240).contains(&y) {
                            // [#N] — open index picker, then return to MultisigPickAddr
                            ad.addr_input_len = 0;
                            ad.ms_picking_key = key_idx + 1; // +1 so 0 means "not picking"
                            ad.app.state = crate::app::input::AppState::AddrIndexPicker;
                        } else if (90..=230).contains(&x) && (145..=185).contains(&y) {
                            // SELECT button — store device's own account-level x-only pubkey.
                            //
                            // BUG FIX (TODO 7): we were previously storing an ADDRESS-level
                            // key (pubkey_cache[current_addr_index] = m/44'/111111'/0'/0/N).
                            // Meanwhile, the OTHER cosigner's kpub comes in through
                            // import_kpub() which returns the ACCOUNT-level x-only key
                            // (m/44'/111111'/0'). Two different 32-byte keys sort
                            // differently, produce different multisig scripts, and
                            // therefore different P2SH addresses on each device — even
                            // with the same pubkeys "in the same order".
                            //
                            // Fix: both devices now supply their account-level x-only
                            // pubkey. After lexicographic sort in build_script(), both
                            // devices produce byte-identical scripts → identical P2SH
                            // address. The account key is already cached in acct_key_raw
                            // when the seed was loaded.
                            if key_idx < ad.ms_creating.n {
                                let acct = wallet::bip32::ExtendedPrivKey::from_raw(&ad.acct_key_raw);
                                // Export own account xpub (pubkey + chain code) —
                                // both needed for HD derivation of per-address children.
                                if let Ok(own_xpub) = acct.to_xpub() {
                                    ad.ms_creating.cosigner_pubkeys[key_idx as usize] = own_xpub.pubkey;
                                    ad.ms_creating.cosigner_chain_codes[key_idx as usize] = own_xpub.chain_code;
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
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigShowAddress => {
                        if is_back {
                            ad.app.go_main_menu();
                            needs_redraw = true;
                        } else if y >= 195 {
                            // Bottom nav band — split by x into [<] / [#N] / [>].
                            if x <= 90 {
                                // [<] — previous address (saturating at 0)
                                if ad.ms_creating.addr_index > 0 {
                                    ad.ms_creating.addr_index -= 1;
                                    ad.ms_creating.build_script();
                                    for i in 0..crate::wallet::transaction::MAX_MULTISIG_WALLETS {
                                        if ad.ms_store.configs[i].active
                                            && ad.ms_store.configs[i].m == ad.ms_creating.m
                                            && ad.ms_store.configs[i].n == ad.ms_creating.n
                                            && ad.ms_store.configs[i].cosigner_pubkeys
                                                == ad.ms_creating.cosigner_pubkeys
                                        {
                                            ad.ms_store.configs[i] = ad.ms_creating.clone();
                                            break;
                                        }
                                    }
                                }
                                needs_redraw = true;
                            } else if x >= 230 {
                                // [>] — next address
                                if ad.ms_creating.addr_index < u16::MAX as u32 {
                                    ad.ms_creating.addr_index += 1;
                                    ad.ms_creating.build_script();
                                    for i in 0..crate::wallet::transaction::MAX_MULTISIG_WALLETS {
                                        if ad.ms_store.configs[i].active
                                            && ad.ms_store.configs[i].m == ad.ms_creating.m
                                            && ad.ms_store.configs[i].n == ad.ms_creating.n
                                            && ad.ms_store.configs[i].cosigner_pubkeys
                                                == ad.ms_creating.cosigner_pubkeys
                                        {
                                            ad.ms_store.configs[i] = ad.ms_creating.clone();
                                            break;
                                        }
                                    }
                                }
                                needs_redraw = true;
                            } else {
                                // Center [#N] — numeric picker. Sentinel 255 routes
                                // AddrIndexPicker GO back to MultisigShowAddress.
                                ad.addr_input_len = 0;
                                ad.ms_picking_key = 255;
                                ad.app.state = crate::app::input::AppState::AddrIndexPicker;
                                needs_redraw = true;
                            }
                        } else {
                            // Tap on the address text area → show QR
                            ad.app.state = crate::app::input::AppState::MultisigShowAddressQR;
                            needs_redraw = true;
                        }
                    }
                    crate::app::input::AppState::MultisigShowAddressQR => {
                        if is_back {
                            if ad.ms_creating.active {
                                ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                            } else {
                                // SD-loaded: back to main menu
                                ad.signed_qr_len = 0;
                                ad.app.go_main_menu();
                            }
                        } else {
                            if ad.ms_creating.active {
                                // Live flow: tap → ask whether to save address to SD
                                ad.app.state = crate::app::input::AppState::MultisigSaveAddrAsk;
                            } else {
                                // SD-loaded: tap → back to main menu (already on disk)
                                ad.signed_qr_len = 0;
                                ad.app.go_main_menu();
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigSaveAddrAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                        } else if (30..=155).contains(&x) && (140..=185).contains(&y) {
                            // Yes — save address to SD: go to filename keyboard
                            // Build the address string and store in kpub_data for later save
                            let script_hash = wallet::sighash::blake2b_hash(
                                &ad.ms_creating.script[..ad.ms_creating.script_len]);
                            let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                            let addr_len = wallet::address::encode_address(
                                &script_hash, wallet::address::AddressType::P2SH, &mut addr_buf);
                            ad.kpub_data[..addr_len].copy_from_slice(&addr_buf[..addr_len]);
                            ad.kpub_len = addr_len;

                            // Auto-increment: MS000001.TXT
                            let next = crate::handlers::sd::scan_auto_increment(i2c, delay, b"MS", b"TXT");
                            let name = crate::handlers::sd::format_auto_name(b"MS", next, b"TXT");
                            ad.kspt_filename = name;
                            ad.pp_input.reset();
                            for j in 0..8usize {
                                if name[j] != b' ' {
                                    ad.pp_input.push_char(name[j]);
                                }
                            }
                            ad.app.state = crate::app::input::AppState::SdMsAddrFilename;
                        } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                            // No — skip to descriptor
                            ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigDescriptor => {
                        if is_back {
                            if ad.ms_creating.active {
                                ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                            } else {
                                // SD-loaded view-only flow: back to main menu
                                ad.app.go_main_menu();
                            }
                        } else if (190..=230).contains(&y) && (170..=310).contains(&x) {
                                // SD CARD button — build HD descriptor text and go to filename keyboard.
                                // Format: multi_hd(M,<65-byte hex>,<65-byte hex>,...) where each
                                // participant hex = compressed pubkey(33) + chain code(32). This
                                // carries the information both devices need to rederive
                                // per-address cosigner children. Old 32-byte-hex single-point
                                // multi(...) descriptors from v1.0.x are incompatible — the
                                // "multi_hd" function name signals the new format.
                                //
                                // Size: 130 hex chars per cosigner vs 64 in v1.0.x — descriptor
                                // QR roughly 2× larger. Still fits in single QR for N≤3; N=4..5
                                // may require multi-frame.
                                let hex = b"0123456789abcdef";
                                let mut pos: usize = 0;
                                for &b in b"multi_hd(" { ad.signed_qr_buf[pos] = b; pos += 1; }
                                ad.signed_qr_buf[pos] = b'0' + ad.ms_creating.m; pos += 1;
                                for i in 0..ad.ms_creating.n as usize {
                                    ad.signed_qr_buf[pos] = b','; pos += 1;
                                    // Compressed pubkey (33 bytes = 66 hex chars)
                                    let pk = &ad.ms_creating.cosigner_pubkeys[i];
                                    for j in 0..33 {
                                        ad.signed_qr_buf[pos] = hex[(pk[j] >> 4) as usize]; pos += 1;
                                        ad.signed_qr_buf[pos] = hex[(pk[j] & 0x0f) as usize]; pos += 1;
                                    }
                                    // Chain code (32 bytes = 64 hex chars)
                                    let cc = &ad.ms_creating.cosigner_chain_codes[i];
                                    for j in 0..32 {
                                        ad.signed_qr_buf[pos] = hex[(cc[j] >> 4) as usize]; pos += 1;
                                        ad.signed_qr_buf[pos] = hex[(cc[j] & 0x0f) as usize]; pos += 1;
                                    }
                                }
                                ad.signed_qr_buf[pos] = b')'; pos += 1;
                                ad.signed_qr_len = pos;

                                // Auto-increment filename: MD000001.TXT
                                let next = crate::handlers::sd::scan_auto_increment(i2c, delay, b"MD", b"TXT");
                                let name = crate::handlers::sd::format_auto_name(b"MD", next, b"TXT");
                                ad.kspt_filename = name;
                                ad.pp_input.reset();
                                for j in 0..8usize {
                                    if name[j] != b' ' {
                                        ad.pp_input.push_char(name[j]);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::SdMsDescFilename;
                        } else if (190..=230).contains(&y) && (10..=150).contains(&x) {
                                // QR button — show HD descriptor as QR for KasSee / another KasSigner.
                                let hex = b"0123456789abcdef";
                                let mut pos: usize = 0;
                                for &b in b"multi_hd(" { ad.signed_qr_buf[pos] = b; pos += 1; }
                                ad.signed_qr_buf[pos] = b'0' + ad.ms_creating.m; pos += 1;
                                for i in 0..ad.ms_creating.n as usize {
                                    ad.signed_qr_buf[pos] = b','; pos += 1;
                                    let pk = &ad.ms_creating.cosigner_pubkeys[i];
                                    for j in 0..33 {
                                        ad.signed_qr_buf[pos] = hex[(pk[j] >> 4) as usize]; pos += 1;
                                        ad.signed_qr_buf[pos] = hex[(pk[j] & 0x0f) as usize]; pos += 1;
                                    }
                                    let cc = &ad.ms_creating.cosigner_chain_codes[i];
                                    for j in 0..32 {
                                        ad.signed_qr_buf[pos] = hex[(cc[j] >> 4) as usize]; pos += 1;
                                        ad.signed_qr_buf[pos] = hex[(cc[j] & 0x0f) as usize]; pos += 1;
                                    }
                                }
                                ad.signed_qr_buf[pos] = b')'; pos += 1;
                                ad.signed_qr_len = pos;
                                ad.signed_qr_nframes = 0;
                                ad.signed_qr_frame = 0;
                                ad.qr_manual_frames = false;
                                ad.app.state = crate::app::input::AppState::ShowQR;
                        }
                        needs_redraw = true;
                    }
                    // ─── Sign Message Flow ────────────
                    crate::app::input::AppState::SignMsgChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ToolsMenu;
                        } else if (40..280).contains(&x) && (68..112).contains(&y) {
                            // Type manually
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SignMsgType;
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
                        } else if (185..=225).contains(&y) && (100..=220).contains(&x) {
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
                        } else if (155..=191).contains(&y) && (60..=260).contains(&x) {
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
