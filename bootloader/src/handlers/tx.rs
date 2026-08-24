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
                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
                            needs_redraw = true;
                        } else if ad.seed_loaded {
                            // Two buttons at y=194..230
                            // Left: "EXPORT KPUB" x=30..154
                            // Right: "SCAN PSKB"  x=166..290
                            if (190..=234).contains(&y) {
                                if (25..=159).contains(&x) {
                                    // EXPORT KPUB
                                    ad.kpub_export_return = crate::app::input::AppState::SignTxGuide;
                                    ad.app.state = crate::app::input::AppState::ExportKpubFrameCount;
                                    needs_redraw = true;
                                } else if (161..=295).contains(&x) {
                                    // SCAN PSKB
                                    ad.app.state = crate::app::input::AppState::ScanQR;
                                    needs_redraw = true;
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::ScanQR => {
                        // Back button (top-left) — both platforms
                        if x <= 48 && y <= 48 {
                            #[cfg(feature = "waveshare")]
                            { ad.cam_tune_active = false; }
                            if ad.sign_msg_scan_hash {
                                ad.sign_msg_scan_hash = false;
                                ad.app.state = crate::app::input::AppState::SignMsgChoice;
                            } else if ad.ms_creating.n > 0 && !ad.ms_creating.active {
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
                        }
                        // Note: in v1.0.3 the top-right home shortcut was
                        // removed on M5Stack for UX consistency with Waveshare.
                        // Back button (top-left) is the only way out of ScanQR.
                        // The old gear-icon cam-tune trigger was also removed
                        // (cam-tune now lives in Settings → Camera).
                    }
                    crate::app::input::AppState::ReviewTx { .. } => {
                        if is_back {
                            ad.app.go_main_menu();
                            needs_redraw = true;
                        } else {
                            // Next page
                            let evt = crate::app::input::ButtonEvent::ShortPress;
                            ad.app.handle_boot(evt);
                            needs_redraw = true;
                        }
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
                                // REFUSE a transaction whose change claim a
                                // trusted descriptor contradicts.
                                //
                                // Not the same as an unverifiable claim, which
                                // is only warned about: there the device lacks
                                // the information and the risk is the user's to
                                // take. Here a descriptor that reproduces this
                                // transaction's own INPUT - so it is this
                                // wallet's key set - fails to reproduce the
                                // output. The claim is false, and no honest
                                // coordinator produces that.
                                //
                                // Forging it would need the whole cosigner set,
                                // and anyone holding that already knows the real
                                // addresses, so there is no benign reading.
                                if let Some(o) = crate::wallet::transaction::find_forged_change(
                                    &ad.demo_tx, &ad.ms_store.configs,
                                ) {
                                    crate::log!(
                                        "   REFUSED: output {} claims to be change at a path \
                                         this wallet's descriptor does not produce",
                                        o + 1
                                    );
                                    boot_display.draw_rejected_screen("Forged change output");
                                    sound::beep_error(delay);
                                    delay.delay_millis(2500);
                                    ad.app.go_main_menu();
                                    return Some(true);
                                }
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
                            ad.ms_creating.n = 0;
                            ad.app.state = crate::app::input::AppState::MultisigMenu;
                            needs_redraw = true;
                        } else {
                            // M-: x=60..110, y=65..103
                            if (60..=110).contains(&x) && (65..=103).contains(&y) {
                                if ad.ms_m > 1 { ad.ms_m -= 1; needs_redraw = true; }
                            }
                            // M+: x=210..260, y=65..103
                            else if (210..=260).contains(&x) && (65..=103).contains(&y) {
                                if ad.ms_m < 5 { ad.ms_m += 1; needs_redraw = true; }
                            }
                            // N-: x=60..110, y=125..163
                            else if (60..=110).contains(&x) && (125..=163).contains(&y) {
                                if ad.ms_n > 1 { ad.ms_n -= 1; needs_redraw = true; }
                            }
                            // N+: x=210..260, y=125..163
                            else if (210..=260).contains(&x) && (125..=163).contains(&y) {
                                if ad.ms_n < 5 { ad.ms_n += 1; needs_redraw = true; }
                            }
                            // NEXT: centered, x=80..240, y=190..230
                            else if (80..=240).contains(&x) && (190..=230).contains(&y)
                                && ad.ms_m >= 1 && ad.ms_m <= ad.ms_n && ad.ms_n <= 5
                            {
                                ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                ad.ms_creating.m = ad.ms_m;
                                ad.ms_creating.n = ad.ms_n;
                                // 45' ONLY from v1.0.6. The rusty-kaspa standard, so a
                                // wallet made here is reproducible by kaspawallet.
                                //
                                // Every 44' path stays reachable forever: existing
                                // wallets hold funds at those addresses, and the device
                                // must still parse `multi_hd(`, run the 44' branch of
                                // build_script, match keys with the 44' matcher, and
                                // re-export a 44' descriptor. What dies here is only the
                                // ability to CREATE a new one. The 44' branch is legacy,
                                // not dead code: deleting it strands every existing
                                // wallet with no way to rebuild its address.
                                ad.ms_creating.v45 = true;
                                ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: 0 };
                                needs_redraw = true;
                            }
                            // Keep M <= N
                            if ad.ms_m > ad.ms_n { ad.ms_m = ad.ms_n; needs_redraw = true; }
                        }
                    }
                    crate::app::input::AppState::MultisigAddKey { key_idx } => {
                        if is_back {
                            if key_idx == 0 {
                                ad.ms_creating.n = 0;
                                ad.app.state = crate::app::input::AppState::MultisigChooseMN;
                                needs_redraw = true;
                            } else {
                                ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: key_idx - 1 };
                            }
                        } else {
                            // "Scan QR": x=30..290, y=90..135
                            if (30..=290).contains(&x) && (90..=135).contains(&y) {
                                ad.app.state = crate::app::input::AppState::ScanQR;
                                needs_redraw = true;
                            }
                            // "Use Loaded Seed": x=30..290, y=145..190
                            else if (30..=290).contains(&x) && (145..=190).contains(&y) {
                                if ad.seed_loaded {
                                    ad.app.state = crate::app::input::AppState::MultisigPickSeed { key_idx };
                                    needs_redraw = true;
                                } else {
                                    // No seed loaded — show warning
                                    boot_display.draw_rejected_screen("Load a seed first");
                                    delay.delay_millis(1500);
                                    needs_redraw = true;
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::MultisigPickSeed { key_idx } => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx };
                            needs_redraw = true;
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
                                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
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
                                            {
                                                let slot = &ad.seed_mgr.slots[real_slot as usize];
                                                ad.word_count = slot.word_count;
                                                // BEHAVIOUR CHANGE, 2026-08-02.
                                                // This used to copy `slot.indices`
                                                // unconditionally, so for an xprv
                                                // slot a packed PRIVATE KEY was
                                                // written into a field named
                                                // `mnemonic_indices`. Nothing reads
                                                // it for that kind: the `as_xprv`
                                                // branch below populates
                                                // `acct_key_raw` from the slot, and
                                                // `fill_display_caches` dispatches on
                                                // `word_count`. Now non-mnemonic
                                                // slots leave it zeroed (H-08).
                                                ad.mnemonic_indices = match slot.as_mnemonic() {
                                                    Some((idx, _)) => *idx,
                                                    None => [0u16; 24],
                                                };
                                                // xprv slot: the slot IS the
                                                // account key. Without this the
                                                // xpub exported below came from
                                                // whatever the previous slot
                                                // left in acct_key_raw.
                                                //
                                                // `as_xprv` checks the kind and
                                                // decodes in one step, so the two
                                                // cannot disagree (H-08).
                                                if let Some((key, chain_code, depth)) = slot.as_xprv() {
                                                    ad.acct_key_raw[..32].copy_from_slice(&key);
                                                    ad.acct_key_raw[32..64].copy_from_slice(&chain_code);
                                                    ad.acct_key_raw[64] = depth;
                                                }
                                            }
                                            ad.seed_loaded = true;
                                            ad.chain_cache = None;
                                            ad.ext_recv_n = 0;
                                            ad.ext_chg_n = 0;
                                            boot_display.draw_saving_screen("Deriving addresses...");
                                            boot_display.update_progress_bar(50);
                                            let hw = crate::hw::display::measure_hint("Deriving...");
                                            crate::hw::display::draw_lato_hint(
                                                &mut boot_display.display, "Deriving...",
                                                (320 - hw) / 2, 170,
                                                crate::hw::display::COLOR_TEXT_DIM);
                                            // Dispatches on word_count and sets
                                            // pubkeys_cached only on success.
                                            crate::app::signing::fill_display_caches(ad);
                                        }
                                        // Store the account-level xpub directly.
                                        // The account path is fixed (m/44'/111111'/0'),
                                        // so tapping the seed fully determines the
                                        // cosigner key. The former address-browse
                                        // screen implied a per-key index choice that
                                        // build_script() never used; it has been
                                        // removed entirely.
                                        if key_idx < ad.ms_creating.n {
                                            // Our own entry, from the 45' subtree.
                                            //
                                            // NOT `acct_key_raw`: that holds the 44' account
                                            // key at m/44'/111111'/0', a different subtree
                                            // entirely. Using it here would put a 44' key in a
                                            // 45' descriptor, which parses cleanly, has a valid
                                            // checksum, and yields an address no quorum can
                                            // spend. The seed is derived fresh and wiped.
                                            let own = crate::app::signing::own_multisig_parts(ad);
                                            if own.is_none() {
                                                // Say so. This used to be a bare
                                                // `if let Some(..)` with no else: on a
                                                // slot that cannot produce a 45' key the
                                                // tap did nothing at all - no key added,
                                                // no state change, no message.
                                                //
                                                // An xprv slot is imported AT 44' account
                                                // level, so the parent to walk down the
                                                // 45' branch from does not exist. It can
                                                // never be a cosigner in a 45' wallet, and
                                                // that is worth saying at the moment
                                                // someone tries rather than leaving them
                                                // tapping a dead button.
                                                boot_display.draw_rejected_screen(
                                                    if ad.active_kind()
                                                        == crate::ui::seed_manager::SlotKind::Xprv
                                                    {
                                                        "xprv slot cannot be a 45' cosigner"
                                                    } else {
                                                        "No seed loaded"
                                                    },
                                                );
                                                sound::beep_error(delay);
                                                delay.delay_millis(2000);
                                                needs_redraw = true;
                                                break;
                                            }
                                            if let Some(parts) = own {
                                                ad.ms_creating.set_cosigner(key_idx as usize, &parts);
                                                let next = key_idx + 1;
                                                if next >= ad.ms_creating.n {
                                                    // Canonical order before the
                                                    // script, then re-derive our
                                                    // own slot. See the note at
                                                    // the camera_loop site.
                                                    ad.ms_creating.sort_cosigners();
                                                    let _ = crate::app::signing::resolve_ms_cosigner_index(ad);
                                                    ad.ms_creating.build_script();
                                                    ad.ms_creating.active = true;
                                                    // Always registered: `slot_for_next` evicts the oldest when both
                                                    // slots are taken, rather than returning None and dropping the
                                                    // config the user just finished building.
                                                    let ms_slot = ad.ms_store.slot_for_next();
                                                    ad.ms_store.configs[ms_slot] = ad.ms_creating.clone();
                                                    ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                                                } else {
                                                    ad.app.state = crate::app::input::AppState::MultisigAddKey { key_idx: next };
                                                }
                                            }
                                        }
                                        needs_redraw = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::MultisigShowAddress => {
                        if is_back {
                            if ad.ms_creating.active {
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            } else {
                                // SD-loaded: back to SD import
                                ad.app.state = crate::app::input::AppState::SdImportMenu;
                            }
                            needs_redraw = true;
                        } else if y >= 195 {
                            // Bottom nav band — [<] [cN] [#N] [>].
                            //
                            // [cN] is 45' only: it picks the COSIGNER family, the
                            // level 44' does not have. Placed in the gap between
                            // [<] and [#N] so neither existing target shrinks.
                            // 45' band: [<] S1 / C0 / #5 [>]. S and C CYCLE on tap;
                            // #N keeps the picker, where 0..99 needs one.
                            //
                            // Cycling suits a value with two or five options: no
                            // keypad, no wrong prompt, and an invalid value cannot
                            // be entered at all.
                            if ad.ms_creating.v45 && (118..=158).contains(&x) {
                                // C — chain: 0 receive, 1 change.
                                ad.ms_creating.chain ^= 1;
                                ad.ms_creating.build_script();
                                needs_redraw = true;
                            } else if ad.ms_creating.v45 && (166..=250).contains(&x) {
                                // #N — address index picker.
                                ad.addr_input_len = 0;
                                ad.ms_picking_key = 255;
                                ad.app.state = crate::app::input::AppState::AddrIndexPicker;
                                needs_redraw = true;
                            } else if ad.ms_creating.v45 && (62..=110).contains(&x) {
                                // CYCLES, it does not open the picker.
                                //
                                // The cosigner index has at most MAX_MULTISIG_KEYS
                                // values - two for a 2-of-2 - so a numeric keypad
                                // titled "go to address #" was the wrong instrument
                                // for it: wrong prompt, and it accepted values that
                                // are not families. One tap advances, wrapping at n,
                                // so an invalid value cannot be entered at all.
                                //
                                // [#N] keeps the picker, where 0..99 needs one.
                                let n = ad.ms_creating.n;
                                if n > 0 {
                                    ad.ms_creating.cosigner_index =
                                        (ad.ms_creating.cosigner_index + 1) % n;
                                    ad.ms_creating.build_script();
                                }
                                needs_redraw = true;
                            } else if x <= 90 {
                                // [<] — previous address (saturating at 0)
                                if ad.ms_creating.addr_index > 0 {
                                    ad.ms_creating.addr_index -= 1;
                                    ad.ms_creating.build_script();
                                    for i in 0..crate::wallet::transaction::MAX_MULTISIG_WALLETS {
                                        if ad.ms_store.configs[i].active
                                            && ad.ms_store.configs[i]
                                                .same_wallet_as(&ad.ms_creating)
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
                                            && ad.ms_store.configs[i]
                                                .same_wallet_as(&ad.ms_creating)
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
                        // Full-screen QR: any tap goes to save/back popup or back
                        if ad.ms_creating.active {
                            ad.app.state = crate::app::input::AppState::MultisigSaveAddrAsk;
                        } else {
                            // SD-loaded flow: return to SD import
                            ad.app.state = crate::app::input::AppState::SdImportMenu;
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::MultisigSaveAddrAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                            needs_redraw = true;
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
                            needs_redraw = true;
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
                                needs_redraw = true;
                            } else {
                                // SD-loaded view-only flow: back to SD import
                                ad.app.state = crate::app::input::AppState::SdImportMenu;
                                needs_redraw = true;
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
                                // One writer for both schemes, next to the parser
                                // that reads it back. Header on for a file: it
                                // tells a human what they opened, and every
                                // reader skips it.
                                let pos = crate::handlers::sd::write_descriptor(
                                    &ad.ms_creating,
                                    &mut ad.signed_qr_buf,
                                    true,
                                );
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
                                needs_redraw = true;
                        } else if (190..=230).contains(&y) && (10..=150).contains(&x) {
                                // QR button — show HD descriptor as QR for KasSee / another KasSigner.
                                // Header OFF for a QR: 46 bytes of payload that
                                // cost frames, that nobody reads on screen, and
                                // that KasSee's parser does not skip.
                                let pos = crate::handlers::sd::write_descriptor(
                                    &ad.ms_creating,
                                    &mut ad.signed_qr_buf,
                                    false,
                                );
                                ad.signed_qr_len = pos;
                                ad.signed_qr_nframes = 0;
                                ad.signed_qr_frame = 0;
                                ad.qr_manual_frames = false;
                                // Not a transaction: suppress the signature
                                // badges `ShowQR` draws from `demo_tx`, which
                                // here is whatever was parsed last.
                                ad.qr_is_descriptor = true;
                                ad.app.state = crate::app::input::AppState::ShowQR;
                                needs_redraw = true;
                        }
                    }
                    // ─── Sign Message Flow ────────────
                    crate::app::input::AppState::SignMsgChoice => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
                            needs_redraw = true;
                        } else if (40..280).contains(&x) && (68..112).contains(&y) {
                            // Type manually
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SignMsgType;
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
                                        && entry.file_size <= 1024
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
                                needs_redraw = true;
                            } else {
                                ad.app.state = crate::app::input::AppState::SignMsgFile;
                                needs_redraw = true;
                            }
                        } else if (40..280).contains(&x) && (160..204).contains(&y) {
                            // Scan hash QR — use standard ScanQR with hash flag
                            ad.sign_msg_scan_hash = true;
                            ad.app.state = crate::app::input::AppState::ScanQR;
                            needs_redraw = true;
                        }
                    }
                    crate::app::input::AppState::SignMsgScanQr => {
                        if is_back {
                            ad.sign_msg_scan_hash = false;
                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                            needs_redraw = true;
                        }
                    }
                    crate::app::input::AppState::SignMsgType => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
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
                                            needs_redraw = true;
                                        } else {
                                            boot_display.draw_rejected_screen("Read failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(1500);
                                            needs_redraw = true;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        
                    }
                    crate::app::input::AppState::SignMsgPreview => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                            needs_redraw = true;
                        } else if (185..=225).contains(&y) && (100..=220).contains(&x) {
                            // SIGN button tapped
                            boot_display.draw_saving_screen("Signing...");
                            boot_display.update_progress_bar(20);
                            delay.delay_millis(50);

                            // SHA256 hash the message
                            let msg = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                            let msg_hash = wallet::hmac::sha256(msg);
                            ad.sign_msg_hash = msg_hash;
                            boot_display.update_progress_bar(40);

                            // Derive private key at account level (depth 3: m/44'/111111'/0')
                            // This matches the kpub xonly pubkey, which is what users
                            // enter as the oracle pubkey in covenant scripts.
                            let pp = ad.seed_mgr.active_slot()
                                .map(|s| s.passphrase_str())
                                .unwrap_or("");
                            let mut privkey = [0u8; 32];
                            // None for raw-key/xprv slots, which have no BIP39
                            // seed. Leaves privkey zeroed, the same outcome the
                            // Err path already produced.
                            if let Some(seed) = crate::app::signing::derive_seed(
                                &ad.mnemonic_indices, ad.word_count, pp)
                            {
                                if let Ok(acct_key) = wallet::bip32::derive_account_key(&seed.bytes) {
                                    privkey.copy_from_slice(acct_key.private_key_bytes());
                                }
                            }
                            boot_display.update_progress_bar(70);

                            // Schnorr sign
                            match wallet::schnorr::schnorr_sign(&privkey, &msg_hash) {
                                Ok(sig) => {
                                    ad.sign_msg_sig = sig.bytes;
                                    boot_display.update_progress_bar(100);
                                    sound::success(delay);
                                    ad.app.state = crate::app::input::AppState::SignMsgResult;
                                    needs_redraw = true;
                                }
                                Err(_) => {
                                    boot_display.draw_rejected_screen("Signing failed");
                                    sound::beep_error(delay);
                                    delay.delay_millis(2000);
                                    needs_redraw = true;
                                }
                            }
                            // Zeroize private key
                            wallet::hmac::zeroize_buf(&mut privkey);
                        }
                    }
                    crate::app::input::AppState::SignMsgHashPreview => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SignMsgChoice;
                            needs_redraw = true;
                        } else if (185..=225).contains(&y) && (100..=220).contains(&x) {
                            // SIGN button tapped — sign the raw hash (no SHA256)
                            boot_display.draw_saving_screen("Signing...");
                            boot_display.update_progress_bar(20);
                            delay.delay_millis(50);

                            // Hash is already in ad.sign_msg_hash (set by QR scan)
                            boot_display.update_progress_bar(40);

                            let pp = ad.seed_mgr.active_slot()
                                .map(|s| s.passphrase_str())
                                .unwrap_or("");
                            let mut privkey = [0u8; 32];
                            // None for raw-key/xprv slots, which have no BIP39
                            // seed. Leaves privkey zeroed, the same outcome the
                            // Err path already produced.
                            if let Some(seed) = crate::app::signing::derive_seed(
                                &ad.mnemonic_indices, ad.word_count, pp)
                            {
                                if let Ok(acct_key) = wallet::bip32::derive_account_key(&seed.bytes) {
                                    privkey.copy_from_slice(acct_key.private_key_bytes());
                                }
                            }
                            boot_display.update_progress_bar(70);

                            match wallet::schnorr::schnorr_sign(&privkey, &ad.sign_msg_hash) {
                                Ok(sig) => {
                                    ad.sign_msg_sig = sig.bytes;
                                    boot_display.update_progress_bar(100);
                                    sound::success(delay);
                                    ad.app.state = crate::app::input::AppState::SignMsgResult;
                                    needs_redraw = true;
                                }
                                Err(_) => {
                                    boot_display.draw_rejected_screen("Signing failed");
                                    sound::beep_error(delay);
                                    delay.delay_millis(2000);
                                    needs_redraw = true;
                                }
                            }
                            wallet::hmac::zeroize_buf(&mut privkey);
                        }
                    }
                    crate::app::input::AppState::SignMsgResult => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
                            needs_redraw = true;
                        } else if (155..=191).contains(&y) && (20..=150).contains(&x) {
                            // SAVE SD button (left)
                            if bb_card_type.is_some() {
                                // Auto-increment: SG00001.TXT
                                let next = crate::handlers::sd::scan_auto_increment(i2c, delay, b"SG", b"TXT");
                                let name = crate::handlers::sd::format_auto_name(b"SG", next, b"TXT");
                                ad.kspt_filename = name;
                                ad.pp_input.reset();
                                for j in 0..8usize {
                                    if name[j] != b' ' {
                                        ad.pp_input.push_char(name[j]);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::SdSigFilename;
                                needs_redraw = true;
                            } else {
                                boot_display.draw_rejected_screen("No SD card");
                                sound::beep_error(delay);
                                delay.delay_millis(1500);
                                needs_redraw = true;
                            }
                        } else if (155..=191).contains(&y) && (170..=300).contains(&x) {
                            // SHOW QR button (right) — oracle attestation QR
                            // Raw bytes: sig (64) + hash (32) = 96 bytes → fits V5 QR
                            let mut qr_data = [0u8; 96];
                            qr_data[..64].copy_from_slice(&ad.sign_msg_sig);
                            qr_data[64..96].copy_from_slice(&ad.sign_msg_hash);
                            boot_display.draw_qr_fullscreen(&qr_data, "ORACLE ATTESTATION");
                            ad.app.state = crate::app::input::AppState::SignMsgResultQr;
                            // Any touch in SignMsgResultQr returns to SignMsgResult
                        }
                    }
                    crate::app::input::AppState::SignMsgResultQr => {
                        // Any touch returns to the result screen
                        ad.app.state = crate::app::input::AppState::SignMsgResult;
                        needs_redraw = true;
                    }

                    // ─── Commit-Reveal Flow ────────────
                    crate::app::input::AppState::CommitRevealType => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "SECRET"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "SECRET"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "SECRET"); }
                                6 => {
                                    // OK pressed
                                    let len = ad.pp_input.len;
                                    if len == 0 {
                                        boot_display.draw_rejected_screen("Enter a message");
                                        sound::beep_error(delay);
                                        delay.delay_millis(1500);
                                        needs_redraw = true;
                                    } else if len > 33 {
                                        // Preimage budget is 41 bytes (ECIES ct + hash
                                        // must fit one V6 QR): 8-byte salt + 33 secret.
                                        boot_display.draw_rejected_screen("Max 33 characters");
                                        sound::beep_error(delay);
                                        delay.delay_millis(1500);
                                        needs_redraw = true;
                                    } else {
                                        // Salted preimage: salt(8) || secret. Without the
                                        // salt the commitment is BLAKE2B(secret) alone, so
                                        // the same secret always yields the same hash and
                                        // therefore the same covenant address, and a short
                                        // human secret is dictionary-attackable against the
                                        // on-chain commitment. The salt lives inside the
                                        // preimage, never in the script — script layout is
                                        // byte-identical, so type detection is unaffected.
                                        let mut salt = [0u8; 8];
                                        if crate::crypto::entropy::fill(&mut salt).is_err() {
                                            // Fail closed. An all-zero salt gives
                                            // BLAKE2B(secret) alone, which is exactly the
                                            // dictionary-attackable commitment the salt
                                            // exists to prevent, and the covenant address
                                            // would be reproducible by anyone who guesses
                                            // the secret.
                                            boot_display.draw_rejected_screen("Secure RNG failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(2000);
                                            needs_redraw = true;
                                            return Some(needs_redraw);
                                        }
                                        let copy_len = len.min(ad.jpeg_desc_buf.len() - 8);
                                        // Write secret after the salt slot, then the salt.
                                        for i in (0..copy_len).rev() {
                                            ad.jpeg_desc_buf[8 + i] = ad.pp_input.buf[i];
                                        }
                                        ad.jpeg_desc_buf[..8].copy_from_slice(&salt);
                                        ad.jpeg_desc_len = 8 + copy_len;

                                        // BLAKE2B hash the salted preimage
                                        use blake2::{Blake2b, Digest};
                                        use blake2::digest::consts::U32;
                                        type B2b256 = Blake2b<U32>;
                                        let mut hasher = B2b256::new();
                                        hasher.update(&ad.jpeg_desc_buf[..ad.jpeg_desc_len]);
                                        let hash_result: [u8; 32] = hasher.finalize().into();
                                        ad.cr_hash = hash_result;

                                        ad.app.state = crate::app::input::AppState::CommitRevealPreview;
                                        needs_redraw = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::CommitRevealPreview => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::CommitRevealType;
                            needs_redraw = true;
                        } else if (165..=201).contains(&y) && (60..=260).contains(&x) {
                            // ENCRYPT & EXPORT button tapped
                            boot_display.draw_saving_screen("Encrypting...");
                            boot_display.update_progress_bar(20);
                            delay.delay_millis(50);

                            // Derive account-level xonly pubkey for ECIES encryption
                            let pp = ad.seed_mgr.active_slot()
                                .map(|s| s.passphrase_str())
                                .unwrap_or("");
                            let mut xonly_pub = [0u8; 32];
                            // None for raw-key/xprv slots; leaves xonly_pub
                            // zeroed as the Err path already did.
                            if let Some(seed) = crate::app::signing::derive_seed(
                                &ad.mnemonic_indices, ad.word_count, pp)
                            {
                                if let Ok(acct_key) = wallet::bip32::derive_account_key(&seed.bytes) {
                                    if let Ok(xo) = acct_key.public_key_x_only() {
                                        xonly_pub = xo;
                                    }
                                }
                            }
                            boot_display.update_progress_bar(40);

                            // Generate 44 bytes of randomness: 32 for ephemeral key + 12 for nonce.
                            // Shared collector: enables RC_FAST (correct DIG_CLK8M_EN bit) and
                            // mixes WDEV + SYSTIMER + eFuse + camera sensor noise. The previous
                            // inline sampler set bit 8 (DIG_XTAL32K_EN) by mistake, so the WDEV
                            // RNG ran without its jitter feed.
                            let mut rng_bytes = [0u8; 44];
                            // On failure `fill` leaves this zeroed, and ECIES then
                            // rejects it: an all-zero 32 bytes is not a valid secp256k1
                            // scalar, so `SecretKey::from_slice` returns "bad ephemeral
                            // key" and the encrypt refuses. Fails closed already, but
                            // not by design, so the result is checked here too.
                            if crate::crypto::entropy::fill(&mut rng_bytes).is_err() {
                                boot_display.draw_rejected_screen("Secure RNG failed");
                                sound::beep_error(delay);
                                delay.delay_millis(2000);
                                needs_redraw = true;
                                return Some(needs_redraw);
                            }
                            boot_display.update_progress_bar(60);

                            // ECIES encrypt the plaintext message
                            let plaintext = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                            match wallet::ecies::encrypt(&xonly_pub, plaintext, &rng_bytes) {
                                Ok(ct) => {
                                    ad.cr_ciphertext = ct;

                                    // Split plaintext into two parts for heartbeat TXs
                                    // Split at midpoint (or random point for better obscurity)
                                    let mid = if ad.jpeg_desc_len > 1 {
                                        // Use a byte from RNG to pick split point (1..len-1)
                                        let r = rng_bytes[0] as usize;
                                        1 + (r % (ad.jpeg_desc_len - 1))
                                    } else {
                                        ad.jpeg_desc_len
                                    };
                                    ad.cr_part_a = alloc::vec::Vec::from(&plaintext[..mid]);
                                    ad.cr_part_b = alloc::vec::Vec::from(&plaintext[mid..]);

                                    boot_display.update_progress_bar(100);
                                    sound::success(delay);
                                    ad.app.state = crate::app::input::AppState::CommitRevealResult;
                                    needs_redraw = true;
                                }
                                Err(e) => {
                                    // Show which step failed
                                    let msg = match e {
                                        "bad ephemeral key" => "Bad RNG key",
                                        "invalid recipient pubkey" => "Bad pubkey",
                                        "encryption failed" => "AES encrypt err",
                                        _ => "ECIES failed",
                                    };
                                    boot_display.draw_rejected_screen(msg);
                                    sound::beep_error(delay);
                                    delay.delay_millis(2000);
                                    needs_redraw = true;
                                }
                            }

                            // Zeroize plaintext from buffer
                            for b in ad.jpeg_desc_buf[..ad.jpeg_desc_len].iter_mut() { *b = 0; }
                            ad.jpeg_desc_len = 0;
                            ad.pp_input.reset();
                        }
                    }
                    crate::app::input::AppState::CommitRevealResult => {
                        if is_back {
                            ad.cr_ciphertext.clear();
                            ad.cr_part_a.clear();
                            ad.cr_part_b.clear();
                            ad.cr_hash = [0u8; 32];
                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
                            needs_redraw = true;
                        } else if (150..=186).contains(&y) && (60..=260).contains(&x) {
                            // SHOW QR — export: hash(32) + ciphertext
                            let total = 32 + ad.cr_ciphertext.len();
                            if total > 134 {
                                boot_display.draw_rejected_screen("Message too long for QR");
                                sound::beep_error(delay);
                                delay.delay_millis(2000);
                                needs_redraw = true;
                            } else {
                                let mut qr_data = alloc::vec![0u8; total];
                                qr_data[..32].copy_from_slice(&ad.cr_hash);
                                qr_data[32..].copy_from_slice(&ad.cr_ciphertext);
                                boot_display.draw_qr_fullscreen(&qr_data, "COMMITMENT");
                                ad.app.state = crate::app::input::AppState::CommitRevealResultQr;
                            }
                        }
                    }
                    crate::app::input::AppState::CommitRevealResultQr => {
                        // Any touch returns to result screen
                        ad.app.state = crate::app::input::AppState::CommitRevealResult;
                        needs_redraw = true;
                    }

                    crate::app::input::AppState::DecryptSecretScan => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
                            needs_redraw = true;
                        }
                        // Camera scan handled by camera_loop.rs
                    }
                    crate::app::input::AppState::DecryptSecretResult => {
                        if is_back {
                            for b in ad.jpeg_desc_buf[..ad.jpeg_desc_len].iter_mut() { *b = 0; }
                            ad.jpeg_desc_len = 0;
                            ad.app.state = crate::app::input::AppState::SingleSigMenu;
                            needs_redraw = true;
                        } else if (150..=186).contains(&y) && (70..=250).contains(&x) {
                            // EXPORT PREIMAGE QR button
                            let plain = &ad.jpeg_desc_buf[..ad.jpeg_desc_len];
                            let hex_chars = b"0123456789abcdef";
                            let mut hex_buf = alloc::vec![0u8; ad.jpeg_desc_len * 2];
                            for (i, &b) in plain.iter().enumerate() {
                                hex_buf[i * 2] = hex_chars[(b >> 4) as usize];
                                hex_buf[i * 2 + 1] = hex_chars[(b & 0x0f) as usize];
                            }
                            boot_display.draw_qr_fullscreen(&hex_buf, "PREIMAGE");
                            ad.app.state = crate::app::input::AppState::DecryptSecretResultQr;
                        }
                    }
                    crate::app::input::AppState::DecryptSecretResultQr => {
                        ad.app.state = crate::app::input::AppState::DecryptSecretResult;
                        needs_redraw = true;
                    }

                    _ => { return None; }
                }
    Some(needs_redraw)
}
