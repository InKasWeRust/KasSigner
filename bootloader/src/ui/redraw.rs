// ui/redraw.rs — Screen redraw dispatch for all AppState variants
//
// All draw_*_screen() calls dispatched by AppState.
// Called from main loop when needs_redraw is true.

use crate::{hw::battery, hw::display, hw::sound, features::fw_update, hw::sdcard, ui::seed_manager, wallet};
/// Redraw the current screen based on AppState. Called when needs_redraw is set.
pub fn redraw_screen(
    ad: &mut crate::app::data::AppData,
    boot_display: &mut display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    bb_card_type: &Option<sdcard::SdCardType>,
) {
    // Stop any ticking sound from loading/saving screens
    sound::stop_ticking();
    match ad.app.state {
                crate::app::input::AppState::MainMenu => {
                    boot_display.draw_home_grid();
                    // Battery indicator on home screen
                    if let Some(batt) = battery::read_battery(i2c) {
                        let charging = batt.state == battery::ChargeState::Charging;
                        boot_display.draw_battery_icon(batt.percentage, charging);
                    }
                }
                crate::app::input::AppState::ScanQR => {
                    // Only draw camera chrome on initial entry to ScanQR.
                    // The camera blit loop handles continuous display + back button overlay.
                    boot_display.draw_camera_screen("", "");
                    // Signal camera loop to reset QR decode state
                    unsafe { crate::QR_RESET_FLAG = true; }
                }
                crate::app::input::AppState::SeedsMenu => {
                    // SeedsMenu now just shows SeedList
                    ad.app.state = crate::app::input::AppState::SeedList;
                    boot_display.draw_seed_list_screen(&ad.seed_mgr, ad.seed_list_scroll);
                }
                crate::app::input::AppState::SeedList => {
                    boot_display.draw_seed_list_screen(&ad.seed_mgr, ad.seed_list_scroll);
                }
                crate::app::input::AppState::ConfirmDeleteSeed => {
                    let slot_idx = ad.pending_delete_slot as usize;
                    if slot_idx < ad.seed_mgr.slots.len() && !ad.seed_mgr.slots[slot_idx].is_empty() {
                        let slot = &ad.seed_mgr.slots[slot_idx];
                        let mut fp_hex = [0u8; 8];
                        slot.fingerprint_hex(&mut fp_hex);
                        let fp_str = core::str::from_utf8(&fp_hex).unwrap_or("????????");
                        let wc = slot.word_count;
                        boot_display.draw_confirm_delete_screen(fp_str, wc);
                    }
                }
                crate::app::input::AppState::ViewSeed => {
                    if ad.seed_loaded && ad.pubkeys_cached {
                        let pk = if (ad.current_addr_index as usize) < 20 {
                            ad.pubkey_cache[ad.current_addr_index as usize]
                        } else if ad.extra_pubkey_index == ad.current_addr_index {
                            ad.extra_pubkey
                        } else {
                            [0u8; 32] // shouldn't happen — picker ensures derivation
                        };
                        let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                        let addr = wallet::address::encode_address_str(
                            &pk,
                            wallet::address::AddressType::P2PK,
                            &mut addr_buf,
                        );
                        boot_display.draw_seed_info_screen(ad.word_count, addr);
                    } else if ad.seed_loaded {
                        boot_display.draw_seed_info_screen(ad.word_count, "kaspa:q...(keys not derived)");
                    } else {
                        boot_display.draw_about_screen();
                    }
                }
                crate::app::input::AppState::SeedBackup { word_idx } => {
                    if ad.seed_loaded {
                        let word = wallet::bip39::index_to_word(ad.mnemonic_indices[word_idx as usize]);
                        boot_display.draw_word_screen(word_idx, ad.word_count, word);
                    }
                }
                crate::app::input::AppState::ToolsMenu => {
                    boot_display.draw_menu_screen("TOOLS", &ad.tools_menu);
                }
                crate::app::input::AppState::ChooseWordCount { action } => {
                    let title = match action {
                        0 => "New Seed (Camera)",
                        1 => "New Seed (Dice)",
                        2 => "Import Words",
                        3 => "Calc Last Word",
                        4 => "BIP85 Child",
                        _ => "Choose",
                    };
                    boot_display.draw_choose_wc_screen(title);
                }
                crate::app::input::AppState::PassphraseEntry => {
                    boot_display.draw_passphrase_screen_full(&ad.pp_input);
                }
                crate::app::input::AppState::SdBackupWarning => {
                    boot_display.draw_sd_backup_warning();
                }
                crate::app::input::AppState::SdBackupPassphrase => {
                    boot_display.draw_keyboard_screen_full(&ad.pp_input, "PASSWORD");
                }
                crate::app::input::AppState::SdRestorePassphrase => {
                    boot_display.draw_passphrase_screen_full(&ad.pp_input);
                }
                crate::app::input::AppState::SdFileList => {
                    boot_display.draw_sd_file_list(&ad.sd_file_list, ad.sd_file_count);
                }
                crate::app::input::AppState::SdXprvExportPassphrase => {
                    boot_display.draw_passphrase_screen_full(&ad.pp_input);
                }
                crate::app::input::AppState::SdXprvFileList => {
                    boot_display.draw_sd_file_list(&ad.sd_file_list, ad.sd_file_count);
                }
                crate::app::input::AppState::SdXprvImportPassphrase => {
                    boot_display.draw_passphrase_screen_full(&ad.pp_input);
                }
                crate::app::input::AppState::SdBackupWriting
                | crate::app::input::AppState::SdRestoreReading => {
                    // Transient — progress screen drawn inline before operation
                }
                crate::app::input::AppState::ExportSeedQR => {
                    if let Some(slot) = ad.seed_mgr.active_slot() {
                        let mut seedqr_buf = [0u8; 96];
                        let len = seed_manager::encode_seedqr(
                            &slot.indices, slot.word_count, &mut seedqr_buf);
                        boot_display.draw_export_seed_qr_screen(
                            &seedqr_buf[..len], slot.word_count);
                    }
                }
                crate::app::input::AppState::ExportCompactSeedQR => {
                    if let Some(slot) = ad.seed_mgr.active_slot() {
                        let mut compact_buf = [0u8; 32];
                        let len = seed_manager::encode_compact_seedqr(
                            &slot.indices, slot.word_count, &mut compact_buf);
                        boot_display.draw_export_compact_seedqr_screen(
                            &compact_buf[..len], slot.word_count);
                    }
                }
                crate::app::input::AppState::QrExportMenu => {
                    boot_display.draw_qr_export_menu(&ad.qr_export_menu, ad.word_count);
                }
                crate::app::input::AppState::ExportPlainWordsQR => {
                    if let Some(slot) = ad.seed_mgr.active_slot() {
                        boot_display.draw_export_plain_words_qr(&slot.indices, slot.word_count);
                    }
                }
                crate::app::input::AppState::SeedQrGrid { pan_x, pan_y, compact } => {
                    if let Some(slot) = ad.seed_mgr.active_slot() {
                        if compact {
                            let mut compact_buf = [0u8; 32];
                            let len = seed_manager::encode_compact_seedqr(
                                &slot.indices, slot.word_count, &mut compact_buf);
                            boot_display.draw_seedqr_grid(
                                &compact_buf[..len], slot.word_count, pan_x, pan_y);
                        } else {
                            let mut seedqr_buf = [0u8; 96];
                            let len = seed_manager::encode_seedqr(
                                &slot.indices, slot.word_count, &mut seedqr_buf);
                            boot_display.draw_seedqr_grid(
                                &seedqr_buf[..len], slot.word_count, pan_x, pan_y);
                        }
                    }
                }
                crate::app::input::AppState::ExportKpub => {
                    if ad.kpub_len > 0 {
                        boot_display.draw_export_kpub_screen(&ad.kpub_data, ad.kpub_len);
                    }
                }
                crate::app::input::AppState::ExportPrivKey => {
                    boot_display.draw_export_privkey_screen(&ad.export_key_hex);
                }
                crate::app::input::AppState::ExportChoice => {
                    boot_display.draw_export_choice_screen(&ad.export_menu);
                }
                crate::app::input::AppState::ExportXprv => {
                    if ad.xprv_len > 0 {
                        boot_display.draw_export_xprv_screen(&ad.xprv_data, ad.xprv_len);
                    }
                }
                crate::app::input::AppState::SettingsMenu => {
                    boot_display.draw_menu_screen("SETTINGS", &ad.settings_menu);
                }
                crate::app::input::AppState::DisplaySettings => {
                    boot_display.draw_display_settings(ad.brightness);
                }
                crate::app::input::AppState::SdCardSettings => {
                    let card_str = match bb_card_type {
                        Some(sdcard::SdCardType::SdV2Hc) => "SDHC (High Capacity)",
                        Some(sdcard::SdCardType::SdV2Sc) => "SD v2 (Standard)",
                        Some(sdcard::SdCardType::SdV1) => "SD v1",
                        _ => "Unknown",
                    };
                    boot_display.draw_sdcard_settings(bb_card_type.is_some(), card_str, ad.seed_loaded);
                }
                crate::app::input::AppState::SignTxGuide => {
                    if ad.seed_loaded && ad.pubkeys_cached {
                        let pk = if (ad.current_addr_index as usize) < 20 {
                            ad.pubkey_cache[ad.current_addr_index as usize]
                        } else {
                            [0u8; 32]
                        };
                        let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                        let addr = wallet::address::encode_address_str(
                            &pk,
                            wallet::address::AddressType::P2PK,
                            &mut addr_buf,
                        );
                        boot_display.draw_sign_tx_guide(true, addr, ad.current_addr_index);
                    } else {
                        boot_display.draw_sign_tx_guide(false, "", 0);
                    }
                }
                // ─── Sign Message Redraws ────────────
                crate::app::input::AppState::SignMsgChoice => {
                    boot_display.draw_sign_msg_choice();
                }
                crate::app::input::AppState::SignMsgType => {
                    boot_display.draw_keyboard_screen_full(&ad.pp_input, "MESSAGE");
                }
                crate::app::input::AppState::SignMsgFile => {
                    boot_display.draw_stego_txt_pick(&ad.txt_display_names, &ad.txt_display_lens, ad.txt_file_count);
                }
                crate::app::input::AppState::SignMsgPreview => {
                    let msg = core::str::from_utf8(&ad.jpeg_desc_buf[..ad.jpeg_desc_len]).unwrap_or("");
                    boot_display.draw_sign_msg_preview(msg);
                }
                crate::app::input::AppState::SignMsgResult => {
                    boot_display.draw_sign_msg_result(&ad.sign_msg_sig);
                }
                #[cfg(feature = "icon-browser")]
                crate::app::input::AppState::IconBrowser { page } => {
                    use embedded_graphics::prelude::DrawTarget;
                    boot_display.display.clear(crate::hw::display::COLOR_BG).ok();
                    crate::ui::icon_browser::draw_icon_page(&mut boot_display.display, page);
                    boot_display.draw_back_button();
                }
                crate::app::input::AppState::ReviewTx { page } => {
                    boot_display.draw_tx_page(&ad.demo_tx, page);
                }
                crate::app::input::AppState::ConfirmTx => {
                    let mut amt_buf = [0u8; 20];
                    let amt_len = wallet::transaction::Transaction::format_kas(
                        ad.demo_tx.outputs[0].value, &mut amt_buf);
                    let mut fee_buf_fmt = [0u8; 20];
                    let fee_len = wallet::transaction::Transaction::format_kas(
                        ad.demo_tx.fee(), &mut fee_buf_fmt);
                    let amt_str = core::str::from_utf8(&amt_buf[..amt_len]).unwrap_or("?.??");
                    let fee_str = core::str::from_utf8(&fee_buf_fmt[..fee_len]).unwrap_or("?.??");
                    let mut amt_kas: heapless::String<24> = heapless::String::new();
                    core::fmt::Write::write_fmt(&mut amt_kas, format_args!("{} KAS", amt_str)).ok();
                    let mut fee_kas: heapless::String<24> = heapless::String::new();
                    core::fmt::Write::write_fmt(&mut fee_kas, format_args!("{} KAS", fee_str)).ok();

                    // Detect multisig
                    let has_multisig = (0..ad.demo_tx.num_inputs).any(|i| {
                        let (st, _) = wallet::pskt::analyze_input_script(&ad.demo_tx, i);
                        st == wallet::transaction::ScriptType::Multisig
                    });
                    if has_multisig {
                        let (present, required) = wallet::pskt::signature_status(&ad.demo_tx);
                        boot_display.draw_confirm_send_multisig(&amt_kas, &fee_kas, present, required);
                    } else {
                        boot_display.draw_confirm_send_screen(&amt_kas, &fee_kas);
                    }
                }
                crate::app::input::AppState::Signing { input_idx } => {
                    boot_display.draw_signing_screen(
                        input_idx as usize,
                        ad.app.total_inputs as usize,
                    );
                }
                crate::app::input::AppState::ShowQR => {
                    if ad.signed_qr_len > 0 {
                        let max_payload = 103usize; // V5-L payload per frame
                        if ad.signed_qr_len <= 134 {
                            // Fits in single QR — display directly
                            boot_display.draw_qr_screen(&ad.signed_qr_buf[..ad.signed_qr_len]);
                        } else {
                            // Multi-frame: build frame 0 and start cycling
                            let n_frames = (ad.signed_qr_len + max_payload - 1) / max_payload;
                            // Build frame 0
                            let frag_len = (ad.signed_qr_len).min(max_payload);
                            let mut frame_buf = [0u8; 134];
                            frame_buf[0] = 0; // frame_num
                            frame_buf[1] = n_frames as u8;
                            frame_buf[2] = frag_len as u8;
                            frame_buf[3..3 + frag_len].copy_from_slice(&ad.signed_qr_buf[..frag_len]);
                            boot_display.draw_qr_screen(&frame_buf[..3 + frag_len]);
                            // Frame counter overlay
                            let mut fc_buf: heapless::String<8> = heapless::String::new();
                            core::fmt::Write::write_fmt(&mut fc_buf,
                                format_args!("1/{}", n_frames)).ok();
                            boot_display.draw_frame_counter(&fc_buf);
                            // Store state for cycling
                            ad.signed_qr_frame = 0;
                            ad.signed_qr_nframes = n_frames as u8;
                        }
                    } else {
                        boot_display.draw_rejected_screen("Signing Failed");
                    }
                }
                crate::app::input::AppState::Rejected => {
                    boot_display.draw_rejected_screen("TX Cancelled");
                }
                // ─── Multisig Creation Redraws ────────────
                crate::app::input::AppState::MultisigChooseMN => {
                    boot_display.draw_multisig_choose_mn(ad.ms_m, ad.ms_n);
                }
                crate::app::input::AppState::MultisigAddKey { key_idx } => {
                    boot_display.draw_multisig_add_key(key_idx, ad.ms_creating.n, ad.seed_loaded);
                }
                crate::app::input::AppState::MultisigPickSeed { key_idx } => {
                    boot_display.draw_multisig_pick_seed(key_idx, ad.ms_creating.n, &ad.seed_mgr, ad.ms_scroll);
                }
                crate::app::input::AppState::MultisigPickAddr { key_idx: _ } => {
                    let pk = if (ad.current_addr_index as usize) < 20 {
                        ad.pubkey_cache[ad.current_addr_index as usize]
                    } else if ad.extra_pubkey_index == ad.current_addr_index {
                        ad.extra_pubkey
                    } else {
                        [0u8; 32]
                    };
                    let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                    let addr = wallet::address::encode_address_str(
                        &pk, wallet::address::AddressType::P2PK, &mut addr_buf);
                    boot_display.draw_address_screen(addr, true,
                        Some(ad.current_addr_index), Some("SELECT"));
                }
                crate::app::input::AppState::MultisigShowAddress => {
                    let mut label_buf = [0u8; 8];
                    let label_len = ad.ms_creating.label(&mut label_buf);
                    let label = core::str::from_utf8(&label_buf[..label_len]).unwrap_or("?-of-?");
                    let script_hash = wallet::sighash::blake2b_hash(
                        &ad.ms_creating.script[..ad.ms_creating.script_len]);
                    let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                    let addr = wallet::address::encode_address_str(
                        &script_hash, wallet::address::AddressType::P2SH, &mut addr_buf);
                    boot_display.draw_multisig_result(label, addr,
                        &ad.ms_creating.script[..ad.ms_creating.script_len]);
                }
                crate::app::input::AppState::MultisigShowAddressQR => {
                    let script_hash = wallet::sighash::blake2b_hash(
                        &ad.ms_creating.script[..ad.ms_creating.script_len]);
                    let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                    let addr_len = wallet::address::encode_address(
                        &script_hash, wallet::address::AddressType::P2SH, &mut addr_buf);
                    boot_display.draw_qr_fullscreen(&addr_buf[..addr_len], "MULTISIG QR");
                }
                // ─── Steganography Redraws ────────────
                crate::app::input::AppState::StegoModeSelect => {
                    // Auto-skip screen — show loading while SD scan runs
                    boot_display.draw_loading_screen("JPEG Stego Export...");
                }
                crate::app::input::AppState::StegoEmbed => {
                    boot_display.draw_saving_screen("Encoding stego...");
                }
                crate::app::input::AppState::StegoResult => {
                    if ad.stego_result_ok {
                        boot_display.draw_success_screen("Stego Backup Created");
                    } else {
                        boot_display.draw_rejected_screen("Stego Failed");
                    }
                }
                // ─── JPEG Stego Flow Redraws ────────────
                crate::app::input::AppState::StegoJpegPick => {
                    boot_display.draw_stego_jpeg_pick(&ad.jpeg_display_names, &ad.jpeg_display_lens, ad.jpeg_file_count, ad.jpeg_selected);
                }
                crate::app::input::AppState::StegoJpegDescChoice => {
                    boot_display.draw_stego_desc_choice(false);
                }
                crate::app::input::AppState::StegoJpegDescFile => {
                    boot_display.draw_stego_txt_pick(&ad.txt_display_names, &ad.txt_display_lens, ad.txt_file_count);
                }
                crate::app::input::AppState::StegoJpegDesc => {
                    boot_display.draw_keyboard_screen_full(&ad.pp_input, "IMAGE DESCRIPTOR");
                }
                crate::app::input::AppState::StegoJpegDescPreview => {
                    let desc_str = core::str::from_utf8(&ad.jpeg_desc_buf[..ad.jpeg_desc_len]).unwrap_or("");
                    boot_display.draw_stego_desc_preview(desc_str);
                }
                crate::app::input::AppState::StegoJpegPpAsk => {
                    boot_display.draw_stego_pp_ask();
                }
                crate::app::input::AppState::StegoJpegPpInfo => {
                    boot_display.draw_stego_hint_picker(ad.hint_selected);
                }
                crate::app::input::AppState::StegoJpegPpEntry => {
                    boot_display.draw_keyboard_screen_full(&ad.pp_input, "CUSTOM HINT");
                }
                crate::app::input::AppState::StegoJpegConfirm => {
                    let idx = ad.jpeg_selected as usize;
                    let nl = ad.jpeg_display_lens[idx] as usize;
                    let name_str = core::str::from_utf8(&ad.jpeg_display_names[idx][..nl]).unwrap_or("?");
                    let desc_str = core::str::from_utf8(&ad.jpeg_desc_buf[..ad.jpeg_desc_len]).unwrap_or("");
                    boot_display.draw_stego_jpeg_confirm(name_str, desc_str, ad.stego_pp_enc_len > 0);
                }
                // ─── Stego Import Redraws ────────────
                crate::app::input::AppState::StegoImportPick => {
                    boot_display.draw_stego_jpeg_pick(&ad.import_jpeg_display, &ad.import_jpeg_disp_lens, ad.import_jpeg_count, ad.import_jpeg_selected);
                }
                crate::app::input::AppState::StegoImportDescChoice => {
                    boot_display.draw_stego_desc_choice(true);
                }
                crate::app::input::AppState::StegoImportDescFile => {
                    boot_display.draw_stego_txt_pick(&ad.txt_display_names, &ad.txt_display_lens, ad.txt_file_count);
                }
                crate::app::input::AppState::StegoImportPass => {
                    boot_display.draw_keyboard_screen_full(&ad.pp_input, "IMAGE DESCRIPTOR");
                }
                crate::app::input::AppState::StegoHintReveal => {
                    let hint_str = core::str::from_utf8(&ad.recovered_hint[..ad.recovered_hint_len]).unwrap_or("???");
                    boot_display.draw_stego_hint_reveal(hint_str);
                }
                crate::app::input::AppState::StegoHintPassphrase => {
                    boot_display.draw_keyboard_screen_full(&ad.pp_input, "25TH WORD");
                }
                crate::app::input::AppState::FwUpdateResult => {
                    if ad.fw_update_verified {
                        let mut ver_buf = [0u8; 16];
                        let ver_len = fw_update::format_version(ad.fw_update_info.version, &mut ver_buf);
                        let ver_str = core::str::from_utf8(&ver_buf[..ver_len]).unwrap_or("?.?.?");
                        boot_display.draw_fw_update_screen(ver_str, true);
                    } else {
                        boot_display.draw_fw_update_screen("", false);
                    }
                }
                crate::app::input::AppState::About => {
                    boot_display.draw_about_screen();
                }
                crate::app::input::AppState::ShowAddress => {
                    if ad.scanned_addr_len > 0 {
                        let addr = core::str::from_utf8(&ad.scanned_addr[..ad.scanned_addr_len])
                            .unwrap_or("(invalid)");
                        boot_display.draw_address_screen(addr, ad.scanned_addr_valid, None, None);
                    } else {
                        let pk = if (ad.current_addr_index as usize) < 20 {
                            ad.pubkey_cache[ad.current_addr_index as usize]
                        } else if ad.extra_pubkey_index == ad.current_addr_index {
                            ad.extra_pubkey
                        } else {
                            [0u8; 32]
                        };
                        let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                        let addr = wallet::address::encode_address_str(
                            &pk,
                            wallet::address::AddressType::P2PK,
                            &mut addr_buf,
                        );
                        let idx_option = if ad.word_count == 1 { None } else { Some(ad.current_addr_index) };
                        boot_display.draw_address_screen(addr, true, idx_option, None);
                    }
                }
                crate::app::input::AppState::ShowAddressQR => {
                    let pk = if (ad.current_addr_index as usize) < 20 {
                        ad.pubkey_cache[ad.current_addr_index as usize]
                    } else if ad.extra_pubkey_index == ad.current_addr_index {
                        ad.extra_pubkey
                    } else {
                        [0u8; 32]
                    };
                    let mut addr_buf = [0u8; wallet::address::MAX_ADDR_LEN];
                    let addr_len = wallet::address::encode_p2pk(
                        &pk,
                        &mut addr_buf,
                    );
                    boot_display.draw_qr_screen(&addr_buf[..addr_len]);
                }
                crate::app::input::AppState::AddrIndexPicker => {
                    let input_str = core::str::from_utf8(&ad.addr_input_buf[..ad.addr_input_len as usize])
                        .unwrap_or("");
                    boot_display.draw_addr_index_screen(input_str);
                }
                crate::app::input::AppState::ImportPrivKey => {
                    boot_display.draw_import_privkey_screen(&ad.hex_input, ad.hex_input_len);
                }
                crate::app::input::AppState::DiceRoll => {
                    boot_display.draw_dice_screen(
                        ad.dice_collector.count,
                        ad.dice_collector.target,
                    );
                }
                crate::app::input::AppState::ImportWord { word_idx, word_count: wc } => {
                    boot_display.draw_import_word_screen(word_idx, wc, &ad.word_input);
                }
                crate::app::input::AppState::CalcLastWord { word_idx, word_count: wc } => {
                    boot_display.draw_calc_last_word_screen(word_idx, wc, &ad.word_input);
                }
                crate::app::input::AppState::Bip85Index { word_count: bwc } => {
                    boot_display.draw_bip85_index_screen(ad.bip85_index, bwc);
                }
                crate::app::input::AppState::Bip85Deriving => {
                    boot_display.draw_bip85_deriving();
                }
                crate::app::input::AppState::Bip85ShowWord { word_idx, word_count: bwc } => {
                    let word = wallet::bip39::index_to_word(ad.bip85_child_indices[word_idx as usize]);
                    boot_display.draw_bip85_word_screen(word_idx, bwc, word);
                }
            }
}
