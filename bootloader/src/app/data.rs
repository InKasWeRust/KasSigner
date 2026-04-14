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

// app/data.rs — All application state bundled into one struct
//
// This eliminates ~80 local variables from fn main() and makes handler
// dispatch cleaner: pass &mut AppData instead of 20-50 individual refs.

use crate::{features::fw_update, hw::sd_backup, ui::seed_manager, ui::setup_wizard, wallet};

/// All mutable application state that handlers read/write.
/// Hardware peripherals (display, i2c, delay, camera) are NOT included —
/// they have peripheral lifetimes tied to fn main() scope.
pub struct AppData {
    // ─── Core app state ───
    pub app: crate::app::input::WalletApp,
    pub needs_redraw: bool,
    pub idle_ticks: u32,
    pub display_asleep: bool,

    // ─── Menus ───
    pub tools_menu: crate::app::input::Menu,
    pub export_menu: crate::app::input::Menu,
    pub qr_export_menu: crate::app::input::Menu,
    pub xprv_export_menu: crate::app::input::Menu,
    pub settings_menu: crate::app::input::Menu,
    pub sd_import_menu: crate::app::input::Menu,

    // ─── Seed management ───
    pub seed_mgr: seed_manager::SeedManager,
    pub mnemonic_indices: [u16; 24],
    pub word_count: u8,
    pub seed_loaded: bool,
    pub seed_list_scroll: u8,
    pub pending_delete_slot: u8,
    pub dice_collector: setup_wizard::DiceCollector,
    pub word_input: setup_wizard::WordInput,
    pub pp_input: seed_manager::PassphraseInput,

    // ─── BIP85 ───
    pub bip85_index: u8,
    pub bip85_child_indices: [u16; 24],
    pub bip85_child_wc: u8,

    // ─── Keys & addresses ───
    pub our_privkey: [u8; 32],
    pub current_addr_index: u16,
    pub pubkey_cache: [[u8; 32]; 20],       // receive addresses: m/44'/111111'/0'/0/{0..19}
    pub change_pubkey_cache: [[u8; 32]; 5], // change addresses: m/44'/111111'/0'/1/{0..4}
    pub pubkeys_cached: bool,
    pub acct_key_raw: [u8; 65],
    pub extra_pubkey: [u8; 32],
    pub extra_pubkey_index: u16,
    pub addr_input_buf: [u8; 5],
    pub addr_input_len: u8,
    pub hex_input: [u8; 64],
    pub hex_input_len: u8,
    pub export_key_hex: [u8; 64],

    // ─── Export ───
    pub kpub_data: [u8; wallet::xpub::KPUB_MAX_LEN],
    pub kpub_len: usize,
    pub kpub_frame: u8,
    pub kpub_nframes: u8,
    pub kpub_manual_frames: bool,
    pub kpub_user_nframes: u8, // user-chosen frame count (2/3/4), 0 = ask
    pub xprv_data: [u8; wallet::xpub::XPRV_MAX_LEN],
    pub xprv_len: usize,

    // ─── SD card ───
    pub sd_file_list: [[u8; 11]; 8],
    pub sd_file_count: u8,
    pub sd_file_scroll: u8,
    pub sd_selected_file: [u8; 11],
    /// TXT import type: 0=kpub, 1=multisig address, 2=multisig descriptor
    pub txt_import_type: u8,
    /// KSPT save: 8.3 filename entered by user (8 name + 3 ext)
    pub kspt_filename: [u8; 11],
    /// KSPT save: whether user chose to encrypt
    pub kspt_encrypt: bool,
    /// SD overwrite: state to go to after user confirms overwrite
    pub sd_overwrite_next: crate::app::input::AppState,
    /// SD overwrite: state to return to if user declines (filename keyboard)
    pub sd_overwrite_back: crate::app::input::AppState,
    /// SD TXT save origin: 0=multisig address, 1=kpub (used by SdKsptEncryptPass back-nav)
    pub sd_txt_origin: u8,
    /// QR multi-frame display: true = manual tap-to-advance, false = auto-cycle
    pub qr_manual_frames: bool,

    // ─── Transaction / multisig ───
    pub demo_tx: wallet::transaction::Transaction,
    pub ms_store: wallet::transaction::MultisigStore,
    pub ms_creating: wallet::transaction::MultisigConfig,
    pub ms_m: u8,
    pub ms_n: u8,
    pub ms_scroll: u8,
    /// When >0, AddrIndexPicker returns to MultisigPickAddr with this key_idx
    pub ms_picking_key: u8,
    pub signed_qr_buf: [u8; 1024],
    pub signed_qr_len: usize,
    pub signed_qr_frame: u8,
    pub signed_qr_nframes: u8,
    pub signed_qr_large: bool, // true = multi-frame large QR for device-to-device
    /// Multisig signature status after signing (for ShowQR display)
    pub tx_sigs_present: u8,
    pub tx_sigs_required: u8,
    pub scanned_addr: [u8; 80],
    pub scanned_addr_len: usize,
    pub scanned_addr_valid: bool,

    // ─── Steganography ───
    pub stego_mode_idx: u8,
    pub stego_result_ok: bool,
    pub stego_auto_scan: bool,
    pub jpeg_file_names: [[u8; 11]; 8],
    pub jpeg_display_names: [[u8; 32]; 8],
    pub jpeg_display_lens: [u8; 8],
    pub jpeg_file_count: u8,
    pub jpeg_selected: u8,
    pub jpeg_desc_buf: [u8; 128],
    pub jpeg_desc_len: usize,
    pub txt_file_names: [[u8; 11]; 8],
    pub txt_display_names: [[u8; 32]; 8],
    pub txt_display_lens: [u8; 8],
    pub txt_file_count: u8,
    pub stego_pp_buf: [u8; 64],
    pub stego_pp_len: usize,
    pub stego_pp_encrypted: [u8; sd_backup::MAX_RAW_ENCRYPTED],
    pub stego_pp_enc_len: usize,
    pub hint_selected: u8,
    pub import_jpeg_names: [[u8; 11]; 8],
    pub import_jpeg_display: [[u8; 32]; 8],
    pub import_jpeg_disp_lens: [u8; 8],
    pub import_jpeg_count: u8,
    pub import_jpeg_selected: u8,
    pub import_exif_b64: [u8; 256],
    pub import_exif_b64_len: usize,
    pub recovered_hint: [u8; sd_backup::MAX_RAW_PAYLOAD],
    pub recovered_hint_len: usize,

    // ─── Firmware update ───
    pub fw_update_info: fw_update::FirmwareUpdate,
    pub fw_update_verified: bool,

    // ─── Message signing ───
    pub sign_msg_sig: [u8; 64],

    // ─── Display settings ───
    pub brightness: u8,

    // ─── Camera tune (overlay on ScanQR) — Waveshare only ───
    #[cfg(feature = "waveshare")]
    pub cam_tune_active: bool,
    #[cfg(feature = "waveshare")]
    pub cam_tune_dirty: bool,    // true = values changed, need I2C apply
    #[cfg(feature = "waveshare")]
    pub cam_tune_param: u8,      // 0=AEC_H, 1=AEC_L, 2=contrast, 3=brightness, 4=AGC_ceil, 5=sharpness
    #[cfg(feature = "waveshare")]
    pub cam_tune_vals: [u8; 6],  // current values for each parameter

    // ─── Camera touch forwarding — Waveshare only ───
    #[cfg(feature = "waveshare")]
    pub cam_tap_x: u16,
    #[cfg(feature = "waveshare")]
    pub cam_tap_y: u16,
    #[cfg(feature = "waveshare")]
    pub cam_tap_ready: bool,     // true = unprocessed tap waiting

    // ─── Audio — M5Stack only ───
    #[cfg(feature = "m5stack")]
    pub volume: u8,
}

impl AppData {
        /// Create a new AppData with all fields at default/zero state.
pub fn new() -> Self {
        Self {
            app: crate::app::input::WalletApp::new(),
            needs_redraw: true,
            idle_ticks: 0,
            display_asleep: false,

            tools_menu: crate::app::input::Menu::from_items(
                &["New Seed", "Dice Seed", "Import Words", "Calc Last Word",
                  "BIP85 Child", "Import Raw Key", "Import from SD", "Create Multisig", "Stego Import", "Sign TX",
                  "Sign Message"]
            ),
            export_menu: crate::app::input::Menu::from_items(
                &["Show Seed Words", "QR Export", "JPEG Stego Export",
                  "kpub Watch-Only", "kpub to SD",
                  "xprv Account",
                  "Seed Backup to SD",
                  "Private Key"]
            ),
            xprv_export_menu: crate::app::input::Menu::from_items(
                &["Show as QR", "Encrypt to SD"]
            ),
            qr_export_menu: crate::app::input::Menu::from_items(
                &["CompactSeedQR", "Standard SeedQR", "Plain Words QR"]
            ),
            #[cfg(feature = "waveshare")]
            settings_menu: crate::app::input::Menu::from_items(
                &["Display", "SD Card", "About"]
            ),
            #[cfg(feature = "m5stack")]
            settings_menu: crate::app::input::Menu::from_items(
                &["Display", "Audio", "SD Card", "About"]
            ),
            sd_import_menu: crate::app::input::Menu::from_items(
                &["Seed Backup", "Transaction", "kpub (Watch-Only)",
                  "Multisig Address", "Multisig Descriptor"]
            ),

            seed_mgr: seed_manager::SeedManager::new(),
            mnemonic_indices: [0; 24],
            word_count: 0,
            seed_loaded: false,
            seed_list_scroll: 0,
            pending_delete_slot: 0xFF,
            dice_collector: setup_wizard::DiceCollector::new_12_word(),
            word_input: setup_wizard::WordInput::new(),
            pp_input: seed_manager::PassphraseInput::new(),

            bip85_index: 0,
            bip85_child_indices: [0; 24],
            bip85_child_wc: 0,

            our_privkey: [0u8; 32],
            current_addr_index: 0,
            pubkey_cache: [[0u8; 32]; 20],
            change_pubkey_cache: [[0u8; 32]; 5],
            pubkeys_cached: false,
            acct_key_raw: [0u8; 65],
            extra_pubkey: [0u8; 32],
            extra_pubkey_index: 0xFFFF,
            addr_input_buf: [0u8; 5],
            addr_input_len: 0,
            hex_input: [0u8; 64],
            hex_input_len: 0,
            export_key_hex: [0u8; 64],

            kpub_data: [0u8; wallet::xpub::KPUB_MAX_LEN],
            kpub_len: 0,
            kpub_frame: 0,
            kpub_nframes: 0,
            kpub_manual_frames: false,
            kpub_user_nframes: 0,
            xprv_data: [0u8; wallet::xpub::XPRV_MAX_LEN],
            xprv_len: 0,

            sd_file_list: [[b' '; 11]; 8],
            sd_file_count: 0,
            sd_file_scroll: 0,
            sd_selected_file: [b' '; 11],
            txt_import_type: 0,
            kspt_filename: [b' '; 11],
            kspt_encrypt: false,
            sd_overwrite_next: crate::app::input::AppState::MainMenu,
            sd_overwrite_back: crate::app::input::AppState::MainMenu,
            sd_txt_origin: 0,
            qr_manual_frames: false,

            demo_tx: wallet::transaction::Transaction::new(),
            ms_store: wallet::transaction::MultisigStore::new(),
            ms_creating: wallet::transaction::MultisigConfig::new(),
            ms_m: 2,
            ms_n: 3,
            ms_scroll: 0,
            ms_picking_key: 0,
            signed_qr_buf: [0u8; 1024],
            signed_qr_len: 0,
            signed_qr_frame: 0,
            signed_qr_nframes: 0,
            signed_qr_large: false,
            tx_sigs_present: 0,
            tx_sigs_required: 0,
            scanned_addr: [0u8; 80],
            scanned_addr_len: 0,
            scanned_addr_valid: false,

            stego_mode_idx: 0,
            stego_result_ok: false,
            stego_auto_scan: false,
            jpeg_file_names: [[0u8; 11]; 8],
            jpeg_display_names: [[0u8; 32]; 8],
            jpeg_display_lens: [0u8; 8],
            jpeg_file_count: 0,
            jpeg_selected: 0,
            jpeg_desc_buf: [0u8; 128],
            jpeg_desc_len: 0,
            txt_file_names: [[0u8; 11]; 8],
            txt_display_names: [[0u8; 32]; 8],
            txt_display_lens: [0u8; 8],
            txt_file_count: 0,
            stego_pp_buf: [0u8; 64],
            stego_pp_len: 0,
            stego_pp_encrypted: [0u8; sd_backup::MAX_RAW_ENCRYPTED],
            stego_pp_enc_len: 0,
            hint_selected: 0,
            import_jpeg_names: [[0u8; 11]; 8],
            import_jpeg_display: [[0u8; 32]; 8],
            import_jpeg_disp_lens: [0u8; 8],
            import_jpeg_count: 0,
            import_jpeg_selected: 0,
            import_exif_b64: [0u8; 256],
            import_exif_b64_len: 0,
            recovered_hint: [0u8; sd_backup::MAX_RAW_PAYLOAD],
            recovered_hint_len: 0,

            fw_update_info: fw_update::FirmwareUpdate::empty(),
            fw_update_verified: false,

            sign_msg_sig: [0u8; 64],

            brightness: 102,

            #[cfg(feature = "waveshare")]
            cam_tune_active: false,
            #[cfg(feature = "waveshare")]
            cam_tune_dirty: true,
            #[cfg(feature = "waveshare")]
            cam_tune_param: 0,
            #[cfg(feature = "waveshare")]
            // Proven QR scanning defaults (iPad screen decode): AEC=58/48 CTR=8B BRT=08 AGC=70 SHP=50
            // [0]=AEC_H(0x3A0F) [1]=AEC_L(0x3A10) [2]=contrast(0x5586) [3]=brightness(0x5587) [4]=AGC_ceil(0x3A19) [5]=sharpness(0x5308)
            cam_tune_vals: [0x58, 0x48, 0x8B, 0x08, 0x70, 0x50],

            #[cfg(feature = "waveshare")]
            cam_tap_x: 0,
            #[cfg(feature = "waveshare")]
            cam_tap_y: 0,
            #[cfg(feature = "waveshare")]
            cam_tap_ready: false,

            #[cfg(feature = "m5stack")]
            volume: 18,
        }
    }
}
