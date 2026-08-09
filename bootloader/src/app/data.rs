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

// features::fw_update dropped from this import with the two fields above.
// The module itself stays: verify.rs uses DEV_PUBKEY, and the displays use
// CURRENT_VERSION and format_version.
use crate::{hw::sd_backup, ui::seed_manager, ui::setup_wizard, wallet};

/// Backlight duty applied at boot and stored in `AppData::brightness`.
///
/// Scale is 0-255 (LEDC duty on Waveshare, PMU level on M5Stack). The
/// Display Settings screen renders it as `duty * 100 / 255`, so 39 reads
/// as 15% and 102 as 40%.
///
/// This constant is the ONLY place the boot value lives. The backlight is
/// switched on during peripheral init, well before `AppData::new()` runs,
/// so the boot call site has to use the same value or the field and the
/// hardware disagree until the first wake, idle-dim restore, or settings
/// drag re-applies the field.
#[cfg(feature = "waveshare")]
pub const DEFAULT_BRIGHTNESS: u8 = 39;
/// See the Waveshare variant above.
#[cfg(not(feature = "waveshare"))]
pub const DEFAULT_BRIGHTNESS: u8 = 102;

/// Depth of each extended pubkey bank (receive and change).
///
/// This is a hard signing wall, not a speed knob: an input whose pubkey is
/// not found within the banks resolves as unmatched and is only signed on
/// the stealth-tweak path, so a wallet that never reuses addresses stops
/// being able to spend past this index.
///
/// Costs at 1000, measured against ~39ms per scalar multiply on this
/// chip and one multiply per index (see `ChainParent`):
///   RAM        64KB, heap-allocated in PSRAM, not internal DRAM.
///   Idle fill  2000 derivations, ~78s of cumulative idle for both banks.
///   Cold worst An input that is NOT ours forces the scan to run the full
///              depth before reporting unmatched: ~78s, paid ONCE per
///              signing pass (the banks keep what it derived, so later
///              inputs resolve from RAM). At 200 this was ~16s.
///
/// That last line is the real cost of raising this number, and it lands
/// on stealth (DKSAP) inputs in particular: they are unmatched by
/// construction, so from cold they walk the whole depth before falling
/// through to the stealth path. Normal idle hides it; a stealth spend
/// immediately after a seed load does not. Skipping the bank scan when
/// `tx.has_stealth_tweak` is set would remove that, and is worth doing
/// before this depth is raised any further.
pub const EXT_BANK_DEPTH: usize = 1000;

/// Capacity of `AppData::signed_qr_buf`.
///
/// Header 48 bytes, ~156 per input, ~45 per output, so this holds well
/// over MAX_INPUTS worth of signed transaction. The signing pre-check
/// reads `signed_qr_buf.len()` rather than repeating the number.
pub const SIGNED_QR_BUF_LEN: usize = 8192;

/// Capacity of every SD file picker: `sd_file_list` plus the TXT, JPEG
/// and import-JPEG lists.
///
/// Was 8, which is two pages at four rows each, and the scan filters
/// stopped there regardless of how many files the card held, so files
/// beyond the eighth were silently invisible. The card deliberately mixes
/// file types on one picker, so eight is easily exceeded in normal use.
///
/// The 11-byte short-name arrays stay inline: 352 bytes each at 32. The
/// 32-byte display-name arrays are boxed instead, because inline they
/// would add ~1KB apiece, and `AppData` is materialized on `main`'s
/// frame. Boxed, the three cost 24 bytes of stack and 3KB of PSRAM.
pub const SD_FILE_LIST_MAX: usize = 32;

/// Envelope format of the transaction payload currently loaded in AppData.
/// Determines which serializer to use for the signed-response QR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxInputFormat {
    /// Legacy KSPT v1 (our custom compact binary, unsigned).
    KsptV1,
    /// Legacy KSPT v2 (our custom compact binary, partially signed).
    KsptV2,
    /// Kaspa-standard PSKT, hex-wrapped bundle JSON, `PSKB` magic prefix.
    PsktPskb,
    /// Kaspa-standard single PSKT (non-bundle), `PSKT` magic prefix.
    PsktSingle,
}

impl TxInputFormat {
    /// Returns true if this format is a Kaspa-standard PSKT variant.
    pub fn is_pskt(self) -> bool {
        matches!(self, Self::PsktPskb | Self::PsktSingle)
    }
}

/// Maximum byte-range regions the PSKT parser can capture from an
/// incoming JSON for verbatim pass-through on re-emission.
///
/// Used for opaque fields the signer doesn't interpret but must round-trip
/// (`xpubs`, `proprietaries`, `bip32Derivations` values carrying unknown
/// KeySource shapes, per-input/output unknown fields). Each region is a
/// `(start, end)` offset pair into the original JSON bytes.
///
/// 16 slots covers: globals (3) + per-input (5 × 2 inputs = 10) +
/// per-output (2 × 2 outputs = 4) with headroom. Kept small since each
/// pair is 4 bytes.
pub const MAX_PSKT_UNKNOWN_REGIONS: usize = 16;

/// Byte-range capture state populated by the PSKT parser, consumed by the
/// PSKT serializer on re-emission. Empty/zeroed for KSPT flows.
#[derive(Debug, Clone, Copy)]
pub struct PsktParsed {
    /// `(start, end)` offsets into the original JSON bytes for regions
    /// the parser didn't interpret. `start == end` means unused slot.
    pub unknowns: [(u16, u16); MAX_PSKT_UNKNOWN_REGIONS],
    pub unknowns_count: u8,
    /// Start/end offsets of the raw JSON fragment inside the original
    /// wire payload (after the magic prefix, after hex-decode). Used by
    /// the serializer to slice unknown regions out of the scratch buffer.
    pub json_start: u16,
    pub json_len: u16,
}

impl PsktParsed {
    pub const fn empty() -> Self {
        Self {
            unknowns: [(0u16, 0u16); MAX_PSKT_UNKNOWN_REGIONS],
            unknowns_count: 0,
            json_start: 0,
            json_len: 0,
        }
    }
}

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
    pub seed_tools_menu: crate::app::input::Menu,
    pub import_menu: crate::app::input::Menu,
    pub single_sig_menu: crate::app::input::Menu,
    pub multisig_menu: crate::app::input::Menu,
    pub export_menu: crate::app::input::Menu,
    pub seed_backup_menu: crate::app::input::Menu,
    pub watch_only_menu: crate::app::input::Menu,
    pub signing_keys_menu: crate::app::input::Menu,
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
    /// Which BIP44 chain the address browser (AppState::ShowAddress)
    /// is currently displaying: false = receive (chain 0), true = change
    /// (chain 1). Toggled by the R/C button on the address screen.
    /// Change chain uses `change_pubkey_cache` (5 entries) instead of
    /// `pubkey_cache` (20 entries + `extra_pubkey`).
    pub addr_view_is_change: bool,
    pub addr_partial_redraw: bool,
    pub pubkeys_cached: bool,
    pub acct_key_raw: [u8; 65],
    /// Extended pubkey banks: idle-derived to depth `EXT_BANK_DEPTH` per
    /// chain so that input matching and output labeling are RAM lookups at
    /// any practical index (the live caches only cover 20 receive / 5
    /// change; beyond them signing hit the SIGN_MATCH_DEPTH=100 wall and
    /// review ran a live derivation search). Filled by the idle pump in
    /// the main menu.
    ///
    /// Boxed, NOT inline arrays. When these were inline
    /// `[[u8; 32]; 200]` fields they added 12.8KB to `AppData`, and
    /// `main` builds the struct with `Box::new(AppData::new())`, whose
    /// return value can materialize in `main`'s frame before it is moved
    /// into the allocation. A stack slot in a function lives for that
    /// function's whole extent, so every callee of `main` lost 12.8KB of
    /// headroom permanently, which is what tripped the stack guard inside
    /// PBKDF2 on the SD restore path. The sign path already knew this
    /// number was fatal: see the disjoint borrow at the
    /// `sign_and_serialize_pskt_multi` call site, kept that way so the
    /// banks are never copied onto the sign stack.
    ///
    /// The global allocator is PSRAM (`psram_allocator!` in main), so the
    /// banks sit in external RAM and cost internal DRAM nothing. That is
    /// also what makes `EXT_BANK_DEPTH` cheap to raise: at the current
    /// depth these are 64KB of PSRAM that would have been unthinkable on
    /// the stack. They hold x-only PUBLIC keys, no secret material.
    pub ext_recv: alloc::boxed::Box<[[u8; 32]]>,
    pub ext_recv_n: u16,
    pub ext_chg: alloc::boxed::Box<[[u8; 32]]>,
    pub ext_chg_n: u16,
    /// Both chain parents for the active account key, so the idle pump
    /// pays one scalar multiply per index instead of three. Rebuilt
    /// automatically whenever `acct_key_raw` changes; see `ChainCache`,
    /// which stores the account key it came from and compares all 65
    /// bytes rather than trusting write sites to invalidate it.
    ///
    /// Boxed so the ~260 bytes live in PSRAM and `AppData` grows by a
    /// pointer, keeping them off `main`'s frame (see the note on the
    /// banks above).
    pub chain_cache: Option<alloc::boxed::Box<wallet::bip32::ChainCache>>,
    pub extra_pubkey: [u8; 32],
    pub extra_pubkey_index: u16,
    /// On-demand change pubkey for indices beyond change_pubkey_cache
    /// (which only holds 5 entries). Mirrors the receive-chain
    /// `extra_pubkey` pattern so the R/C toggle in ShowAddress can
    /// scroll through change addresses at arbitrary indices without
    /// a hard cap. `extra_change_pubkey_index == 0xFFFF` means empty.
    pub extra_change_pubkey: [u8; 32],
    pub extra_change_pubkey_index: u16,
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
    // ═════════════════════════════════════════════════════════════════
    // QR DENSITY TEST — diagnostic feature, disabled after data capture.
    // Preserved as commented code for re-characterization when new
    // camera hardware ships (OV2640-AF, next-gen sensors). To re-enable:
    // (1) uncomment the field below and its init in `new()`;
    // (2) uncomment the handler branches in handlers/export.rs and the
    //     ExportKpubTestQr AppState variant in app/input.rs;
    // (3) uncomment the TEST QR button in screens.rs::draw_kpub_frame_count_choice
    //     and the draw_qr_test_screen function;
    // (4) uncomment the redraw dispatch case in ui/redraw.rs.
    // Results captured 20 Apr 2026: M5↔M5 V5 top (106B) reliable with
    // retries, V6 (120B+) never decoded in 14+ attempts.
    // ═════════════════════════════════════════════════════════════════
    // pub qr_test_buf: [u8; 134],
    // pub qr_test_len: usize,

    // ─── SD card ───
    pub sd_file_list: [[u8; 11]; SD_FILE_LIST_MAX],
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
    /// SD delete: state to return to after delete completes or is cancelled.
    /// Set by any file-list handler before routing to SdDeleteConfirm, so
    /// the confirm screen can bounce back to the correct list.
    pub sd_delete_return: crate::app::input::AppState,
    pub seed_backup_return: crate::app::input::AppState,
    pub address_return: crate::app::input::AppState,
    pub kpub_export_return: crate::app::input::AppState,
    /// SD TXT save origin: 0=multisig address, 1=kpub (used by SdKsptEncryptPass back-nav)
    pub sd_txt_origin: u8,
    /// QR multi-frame display: true = manual tap-to-advance, false = auto-cycle
    pub qr_manual_frames: bool,

    // ─── Transaction / multisig ───
    /// The current transaction being signed.
    ///
    /// Heap-allocated (PSRAM) to keep AppData's stack footprint down —
    /// Transaction post-PSKT-migration is ~11 KB (8 inputs × ~1.3 KB
    /// each after IncomingPartialSig and pubkey_compressed additions),
    /// and a Transaction-by-value field would make main's frame
    /// materialize that during AppData::new(). Boxing puts the struct
    /// on PSRAM directly; field access via DerefMut works transparently
    /// at call sites.
    pub demo_tx: alloc::boxed::Box<wallet::transaction::Transaction>,
    pub ms_store: wallet::transaction::MultisigStore,
    pub ms_creating: wallet::transaction::MultisigConfig,
    pub ms_m: u8,
    pub ms_n: u8,
    pub ms_scroll: u8,
    /// AddrIndexPicker routing: 255 = multisig wallet index (returns to
    /// MultisigShowAddress), 0 = plain address picking (ShowAddress).
    pub ms_picking_key: u8,
    /// Buffer for pending signed-tx QR payload (KSPT or PSKB).
    /// Sized for the PSKB wire format of a fully-signed 2-of-3 multisig
    /// (measured ~3.5 KB max; 4096 B gives headroom). KSPT payloads sit
    /// well under 1 KB and use the same buffer.
    /// Buffer for the outgoing signed KSPT/PSKT response.
    /// Sized at 4 KB: realistic PSKBs are ~2-3 KB after signing
    /// (measured: unsigned 2,106B → fully-signed 2-of-3 ~2,660B).
    /// 4 KB leaves headroom for larger txs and 4-of-N multisig variants.
    /// Lives inside Box<AppData> so it doesn't hit the stack.
    /// Signed-transaction / scratch buffer, heap-allocated in PSRAM.
    ///
    /// At 8192 bytes inline this was the single largest field on
    /// `AppData`, and `main` builds the struct with
    /// `Box::new(AppData::new())`, whose return value materializes in
    /// `main`'s frame before being moved into the allocation. A stack
    /// slot lives for the whole extent of its function, so those 8KB were
    /// charged to every callee of `main` for the life of the program.
    /// That is the same mechanism that put the pubkey banks on the stack
    /// and tripped the guard inside PBKDF2 on the SD restore path.
    ///
    /// Sized for 32 P2SH inputs at ~215B signed, plus outputs. Callers
    /// pass it as a slice, so read `.len()` rather than assuming 8192.
    pub signed_qr_buf: alloc::boxed::Box<[u8]>,
    pub signed_qr_len: usize,
    pub signed_qr_frame: u8,
    pub signed_qr_nframes: u8,
    /// Covenant backup: bytes stored in signed_qr_buf[0..covb_len]. >0 triggers SD save.
    pub covb_len: usize,
    pub signed_qr_large: bool, // true = multi-frame large QR for device-to-device
    /// Signed-KSPT QR frame-size mode (v1.0.3+).
    ///   0 = use signed_qr_large legacy picker (phone=106B or device=55B)
    ///   1 = 85 B/frame (V5, ~5 frames/398B — risky on close LCD)
    ///   2 = 55 B/frame (V4, ~8 frames — borderline on close LCD)
    ///   3 = 40 B/frame (V3, ~10 frames — reliable close-LCD decode)
    ///   4 = 27 B/frame (V3 smaller fill, ~15 frames — rock solid)
    /// Higher = smaller QRs = more scans but more reliable. Paired
    /// with the ShowQrFrameChoice selector for user-chosen tradeoff.
    pub signed_qr_mode: u8,
    /// Remember whether the user entered the KSPT export flow via the
    /// "KasSigner" → density (Fast/Safe) sub-screen, so Back from later
    /// screens (Auto/Manual, Save to SD popup) can return to the density
    /// picker instead of skipping past it to the top-level Phone/KasSigner
    /// choice. Set true when ShowQrDensityChoice is entered; reset false
    /// when the flow starts over (main menu, ShowQrFrameChoice re-entry).
    pub signed_qr_via_density: bool,
    /// Multisig signature status after signing (for ShowQR display)
    pub tx_sigs_present: u8,
    pub tx_sigs_required: u8,
    /// Envelope format of the currently loaded transaction.
    /// Set by the camera-loop dispatcher at receive time; read by the
    /// signing-response serializer to emit in the matching format.
    pub tx_input_format: TxInputFormat,
    /// PSKT byte-range capture — populated by std_pskt parser, consumed
    /// by std_pskt serializer. Zeroed for KSPT flows.
    pub pskt_parsed: PsktParsed,
    pub scanned_addr: [u8; 80],
    pub scanned_addr_len: usize,
    pub scanned_addr_valid: bool,

    // ─── Steganography ───
    pub stego_mode_idx: u8,
    pub stego_result_ok: bool,
    pub stego_auto_scan: bool,
    pub jpeg_file_names: [[u8; 11]; SD_FILE_LIST_MAX],
    pub jpeg_display_names: alloc::boxed::Box<[[u8; 32]]>,
    pub jpeg_display_lens: [u8; SD_FILE_LIST_MAX],
    pub jpeg_file_count: u8,
    pub jpeg_selected: u8,
    pub jpeg_desc_buf: [u8; 128],
    pub jpeg_desc_len: usize,
    pub txt_file_names: [[u8; 11]; SD_FILE_LIST_MAX],
    pub txt_display_names: alloc::boxed::Box<[[u8; 32]]>,
    pub txt_display_lens: [u8; SD_FILE_LIST_MAX],
    pub txt_file_count: u8,
    /// Page offset for the TXT picker. It previously had no scroll state
    /// at all, so `draw_stego_txt_pick` painted left/right arrows that
    /// were wired to nothing and only the first four files were ever
    /// reachable.
    pub txt_file_scroll: u8,
    pub stego_pp_buf: [u8; 64],
    pub stego_pp_len: usize,
    pub stego_pp_encrypted: [u8; sd_backup::MAX_RAW_ENCRYPTED],
    pub stego_pp_enc_len: usize,
    pub hint_selected: u8,
    pub import_jpeg_names: [[u8; 11]; SD_FILE_LIST_MAX],
    pub import_jpeg_display: alloc::boxed::Box<[[u8; 32]]>,
    pub import_jpeg_disp_lens: [u8; SD_FILE_LIST_MAX],
    pub import_jpeg_count: u8,
    pub import_jpeg_selected: u8,
    /// base64 of a v3 seed container (136) + separator + base64 of a v3
    /// hint container (156) = 293. Was 256, exact for the v1 sizes.
    pub import_exif_b64: [u8; 384],
    pub import_exif_b64_len: usize,
    pub recovered_hint: [u8; sd_backup::MAX_RAW_PAYLOAD],
    pub recovered_hint_len: usize,

    // ─── Firmware update ───
    // H-03: firmware-update-over-QR was an abandoned design. Nothing ever
// installed anything: the flow stopped at a screen showing a verified tick,
// and the signature covered only the hash, never the version, so a replayed
// signature with any version number displayed as verified. Commented out
// rather than deleted so the abandoned design stays visible.
    // pub fw_update_info: fw_update::FirmwareUpdate,
    // pub fw_update_verified: bool,

    // ─── Message signing ───
    pub sign_msg_sig: [u8; 64],
    pub sign_msg_hash: [u8; 32],
    /// When true, ScanQR routes decoded QR to hash signing instead of KSPT/address
    pub sign_msg_scan_hash: bool,

    // ─── Commit-Reveal ECIES ───
    /// BLAKE2B hash of the preimage (32 bytes) — the commitment
    pub cr_hash: [u8; 32],
    /// ECIES ciphertext of the preimage (variable length, stored in Vec on PSRAM)
    pub cr_ciphertext: alloc::vec::Vec<u8>,
    /// Split preimage part A (random, for heartbeat TX 1)
    pub cr_part_a: alloc::vec::Vec<u8>,
    /// Split preimage part B (remainder, for heartbeat TX 2)
    pub cr_part_b: alloc::vec::Vec<u8>,

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
    /// Zeroize every buffer holding key material.
    ///
    /// ORDER MATTERS. `chain_cache` is a SEPARATE PSRAM allocation holding
    /// three private keys: `acct_src`, the 65-byte account xprv, plus a
    /// `ChainParent` per chain each wrapping an `ExtendedPrivKey`. `AppData`
    /// stores only a pointer to it, so wiping the `AppData` block alone zeroes
    /// the pointer and leaves the keys resident elsewhere in PSRAM. The heap
    /// must therefore be cleared THROUGH the pointers before they are dropped.
    ///
    /// `ExtendedPrivKey` zeroizes on drop, so releasing the Box handles the two
    /// `ChainParent` keys. The plain `[u8; 65]` `acct_src` has no Drop and must
    /// be cleared explicitly first.
    #[inline(never)]   // keep this frame out of main via handle_idle
    /// What kind of key material the session currently holds (H-08).
    ///
    /// Derived from `self.word_count`, which is the same discriminant
    /// `SeedSlot` uses: 1 raw key, 2 xprv, 12 or 24 mnemonic. This is a naming
    /// change with identical semantics, not a safety fix; it exists so that the
    /// ten `ad.word_count == 2` tests scattered across the handlers say what
    /// they mean, and so that adding a slot kind surfaces them.
    ///
    /// Note that `word_count` is overloaded at this level too: during seed entry
    /// it is the number of words being typed, before any slot exists. Those
    /// sites are not kind checks and are deliberately left alone.
    pub fn active_kind(&self) -> crate::ui::seed_manager::SlotKind {
        use crate::ui::seed_manager::SlotKind;
        match self.word_count {
            0 => SlotKind::Empty,
            1 => SlotKind::RawKey,
            2 => SlotKind::Xprv,
            wc => SlotKind::Mnemonic { word_count: wc },
        }
    }

    pub fn wipe_secrets(&mut self) {
        use crate::wallet::hmac::zeroize_buf;

        // 1. Through the heap pointers, while they still point somewhere.
        if let Some(cc) = self.chain_cache.as_mut() {
            zeroize_buf(&mut cc.acct_src);
        }
        self.chain_cache = None;

        for e in self.ext_recv.iter_mut() { zeroize_buf(e); }
        for e in self.ext_chg.iter_mut()  { zeroize_buf(e); }
        self.ext_recv_n = 0;
        self.ext_chg_n = 0;

        // 2. The AppData block itself.
        self.seed_mgr.zeroize_all();
        for w in self.mnemonic_indices.iter_mut()    { *w = 0; }
        for w in self.bip85_child_indices.iter_mut() { *w = 0; }
        zeroize_buf(&mut self.our_privkey);
        zeroize_buf(&mut self.acct_key_raw);
        for pk in self.pubkey_cache.iter_mut()        { zeroize_buf(pk); }
        for pk in self.change_pubkey_cache.iter_mut() { zeroize_buf(pk); }

        // 3. Input buffers that can hold partial secrets mid-entry.
        self.pp_input.reset();
        self.word_input.reset();
        // DiceCollector has no reset; assignment overwrites the rolls in place.
        self.dice_collector = crate::ui::setup_wizard::DiceCollector::new_12_word();

        // 4. Flags last, so no early return above can leave them lying.
        self.seed_loaded = false;
        self.pubkeys_cached = false;
        self.word_count = 0;
        self.bip85_child_wc = 0;

        // Before the wipe, so the after-scan has something to be compared
        // against. An after-scan alone proves nothing: zero hits could mean the
        // wipe worked or that the secret was never there. Both scans, same
        // boot, same sentinel.
        #[cfg(feature = "sentinel-scan")]
        crate::app::stack_probe::scan_sentinel("before wipe");

        // 5. The stack, which steps 1 through 4 cannot reach (H-01).
        //
        // Everything above clears structures this type owns. None of it touches
        // the copies left in returned frames: PBKDF2 intermediate state, the
        // 64-byte BIP39 seed from `ensure_session_account_key`, Schnorr scalars,
        // `SeedSlot` temporaries. Returning from a function does not erase its
        // frame, and on a device idling in a touch loop that region is not
        // reused for a long time. A wipe that leaves the seed on the stack is
        // not a wipe.
        //
        // `wipe_below_sp` clears only between the stack guard and its own frame,
        // so it cannot reach the IRAM alias and cannot touch anything live. That
        // is what makes it safe where `hw::lockdown::panic_wipe` is not.
        //
        // Interrupts OFF for the duration. An ISR pushes its frame below the
        // current stack pointer, which is exactly the region being zeroed, so
        // without this a touch or timer interrupt during the wipe would be
        // corrupted. About a millisecond at ~110 KB, which is nothing beside the
        // camera DMA that keeps running regardless.
        //
        // The panic handler calls `wipe_below_sp` directly, without a critical
        // section, because interrupts are already down there.
        let stack_wiped = critical_section::with(|_| {
            crate::app::stack_probe::wipe_below_sp()
        });
        // Logged because the heap wipe and the stack wipe are separate and only
        // one of them was visible: "Duress wipe: key material cleared" is
        // printed by the caller and says nothing about this step.
        //
        // Note for anyone reading stack figures afterwards: this destroys the
        // 0xC0DEFEED paint laid down at boot, so `stack_probe::report` is
        // meaningless until the next reset. A report taken immediately after
        // this should show `deepest` at the floor and `free` near zero, which is
        // the cheap confirmation that the wipe reached the stack at all.
        crate::log!("   [SEC] Stack wiped: {} B", stack_wiped);

        // Expect zero hits. A hit above the wipe ceiling means a secret lives
        // in a frame no wipe reaches, which the byte count cannot reveal.
        #[cfg(feature = "sentinel-scan")]
        crate::app::stack_probe::scan_sentinel("after wipe");
    }

        /// Create a new AppData with all fields at default/zero state.
pub fn new() -> Self {
        Self {
            app: crate::app::input::WalletApp::new(),
            needs_redraw: true,
            idle_ticks: 0,
            display_asleep: false,

            tools_menu: crate::app::input::Menu::from_items(
                &["Seed Tools", "Import / Export", "Single Signature", "Multisig"]
            ),
            seed_tools_menu: crate::app::input::Menu::from_items(
                &["New Seed", "Dice Seed", "Touch Seed", "Import Words", "Address", "BIP85 Child", "Calc Last Word"]
            ),
            import_menu: crate::app::input::Menu::from_items(
                &["Import from SD", "Stego Import", "Import Raw Key", "Covenant Restore"]
            ),
            single_sig_menu: crate::app::input::Menu::from_items(
                &["Sign TX", "Sign Message", "Commit Secret", "Decrypt Secret"]
            ),
            multisig_menu: crate::app::input::Menu::from_items(
                &["Create Multisig"]
            ),
            export_menu: crate::app::input::Menu::from_items(
                &["Seed Backup", "Watch-Only",
                  "Signing Keys", "Steganography"]
            ),
            seed_backup_menu: crate::app::input::Menu::from_items(
                &["Show Seed Words", "QR Export", "Backup to SD"]
            ),
            watch_only_menu: crate::app::input::Menu::from_items(
                &["kpub as QR", "kpub to SD"]
            ),
            signing_keys_menu: crate::app::input::Menu::from_items(
                &["xprv Account", "Private Key"]
            ),
            xprv_export_menu: crate::app::input::Menu::from_items(
                &["Show as QR", "Encrypt to SD"]
            ),
            qr_export_menu: crate::app::input::Menu::from_items(
                &["CompactSeedQR", "Standard SeedQR", "Plain Text QR"]
            ),
            #[cfg(feature = "waveshare")]
            settings_menu: crate::app::input::Menu::from_items(
                &["Display", "Camera", "SD Card", "About"]
            ),
            #[cfg(feature = "m5stack")]
            settings_menu: crate::app::input::Menu::from_items(
                &["Display", "Audio", "SD Card", "About"]
            ),
            sd_import_menu: crate::app::input::Menu::from_items(
                &["Seed Backup", "Transaction", "kpub (Watch-Only)",
                  "Multisig Address", "Multisig Descriptor", "Covenant Restore"]
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
            addr_view_is_change: false,
            addr_partial_redraw: false,
            pubkeys_cached: false,
            acct_key_raw: [0u8; 65],
            // `alloc::vec![elem; n]` allocates the buffer on the heap and
            // fills it in place; nothing 6.4KB ever exists in this frame.
            // `Box::new([[0u8; 32]; N])` would build the whole array here
            // first and then copy it into the allocation, reintroducing
            // exactly the stack temporary this move exists to remove.
            ext_recv: alloc::vec![[0u8; 32]; EXT_BANK_DEPTH].into_boxed_slice(),
            ext_recv_n: 0,
            ext_chg: alloc::vec![[0u8; 32]; EXT_BANK_DEPTH].into_boxed_slice(),
            ext_chg_n: 0,
            chain_cache: None,
            extra_pubkey: [0u8; 32],
            extra_pubkey_index: 0xFFFF,
            extra_change_pubkey: [0u8; 32],
            extra_change_pubkey_index: 0xFFFF,
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
            // qr_test_buf: [0u8; 134],    // disabled — see struct def
            // qr_test_len: 0,

            sd_file_list: [[b' '; 11]; SD_FILE_LIST_MAX],
            sd_file_count: 0,
            sd_file_scroll: 0,
            sd_selected_file: [b' '; 11],
            txt_import_type: 0,
            kspt_filename: [b' '; 11],
            kspt_encrypt: false,
            sd_overwrite_next: crate::app::input::AppState::MainMenu,
            sd_overwrite_back: crate::app::input::AppState::MainMenu,
            sd_delete_return: crate::app::input::AppState::MainMenu,
            seed_backup_return: crate::app::input::AppState::SeedList,
            address_return: crate::app::input::AppState::SeedList,
            kpub_export_return: crate::app::input::AppState::WatchOnlyMenu,
            sd_txt_origin: 0,
            qr_manual_frames: false,

            demo_tx: wallet::transaction::Transaction::new_boxed()
                .expect("demo_tx allocation failed"),
            ms_store: wallet::transaction::MultisigStore::new(),
            ms_creating: wallet::transaction::MultisigConfig::new(),
            ms_m: 2,
            ms_n: 3,
            ms_scroll: 0,
            ms_picking_key: 0,
            // Built in place on the heap. `Box::new([0u8; 8192])` would
            // construct the array in this frame first and then copy it,
            // reintroducing the very cost being removed.
            signed_qr_buf: alloc::vec![0u8; SIGNED_QR_BUF_LEN].into_boxed_slice(),
            signed_qr_len: 0,
            signed_qr_frame: 0,
            signed_qr_nframes: 0,
            covb_len: 0,
            signed_qr_large: false,
            signed_qr_mode: 0,
            signed_qr_via_density: false,
            tx_sigs_present: 0,
            tx_sigs_required: 0,
            tx_input_format: TxInputFormat::KsptV1,
            pskt_parsed: PsktParsed::empty(),
            scanned_addr: [0u8; 80],
            scanned_addr_len: 0,
            scanned_addr_valid: false,

            stego_mode_idx: 0,
            stego_result_ok: false,
            stego_auto_scan: false,
            jpeg_file_names: [[0u8; 11]; SD_FILE_LIST_MAX],
            jpeg_display_names: alloc::vec![[0u8; 32]; SD_FILE_LIST_MAX].into_boxed_slice(),
            jpeg_display_lens: [0u8; SD_FILE_LIST_MAX],
            jpeg_file_count: 0,
            jpeg_selected: 0,
            jpeg_desc_buf: [0u8; 128],
            jpeg_desc_len: 0,
            txt_file_names: [[0u8; 11]; SD_FILE_LIST_MAX],
            txt_display_names: alloc::vec![[0u8; 32]; SD_FILE_LIST_MAX].into_boxed_slice(),
            txt_display_lens: [0u8; SD_FILE_LIST_MAX],
            txt_file_count: 0,
            txt_file_scroll: 0,
            stego_pp_buf: [0u8; 64],
            stego_pp_len: 0,
            stego_pp_encrypted: [0u8; sd_backup::MAX_RAW_ENCRYPTED],
            stego_pp_enc_len: 0,
            hint_selected: 0,
            import_jpeg_names: [[0u8; 11]; SD_FILE_LIST_MAX],
            import_jpeg_display: alloc::vec![[0u8; 32]; SD_FILE_LIST_MAX].into_boxed_slice(),
            import_jpeg_disp_lens: [0u8; SD_FILE_LIST_MAX],
            import_jpeg_count: 0,
            import_jpeg_selected: 0,
            import_exif_b64: [0u8; 384],
            import_exif_b64_len: 0,
            recovered_hint: [0u8; sd_backup::MAX_RAW_PAYLOAD],
            recovered_hint_len: 0,

            // fw_update_info: fw_update::FirmwareUpdate::empty(),
            // fw_update_verified: false,

            sign_msg_sig: [0u8; 64],
            sign_msg_hash: [0u8; 32],
            sign_msg_scan_hash: false,
            cr_hash: [0u8; 32],
            cr_ciphertext: alloc::vec::Vec::new(),
            cr_part_a: alloc::vec::Vec::new(),
            cr_part_b: alloc::vec::Vec::new(),

            brightness: DEFAULT_BRIGHTNESS,

            #[cfg(feature = "waveshare")]
            cam_tune_active: false,
            #[cfg(feature = "waveshare")]
            cam_tune_dirty: true,
            #[cfg(feature = "waveshare")]
            cam_tune_param: 0,
            #[cfg(feature = "waveshare")]
            // Waveshare cam-tune defaults. Shared by every sensor on this
            // board: OV5640 (cam_tune_apply_all), OV2640
            // (cam_tune_apply_ov2640). The array is one set of six slider
            // positions; each apply path maps them to its own registers.
            //
            // AEC=58/48: the reference targets from the OV5640 init table.
            // The datasheet defines average-based AEC as holding AVG
            // READOUT (0x56A1) between the low threshold (0x3A10) and the
            // high one (0x3A0F), while the fast zone halves exposure above
            // 0x3A11 and doubles it below 0x3A1F. The apply path writes
            // only the stable pair, leaving 0x3A11=0x80 and 0x3A1F=0x20
            // from init, so the ordering 0x3A1F <= low <= high <= 0x3A11
            // has to hold or the loop cannot converge. The previous 1A/00
            // put the stable high (26) BELOW the fast-zone low (32): the
            // fast rule kept doubling, the stable rule kept cutting back,
            // and the loop parked the frame near black (AVG=04 in the
            // field logs). rqrr then found no finder patterns, which armed
            // the 8-miss full-resolution escalation over and over.
            // CTR=38: above the 0x28 init baseline. QR content is binary,
            // so a stretched histogram helps the adaptive threshold, but
            // below the old 0x3E, which was compensating for darkness
            // rather than fixing it.
            // BRT=00: measured better than the 0x10 init value. Contrast
            // does the work.
            // AGC=F8: the init ceiling, raised from 0xB8 on purpose. R1
            // and R2 are unpopulated on this board, so the VCM has no
            // power and the lens cannot refocus; blur is permanent and
            // motion blur is the enemy. A higher gain ceiling lets AEC
            // reach target with a shorter exposure, and the box filter
            // that averages four pixels per 240x240 sample absorbs part
            // of the added noise.
            // SHP=50: slider position only. OV5640 ignores it (0x5302 is
            // locked to 0x30 in the apply path); OV2640 honors it.
            // [0]=AEC_H(0x3A0F) [1]=AEC_L(0x3A10) [2]=contrast(0x5586)
            // [3]=brightness(0x5587) [4]=AGC_ceil(0x3A19) [5]=sharpness
            cam_tune_vals: [0x58, 0x48, 0x38, 0x00, 0xF8, 0x50],

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
