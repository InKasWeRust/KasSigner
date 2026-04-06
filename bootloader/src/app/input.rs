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

// app/input.rs — Input handling, Menu, AppState machine, HandlerGroup
// 100% Rust, no-std, no-alloc
//
// Single-button navigation system:
//
//   SHORT PRESS = Move cursor to next option
//   LONG PRESS  = Select / Execute current option
//
// Works with any menu or screen type:
//   - Main menu (New Wallet, Import, Send demo...)
//   - Transaction review (pages)
//   - Confirmation (OK / Cancel)
//   - PIN entry (future)
//
// The PIR (GPIO17) is used as an optional back/cancel button.


use esp_hal::gpio::Input;

// ═══════════════════════════════════════════════════════════════════
// ██  CONFIGURABLE PARAMETERS  ██
// ═══════════════════════════════════════════════════════════════════
//
// ─── BOOT BUTTON (GPIO0) ───────────────────────────────────────

/// BOOT button debounce (ms). Range: 30-80
pub const BOOT_DEBOUNCE_MS: u32 = 50;

/// BOOT button short/long press threshold (ms).
/// < this value = ShortPress (move cursor)
/// >= this value = LongPress (select)
/// Range: 600-1200
pub const BOOT_LONG_PRESS_MS: u32 = 800;

// ─── PIR SENSOR (GPIO17) ──────────────────────────────────────

/// PIR debounce (ms). Values: 100(sensitive) 500(medium) 1500(slow)
pub const PIR_DEBOUNCE_MS: u32 = 500;

/// Long press PIR (ms). Range: 1500-3000
pub const PIR_LONG_PRESS_MS: u32 = 2000;

/// PIR cooldown (ms). Values: 500(fast) 1000(normal) 2000(slow)
pub const PIR_COOLDOWN_MS: u32 = 1000;

// ═══════════════════════════════════════════════════════════════════
// Button Events
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq)]
/// Physical button events (short press, long press, none).
pub enum ButtonEvent {
    ShortPress,
    LongPress,
    None,
}

// ═══════════════════════════════════════════════════════════════════
// Button with configurable debounce
// ═══════════════════════════════════════════════════════════════════

/// Debounced button state machine with hold detection.
pub struct Button {
    was_pressed: bool,
    press_start: u32,
    last_event: u32,
    time_ms: u32,
    pending_press: bool,
    debounce_ms: u32,
    long_press_ms: u32,
    cooldown_ms: u32,
}

impl Button {
    pub fn new() -> Self {
        Self {
            was_pressed: false,
            press_start: 0,
            last_event: 0,
            time_ms: 0,
            pending_press: false,
            debounce_ms: BOOT_DEBOUNCE_MS,
            long_press_ms: BOOT_LONG_PRESS_MS,
            cooldown_ms: 0,
        }
    }

        /// Create a PIR-optimized Button with longer thresholds.
pub fn new_pir() -> Self {
        Self {
            was_pressed: false,
            press_start: 0,
            last_event: 0,
            time_ms: 0,
            pending_press: false,
            debounce_ms: PIR_DEBOUNCE_MS,
            long_press_ms: PIR_LONG_PRESS_MS,
            cooldown_ms: PIR_COOLDOWN_MS,
        }
    }

        /// Update button state and return any triggered event.
pub fn update(&mut self, active: bool, elapsed_ms: u32) -> ButtonEvent {
        self.time_ms = self.time_ms.wrapping_add(elapsed_ms);

        if self.cooldown_ms > 0 && self.last_event > 0 {
            let since_last = self.time_ms.wrapping_sub(self.last_event);
            if since_last < self.cooldown_ms {
                self.was_pressed = active;
                self.pending_press = false;
                return ButtonEvent::None;
            }
        }

        if active && !self.was_pressed {
            self.press_start = self.time_ms;
            self.pending_press = true;
            self.was_pressed = true;
        } else if !active && self.was_pressed {
            self.was_pressed = false;
            if self.pending_press {
                self.pending_press = false;
                let duration = self.time_ms.wrapping_sub(self.press_start);
                if duration >= self.long_press_ms {
                    self.last_event = self.time_ms;
                    return ButtonEvent::LongPress;
                } else if duration >= self.debounce_ms {
                    self.last_event = self.time_ms;
                    return ButtonEvent::ShortPress;
                }
            }
        }

        ButtonEvent::None
    }
}

// ═══════════════════════════════════════════════════════════════════
// Generic Menu System
// ═══════════════════════════════════════════════════════════════════

/// Maximum menu items
pub const MAX_MENU_ITEMS: usize = 16;

/// A menu with up to 16 items, page-scrolled with L/R strip arrows
pub struct Menu {
    /// Number of active items
    pub count: u8,
    /// Currently highlighted item (cursor position)
    pub cursor: u8,
    /// Scroll offset (first visible item index, always a multiple of MAX_VISIBLE)
    pub scroll: u8,
    /// Item labels (static strings)
    pub items: [&'static str; MAX_MENU_ITEMS],
}

impl Menu {
    /// Create a new empty menu
    pub const fn new() -> Self {
        Self {
            count: 0,
            cursor: 0,
            scroll: 0,
            items: [""; MAX_MENU_ITEMS],
        }
    }

    /// Create menu from a slice of labels
    pub fn from_items(labels: &[&'static str]) -> Self {
        let mut menu = Self::new();
        let n = labels.len().min(MAX_MENU_ITEMS);
        for i in 0..n {
            menu.items[i] = labels[i];
        }
        menu.count = n as u8;
        menu
    }

    /// Handle button event.
    /// ShortPress = move cursor to next item (wraps around)
    /// LongPress = select current item
    /// Returns: Some(selected_index) on LongPress, None otherwise
    pub fn handle(&mut self, event: ButtonEvent) -> Option<u8> {
        match event {
            ButtonEvent::ShortPress => {
                if self.count > 0 {
                    self.cursor = (self.cursor + 1) % self.count;
                }
                None // cursor moved, no selection
            }
            ButtonEvent::LongPress => {
                Some(self.cursor) // item selected!
            }
            ButtonEvent::None => None,
        }
    }

    /// Move cursor backward (for PIR/back button)
    pub fn prev(&mut self) {
        if self.count > 0 {
            if self.cursor == 0 {
                self.cursor = self.count - 1;
            } else {
                self.cursor -= 1;
            }
        }
    }

    /// Reset cursor and scroll to first item
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.scroll = 0;
    }

    /// Maximum visible rows per page (4 rows)
    pub const MAX_VISIBLE: u8 = 4;

    /// Page up: scroll back by one full page (MAX_VISIBLE rows).
    /// Returns true if scroll changed.
    pub fn page_up(&mut self) -> bool {
        if self.scroll > 0 {
            if self.scroll >= Self::MAX_VISIBLE {
                self.scroll -= Self::MAX_VISIBLE;
            } else {
                self.scroll = 0;
            }
            true
        } else {
            false
        }
    }

    /// Page down: scroll forward by one full page (MAX_VISIBLE rows).
    /// Scroll always lands on page boundaries (multiples of MAX_VISIBLE).
    /// Returns true if scroll changed.
    pub fn page_down(&mut self) -> bool {
        if self.count <= Self::MAX_VISIBLE {
            return false;
        }
        let next = self.scroll + Self::MAX_VISIBLE;
        if next < self.count {
            // There are items to show on the next page
            self.scroll = next;
            true
        } else {
            false
        }
    }

    /// Can page up? (not on first page)
    pub fn can_page_up(&self) -> bool {
        self.scroll > 0
    }

    /// Can page down? (there is a next page with items)
    pub fn can_page_down(&self) -> bool {
        self.count > Self::MAX_VISIBLE && (self.scroll + Self::MAX_VISIBLE) < self.count
    }

    /// Total number of pages
    pub fn total_pages(&self) -> u8 {
        if self.count == 0 { return 1; }
        (self.count + Self::MAX_VISIBLE - 1) / Self::MAX_VISIBLE
    }

    /// Current page (0-based)
    pub fn current_page(&self) -> u8 {
        self.scroll / Self::MAX_VISIBLE
    }

    /// Convert a visible slot index (0..MAX_VISIBLE) to absolute item index
    pub fn visible_to_absolute(&self, visible_idx: u8) -> u8 {
        self.scroll + visible_idx
    }
}

// ═══════════════════════════════════════════════════════════════════
// Application State Machine
// ═══════════════════════════════════════════════════════════════════

/// Main menu items
pub const MAIN_MENU_ITEMS: &[&str] = &[
    "Scan QR",
    "Seeds",
    "Tools",
    "Settings",
];

/// Confirm menu (used in TX review confirm page)
pub const CONFIRM_MENU_ITEMS: &[&str] = &[
    "Confirm",
    "Cancel",
];

/// Main application states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppState {
    /// Main menu (2x2 grid: Scan QR, Seeds, Tools, Settings)
    MainMenu,
    /// Scan QR: waiting for camera/QR input
    ScanQR,
    /// Seeds sub-menu
    SeedsMenu,
    /// View loaded seed info
    ViewSeed,
    /// Seed backup (show words)
    SeedBackup { word_idx: u8 },
    /// Tools sub-menu
    ToolsMenu,
    /// Settings sub-menu (Display / Audio / About)
    SettingsMenu,
    /// Display settings (brightness)
    DisplaySettings,
    /// Audio settings (volume) — M5Stack only (Waveshare has no speaker)
    AudioSettings,
    /// SD Card settings (format, info)
    SdCardSettings,
    /// About screen
    About,
    /// Reviewing a transaction (page by page)
    ReviewTx { page: u8 },
    /// Confirm page with OK/Cancel selection
    ConfirmTx,
    /// Sign TX guide — step-by-step instructions before scanning KSPT
    SignTxGuide,
    /// Sign Message — choose how to enter message (type / load TXT)
    SignMsgChoice,
    /// Sign Message — type message via keyboard
    SignMsgType,
    /// Sign Message — pick .TXT file from SD
    SignMsgFile,
    /// Sign Message — preview message + confirm sign
    SignMsgPreview,
    /// Sign Message — show signature result (hex + QR)
    SignMsgResult,
    /// Icon browser test screen (feature: icon-browser)
    #[cfg(feature = "icon-browser")]
    IconBrowser { page: u16 },
    /// Signing in progress
    Signing { input_idx: u8 },
    /// Showing signed QR code
    ShowQR,
    /// Transaction was rejected
    Rejected,
    /// Show address screen
    ShowAddress,
    /// Dice roll entropy collection
    DiceRoll,
    /// Show address as QR code
    ShowAddressQR,
    /// Import seed words one by one
    ImportWord { word_idx: u8, word_count: u8 },
    /// Calculate last word (enter 11 or 23, auto-compute)
    CalcLastWord { word_idx: u8, word_count: u8 },
    /// Choose word count (12 or 24) before an action
    /// action: 0=TRNG, 1=Dice, 2=Import, 3=CalcLastWord
    ChooseWordCount { action: u8 },
    /// Passphrase entry after seed creation/import
    PassphraseEntry,
    /// Export active seed as SeedQR
    ExportSeedQR,
    /// QR Export sub-menu (Compact, Standard, Plain Words)
    QrExportMenu,
    /// xprv export submenu: "Show as QR" / "Encrypt to SD"
    XprvExportMenu,
    /// Export plain BIP39 words as text QR code
    ExportPlainWordsQR,
    /// Export account-level kpub as QR for watch-only wallet import
    ExportKpub,
    /// Seed list — show all slots, tap to activate or manage
    SeedList,
    /// Confirm seed deletion — warning screen before erasing a slot
    ConfirmDeleteSeed,
    /// BIP85 index entry (choose child index 0-99)
    Bip85Index { word_count: u8 },
    /// BIP85 deriving in progress
    Bip85Deriving,
    /// BIP85 show child mnemonic word-by-word
    Bip85ShowWord { word_idx: u8, word_count: u8 },
    /// Address index picker (select index 0-19 with +/- and GO)
    AddrIndexPicker,
    /// Import raw private key via hex keypad
    ImportPrivKey,
    /// Export private key as hex (show on screen / QR)
    ExportPrivKey,
    /// Choose export format: kpub QR or xprv QR
    ExportChoice,
    /// Show xprv as QR code
    ExportXprv,
    /// Show compact seed QR (21x21 / 25x25)
    ExportCompactSeedQR,
    /// Zoomed grid view of SeedQR for manual card filling
    SeedQrGrid { pan_x: u8, pan_y: u8, compact: bool },
    /// SD backup: security warning before passphrase entry
    SdBackupWarning,
    /// SD backup: enter passphrase for encryption
    SdBackupPassphrase,
    /// SD backup: encrypting and writing
    SdBackupWriting,
    /// SD restore: list .KAS files on SD, user picks one
    SdFileList,
    /// SD restore: enter passphrase for decryption
    SdRestorePassphrase,
    /// SD restore: decrypting and loading
    SdRestoreReading,
    /// SD backup: confirm deletion of selected file
    SdDeleteConfirm,
    /// SD xprv export: enter passphrase for encryption
    SdXprvExportPassphrase,
    /// SD xprv import: list XP* files
    SdXprvFileList,
    /// SD xprv import: enter passphrase for decryption
    SdXprvImportPassphrase,
    /// Multisig: choose M-of-N
    MultisigChooseMN,
    /// Multisig: pick which seed to use for this key
    MultisigPickSeed { key_idx: u8 },
    /// Multisig: pick which address index from the selected seed
    MultisigPickAddr { key_idx: u8 },
    /// Multisig: scan/add pubkey (which key index 0..N-1 we're collecting)
    MultisigAddKey { key_idx: u8 },
    /// Multisig: show the created multisig address as QR
    MultisigShowAddress,
    /// Multisig: show QR of multisig address
    MultisigShowAddressQR,
    /// Multisig: show wallet descriptor text (multi(M, pk1, pk2, ...))
    MultisigDescriptor,
    /// Multisig: show QR of wallet descriptor

    /// Steganography: select mode (list of 6 modes)
    StegoModeSelect,
    /// Steganography: processing embed (mode stored externally)
    StegoEmbed,
    /// Steganography: show result (QR or "saved" message)
    StegoResult,
    /// JPEG stego: file picker (list JPGs on SD)
    StegoJpegPick,
    /// JPEG stego: choose descriptor input method (type / load from SD)
    StegoJpegDescChoice,
    /// JPEG stego: pick .TXT file from SD for descriptor
    StegoJpegDescFile,
    /// JPEG stego: enter description text (IMAGE DESCRIPTOR)
    StegoJpegDesc,
    /// JPEG stego: preview loaded .TXT content with strength indicator
    StegoJpegDescPreview,
    /// JPEG stego: ask user if they want to hide a recovery hint
    StegoJpegPpAsk,
    /// JPEG stego: info screen explaining recovery hint
    StegoJpegPpInfo,
    /// JPEG stego: enter recovery hint text
    StegoJpegPpEntry,
    /// JPEG stego: confirm overwrite warning
    StegoJpegConfirm,
    /// Stego import: pick JPEG file from SD
    StegoImportPick,
    /// Stego import: choose how to enter descriptor (type / load from SD)
    StegoImportDescChoice,
    /// Stego import: pick .TXT file from SD for descriptor
    StegoImportDescFile,
    /// Stego import: enter passphrase to decode
    StegoImportPass,
    /// Stego import: hint revealed, tap to continue to passphrase entry
    StegoHintReveal,
    /// Stego import: enter passphrase after seeing hint
    StegoHintPassphrase,
    /// Firmware update: verification result screen
    FwUpdateResult,
    /// SD import: submenu (Seed Backup, Transaction, future KRC20/721...)
    SdImportMenu,
    /// SD KSPT: list .KSP files on SD to load
    SdKsptFileList,
    /// ShowQR popup: Save to SD / Back to QR / header back = menu
    ShowQrPopup,
    /// SD KSPT: keyboard for naming the .KSP file before save
    SdKsptFilename,
    /// SD KSPT: ask user whether to encrypt the file
    SdKsptEncryptAsk,
    /// SD KSPT: password keyboard for encrypting .KSP file
    SdKsptEncryptPass,
    /// QR display mode choice: Auto Cycle / Manual (tap to advance)
    ShowQrModeChoice,
}

/// Result of handling a button event
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    /// Nothing happened
    None,
    /// Display needs redraw (cursor moved, state changed, etc)
    Redraw,
    /// Main menu: "Send Demo TX" was selected — caller must call start_review()
    StartDemoTx,
}

/// Wallet application controller
pub struct WalletApp {
    pub state: AppState,
    /// Menu for current screen
    pub menu: Menu,
    /// Total review pages (summary + outputs, NOT including confirm)
    pub review_pages: u8,
    /// Total inputs to sign
    pub total_inputs: u8,
}

impl WalletApp {
        /// Create a new WalletApp in MainMenu state.
pub fn new() -> Self {
        Self {
            state: AppState::MainMenu,
            menu: Menu::from_items(MAIN_MENU_ITEMS),
            review_pages: 0,
            total_inputs: 0,
        }
    }

    /// Handle BOOT button (short=move cursor, long=select)
    /// Returns an Action telling the caller what happened
    pub fn handle_boot(&mut self, event: ButtonEvent) -> Action {
        if event == ButtonEvent::None {
            return Action::None;
        }

        match self.state {
            AppState::MainMenu => {
                if let Some(selected) = self.menu.handle(event) {
                    match selected {
                        0 => {
                            self.state = AppState::ScanQR;
                            return Action::Redraw;
                        }
                        1 => {
                            self.state = AppState::SeedsMenu;
                            return Action::Redraw;
                        }
                        2 => {
                            self.state = AppState::ToolsMenu;
                            return Action::Redraw;
                        }
                        3 => {
                            self.state = AppState::SettingsMenu;
                            return Action::Redraw;
                        }
                        _ => {}
                    }
                }
                Action::Redraw // cursor moved
            }

            AppState::ReviewTx { page } => {
                match event {
                    ButtonEvent::ShortPress => {
                        let next = page + 1;
                        if next < self.review_pages {
                            self.state = AppState::ReviewTx { page: next };
                        } else {
                            self.menu = Menu::from_items(CONFIRM_MENU_ITEMS);
                            self.state = AppState::ConfirmTx;
                        }
                        Action::Redraw
                    }
                    ButtonEvent::LongPress => {
                        self.menu = Menu::from_items(CONFIRM_MENU_ITEMS);
                        self.state = AppState::ConfirmTx;
                        Action::Redraw
                    }
                    _ => Action::None,
                }
            }

            AppState::ConfirmTx => {
                if let Some(selected) = self.menu.handle(event) {
                    match selected {
                        0 => {
                            self.state = AppState::Signing { input_idx: 0 };
                        }
                        1 => {
                            self.state = AppState::Rejected;
                        }
                        _ => {}
                    }
                }
                Action::Redraw
            }

            AppState::Signing { .. } => Action::None,

            // Confirm delete: back returns to seed list
            AppState::ConfirmDeleteSeed => {
                if event == ButtonEvent::ShortPress || event == ButtonEvent::LongPress {
                    self.state = AppState::SeedList;
                    return Action::Redraw;
                }
                Action::None
            }

            // All sub-screens: any tap goes back to main
            AppState::ShowQR | AppState::Rejected | AppState::About
            | AppState::ShowAddress | AppState::ShowAddressQR | AppState::ScanQR
            | AppState::ViewSeed | AppState::SeedBackup { .. }
            | AppState::DiceRoll | AppState::ImportWord { .. }
            | AppState::CalcLastWord { .. } | AppState::ChooseWordCount { .. }
            | AppState::PassphraseEntry | AppState::ExportSeedQR | AppState::ExportKpub
            | AppState::SeedList | AppState::DisplaySettings
            | AppState::AudioSettings | AppState::SdCardSettings
            | AppState::SignTxGuide
            | AppState::SignMsgChoice | AppState::SignMsgType | AppState::SignMsgFile
            | AppState::SignMsgPreview | AppState::SignMsgResult
            | AppState::QrExportMenu | AppState::XprvExportMenu | AppState::ExportPlainWordsQR => {
                if event == ButtonEvent::ShortPress || event == ButtonEvent::LongPress {
                    self.go_main_menu();
                    return Action::Redraw;
                }
                Action::None
            }

            // Sub-menus handled by main.rs touch directly
            AppState::SeedsMenu | AppState::ToolsMenu | AppState::SettingsMenu
            | AppState::Bip85Index { .. } | AppState::Bip85Deriving
            | AppState::Bip85ShowWord { .. } | AppState::AddrIndexPicker
            | AppState::ImportPrivKey | AppState::ExportPrivKey
            | AppState::ExportChoice | AppState::ExportXprv
            | AppState::ExportCompactSeedQR
            | AppState::SeedQrGrid { .. }
            | AppState::SdBackupWarning | AppState::SdBackupPassphrase | AppState::SdBackupWriting
            | AppState::SdFileList | AppState::SdRestorePassphrase | AppState::SdRestoreReading
            | AppState::SdDeleteConfirm
            | AppState::SdXprvExportPassphrase | AppState::SdXprvFileList | AppState::SdXprvImportPassphrase
            | AppState::SdImportMenu | AppState::SdKsptFileList
            | AppState::ShowQrPopup | AppState::SdKsptFilename
            | AppState::SdKsptEncryptAsk | AppState::SdKsptEncryptPass
            | AppState::ShowQrModeChoice
            | AppState::MultisigChooseMN | AppState::MultisigPickSeed { .. }
            | AppState::MultisigPickAddr { .. }
            | AppState::MultisigAddKey { .. } | AppState::MultisigShowAddress
            | AppState::MultisigShowAddressQR
            | AppState::MultisigDescriptor
            | AppState::StegoModeSelect | AppState::StegoEmbed | AppState::StegoResult
            | AppState::StegoJpegPick | AppState::StegoJpegDescChoice | AppState::StegoJpegDescFile
            | AppState::StegoJpegDesc | AppState::StegoJpegDescPreview | AppState::StegoJpegConfirm
            | AppState::StegoJpegPpAsk | AppState::StegoJpegPpInfo | AppState::StegoJpegPpEntry
            | AppState::StegoImportPick | AppState::StegoImportDescChoice
            | AppState::StegoImportDescFile | AppState::StegoImportPass
            | AppState::StegoHintReveal | AppState::StegoHintPassphrase
            | AppState::FwUpdateResult
            => {
                Action::None
            }
            #[cfg(feature = "icon-browser")]
            AppState::IconBrowser { .. } => {
                Action::None
            }
        }
    }
    /// Start reviewing a transaction
    pub fn start_review(&mut self, num_outputs: u8, num_inputs: u8) {
        // review_pages = 1 summary + num_outputs (confirm is separate state)
        self.review_pages = 1 + num_outputs;
        self.total_inputs = num_inputs;
        self.state = AppState::ReviewTx { page: 0 };
    }

    /// Advance signing progress
    pub fn advance_signing(&mut self) -> bool {
        if let AppState::Signing { input_idx } = self.state {
            let next = input_idx + 1;
            if next >= self.total_inputs {
                self.state = AppState::ShowQR;
                true
            } else {
                self.state = AppState::Signing { input_idx: next };
                true
            }
        } else {
            false
        }
    }

    /// Return to main menu
    pub fn go_main_menu(&mut self) {
        self.menu = Menu::from_items(MAIN_MENU_ITEMS);
        self.state = AppState::MainMenu;
    }
}

// ═══════════════════════════════════════════════════════════════════
// GPIO helpers
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
// Self-tests
// ═══════════════════════════════════════════════════════════════════

/// Run input subsystem tests. Returns (passed, total).
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    // Test 1: BOOT short press
    {
        let mut btn = Button::new();
        let _ = btn.update(false, 100);
        let _ = btn.update(true, 100);
        let _ = btn.update(true, 100);
        let e = btn.update(false, 20);
        if e == ButtonEvent::ShortPress { passed += 1; }
    }

    // Test 2: BOOT long press
    {
        let mut btn = Button::new();
        let _ = btn.update(true, 100);
        let _ = btn.update(true, 400);
        let _ = btn.update(true, 400);
        let e = btn.update(false, 20);
        if e == ButtonEvent::LongPress { passed += 1; }
    }

    // Test 3: PIR short noise rejected
    {
        let mut btn = Button::new_pir();
        let _ = btn.update(true, 50);
        let _ = btn.update(true, 50);
        let e = btn.update(false, 20);
        if e == ButtonEvent::None { passed += 1; }
    }

    // Test 4: Menu navigation — short=move, long=select
    {
        let mut menu = Menu::from_items(&["Alpha", "Beta", "Gamma"]);
        // Initial cursor = 0
        let r1 = menu.handle(ButtonEvent::ShortPress); // cursor → 1
        let ok1 = r1.is_none() && menu.cursor == 1;

        let r2 = menu.handle(ButtonEvent::ShortPress); // cursor → 2
        let ok2 = r2.is_none() && menu.cursor == 2;

        let r3 = menu.handle(ButtonEvent::ShortPress); // cursor → 0 (wrap)
        let ok3 = r3.is_none() && menu.cursor == 0;

        let r4 = menu.handle(ButtonEvent::LongPress);  // select item 0
        let ok4 = r4 == Some(0);

        if ok1 && ok2 && ok3 && ok4 { passed += 1; }
    }

    // Test 5: App flow — main menu → ScanQR, then review → confirm → sign → QR → menu
    {
        let mut app = WalletApp::new();

        // Select item 0 (Scan QR) — goes to ScanQR state
        let action = app.handle_boot(ButtonEvent::LongPress);
        let ok0 = app.state == AppState::ScanQR && action == Action::Redraw;

        // Go back to main menu, then test review flow
        app.go_main_menu();
        app.start_review(2, 1);
        let ok1 = app.state == AppState::ReviewTx { page: 0 };

        // Navigate pages: summary(0) → out0(1) → out1(2)
        app.handle_boot(ButtonEvent::ShortPress); // page 1
        app.handle_boot(ButtonEvent::ShortPress); // page 2
        let ok2 = app.state == AppState::ReviewTx { page: 2 };

        // Next page after last output → ConfirmTx
        app.handle_boot(ButtonEvent::ShortPress);
        let ok3 = app.state == AppState::ConfirmTx;

        // Cursor on "Confirm" (0), long press = select → Signing
        app.handle_boot(ButtonEvent::LongPress);
        let ok4 = matches!(app.state, AppState::Signing { .. });

        // Sign → QR → back to menu
        app.advance_signing();
        let ok5 = app.state == AppState::ShowQR;

        app.handle_boot(ButtonEvent::ShortPress);
        let ok6 = app.state == AppState::MainMenu;

        if ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && ok6 { passed += 1; }
    }

    (passed, total)
}

// ─── Handler group dispatch ──────────────────────────────────────────
//
// Maps each AppState to the handler module responsible for its touch events.
// Used by main.rs to route taps without listing every variant inline.

#[derive(Debug, Clone, Copy, PartialEq)]
/// Groups AppState variants by their touch handler module.
pub enum HandlerGroup {
    Menu,
    Stego,
    Sd,
    Seed,
    Export,
    Settings,
    Tx,
    /// No touch handler — state is transient or handled elsewhere
    None,
}

impl AppState {
        /// Map this AppState to its responsible handler module.
pub fn handler_group(&self) -> HandlerGroup {
        use AppState::*;
        match self {
            // Menu screens
            MainMenu | SeedsMenu | ToolsMenu | DiceRoll
            | ChooseWordCount { .. } | ShowQR | Rejected | ViewSeed
                => HandlerGroup::Menu,

            // Steganography flow
            StegoModeSelect | StegoEmbed | StegoResult | StegoJpegPick
            | StegoJpegDescChoice | StegoJpegDescFile | StegoJpegDesc
            | StegoJpegDescPreview | StegoJpegPpAsk | StegoJpegPpInfo
            | StegoJpegPpEntry | StegoJpegConfirm | StegoImportPick
            | StegoImportDescChoice | StegoImportDescFile
            | StegoImportPass | StegoHintReveal | StegoHintPassphrase
            | FwUpdateResult
                => HandlerGroup::Stego,

            // SD backup/restore
            SdBackupWarning | SdBackupPassphrase | SdFileList
            | SdRestorePassphrase | SdDeleteConfirm | SdXprvExportPassphrase
            | SdXprvFileList | SdXprvImportPassphrase
            | SdImportMenu | SdKsptFileList
            | ShowQrPopup | SdKsptFilename
            | SdKsptEncryptAsk | SdKsptEncryptPass
            | ShowQrModeChoice
                => HandlerGroup::Sd,

            // Seed management
            Bip85Index { .. } | Bip85ShowWord { .. } | Bip85Deriving
            | ImportPrivKey | ImportWord { .. } | CalcLastWord { .. }
            | PassphraseEntry | SeedList | ConfirmDeleteSeed
                => HandlerGroup::Seed,

            // Export/display
            SeedBackup { .. } | ShowAddress | ShowAddressQR | AddrIndexPicker
            | ExportSeedQR | ExportCompactSeedQR | SeedQrGrid { .. }
            | QrExportMenu | XprvExportMenu | ExportPlainWordsQR
            | ExportKpub | ExportXprv | ExportChoice | ExportPrivKey
                => HandlerGroup::Export,

            // Settings
            SettingsMenu | DisplaySettings
            | AudioSettings | SdCardSettings | About
                => HandlerGroup::Settings,
            // Transaction / multisig / camera / message signing
            ScanQR | ReviewTx { .. } | ConfirmTx | SignTxGuide
            | MultisigChooseMN | MultisigPickSeed { .. } | MultisigPickAddr { .. }
            | MultisigAddKey { .. } | MultisigShowAddress | MultisigShowAddressQR
            | MultisigDescriptor
            | SignMsgChoice | SignMsgType | SignMsgFile | SignMsgPreview | SignMsgResult
                => HandlerGroup::Tx,

            // Transient states handled by signing pipeline, not touch
            Signing { .. } | SdBackupWriting | SdRestoreReading
                => HandlerGroup::None,

            // Icon browser — handled by menu handler
            #[cfg(feature = "icon-browser")]
            IconBrowser { .. } => HandlerGroup::Menu,
        }
    }
}