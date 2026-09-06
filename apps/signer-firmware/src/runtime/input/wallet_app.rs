// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Wallet navigation controller for physical-button input.

#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
use super::button::ButtonEvent;
use super::menu::Menu;
use super::state::{AppState, MAIN_MENU_ITEMS};
#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
use super::state::CONFIRM_MENU_ITEMS;

/// Result of handling a button event
#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    /// Nothing happened
    None,
    /// Display needs redraw (cursor moved, state changed, etc)
    Redraw,
}

/// Wallet application controller
pub struct WalletApp {
    pub(crate) state: AppState,
    /// Menu for current screen
    pub menu: Menu,
    /// Total review pages (summary + outputs, NOT including confirm)
    pub review_pages: u8,
    /// Total inputs to sign
    pub total_inputs: usize,
    /// Set only after the explicit transaction confirmation action.
    pub review_authorized: bool,
    /// Host-model operation cursor; production runtime stores this in PresentationState.
    signing_input_idx: Option<usize>,
}

impl WalletApp {
    /// Create a new WalletApp in MainMenu state.
    pub fn new() -> Self {
        Self {
            state: AppState::MainMenu,
            menu: Menu::from_items(MAIN_MENU_ITEMS),
            review_pages: 0,
            total_inputs: 0,
            review_authorized: false,
            signing_input_idx: None,
        }
    }

    /// Handle BOOT button (short=move cursor, long=select).
    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    pub fn handle_boot(&mut self, event: ButtonEvent) -> Action {
        if event == ButtonEvent::None {
            return Action::None;
        }

        if self.signing_input_idx.is_some() {
            return Action::None;
        }
        match self.state {
            AppState::MainMenu => self.handle_main_menu(event),
            AppState::ReviewTx { page } => self.handle_review_page(event, page),
            AppState::InspectUtxoSummary => self.handle_inspect_summary(event),
            AppState::InspectUtxo { index, address_page } => self.handle_inspect_input(event, index, address_page),
            AppState::ConfirmTx => self.handle_confirmation(event),
            AppState::ConfirmDeleteSeed => {
                self.return_on_press(event, AppState::SeedList)
            }
            #[cfg(feature = "waveshare")]
            AppState::CameraSettings => {
                self.return_on_press(event, AppState::SettingsMenu)
            }
            state if returns_to_main_on_press(state) => {
                if is_press(event) {
                    self.go_main_menu();
                    Action::Redraw
                } else {
                    Action::None
                }
            }
            _ => Action::None,
        }
    }

    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    fn handle_main_menu(&mut self, event: ButtonEvent) -> Action {
        if let Some(selected) = self.menu.handle(event) {
            self.state = match selected {
                0 => AppState::ShowAddress,
                1 => AppState::ScanQR,
                2 => AppState::SeedsMenu,
                3 => AppState::SettingsMenu,
                _ => return Action::Redraw,
            };
        }
        Action::Redraw
    }

    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    fn handle_review_page(&mut self, event: ButtonEvent, page: u8) -> Action {
        if !is_press(event) {
            return Action::None;
        }
        let next = page + 1;
        if next < self.review_pages {
            self.state = AppState::ReviewTx { page: next };
        } else {
            self.menu = Menu::from_items(CONFIRM_MENU_ITEMS);
            self.state = AppState::ConfirmTx;
        }
        Action::Redraw
    }

    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    fn handle_inspect_summary(&mut self, event: ButtonEvent) -> Action {
        if !is_press(event) { return Action::None; }
        self.state = if self.total_inputs == 0 {
            AppState::ReviewTx { page: 0 }
        } else {
            AppState::InspectUtxo { index: 0, address_page: false }
        };
        Action::Redraw
    }

    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    fn handle_inspect_input(&mut self, event: ButtonEvent, index: usize, address_page: bool) -> Action {
        if !is_press(event) { return Action::None; }
        if !address_page {
            self.state = AppState::InspectUtxo { index, address_page: true };
        } else if index + 1 < self.total_inputs {
            self.state = AppState::InspectUtxo { index: index + 1, address_page: false };
        } else {
            self.state = AppState::ReviewTx { page: 0 };
        }
        Action::Redraw
    }

    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    fn handle_confirmation(&mut self, event: ButtonEvent) -> Action {
        if let Some(selected) = self.menu.handle(event) {
            self.state = match selected {
                0 => {
                    self.review_authorized = true;
                    self.signing_input_idx = Some(0);
                    AppState::ConfirmTx
                }
                1 => {
                    self.review_authorized = false;
                    AppState::Rejected
                }
                2 => AppState::ReviewTx { page: 0 },
                _ => self.state,
            };
        }
        Action::Redraw
    }

    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    fn return_on_press(&mut self, event: ButtonEvent, state: AppState) -> Action {
        if is_press(event) {
            self.state = state;
            Action::Redraw
        } else {
            Action::None
        }
    }

    /// Start reviewing a transaction
    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    pub fn start_review(&mut self, num_outputs: u8, num_inputs: usize) {
        // review_pages = 1 summary + num_outputs (confirm is separate state)
        self.review_pages = 1 + num_outputs;
        self.total_inputs = num_inputs;
        self.review_authorized = false;
        self.menu = Menu::from_items(CONFIRM_MENU_ITEMS);
        self.state = AppState::ConfirmTx;
    }

    /// Advance signing progress
    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    pub fn advance_signing(&mut self) -> bool {
        let Some(input_idx) = self.signing_input_idx else { return false; };
        let next = input_idx + 1;
        if next >= self.total_inputs {
            self.review_authorized = false;
            self.signing_input_idx = None;
            self.state = AppState::ShowQR;
        } else {
            self.signing_input_idx = Some(next);
        }
        true
    }

    /// Reset main-menu presentation state without changing the screen.
    pub(crate) fn prepare_main_menu(&mut self) {
        self.menu = Menu::from_items(MAIN_MENU_ITEMS);
        self.review_authorized = false;
        self.signing_input_idx = None;
    }

    /// Host-test helper. Runtime AppData navigation uses the central state machine.
    #[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
    pub fn go_main_menu(&mut self) {
        self.prepare_main_menu();
        self.state = AppState::MainMenu;
    }
}

#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
fn is_press(event: ButtonEvent) -> bool {
    matches!(event, ButtonEvent::ShortPress | ButtonEvent::LongPress)
}

#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
fn returns_to_main_on_press(state: AppState) -> bool {
    match state {
        AppState::ShowQR
            | AppState::Rejected
            | AppState::About
            | AppState::ShowAddress
            | AppState::ShowAddressQR
            | AppState::ScanQR
            | AppState::SeedBackup { .. }
            | AppState::DiceRoll
            | AppState::ImportWord { .. }
            | AppState::CalcLastWord { .. }
            | AppState::ChooseWordCount { .. }
            | AppState::ExportSeedQR
            | AppState::ExportKpub
            | AppState::ExportKpubPopup
            | AppState::KpubScannedPopup
            | AppState::SeedList
            | AppState::DisplaySettings
            | AppState::SdCardSettings
            | AppState::SdCardUnlockPassword
            | AppState::SignTxGuide
            | AppState::SignMsgChoice
            | AppState::SignMsgType
            | AppState::SignMsgScan
            | AppState::SignMsgFile
            | AppState::SignMsgPreview
                        | AppState::SignMsgResult
            | AppState::SignMsgResultQr
            | AppState::CommitRevealType
            | AppState::CommitRevealPreview
            | AppState::CommitRevealResult
            | AppState::CommitRevealResultQr
            | AppState::DecryptSecretScan
            | AppState::DecryptSecretResult
            | AppState::DecryptSecretResultQr
            | AppState::QrExportMenu
            | AppState::XprvExportMenu
            | AppState::SeedBackupMenu
            | AppState::WatchOnlyMenu
            | AppState::SigningKeysMenu
            | AppState::ExportPlainWordsQR => true,
        #[cfg(feature = "m5stack")]
        AppState::AudioSettings => true,
        _ => false,
    }
}
