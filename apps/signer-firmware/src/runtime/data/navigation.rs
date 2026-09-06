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

// runtime/data/navigation.rs — NavigationState

mod history;
mod production;
pub use production::ProductionNavigationState;
use history::NavigationHistory;


pub struct NavigationState {
    pub(crate) owner: crate::runtime::navigation::NavigationOwner,
    pub(crate) committed_state: crate::runtime::input::AppState,
    pub(crate) app: crate::runtime::input::WalletApp,
    pub(crate) history: NavigationHistory,
    pub seed_tools_menu: crate::runtime::input::Menu,
    pub import_menu: crate::runtime::input::Menu,
    pub single_sig_menu: crate::runtime::input::Menu,
    pub multisig_menu: crate::runtime::input::Menu,
    pub export_menu: crate::runtime::input::Menu,
    pub seed_backup_menu: crate::runtime::input::Menu,
    pub watch_only_menu: crate::runtime::input::Menu,
    pub signing_keys_menu: crate::runtime::input::Menu,
    pub qr_export_menu: crate::runtime::input::Menu,
    pub xprv_export_menu: crate::runtime::input::Menu,
    pub settings_menu: crate::runtime::input::Menu,
    pub production: ProductionNavigationState,
    #[cfg(feature = "workflow-tests")]
    pub(crate) workflow_tests_menu: crate::runtime::input::Menu,
    #[cfg(feature = "workflow-tests")]
    pub(crate) workflow_category_menu: crate::runtime::input::Menu,
    #[cfg(feature = "workflow-tests")]
    pub(crate) workflow_tests_return: crate::runtime::navigation::ContinuationRoute,
    pub sd_import_menu: crate::runtime::input::Menu,
}

impl NavigationState {
    pub(super) fn new() -> Self {
        debug_assert!(crate::runtime::navigation::ui_graph::validate_static_graph());
        Self {
            owner: crate::runtime::navigation::NavigationOwner::Main,
            committed_state: crate::runtime::input::AppState::MainMenu,
            app: crate::runtime::input::WalletApp::new(),
            history: NavigationHistory::new(),
            seed_tools_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::SEED_TOOLS_LABELS
            ),
            import_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::IMPORT_LABELS
            ),
            single_sig_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::SINGLE_SIG_LABELS
            ),
            multisig_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::MULTISIG_LABELS
            ),
            export_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::EXPORT_LABELS
            ),
            seed_backup_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::SEED_BACKUP_LABELS
            ),
            watch_only_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::WATCH_ONLY_LABELS
            ),
            signing_keys_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::SIGNING_KEYS_LABELS
            ),
            qr_export_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::QR_EXPORT_LABELS
            ),
            xprv_export_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::XPRV_EXPORT_LABELS
            ),
            settings_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::production::SETTINGS_ITEMS
            ),
            production: ProductionNavigationState::new(),
            sd_import_menu: crate::runtime::input::Menu::from_items(
                crate::runtime::navigation::ui_graph::SD_IMPORT_LABELS
            ),
            #[cfg(feature = "workflow-tests")]
            workflow_tests_menu: crate::runtime::input::Menu::from_items(
                &crate::runtime::workflow_tests::category_labels()
            ),
            #[cfg(feature = "workflow-tests")]
            workflow_category_menu: crate::runtime::input::Menu::new(),
            #[cfg(feature = "workflow-tests")]
            workflow_tests_return: crate::runtime::navigation::continuation!(DeveloperMenu),
        }
    }
}
