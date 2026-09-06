//! Hardware-free production intent menus.

use crate::{
    runtime::interactions::menu_selection::{handle_paged_menu_touch, PagedMenuAction},
    hw::touch::TouchZone,
    runtime::{data::AppData, input::{AppState, Menu}},
};

pub(super) fn handle(
    ad: &mut AppData,
    list: &[TouchZone; 4],
    page_up: &TouchZone,
    page_down: &TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::SeedsMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::Wallet)),
        AppState::WalletBackupMethodsMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::WalletBackupMethods)),
        AppState::WalletAdvancedMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::WalletAdvanced)),
        AppState::AdvancedMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::Advanced)),
        #[cfg(feature = "provisioning-ui")]
        AppState::OwnerFirmwareMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::OwnerFirmware)),
        AppState::BackupRecoveryMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::BackupRecovery)),
        #[cfg(feature = "developer-ui")]
        AppState::DeveloperMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::Developer)),
        #[cfg(feature = "developer-ui")]
        AppState::NetworkMenu => Some(handle_menu(ad, list, page_up, page_down, x, y, is_back, MenuKind::Network)),
        AppState::WalletDetails => Some(handle_wallet_details(ad, x, y, is_back)),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum MenuKind { Wallet, WalletBackupMethods, WalletAdvanced, Advanced, #[cfg(feature="provisioning-ui")] OwnerFirmware, BackupRecovery, #[cfg(feature="developer-ui")] Developer, #[cfg(feature="developer-ui")] Network }

fn handle_menu(
    ad: &mut AppData, list: &[TouchZone; 4], up: &TouchZone, down: &TouchZone,
    x: u16, y: u16, is_back: bool, kind: MenuKind,
) -> bool {
    if is_back { route_back(ad, kind); return true; }
    let action = {
        let menu = menu_mut(ad, kind);
        handle_paged_menu_touch(menu, list, up, down, x, y)
    };
    match action {
        PagedMenuAction::PageChanged => true,
        PagedMenuAction::Selected(item) => { route_item(ad, kind, usize::from(item)); true }
        PagedMenuAction::None => false,
    }
}

fn menu_mut(ad: &mut AppData, kind: MenuKind) -> &mut Menu {
    match kind {
        MenuKind::Wallet => &mut ad.navigation.production.wallet_menu,
        MenuKind::WalletBackupMethods => &mut ad.navigation.production.wallet_backup_methods_menu,
        MenuKind::WalletAdvanced => &mut ad.navigation.production.wallet_advanced_menu,
        MenuKind::Advanced => &mut ad.navigation.production.advanced_menu,
        #[cfg(feature="provisioning-ui")]
        MenuKind::OwnerFirmware => &mut ad.navigation.production.owner_firmware_menu,
        MenuKind::BackupRecovery => &mut ad.navigation.production.backup_recovery_menu,
        #[cfg(feature="developer-ui")]
        MenuKind::Developer => &mut ad.navigation.production.developer_menu,
        #[cfg(feature="developer-ui")]
        MenuKind::Network => &mut ad.navigation.production.network_menu,
    }
}

fn route_back(ad: &mut AppData, kind: MenuKind) {
    menu_mut(ad, kind).reset();
    match kind {
        MenuKind::Wallet => crate::runtime::effects::home(ad),
        MenuKind::WalletBackupMethods => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(SeedsMenu),
            );
        }
        MenuKind::WalletAdvanced => {
            let _ = crate::runtime::effects::back(ad);
        }
        MenuKind::Advanced => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(SettingsMenu),
            );
        }
        #[cfg(feature="provisioning-ui")]
        MenuKind::OwnerFirmware => {
            ad.pop_it.error = None;
            let _ = crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedMenu));
        }
        MenuKind::BackupRecovery => {
            let _ = crate::runtime::effects::back(ad);
        }
        #[cfg(feature = "developer-ui")]
        MenuKind::Developer => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(SettingsMenu),
            );
        }
        #[cfg(feature = "developer-ui")]
        MenuKind::Network => {
            let _ = crate::runtime::effects::route(
                ad,
                crate::runtime::navigation::route!(DeveloperMenu),
            );
        }
    }
}

fn route_item(ad: &mut AppData, kind: MenuKind, item: usize) {
    match kind {
        MenuKind::Wallet => route_wallet(ad, item),
        MenuKind::WalletBackupMethods => route_wallet_backup_methods(ad, item),
        MenuKind::WalletAdvanced => route_wallet_advanced(ad, item),
        MenuKind::Advanced => route_advanced(ad, item),
        #[cfg(feature="provisioning-ui")]
        MenuKind::OwnerFirmware => route_owner_firmware(ad, item),
        MenuKind::BackupRecovery => route_backup_recovery(ad, item),
        #[cfg(feature="developer-ui")]
        MenuKind::Developer => route_developer(ad, item),
        #[cfg(feature="developer-ui")]
        MenuKind::Network => route_network(ad, item),
    }
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_wallet_select(ad: &mut AppData, item: usize) -> bool {
    if !matches!(ad.navigation.app.state, AppState::SeedsMenu)
        || item >= usize::from(ad.navigation.production.wallet_menu.count)
    {
        return false;
    }
    route_wallet(ad, item);
    crate::runtime::navigation::reconcile(ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_wallet_details_edit(ad: &mut AppData) -> bool {
    handle_wallet_details(ad, 160, 169, false)
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_wallet_details_delete(ad: &mut AppData) -> bool {
    handle_wallet_details(ad, 160, 207, false)
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_wallet_backup_methods_select(ad: &mut AppData, item: usize) -> bool {
    if !matches!(ad.navigation.app.state, AppState::WalletBackupMethodsMenu)
        || item >= usize::from(ad.navigation.production.wallet_backup_methods_menu.count)
    {
        return false;
    }
    route_wallet_backup_methods(ad, item);
    crate::runtime::navigation::reconcile(ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_advanced_select(ad: &mut AppData, item: usize) -> bool {
    if !matches!(ad.navigation.app.state, AppState::AdvancedMenu)
        || item >= usize::from(ad.navigation.production.advanced_menu.count)
    {
        return false;
    }
    route_advanced(ad, item);
    crate::runtime::navigation::reconcile(ad)
}

#[cfg(all(feature = "workflow-test-auto", feature = "provisioning-ui"))]
pub(super) fn workflow_owner_firmware_select(ad: &mut AppData, item: usize) -> bool {
    if !matches!(ad.navigation.app.state, AppState::OwnerFirmwareMenu)
        || item >= usize::from(ad.navigation.production.owner_firmware_menu.count)
    {
        return false;
    }
    route_owner_firmware(ad, item);
    crate::runtime::navigation::reconcile(ad)
}

#[cfg(all(feature = "workflow-test-auto", feature = "provisioning-ui"))]
pub(super) fn workflow_owner_firmware_back(ad: &mut AppData) -> bool {
    if !matches!(ad.navigation.app.state, AppState::OwnerFirmwareMenu) {
        return false;
    }
    route_back(ad, MenuKind::OwnerFirmware);
    crate::runtime::navigation::reconcile(ad)
}

#[cfg(feature = "workflow-test-auto")]
pub(super) fn workflow_backup_recovery_select(ad: &mut AppData, item: usize) -> bool {
    if !matches!(ad.navigation.app.state, AppState::BackupRecoveryMenu)
        || item >= usize::from(ad.navigation.production.backup_recovery_menu.count)
    {
        return false;
    }
    route_backup_recovery(ad, item);
    crate::runtime::navigation::reconcile(ad)
}

fn select_graph_item(ad: &mut AppData, item: usize) {
    let Ok(index) = u8::try_from(item) else { return; };
    let _ = crate::runtime::effects::menu_select(ad, index);
}

fn route_wallet(ad: &mut AppData, item: usize) {
    match item {
        0 => select_graph_item(ad, item),
        1 => { ad.navigation.production.wallet_backup_methods_menu.reset(); select_graph_item(ad, item); }
        2 => { ad.navigation.sd_import_menu.reset(); select_graph_item(ad, item); }
        3 => select_graph_item(ad, item),
        4 => { ad.wallet.seeds.seed_list_scroll = 0; select_graph_item(ad, item); }
        5 => { ad.navigation.multisig_menu.reset(); select_graph_item(ad, item); }
        6 => { ad.navigation.production.wallet_advanced_menu.reset(); select_graph_item(ad, item); }
        _ => {}
    }
}

fn route_wallet_backup_methods(ad: &mut AppData, item: usize) {
    if item == 3 {
        ad.navigation.production.backup_recovery_menu.reset();
    }
    select_graph_item(ad, item);
}

fn route_wallet_advanced(ad: &mut AppData, item: usize) {
    match item {
        2 => {
            ad.wallet.seeds.pp_input.reset();
            ad.signing.message.payload_len = 0;
        }
        3 => {
            ad.wallet.seeds.pp_input.reset();
            ad.signing.commit_reveal.plaintext_len = 0;
            ad.signing.commit_reveal.ciphertext.clear();
            ad.signing.commit_reveal.hash = [0u8; 32];
        }
        4 => {
            ad.signing.commit_reveal.ciphertext.clear();
            ad.signing.commit_reveal.plaintext_len = 0;
        }
        _ => {}
    }
    select_graph_item(ad, item);
}

fn route_advanced(ad: &mut AppData, item: usize) {
    #[cfg(feature = "provisioning-ui")]
    {
        if item == 2 {
            ad.navigation.production.owner_firmware_menu.reset();
            ad.pop_it.error = None;
        }
        if item == 3 && crate::runtime::navigation::production::pop_it_available() {
            ad.pop_it.return_state = crate::runtime::navigation::continuation!(AdvancedMenu);
            ad.pop_it.owner_authority_enrolled =
                crate::services::verify::boot_security::owner_authority_enrolled();
            ad.pop_it.error = None;
            ad.wallet.seeds.pp_input.reset();
        }
    }
    select_graph_item(ad, item);
}

#[cfg(feature = "provisioning-ui")]
fn route_owner_firmware(ad: &mut AppData, item: usize) {
    ad.pop_it.error = None;
    ad.wallet.seeds.pp_input.reset();
    select_graph_item(ad, item);
}

fn route_backup_recovery(ad: &mut AppData, item: usize) {
    if item == 3 {
        ad.navigation.xprv_export_menu.reset();
    }
    select_graph_item(ad, item);
}


#[cfg(feature="developer-ui")]
fn route_developer(ad: &mut AppData, item: usize) {
    let Some(label) = crate::runtime::navigation::production::DEVELOPER_ITEMS.get(item) else { return; };
    #[cfg(feature="workflow-tests")]
    if *label == "Workflow Tests" {
        ad.navigation.workflow_tests_return = crate::runtime::navigation::continuation!(DeveloperMenu);
        ad.navigation.workflow_tests_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WorkflowTestsMenu));
        return;
    }
    #[cfg(feature="argon2-bench")]
    if *label == "Argon2 Bench" {
        ad.runtime.request_argon2_benchmark();
        return;
    }
    if *label == "Diagnostic Info" {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(DiagnosticInfo));
        return;
    }
    if *label == "Network" {
        ad.navigation.production.network_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(NetworkMenu));
    }
}

#[cfg(feature="developer-ui")]
fn route_network(ad: &mut AppData, item: usize) {
    use crate::wallet::seed_manager::WalletNetwork;
    let network = match item {
        0 => WalletNetwork::Mainnet,
        1 => WalletNetwork::Testnet12,
        2 => WalletNetwork::Testnet10,
        _ => return,
    };
    if ad.wallet.seeds.seed_mgr.network() == network {
        return;
    }
    crate::services::wallet_session::clear_active_wallet(ad);
    ad.wallet.seeds.seed_mgr.set_network(network);
    ad.wallet.seeds.seed_list_scroll = 0;
    ad.settings.mark_device_preferences_dirty();
    crate::log!("   DEV network switched to {}", network.menu_label());
    crate::runtime::interactions::persistence::enter_required_wallet_selection(ad);
}

fn handle_wallet_details(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu)); return true; }
    if !(45..=275).contains(&x) { return false; }
    if (116..=146).contains(&y) {
        let active = usize::from(ad.wallet.seeds.seed_mgr.active);
        let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else { return false; };
        if !ad.storage.persistence.advanced.saved_wallet
            || slot.protection != crate::wallet::seed_manager::WalletProtection::DeviceOnly
        {
            return true;
        }
        if !ad.runtime.begin_wallet_protection_update(active) {
            return true;
        }
        ad.wallet.seeds.clear_pending_wallet_protection();
        ad.wallet.seeds.pp_input.reset();
        shared_signer::bytes::zeroize_bytes(&mut ad.storage.persistence.confirmation_digest);
        ad.storage.persistence.confirmation_pending = false;
        ad.storage.persistence.kind = None;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageCredentialType));
        return true;
    }
    if (154..=184).contains(&y) {
        let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else { return false; };
        let len = usize::from(slot.name_len).min(crate::wallet::seed_manager::WALLET_NAME_MAX);
        let mut name = [0u8; crate::wallet::seed_manager::WALLET_NAME_MAX];
        name[..len].copy_from_slice(&slot.name[..len]);
        ad.wallet.seeds.pp_input.reset();
        ad.wallet.seeds.pp_input.buf[..len].copy_from_slice(&name[..len]);
        ad.wallet.seeds.pp_input.len = len;
        ad.wallet.seeds.pp_input.cursor = len;
        shared_signer::bytes::zeroize_bytes(&mut name);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WalletNameEntry { purpose: 2 }));
        return true;
    }
    if (192..=222).contains(&y) {
        let active = ad.wallet.seeds.seed_mgr.active;
        if active != u8::MAX {
            ad.wallet.seeds.pending_delete_slot = active;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ConfirmDeleteSeed));
            return true;
        }
    }
    false
}
