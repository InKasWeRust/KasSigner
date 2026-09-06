// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0

//! Central firmware navigation state machine.
//!
//! Route mutation is owned here. Controllers request transitions through the
//! runtime effect boundary; direct state writes are rejected by architecture
//! policy. Input dispatch and redraw therefore observe the same committed
//! owner/state pair.

mod back;
mod event;
mod kernel;
mod menu_reducer;
mod onboarding;
mod policy;
pub(crate) mod production;
pub(crate) mod ui_graph;
mod root;

pub(crate) use event::{continuation, route, ContinuationRoute, ResumeTarget, ReturnScope, UiEvent, UiRoute};
pub(crate) use onboarding::OnboardingRoute;
pub(crate) use policy::NavigationOwner;
pub(crate) use root::main_menu_target_at;

#[cfg(feature = "workflow-tests")]
pub(crate) fn workflow_owner_for(
    intent: crate::runtime::data::DeviceStorageIntent,
    state: AppState,
    current: NavigationOwner,
) -> NavigationOwner {
    policy::owner_for_intent(intent, state, current)
}

#[cfg(feature = "workflow-tests")]
pub(crate) fn workflow_input_route_valid(
    intent: crate::runtime::data::DeviceStorageIntent,
    state: AppState,
    owner: NavigationOwner,
) -> bool {
    if owner == NavigationOwner::Onboarding {
        return onboarding::route_for(intent, state).is_some();
    }
    let _ = state.handler_group();
    true
}

#[cfg(feature = "workflow-tests")]
pub(crate) fn workflow_transition_allowed(
    from: NavigationOwner,
    to: NavigationOwner,
    from_state: AppState,
    to_state: AppState,
) -> bool {
    policy::transition_allowed(from, to, from_state, to_state)
}

use crate::runtime::{data::AppData, input::AppState};

/// Dispatch a typed UI event through the single stage-2 navigation kernel.
/// Convert a runtime-selected stable state into an opaque continuation token.
/// Keep this at the navigation boundary; domain structs store the token rather
/// than raw `AppState` destinations.
#[inline]
pub(crate) const fn continuation_from_state(
    state: crate::runtime::input::AppState,
) -> ContinuationRoute {
    ContinuationRoute::new(state)
}

pub(crate) fn dispatch(ad: &mut AppData, event: UiEvent) -> bool { kernel::dispatch(ad, event) }

/// Resolve a scoped caller return from navigation-owned bounded history.
pub(crate) fn return_target(ad: &AppData, scope: ReturnScope) -> Option<AppState> {
    kernel::return_target(ad, scope)
}

/// Recover from a transient error modal to a known-good stable screen. The
/// kernel accepts only the current screen or a target already in bounded
/// navigation history; arbitrary state jumps are rejected.
pub(crate) fn return_from_error(ad: &mut AppData, target: AppState) -> bool {
    kernel::return_from_error(ad, target)
}

/// Whether first-wallet onboarding currently owns all touch input.
pub(crate) fn is_onboarding(ad: &AppData) -> bool {
    ad.navigation.owner == NavigationOwner::Onboarding
}

/// Resolve the one reducer allowed to handle the current onboarding screen.
/// Ownership and reducer selection come from the same state-machine table.
pub(crate) fn onboarding_route(ad: &AppData) -> Option<OnboardingRoute> {
    if !is_onboarding(ad) {
        return None;
    }
    onboarding::route_for(
        ad.storage.persistence.device_storage_intent,
        ad.navigation.app.state,
    )
}

/// Whether the event loop should emit its ordinary navigation click after
/// routing and reconciling a tap. Secret-entry screens own feedback locally so accepted
/// credential keys may click once while the persisted global mute/volume policy remains authoritative.
pub(crate) fn tap_uses_router_click(state: AppState) -> bool {
    !matches!(
        state,
        AppState::ChooseWordCount { .. }
            | AppState::StorageSeedWordCountChoice { .. }
            | AppState::SeedEntropyUnavailable { .. }
            | AppState::StoragePinEntry
            | AppState::StoragePinConfirm
            | AppState::StoragePasswordEntry
            | AppState::StoragePasswordConfirm
            | AppState::StorageUnlockPin
            | AppState::StorageUnlockPassword
    )
}

/// Fail closed when the onboarding router encounters a state it does not own.
pub(crate) fn recover_onboarding(ad: &mut AppData) {
    kernel::force_recover(ad, ad.navigation.app.state);
}

/// Commit one of the four authoritative Home-grid routes.
///
/// Root destinations and their owners are fixed by `root::root_route`; do not
/// run this latency-sensitive hardware UI boundary through generic handler-group
/// owner inference. The production Home controller and connected-device E2E use
/// this exact path.
pub(crate) fn transition_root(ad: &mut AppData, index: usize) -> Option<AppState> {
    crate::log!("   NAV root transition {} BEGIN", index);
    let next = root::root_route(index).map(|route| route.0)?;
    let event_index = u8::try_from(index).ok()?;
    if !kernel::dispatch(ad, UiEvent::RootSelect(event_index)) {
        crate::log!("   NAV root transition {} REJECT", index);
        return None;
    }
    crate::log!("   NAV root transition {} DONE", index);
    Some(next)
}



/// Validate any state change made by a workflow before it can receive input or
/// be rendered. This also fences older direct state writes behind one policy.
pub(crate) fn reconcile(ad: &mut AppData) -> bool {
    let actual = ad.navigation.app.state;
    if actual != ad.navigation.committed_state || !result_screen_is_valid(ad, actual) {
        kernel::force_recover(ad, actual);
        return false;
    }
    true
}

/// Central handling for hierarchy/menu Back behavior. Workflow-specific Back
/// actions remain in their owning reducer when they must mutate domain data.
pub(crate) fn handle_back(ad: &mut AppData) -> bool {
    if !reconcile(ad) { return true; }
    if matches!(ad.navigation.app.state, AppState::StorageUnlockPin | AppState::StorageUnlockPassword) {
        if ad.runtime.cancel_pending_wallet_activation() {
            ad.wallet.seeds.pp_input.reset();
            let _ = kernel::dispatch(ad, UiEvent::Route(route!(SeedList)));
        }
        // Initial device-store unlock and wallet-switch unlock are both modal.
        // The latter may be cancelled only back to WALLETS; neither can escape home.
        return true;
    }
    if ad.navigation.app.state == AppState::SeedList
        && ad.wallet.seeds.seed_mgr.active_slot().is_none()
    {
        return true;
    }
    back::prepare(ad);
    kernel::dispatch(ad, UiEvent::Back)
}


/// Home is a post-onboarding shortcut only. It never appears before the user
/// has actually reached Home, so first-boot onboarding/credential gates cannot
/// be bypassed.
pub(crate) fn home_shortcut_visible(ad: &AppData) -> bool {
    let wallet_protection_setup = ad.runtime.pending_wallet_protection_update().is_some()
        && matches!(
            ad.navigation.app.state,
            AppState::StorageCredentialType
                | AppState::StoragePinEntry
                | AppState::StoragePinConfirm
                | AppState::StoragePasswordEntry
                | AppState::StoragePasswordConfirm
        );
    !wallet_resolution_required(ad)
        && !wallet_protection_setup
        && home_shortcut_allowed(ad.runtime.home_reached, ad.navigation.app.state)
}

fn home_shortcut_allowed(home_reached: bool, state: AppState) -> bool {
    home_reached
        && state != AppState::MainMenu
        && !matches!(state, AppState::StorageUnlockPin | AppState::StorageUnlockPassword)
}

fn wallet_resolution_required(ad: &AppData) -> bool {
    ad.runtime.home_reached && ad.wallet.seeds.seed_mgr.active_slot().is_none()
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_home_shortcut_hidden_for_unlock(state: AppState) -> bool {
    matches!(state, AppState::StorageUnlockPin | AppState::StorageUnlockPassword)
        && !home_shortcut_allowed(true, state)
}


/// Enter the Add Wallet create/restore flow through one explicit Seeds-owned
/// edge. Create continues through the generated-word flow; Restore first opens
/// the shared restore-source menu (Words / SeedQR / SD / Advanced). Generic
/// navigation intentionally remains strict; only AddWalletChoice may enter
/// these wallet-add actions.
pub(crate) fn begin_add_wallet(ad: &mut AppData, action: u8) -> bool {
    let from_choice = ad.navigation.committed_state == AppState::AddWalletChoice
        && ad.navigation.app.state == AppState::AddWalletChoice;
    let from_named_create = action == 0
        && ad.navigation.committed_state == AppState::WalletNameEntry { purpose: 1 }
        && ad.navigation.app.state == AppState::WalletNameEntry { purpose: 1 };
    let ready = ad.navigation.owner == NavigationOwner::Seeds
        && (from_choice || from_named_create)
        && matches!(action, 0 | 2)
        && !ad.storage.persistence.device_storage_intent.is_seed_onboarding();
    if !ready {
        crate::log!("   NAV Add Wallet transition REJECT action={}", action);
        return false;
    }
    if from_choice {
        ad.wallet.seeds.clear_pending_add_wallet();
    } else {
        // Preserve the name staged on WalletNameEntry until the wallet is
        // committed after recovery-word acknowledgement.
        ad.wallet.seeds.clear_pending_seed_entropy();
        ad.wallet.seeds.clear_pending_wallet_protection();
        ad.wallet.seeds.clear_pending_bip39_passphrase();
        ad.wallet.seeds.dice_collector.zeroize();
        ad.wallet.seeds.word_count = 0;
    }
    ad.wallet.seeds.begin_pending_add_wallet(action == 2);
    let Some(slot) = ad.wallet.seeds.seed_mgr.find_free() else {
        ad.wallet.seeds.clear_pending_add_wallet();
        return false;
    };
    ad.wallet.seeds.pending_add_wallet_slot = slot as u8;
    let destination = if action == 2 {
        ad.storage.persistence.onboarding_imported_mnemonic = false;
        ad.navigation.production.restore_menu.reset();
        route!(StorageSeedSourceChoice)
    } else {
        route!(ChooseWordCount { action: action })
    };
    let routed = kernel::dispatch(ad, UiEvent::Route(destination));
    if !routed {
        ad.wallet.seeds.clear_pending_add_wallet();
    }
    routed
}

pub(crate) fn home(ad: &mut AppData) {
    ad.wallet.seeds.clear_multisig_wallet_return();
    if wallet_resolution_required(ad) {
        let _ = kernel::dispatch(ad, UiEvent::Route(route!(SeedList)));
        return;
    }
    if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        crate::runtime::interactions::persistence::cancel_seed_onboarding(ad);
        let _ = kernel::dispatch(ad, UiEvent::Route(route!(StorageModeChoice)));
    } else {
        if ad.wallet.seeds.has_pending_add_wallet() {
            ad.wallet.seeds.clear_pending_add_wallet();
        }
        let _ = kernel::dispatch(ad, UiEvent::Home);
    }
}

mod transaction;
pub(crate) use transaction::{
    advance_inspection, advance_review, advance_signing, confirm_transaction, start_review,
};
#[cfg(feature = "workflow-test-auto")]
pub(crate) use transaction::reject_active_signing;


#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_reject_scanned_transaction(ad: &mut AppData) -> bool {
    let rejected_owner = match (ad.navigation.owner, ad.navigation.committed_state, ad.navigation.app.state) {
        (NavigationOwner::Signing, AppState::ScanQR, AppState::ScanQR) => NavigationOwner::Signing,
        (NavigationOwner::Storage, AppState::SdKsptFileList, AppState::SdKsptFileList) => NavigationOwner::Main,
        _ => {
            crate::log!("KASSIGNER_WORKFLOW_TESTS: TRANSACTION REJECTION NAV CONTEXT REJECT");
            return false;
        }
    };
    kernel::force_commit(ad, AppState::Rejected, rejected_owner, false);
    crate::log!("KASSIGNER_WORKFLOW_TESTS: TRANSACTION REJECTION NAV COMMIT");
    true
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_cleanup_onboarding_to_home(ad: &mut AppData) -> bool {
    if !reconcile(ad) || ad.navigation.owner != NavigationOwner::Onboarding { return false; }
    crate::runtime::interactions::persistence::cancel_seed_onboarding(ad);
    kernel::force_commit(ad, AppState::MainMenu, NavigationOwner::Main, true);
    true
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_reset_to_home(ad: &mut AppData) -> bool {
    if !reconcile(ad) { return false; }
    if ad.navigation.owner == NavigationOwner::Onboarding
        || ad.storage.persistence.device_storage_intent.is_seed_onboarding()
    {
        crate::runtime::interactions::persistence::cancel_seed_onboarding(ad);
    }
    // Connected workflow tranches are independent scenarios. Between tranches,
    // reset through the navigation authority rather than asking production Home
    // to honor first-boot / wallet-resolution guards inherited from a previous
    // scenario. `force_commit` still performs Main-entry abandoned-operation
    // cancellation and sensitive workflow cleanup before committing the tuple.
    kernel::force_commit(ad, AppState::MainMenu, NavigationOwner::Main, true);
    reconcile(ad)
        && ad.navigation.app.state == AppState::MainMenu
        && ad.navigation.committed_state == AppState::MainMenu
        && ad.navigation.owner == NavigationOwner::Main
        && crate::runtime::presentation::operation_kind(ad).is_none()
}

/// Complete seed onboarding through a guarded terminal transition. Generic
/// navigation is intentionally unable to jump from Onboarding to Main.
pub(crate) fn complete_onboarding(ad: &mut AppData) -> bool {
    if !reconcile(ad) { return false; }
    let intent = ad.storage.persistence.device_storage_intent;
    let ready = ad.navigation.owner == NavigationOwner::Onboarding
        && intent.is_seed_onboarding()
        && ad.storage.persistence.recovery_words_acknowledged
        && ad.wallet.seeds.seed_loaded;
    if !ready {
        kernel::force_recover(ad, AppState::MainMenu);
        return false;
    }
    ad.storage.persistence.reset();
    kernel::force_commit(ad, AppState::MainMenu, NavigationOwner::Main, true);
    true
}

fn result_screen_is_valid(ad: &AppData, state: AppState) -> bool {
    if state != AppState::ShowQrPopup { return true; }
    ad.qr.outgoing.length > 0
        && ad.qr.outgoing.purpose == crate::runtime::data::OutgoingQrPurpose::SignedTransaction
}


