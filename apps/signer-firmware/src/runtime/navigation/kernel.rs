//! Single stage-2 navigation reducer and atomic commit boundary.

use crate::runtime::{
    data::{AppData, DeviceStorageIntent, OperationKind},
    input::AppState,
};

use super::{policy, root, NavigationOwner, ResumeTarget, ReturnScope, UiEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryEffect {
    PushCurrent,
    Pop,
    PopTo(AppState),
    Clear,
    Preserve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Transition {
    from: AppState,
    next: AppState,
    owner: NavigationOwner,
    history: HistoryEffect,
    root_index: Option<u8>,
    redraw: bool,
    operation: Option<OperationKind>,
}

#[derive(Debug, Clone, Copy)]
struct ReducerContext {
    from: AppState,
    owner: NavigationOwner,
    intent: DeviceStorageIntent,
    history_back: Option<AppState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejection {
    StateDiverged,
    InvalidRoute,
    InvalidRoot,
    NoBackTarget,
    MenuRejected,
    MenuGuardDenied,
}

pub(super) fn dispatch(ad: &mut AppData, event: UiEvent) -> bool {
    if ad.navigation.app.state != ad.navigation.committed_state {
        recover(ad, Rejection::StateDiverged, ad.navigation.app.state);
        return false;
    }
    let context = ReducerContext {
        from: ad.navigation.committed_state,
        owner: ad.navigation.owner,
        intent: ad.storage.persistence.device_storage_intent,
        history_back: ad.navigation.history.peek(),
    };
    let transition = match reduce(ad, context, event) {
        Ok(transition) => transition,
        Err(Rejection::MenuGuardDenied) => {
            crate::log!("   NAV menu guard denial preserved {:?}: {:?}", context.owner, context.from);
            return false;
        }
        Err(rejection) => {
            let attempted = attempted_state(context.from, event);
            recover(ad, rejection, attempted);
            return false;
        }
    };
    apply(ad, transition);
    true
}

/// Pure route reducer for all route/root/back/home events. Menu selection uses
/// graph/fact lookup to resolve one route, then returns through this same pure
/// policy reducer before anything is committed.
fn reduce(ad: &AppData, context: ReducerContext, event: UiEvent) -> Result<Transition, Rejection> {
    match event {
        UiEvent::Route(route) => route_transition(context, route.state(), HistoryEffect::PushCurrent, None, true),
        UiEvent::Replace(route) => route_transition(context, route.state(), HistoryEffect::Preserve, None, true),
        UiEvent::Continue(route) => route_transition(context, route.state(), HistoryEffect::PushCurrent, None, true),
        UiEvent::RootSelect(index) => reduce_root(ad, context, index),
        UiEvent::Home => reduce_home(context),
        UiEvent::Back => reduce_back(ad, context),
        UiEvent::ReturnTo(scope) => reduce_return(ad, context, scope),
        UiEvent::Resume(target) => reduce_resume(ad, context, target),
        UiEvent::AuthenticatedResume(target) => reduce_authenticated_resume(ad, context, target),
        UiEvent::MenuSelect(index) => reduce_menu(ad, context, index),
    }
}

fn reduce_root(ad: &AppData, context: ReducerContext, index: u8) -> Result<Transition, Rejection> {
    if context.from != AppState::MainMenu || context.owner != NavigationOwner::Main {
        return Err(Rejection::InvalidRoot);
    }
    if index == 0 && !ad.wallet.seeds.seed_loaded {
        return Err(Rejection::MenuGuardDenied);
    }
    if index == 0 && ad.export.connect_kpub_cached() {
        return route_transition(
            context, AppState::ExportKpub, HistoryEffect::PushCurrent, Some(index), true,
        );
    }
    let (next, owner) = root::root_route(usize::from(index)).ok_or(Rejection::InvalidRoot)?;
    Ok(Transition {
        from: context.from,
        next,
        owner,
        history: HistoryEffect::PushCurrent,
        root_index: Some(index),
        redraw: true,
        operation: root::root_operation(usize::from(index)),
    })
}

fn reduce_home(context: ReducerContext) -> Result<Transition, Rejection> {
    let next = if context.intent.is_seed_onboarding() {
        AppState::StorageModeChoice
    } else {
        AppState::MainMenu
    };
    route_transition(context, next, HistoryEffect::Clear, None, true)
}

fn reduce_back(ad: &AppData, context: ReducerContext) -> Result<Transition, Rejection> {
    let next = super::back::target(ad)
        .or(context.history_back)
        .ok_or(Rejection::NoBackTarget)?;
    route_transition(context, next, HistoryEffect::Pop, None, true)
}

fn reduce_return(
    ad: &AppData,
    context: ReducerContext,
    scope: ReturnScope,
) -> Result<Transition, Rejection> {
    let next = return_target(ad, scope).ok_or(Rejection::NoBackTarget)?;
    route_transition(context, next, HistoryEffect::PopTo(next), None, true)
}

fn reduce_resume(
    ad: &AppData,
    context: ReducerContext,
    target: ResumeTarget,
) -> Result<Transition, Rejection> {
    let next = resume_target(ad, target).ok_or(Rejection::NoBackTarget)?;
    let history = if ad.navigation.history.target(&[next]).is_some() {
        HistoryEffect::PopTo(next)
    } else {
        HistoryEffect::Preserve
    };
    route_transition(context, next, history, None, true)
}

fn reduce_authenticated_resume(
    ad: &AppData,
    context: ReducerContext,
    target: super::ContinuationRoute,
) -> Result<Transition, Rejection> {
    if context.from != AppState::StorageUnlockPin {
        return Err(Rejection::InvalidRoute);
    }
    let next = target.state();
    if matches!(next, AppState::StorageUnlockPin | AppState::StorageUnlockPassword) {
        return Err(Rejection::InvalidRoute);
    }
    // The dim-lock target was the committed screen immediately before the
    // challenge, so it must still be present in bounded history. This prevents
    // this authenticated event from becoming a generic dynamic-route escape.
    if ad.navigation.history.target(&[next]).is_none() {
        return Err(Rejection::NoBackTarget);
    }
    let owner = policy::owner_for_intent(context.intent, next, context.owner);
    Ok(Transition {
        from: context.from,
        next,
        owner,
        history: HistoryEffect::PopTo(next),
        root_index: None,
        redraw: true,
        operation: None,
    })
}

fn reduce_menu(
    ad: &AppData,
    context: ReducerContext,
    index: u8,
) -> Result<Transition, Rejection> {
    let resolved = super::menu_reducer::resolve(ad, context.from, index).map_err(|error| {
        match error {
            super::menu_reducer::ResolveError::GuardDenied => Rejection::MenuGuardDenied,
            super::menu_reducer::ResolveError::MissingItem
            | super::menu_reducer::ResolveError::MissingDestination => Rejection::MenuRejected,
        }
    })?;
    let mut transition = route_transition(
        context, resolved.destination, HistoryEffect::PushCurrent, None, true,
    )?;
    transition.operation = resolved.operation;
    Ok(transition)
}

fn route_transition(
    context: ReducerContext,
    next: AppState,
    mut history: HistoryEffect,
    root_index: Option<u8>,
    redraw: bool,
) -> Result<Transition, Rejection> {
    let owner = policy::owner_for_intent(context.intent, next, context.owner);
    if !policy::transition_allowed(context.owner, owner, context.from, next) {
        return Err(Rejection::InvalidRoute);
    }
    if next == AppState::MainMenu {
        history = HistoryEffect::Clear;
    }
    Ok(Transition { from: context.from, next, owner, history, root_index, redraw, operation: None })
}

fn resume_target(ad: &AppData, target: ResumeTarget) -> Option<AppState> {
    match target {
        #[cfg(feature = "workflow-tests")]
        ResumeTarget::WorkflowTests => Some(ad.navigation.workflow_tests_return.state()),
        #[cfg(feature = "workflow-test-auto")]
        ResumeTarget::PopIt => Some(ad.pop_it.return_state.state()),
        ResumeTarget::StorageOverwriteBack => Some(ad.storage.confirmation.overwrite_back.state()),
    }
}

pub(super) fn return_from_error(ad: &mut AppData, target: AppState) -> bool {
    if ad.navigation.app.state != ad.navigation.committed_state {
        recover(ad, Rejection::StateDiverged, target);
        return false;
    }
    if target == ad.navigation.committed_state {
        return true;
    }
    if ad.navigation.history.target(&[target]).is_none() {
        crate::log!("   NAV recoverable error target not in history: {:?}", target);
        return false;
    }
    let context = ReducerContext {
        from: ad.navigation.committed_state,
        owner: ad.navigation.owner,
        intent: ad.storage.persistence.device_storage_intent,
        history_back: ad.navigation.history.peek(),
    };
    let Ok(transition) = route_transition(
        context, target, HistoryEffect::PopTo(target), None, true,
    ) else {
        crate::log!("   NAV recoverable error route rejected: {:?}", target);
        return false;
    };
    apply(ad, transition);
    true
}

pub(super) fn return_target(ad: &AppData, scope: ReturnScope) -> Option<AppState> {
    match scope {
        ReturnScope::SeedTool => ad.navigation.history.target(&[
            AppState::AddWalletChoice,
            AppState::SeedToolsMenu,
            AppState::WalletAdvancedMenu,
        ]),
        ReturnScope::KeyExport => ad.navigation.history.target(&[
            AppState::BackupRecoveryMenu,
            AppState::SigningKeysMenu,
            AppState::WalletAdvancedMenu,
        ]),
        ReturnScope::SigningTool => ad.navigation.history.target(&[
            AppState::SingleSigMenu,
            AppState::WalletAdvancedMenu,
        ]),
        ReturnScope::SeedBackup => ad.navigation.history.target(&[
            AppState::QrExportMenu,
            AppState::SeedBackupMenu,
            AppState::WalletBackupMethodsMenu,
            AppState::BackupRecoveryMenu,
            AppState::ExportChoice,
            AppState::AddWalletChoice,
            AppState::SeedToolsMenu,
        ]),
        ReturnScope::Address => ad.navigation.history.target(&[
            AppState::SeedToolsMenu,
            AppState::SeedsMenu,
            AppState::MainMenu,
        ]),
        ReturnScope::KpubExport => ad.navigation.history.target(&[
            AppState::WatchOnlyMenu,
            AppState::MultisigMenu,
            AppState::SignTxGuide,
            AppState::MainMenu,
        ]),
    }
}

fn attempted_state(from: AppState, event: UiEvent) -> AppState {
    match event {
        UiEvent::Route(route) | UiEvent::Replace(route) => route.state(),
        UiEvent::Continue(route) | UiEvent::AuthenticatedResume(route) => route.state(),
        _ => from,
    }
}

fn apply(ad: &mut AppData, transition: Transition) {
    match transition.history {
        HistoryEffect::PushCurrent if transition.from != transition.next => {
            ad.navigation.history.push(transition.from);
        }
        HistoryEffect::Pop => {
            let _ = ad.navigation.history.pop();
        }
        HistoryEffect::PopTo(target) => ad.navigation.history.pop_to(target),
        HistoryEffect::Clear => ad.navigation.history.clear(),
        HistoryEffect::Preserve | HistoryEffect::PushCurrent => {}
    }

    let owner_changed = transition.owner != ad.navigation.owner;
    if transition.next == AppState::MainMenu {
        clear_abandoned_workflow(ad);
        ad.navigation.app.prepare_main_menu();
        ad.runtime.home_reached = true;
    }
    if owner_changed {
        prepare_owner_entry(ad, transition.owner);
    }

    // These are the only ordinary production writes to the authoritative
    // navigation tuple. They move together as one commit boundary.
    ad.navigation.app.state = transition.next;
    ad.navigation.committed_state = transition.next;
    ad.navigation.owner = transition.owner;
    ad.runtime.needs_redraw = transition.redraw;
    if let Some(operation) = transition.operation {
        if !crate::runtime::presentation::start_operation(ad, operation) {
            crate::runtime::presentation::show_recoverable_error(
                ad, "Another operation is active", "UI-BUSY-01", 0,
            );
        }
    }

    if let Some(index) = transition.root_index {
        apply_root_entry(ad, index);
    }
    crate::log!("   NAV commit {:?}: {:?}", transition.owner, transition.next);
}

fn apply_root_entry(ad: &mut AppData, index: u8) {
    ad.runtime.home_reached = true;
    if index == 0 && ad.navigation.app.state == AppState::ExportKpub {
        if ad.export.restore_connect_kpub() {
            crate::log!("   Connect KasSee RAM cache HIT");
        } else {
            crate::log!("   Connect KasSee RAM cache restore failed");
        }
    }
}

fn prepare_owner_entry(ad: &mut AppData, owner: NavigationOwner) {
    match owner {
        NavigationOwner::Settings => ad.navigation.settings_menu.reset(),
        #[cfg(feature = "workflow-tests")]
        NavigationOwner::WorkflowTests => ad.navigation.workflow_tests_menu.reset(),
        _ => {}
    }
}

fn recover(ad: &mut AppData, rejection: Rejection, attempted: AppState) {
    let owner = ad.navigation.owner;
    let from = ad.navigation.committed_state;
    crate::log!("   NAV rejected {:?} {:?}: {:?} -> {:?}", rejection, owner, from, attempted);
    clear_abandoned_workflow(ad);
    let target = policy::safe_recovery(owner);
    if target == AppState::MainMenu {
        ad.navigation.app.prepare_main_menu();
        ad.navigation.history.clear();
    }
    ad.navigation.app.state = target;
    ad.navigation.committed_state = target;
    ad.navigation.owner = policy::recovery_owner(owner);
    ad.runtime.needs_redraw = true;
    #[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
    crate::runtime::presentation::show_error_spec(ad, crate::runtime::presentation::NAVIGATION);
}

pub(super) fn force_recover(ad: &mut AppData, attempted: AppState) {
    recover(ad, Rejection::InvalidRoute, attempted);
}

pub(super) fn force_commit(
    ad: &mut AppData,
    next: AppState,
    owner: NavigationOwner,
    redraw: bool,
) {
    apply(ad, Transition {
        from: ad.navigation.committed_state,
        next,
        owner,
        history: if next == AppState::MainMenu { HistoryEffect::Clear } else { HistoryEffect::PushCurrent },
        root_index: None,
        redraw,
        operation: None,
    });
}

fn clear_abandoned_workflow(ad: &mut AppData) {
    #[cfg(not(feature = "hardware-tests"))]
    crate::runtime::event_loop::operation_engine::cancel_abandoned(ad);
    crate::runtime::presentation::clear_recoverable_modal(ad);
    ad.navigation.app.review_authorized = false;
    ad.wallet.seeds.pp_input.reset();
    ad.wallet.seeds.touch_collector.reset();
    ad.wallet.seeds.clear_pending_seed_entropy();
    ad.wallet.seeds.dice_collector.zeroize();
    ad.signing.covenant.reset();
    ad.signing.anti_klepto.reset();
    ad.export.reset_kpub_work();
    ad.qr.outgoing.clear();
    ad.stego.export_flow.clear_portable_confirmation();
    ad.stego.session.portable.clear();
    ad.stego.import.clear_descriptor();
}
