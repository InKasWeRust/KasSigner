//! Runtime effect boundary for controller-requested UI work.
//!
//! Stage 2 requires controllers to emit typed `UiEvent`/`UiRoute` intents.
//! Only the navigation kernel may commit `AppState`, owner, history, or redraw
//! state for a route transition.

use crate::runtime::{
    data::AppData,
    navigation::{ContinuationRoute, ResumeTarget, ReturnScope, UiEvent, UiRoute},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UiEffect {
    Event(UiEvent),
    Redraw,
    #[cfg(feature = "workflow-test-auto")]
    KeepFrame,
}

pub(crate) fn apply(ad: &mut AppData, effect: UiEffect) -> bool {
    match effect {
        UiEffect::Event(event) => crate::runtime::navigation::dispatch(ad, event),
        UiEffect::Redraw => { ad.runtime.needs_redraw = true; true }
        #[cfg(feature = "workflow-test-auto")]
        UiEffect::KeepFrame => { ad.runtime.needs_redraw = false; true }
    }
}

#[inline]
pub(crate) fn emit(ad: &mut AppData, event: UiEvent) -> bool {
    apply(ad, UiEffect::Event(event))
}

#[inline]
pub(crate) fn route(ad: &mut AppData, route: UiRoute) -> bool {
    emit(ad, UiEvent::Route(route))
}

/// Replace the current screen instance in place without pushing navigation history.
#[inline]
pub(crate) fn replace(ad: &mut AppData, route: UiRoute) -> bool {
    emit(ad, UiEvent::Replace(route))
}

#[inline]
pub(crate) fn continue_to(ad: &mut AppData, route: ContinuationRoute) -> bool {
    emit(ad, UiEvent::Continue(route))
}

#[inline]
pub(crate) fn menu_select(ad: &mut AppData, index: u8) -> bool {
    emit(ad, UiEvent::MenuSelect(index))
}

#[inline]
pub(crate) fn back(ad: &mut AppData) -> bool {
    emit(ad, UiEvent::Back)
}

#[inline]
pub(crate) fn return_to(ad: &mut AppData, scope: ReturnScope) -> bool {
    emit(ad, UiEvent::ReturnTo(scope))
}

#[inline]
pub(crate) fn resume(ad: &mut AppData, target: ResumeTarget) -> bool {
    emit(ad, UiEvent::Resume(target))
}

#[inline]
pub(crate) fn authenticated_resume(ad: &mut AppData, target: ContinuationRoute) -> bool {
    emit(ad, UiEvent::AuthenticatedResume(target))
}

#[inline]
pub(crate) fn home(ad: &mut AppData) {
    let _ = emit(ad, UiEvent::Home);
}

#[inline]
pub(crate) fn redraw(ad: &mut AppData) {
    let _ = apply(ad, UiEffect::Redraw);
}

#[inline]
#[cfg(feature = "workflow-test-auto")]
pub(crate) fn keep_frame(ad: &mut AppData) {
    let _ = apply(ad, UiEffect::KeepFrame);
}

#[inline]
pub(crate) fn root(ad: &mut AppData, index: usize) -> Option<crate::runtime::input::AppState> {
    crate::runtime::navigation::transition_root(ad, index)
}

#[inline]
pub(crate) fn start_review(ad: &mut AppData, num_outputs: u8, num_inputs: usize) {
    crate::runtime::navigation::start_review(ad, num_outputs, num_inputs);
}

#[inline]
pub(crate) fn advance_review(ad: &mut AppData) -> bool {
    crate::runtime::navigation::advance_review(ad)
}

#[inline]
pub(crate) fn advance_inspection(ad: &mut AppData) -> bool {
    crate::runtime::navigation::advance_inspection(ad)
}

#[inline]
pub(crate) fn confirm_transaction(ad: &mut AppData, cursor: u8) -> bool {
    crate::runtime::navigation::confirm_transaction(ad, cursor)
}

#[inline]
pub(crate) fn complete_onboarding(ad: &mut AppData) -> bool {
    crate::runtime::navigation::complete_onboarding(ad)
}

#[inline]
pub(crate) fn recover_onboarding(ad: &mut AppData) {
    crate::runtime::navigation::recover_onboarding(ad);
}
