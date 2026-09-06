use crate::runtime::input::AppState;

/// Typed route intent. Controllers may name a route, but they never mutate the
/// committed `AppState` directly; only the navigation kernel can unwrap it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UiRoute(AppState);

impl UiRoute {
    #[doc(hidden)]
    pub(crate) const fn new(state: AppState) -> Self { Self(state) }

    pub(super) const fn state(self) -> AppState { self.0 }
}

/// Opaque data-driven continuation route. Domain state may store this token,
/// but only the navigation package can unwrap it to an `AppState`. This replaces
/// the retired Stage-2 dynamic-route escape hatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContinuationRoute(AppState);

impl ContinuationRoute {
    #[doc(hidden)]
    pub(crate) const fn new(state: AppState) -> Self { Self(state) }
    pub(super) const fn state(self) -> AppState { self.0 }
}

/// User/controller events accepted by the navigation reducer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReturnScope {
    SeedTool,
    KeyExport,
    SigningTool,
    SeedBackup,
    Address,
    KpubExport,
}

/// Domain-owned continuation slots that still exist during stage 2. Controllers
/// identify the semantic continuation; only the navigation kernel may read the
/// stored `AppState` and commit it. Stage 3 can retire these slots as modal and
/// operation state are separated from screen state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeTarget {
    #[cfg(feature = "workflow-tests")]
    WorkflowTests,
    #[cfg(feature = "workflow-test-auto")]
    PopIt,
    StorageOverwriteBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UiEvent {
    Route(UiRoute),
    /// Replace the current screen instance without consuming navigation history.
    /// Used for in-place view-state changes such as SeedQR panning.
    Replace(UiRoute),
    Continue(ContinuationRoute),
    MenuSelect(u8),
    RootSelect(u8),
    Back,
    ReturnTo(ReturnScope),
    Resume(ResumeTarget),
    /// Resume the exact stable screen captured when a dim-lock PIN challenge
    /// was armed. Only the credential-success path emits this event.
    AuthenticatedResume(ContinuationRoute),
    Home,
}

/// Construct a typed route intent without exposing navigation field mutation.
/// The architecture gate forbids direct `UiRoute::new` use outside navigation.
macro_rules! route {
    ($variant:ident $(,)?) => {
        $crate::runtime::navigation::UiRoute::new(
            $crate::runtime::input::AppState::$variant
        )
    };
    ($variant:ident { $($fields:tt)* }) => {
        $crate::runtime::navigation::UiRoute::new(
            $crate::runtime::input::AppState::$variant { $($fields)* }
        )
    };
}
pub(crate) use route;

/// Construct an opaque continuation token for workflow-owned destinations.
macro_rules! continuation {
    ($variant:ident $(,)?) => {
        $crate::runtime::navigation::ContinuationRoute::new(
            $crate::runtime::input::AppState::$variant
        )
    };
    ($variant:ident { $($fields:tt)* }) => {
        $crate::runtime::navigation::ContinuationRoute::new(
            $crate::runtime::input::AppState::$variant { $($fields)* }
        )
    };
}
pub(crate) use continuation;
