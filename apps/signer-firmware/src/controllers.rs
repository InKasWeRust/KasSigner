//! Pure firmware input-controller boundary.
//!
//! Controllers normalize physical input and classify it into an application
//! interaction domain. They deliberately own no display, I2C, delay, flash,
//! persistence, crypto, UI-driver, or other hardware/service capability.
//! Effectful touch workflows live under `runtime::interactions`, where the
//! event loop owns the required peripheral adapters.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
use crate::runtime::input::{AppState, HandlerGroup};

/// One normalized touch event emitted by the hardware input adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TouchInput {
    pub(crate) x: u16,
    pub(crate) y: u16,
    pub(crate) is_back: bool,
}

impl TouchInput {
    pub const fn new(x: u16, y: u16, is_back: bool) -> Self {
        Self { x, y, is_back }
    }
}

/// Pure classification used by runtime dispatch. The controller does not
/// execute an interaction; it only states which adapter domain owns it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InteractionDomain {
    Menu,
    Stego,
    Storage,
    Seed,
    Export,
    Settings,
    Persistence,
    Signing,
    #[cfg(feature = "workflow-tests")]
    WorkflowTests,
}

pub(crate) fn classify(state: AppState) -> InteractionDomain {
    match state.handler_group() {
        HandlerGroup::Menu => InteractionDomain::Menu,
        HandlerGroup::Stego => InteractionDomain::Stego,
        HandlerGroup::Sd => InteractionDomain::Storage,
        HandlerGroup::Seed => InteractionDomain::Seed,
        HandlerGroup::Export => InteractionDomain::Export,
        HandlerGroup::Settings => InteractionDomain::Settings,
        HandlerGroup::Persistence => InteractionDomain::Persistence,
        HandlerGroup::Tx => InteractionDomain::Signing,
        #[cfg(feature = "workflow-tests")]
        HandlerGroup::WorkflowTests => InteractionDomain::WorkflowTests,
    }
}
