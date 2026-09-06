//! Stable presentation state: one operation lifecycle plus one modal channel.

use crate::runtime::input::AppState;

mod kind; mod operation;
pub use kind::OperationKind;
#[cfg(not(feature = "hardware-tests"))]
pub(crate) use kind::OperationExecution;
pub use operation::{OperationPhase, OperationState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModalState {
    None,
    RecoverableError {
        message: &'static str,
        code: &'static str,
        return_to: AppState,
        dismiss_after_ms: u64,
    },
    FatalError {
        message: &'static str,
        code: &'static str,
    },
}

pub struct PresentationState {
    pub(crate) operation: OperationState,
    pub(crate) modal: ModalState,
}

impl PresentationState {
    pub(super) fn new() -> Self {
        Self { operation: OperationState::new(), modal: ModalState::None }
    }

    pub(crate) fn blocks_input(&self) -> bool {
        self.operation.is_active() || self.modal != ModalState::None
    }
}
