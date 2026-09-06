//! Developer-only workflow-test UI state.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowTestResultData {
    pub(crate) total: u16,
    pub(crate) passed: u16,
    pub(crate) failed: u16,
    pub(crate) ran_all: bool,
}

pub(crate) struct WorkflowTestState {
    pub(crate) selected_category: u8,
    pub(crate) result: WorkflowTestResultData,
}

impl WorkflowTestState {
    pub(super) const fn new() -> Self {
        Self {
            selected_category: 0,
            result: WorkflowTestResultData { total: 0, passed: 0, failed: 0, ran_all: false },
        }
    }
}
