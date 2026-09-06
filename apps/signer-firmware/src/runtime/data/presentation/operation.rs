//! Single authoritative long-running operation lifecycle.

use super::OperationKind;
use crate::runtime::input::AppState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationPhase {
    Idle,
    Queued,
    Presented,
    Running,
    Progress(u8),
    Success,
    RecoverableError,
    FatalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationState {
    kind: Option<OperationKind>,
    phase: OperationPhase,
    return_to: AppState,
    cursor: usize,
    started_at_ms: u64,
    last_progress_at_ms: u64,
    last_progress: u8,
}

impl OperationState {
    pub(crate) const fn new() -> Self {
        Self {
            kind: None,
            phase: OperationPhase::Idle,
            return_to: AppState::MainMenu,
            cursor: 0,
            started_at_ms: 0,
            last_progress_at_ms: 0,
            last_progress: 0,
        }
    }

    pub(crate) fn start(
        &mut self,
        kind: OperationKind,
        return_to: AppState,
        now_ms: u64,
    ) -> bool {
        self.start_at(kind, return_to, now_ms)
    }

    /// Credential submit remains a bounded state transition and deliberately
    /// avoids sampling the hardware clock from the touch-dispatch boundary.
    pub(crate) fn start_credential(
        &mut self,
        kind: OperationKind,
        return_to: AppState,
    ) -> bool {
        if !kind.is_credential() { return false; }
        self.start_at(kind, return_to, 0)
    }

    fn start_at(
        &mut self,
        kind: OperationKind,
        return_to: AppState,
        now_ms: u64,
    ) -> bool {
        if self.is_active() { return false; }
        self.kind = Some(kind);
        self.phase = OperationPhase::Queued;
        self.return_to = return_to;
        self.cursor = 0;
        self.started_at_ms = now_ms;
        self.last_progress_at_ms = now_ms;
        self.last_progress = 0;
        true
    }

    pub(crate) fn is_active(&self) -> bool {
        self.kind.is_some() && self.phase != OperationPhase::Idle
    }

    pub(crate) const fn kind(&self) -> Option<OperationKind> { self.kind }
    pub(crate) const fn phase(&self) -> OperationPhase { self.phase }
    pub(crate) const fn return_to(&self) -> AppState { self.return_to }
    pub(crate) const fn cursor(&self) -> usize { self.cursor }

    pub(crate) fn mark_presented(&mut self, now_ms: u64) -> bool {
        if self.phase != OperationPhase::Queued { return false; }
        self.phase = OperationPhase::Presented;
        if self.started_at_ms == 0 {
            self.started_at_ms = now_ms;
            self.last_progress_at_ms = now_ms;
        }
        true
    }

    pub(crate) fn take_ready(&mut self) -> Option<OperationKind> {
        if self.phase != OperationPhase::Presented { return None; }
        self.phase = OperationPhase::Running;
        self.kind
    }

    pub(crate) fn execution_result_ready(&self, kind: OperationKind) -> bool {
        self.kind == Some(kind)
            && matches!(self.phase, OperationPhase::Running | OperationPhase::Progress(_))
    }

    pub(crate) fn set_progress(&mut self, progress: u8, now_ms: u64) {
        if !self.is_active() { return; }
        let progress = progress.min(100);
        self.phase = OperationPhase::Progress(progress);
        if progress != self.last_progress {
            self.last_progress = progress;
            self.last_progress_at_ms = now_ms;
        }
    }

    pub(crate) fn timed_out(&self, now_ms: u64) -> bool {
        let Some(kind) = self.kind else { return false; };
        if !kind.asynchronous()
            || !matches!(self.phase, OperationPhase::Presented | OperationPhase::Running | OperationPhase::Progress(_))
        {
            return false;
        }
        now_ms.saturating_sub(self.started_at_ms) >= kind.total_budget_ms()
            || now_ms.saturating_sub(self.last_progress_at_ms) >= kind.stall_budget_ms()
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        if self.is_active() { self.cursor = cursor; }
    }

    pub(crate) fn mark_success(&mut self) {
        if self.is_active() { self.phase = OperationPhase::Success; }
    }

    pub(crate) fn mark_recoverable_error(&mut self) {
        if self.is_active() { self.phase = OperationPhase::RecoverableError; }
    }

    pub(crate) fn mark_fatal_error(&mut self) {
        if self.is_active() { self.phase = OperationPhase::FatalError; }
    }

    pub(crate) fn clear(&mut self) {
        self.kind = None;
        self.phase = OperationPhase::Idle;
        self.return_to = AppState::MainMenu;
        self.cursor = 0;
        self.started_at_ms = 0;
        self.last_progress_at_ms = 0;
        self.last_progress = 0;
    }
}
