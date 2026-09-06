use super::catalog::{workflows, WorkflowCategory, WorkflowSpec, WorkflowTerminal};
use crate::runtime::{
    navigation::{
        workflow_input_route_valid, workflow_owner_for, workflow_transition_allowed, NavigationOwner,
    },
    input::AppState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowSummary {
    pub(crate) total: u16,
    pub(crate) passed: u16,
    pub(crate) failed: u16,
}

impl WorkflowSummary {
    const fn empty() -> Self { Self { total: 0, passed: 0, failed: 0 } }

    fn record(&mut self, passed: bool) {
        self.total = self.total.saturating_add(1);
        if passed {
            self.passed = self.passed.saturating_add(1);
        } else {
            self.failed = self.failed.saturating_add(1);
        }
    }

    fn merge(&mut self, other: Self) {
        self.total = self.total.saturating_add(other.total);
        self.passed = self.passed.saturating_add(other.passed);
        self.failed = self.failed.saturating_add(other.failed);
    }
}

pub(crate) fn run_one(
    spec: &WorkflowSpec,
    liveness: &mut dyn FnMut(),
) -> WorkflowSummary {
    liveness();
    let passed = validate_and_log(spec, liveness);
    let mut summary = WorkflowSummary::empty();
    summary.record(passed);
    liveness();
    summary
}

pub(crate) fn run_category(
    category: WorkflowCategory,
    liveness: &mut dyn FnMut(),
) -> WorkflowSummary {
    let mut summary = WorkflowSummary::empty();
    liveness();
    for spec in workflows(category) {
        summary.record(validate_and_log(spec, liveness));
        liveness();
    }
    summary
}

/// Headless Run All keeps serial I/O entirely outside the validation loop.
/// USB/JTAG logging is a diagnostic transport, not part of the workflow state
/// machine; all catalog contracts are validated first and only the final
/// summary is emitted afterward. On-device execution acknowledges liveness
/// between individual workflows so the CoreS3 runtime watchdog cannot expire.
pub(crate) fn run_all(liveness: &mut dyn FnMut()) -> WorkflowSummary {
    let mut summary = WorkflowSummary::empty();
    liveness();
    for category in WorkflowCategory::ALL {
        summary.merge(validate_group(category, liveness));
    }
    log!("E2E SUMMARY {}/{} passed", summary.passed, summary.total);
    liveness();
    summary
}

fn validate_group(
    category: WorkflowCategory,
    liveness: &mut dyn FnMut(),
) -> WorkflowSummary {
    let mut summary = WorkflowSummary::empty();
    for spec in workflows(category) {
        summary.record(validate(spec, liveness));
        liveness();
    }
    summary
}

fn validate_and_log(spec: &WorkflowSpec, liveness: &mut dyn FnMut()) -> bool {
    let passed = validate(spec, liveness);
    liveness();
    log!(
        "E2E {} {} fixtures=0x{:02x}",
        if passed { "PASS" } else { "FAIL" },
        spec.id,
        spec.fixtures.bits(),
    );
    liveness();
    passed
}

// This validates fixture-driven transition execution only. A fixture may begin
// at an internal AppState, so fixture execution does not establish production reachability.
// Root reachability is a separate hard QA graph rooted at MainMenu.
fn validate(spec: &WorkflowSpec, liveness: &mut dyn FnMut()) -> bool {
    liveness();
    let Some((&first, rest)) = spec.states.split_first() else { return false; };
    let mut owner = workflow_owner_for(spec.intent, first, NavigationOwner::Main);
    liveness();
    if !workflow_input_route_valid(spec.intent, first, owner) { return false; }
    let mut state = first;
    for &next in rest {
        liveness();
        let next_owner = workflow_owner_for(spec.intent, next, owner);
        if !workflow_transition_allowed(owner, next_owner, state, next) { return false; }
        if !workflow_input_route_valid(spec.intent, next, next_owner) { return false; }
        state = next;
        owner = next_owner;
    }
    liveness();
    terminal_valid(spec, owner, state)
}

fn terminal_valid(spec: &WorkflowSpec, owner: NavigationOwner, state: AppState) -> bool {
    match spec.terminal {
        WorkflowTerminal::Ordinary => true,
        WorkflowTerminal::OnboardingComplete => {
            owner == NavigationOwner::Main
                && spec.intent.is_seed_onboarding()
                && state == AppState::MainMenu
        }
    }
}
