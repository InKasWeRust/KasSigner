//! Transport-neutral workflow-test command facade.

use super::{catalog::{WorkflowCategory, WorkflowSpec}, runner, WorkflowSummary};

pub(crate) enum WorkflowCommand<'a> {
    RunAll,
    RunCategory(WorkflowCategory),
    RunOne(&'a WorkflowSpec),
}

/// Execute an on-device workflow command without coupling the catalog/runner
/// to touch or watchdog hardware. The caller supplies the event-loop liveness
/// boundary used between individual workflow validations.
pub(crate) fn execute(
    command: WorkflowCommand<'_>,
    liveness: &mut dyn FnMut(),
) -> WorkflowSummary {
    match command {
        WorkflowCommand::RunAll => runner::run_all(liveness),
        WorkflowCommand::RunCategory(category) => runner::run_category(category, liveness),
        WorkflowCommand::RunOne(spec) => runner::run_one(spec, liveness),
    }
}

