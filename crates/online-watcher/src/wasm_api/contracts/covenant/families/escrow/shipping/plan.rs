//! Test-visible re-exports for the browser-neutral shipping planner.

#[cfg(test)]
pub(super) use crate::transaction_builder::covenant::shipping::plan::{
    build_borrower_plan, build_plan_from_sources, fetch_covenant_utxos, fetch_wallet_utxos,
    parse_plan_request, prepare, PlanSources,
};
