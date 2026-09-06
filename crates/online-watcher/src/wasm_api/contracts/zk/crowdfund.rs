//! Crowdfunding WASM façade.

mod campaign;
mod sweep;

pub use campaign::{
    covenant_crowdfund, crowdfund_campaign_id, zk_crowdfund_prove, zk_crowdfund_setup,
};
pub use sweep::{create_crowdfund_sweep, inspect_crowdfund_contributions};

#[cfg(test)]
pub(super) use campaign::{
    build_crowdfund_address_json, build_proof_json, compute_campaign_id_hex,
};
#[cfg(test)]
pub(super) use sweep::{prepare_crowdfund_sweep, ContributionRef, CrowdfundSweepRequest};
