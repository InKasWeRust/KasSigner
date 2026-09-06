//! Time-locked savings spend planning.

use super::super::sweep::{self, CovenantSweepSpec, SweepSourceKind};
use crate::transaction_builder::pskb::PreparedSweep;

pub(crate) struct SavingsClaimPlan {
    pub(crate) redeem_script: Vec<u8>,
    pub(crate) locktime_daa: u64,
}

impl SavingsClaimPlan {
    pub(crate) fn new(redeem_script_hex: &str, locktime_daa: u64) -> Result<Self, String> {
        Ok(Self {
            redeem_script: sweep::decode_redeem_script(redeem_script_hex)?,
            locktime_daa,
        })
    }

    pub(crate) fn spec<'a>(
        &'a self,
        covenant_address: &'a str,
        destination_address: &'a str,
        fee: u64,
        source: SweepSourceKind,
    ) -> CovenantSweepSpec<'a> {
        super::timelocked_claim_spec(
            covenant_address,
            destination_address,
            fee,
            source,
            super::TimelockedClaimConfig {
                redeem_script: &self.redeem_script,
                input_sequence: 0,
                lock_time: self.locktime_daa,
                branch: "savings",
            },
        )
    }
}

pub(crate) async fn build_automatic(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    fee: u64,
    websocket_url: &str,
) -> Result<(PreparedSweep, String), String> {
    let plan = SavingsClaimPlan::new(redeem_script_hex, locktime_daa)?;
    sweep::build_automatic(
        websocket_url,
        plan.spec(
            covenant_address,
            destination_address,
            fee,
            SweepSourceKind::Automatic,
        ),
    )
    .await
}

pub(crate) fn build_selected(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    locktime_daa: u64,
    utxos_json: &str,
    fee: u64,
) -> Result<(PreparedSweep, String), String> {
    let plan = SavingsClaimPlan::new(redeem_script_hex, locktime_daa)?;
    sweep::build_selected(
        utxos_json,
        plan.spec(
            covenant_address,
            destination_address,
            fee,
            SweepSourceKind::Selected,
        ),
    )
}
