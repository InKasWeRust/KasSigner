//! Standard owner-path covenant spend planning.

use super::super::sweep::{self, CovenantSweepConfig, CovenantSweepSpec};
use crate::transaction_builder::pskb::PreparedSweep;

pub(crate) struct OwnerSpendPlan {
    pub(crate) redeem_script: Vec<u8>,
    pub(crate) branch: String,
}

impl OwnerSpendPlan {
    pub(crate) fn new(redeem_script_hex: &str, branch: &str) -> Result<Self, String> {
        Ok(Self {
            redeem_script: sweep::decode_redeem_script(redeem_script_hex)?,
            branch: branch.to_owned(),
        })
    }

    fn spec<'a>(
        &'a self,
        covenant_address: &'a str,
        destination_address: &'a str,
        fee: u64,
        empty_error: &'a str,
        low_balance_error: &'a str,
    ) -> Result<(CovenantSweepSpec<'a>, u64), String> {
        let lock_time = if self.branch == "owner-time" {
            crate::protocol::script::extract_cltv_locktime(&self.redeem_script)?.unwrap_or(0)
        } else {
            0
        };
        let branch = (!self.branch.is_empty()).then_some(self.branch.as_str());
        Ok((
            CovenantSweepSpec {
                covenant_address,
                destination_address,
                fee,
                empty_error,
                low_balance_error,
                config: CovenantSweepConfig {
                    redeem_script: &self.redeem_script,
                    input_sequence: 0,
                    lock_time,
                    branch,
                    minimum_signatures: None,
                },
            },
            lock_time,
        ))
    }
}

pub(crate) async fn build_automatic(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    fee: u64,
    websocket_url: &str,
    branch: &str,
) -> Result<(PreparedSweep, String, u64), String> {
    let plan = OwnerSpendPlan::new(redeem_script_hex, branch)?;
    let (spec, lock_time) = plan.spec(
        covenant_address,
        destination_address,
        fee,
        "No UTXOs at covenant address",
        "Balance too low to cover fee",
    )?;
    let (prepared, wire) = sweep::build_automatic(websocket_url, spec).await?;
    Ok((prepared, wire, lock_time))
}

pub(crate) fn build_selected(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    utxos_json: &str,
    fee: u64,
    branch: &str,
) -> Result<(PreparedSweep, String, u64), String> {
    let plan = OwnerSpendPlan::new(redeem_script_hex, branch)?;
    let (spec, lock_time) = plan.spec(
        covenant_address,
        destination_address,
        fee,
        "No UTXOs provided",
        "Selected UTXOs too small to cover fee",
    )?;
    let (prepared, wire) = sweep::build_selected(utxos_json, spec)?;
    Ok((prepared, wire, lock_time))
}

#[cfg(test)]
mod unit_tests;
