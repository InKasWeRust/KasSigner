pub(crate) mod owner;
pub(crate) mod savings;
pub(crate) mod timelocked;
use super::sweep::{CovenantSweepConfig, CovenantSweepSpec, SweepSourceKind};

pub(super) struct TimelockedClaimConfig<'a> {
    pub redeem_script: &'a [u8],
    pub input_sequence: u64,
    pub lock_time: u64,
    pub branch: &'a str,
}

pub(super) fn timelocked_claim_spec<'a>(
    covenant_address: &'a str,
    destination_address: &'a str,
    fee: u64,
    source: SweepSourceKind,
    config: TimelockedClaimConfig<'a>,
) -> CovenantSweepSpec<'a> {
    CovenantSweepSpec {
        covenant_address,
        destination_address,
        fee,
        empty_error: source.choose("No UTXOs at covenant address", "No UTXOs provided"),
        low_balance_error: source.choose(
            "Balance too low to cover fee",
            "Selected UTXOs too small to cover fee",
        ),
        config: CovenantSweepConfig {
            redeem_script: config.redeem_script,
            input_sequence: config.input_sequence,
            lock_time: config.lock_time,
            branch: Some(config.branch),
            minimum_signatures: None,
        },
    }
}
