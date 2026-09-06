use serde_json::Value;

use crate::account::utxo::UtxoEntry;

use super::{PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan};

/// Input policy shared by full-sweep covenant, ZK and privacy spends.
#[derive(Clone, Debug)]
pub struct SweepInputPolicy {
    pub sequence: u64,
    pub sig_op_count: u8,
    pub minimum_signatures: u8,
    pub redeem_script: Option<Vec<u8>>,
    pub proprietaries: Value,
    pub min_time: Value,
}

impl SweepInputPolicy {
    #[must_use]
    pub fn covenant(redeem_script: &[u8], sequence: u64, branch_metadata: Value) -> Self {
        Self {
            sequence,
            sig_op_count: 1,
            minimum_signatures: 1,
            redeem_script: Some(redeem_script.to_vec()),
            proprietaries: branch_metadata,
            min_time: Value::from(0),
        }
    }

    #[must_use]
    pub fn p2pk(proprietaries: Value) -> Self {
        Self {
            sequence: 0,
            sig_op_count: 1,
            minimum_signatures: 1,
            redeem_script: None,
            proprietaries,
            min_time: Value::from(0),
        }
    }
}

/// Build the repeated one-source/many-input, one-destination PSKB plan.
#[must_use]
pub fn plan_sweep(
    utxos: &[UtxoEntry],
    source_script_public_key: &[u8],
    destination_script_public_key: &[u8],
    send_amount: u64,
    global: PskbGlobalPlan,
    input_policy: &SweepInputPolicy,
) -> PskbPlan {
    let inputs = utxos
        .iter()
        .cloned()
        .map(|utxo| PskbInputPlan {
            utxo,
            source_script_public_key: source_script_public_key.to_vec(),
            sequence: input_policy.sequence,
            block_daa_score: 0,
            sig_op_count: input_policy.sig_op_count,
            minimum_signatures: input_policy.minimum_signatures,
            redeem_script: input_policy.redeem_script.clone(),
            proprietaries: input_policy.proprietaries.clone(),
            min_time: input_policy.min_time.clone(),
        })
        .collect();

    PskbPlan {
        global,
        inputs,
        outputs: vec![PskbOutputPlan::plain(
            send_amount,
            destination_script_public_key,
        )],
    }
}
