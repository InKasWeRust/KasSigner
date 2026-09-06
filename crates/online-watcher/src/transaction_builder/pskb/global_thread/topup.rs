//! Global-thread top-up planning.

use super::super::thread_policy::GlobalThreadPolicy;
use super::super::{
    CovenantInputSettings, PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan,
};
use super::{checked_utxo_total, GlobalThreadPlanError};
use crate::account::utxo::UtxoEntry;
use serde_json::{json, Value};

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct GlobalThreadTopupPlan {
    pub plan: PskbPlan,
    pub wallet_total: u64,
    pub continuation: u64,
}

#[cfg(any(test, target_arch = "wasm32"))]
pub struct GlobalThreadTopupRequest<'a> {
    pub thread_utxo: UtxoEntry,
    pub wallet_utxos: &'a [UtxoEntry],
    pub covenant_script_public_key: &'a [u8],
    pub redeem_script: &'a [u8],
    pub covenant_id: &'a [u8; 32],
    pub fee: u64,
    pub policy: &'a GlobalThreadPolicy,
}
#[cfg(any(test, target_arch = "wasm32"))]
pub fn plan_global_thread_topup(
    request: GlobalThreadTopupRequest<'_>,
) -> Result<GlobalThreadTopupPlan, GlobalThreadPlanError> {
    let GlobalThreadTopupRequest {
        thread_utxo,
        wallet_utxos,
        covenant_script_public_key,
        redeem_script,
        covenant_id,
        fee,
        policy,
    } = request;
    let wallet_total = checked_utxo_total(wallet_utxos, "summing wallet top-up UTXOs")?;
    if wallet_total <= fee {
        return Err(GlobalThreadPlanError::SelectedFundsTooLow {
            selected_total: wallet_total,
            fee,
        });
    }
    let thread_amount = thread_utxo.amount;
    let continuation = thread_amount
        .checked_add(wallet_total)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "adding thread and wallet balances",
        })?
        .checked_sub(fee)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "subtracting fee from top-up continuation",
        })?;
    let mut inputs = Vec::with_capacity(1 + wallet_utxos.len());
    inputs.push(PskbInputPlan::covenant(
        thread_utxo,
        covenant_script_public_key,
        redeem_script,
        CovenantInputSettings {
            sequence: policy.topup_sequence,
            sig_op_count: 1,
            minimum_signatures: 1,
            proprietaries: Value::Array(Vec::new()),
            min_time: Value::from(0),
        },
    ));
    inputs.extend(wallet_utxos.iter().cloned().map(|utxo| {
        let source_script_public_key = utxo.script_public_key.clone();
        let block_daa_score = utxo.block_daa_score;
        let mut input =
            PskbInputPlan::p2pk(utxo, &source_script_public_key, Value::Array(Vec::new()));
        input.block_daa_score = block_daa_score;
        input
    }));
    let outputs = vec![
        PskbOutputPlan::plain(continuation, covenant_script_public_key).with_binding_field(json!({
            "authorizingInput": 0,
            "covenantId": hex::encode(covenant_id),
        })),
    ];

    Ok(GlobalThreadTopupPlan {
        plan: PskbPlan {
            global: PskbGlobalPlan {
                tx_version: 1,
                fallback_lock_time: Value::from(0),
                covenant_branch: policy.topup_branch.clone(),
                proprietaries: Value::Array(Vec::new()),
                transaction_payload: None,
            },
            inputs,
            outputs,
        },
        wallet_total,
        continuation,
    })
}
