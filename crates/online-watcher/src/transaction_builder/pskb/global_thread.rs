use super::thread_policy::GlobalThreadPolicy;
use super::{CovenantInputSettings, PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan};
use crate::account::utxo::UtxoEntry;
use core::fmt;
use serde_json::{json, Value};

/// Minimum economically useful continuation under the current KIP-9 storage-mass rules.
pub const MIN_THREAD_CONTINUATION_SOMPI: u64 = 10_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GlobalThreadPlanError {
    BalanceTooLow {
        total: u64,
        fee: u64,
    },
    WithdrawalNotAboveFee {
        withdrawal: u64,
        fee: u64,
    },
    ContinuationTooSmall {
        continuation: u64,
    },
    ArithmeticOverflow {
        operation: &'static str,
    },
    #[cfg(any(test, target_arch = "wasm32"))]
    SelectedFundsTooLow {
        selected_total: u64,
        fee: u64,
    },
}
impl fmt::Display for GlobalThreadPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BalanceTooLow { total, fee } =>
                write!(formatter, "Balance {total} too low to cover fee {fee}"),
            Self::WithdrawalNotAboveFee { withdrawal, fee } =>
                write!(formatter, "Withdrawal {withdrawal} must be greater than fee {fee}"),
            Self::ArithmeticOverflow { operation } =>
                write!(formatter, "Global-thread monetary arithmetic overflow while {operation}"),
            Self::ContinuationTooSmall { continuation } => write!(
                formatter,
                "Continuation {} sompi ({:.4} KAS) is too small. Leave at least 0.1 KAS on the thread, or close it by withdrawing the whole balance (allowed only when balance <= cap).",
                continuation,
                *continuation as f64 / 1e8
            ),
            #[cfg(any(test, target_arch = "wasm32"))]
            Self::SelectedFundsTooLow { selected_total, fee } => write!(
                formatter, "Selected wallet funds {selected_total} must exceed fee {fee} to add to the thread"
            ),
        }
    }
}
fn checked_utxo_total(
    utxos: &[UtxoEntry],
    operation: &'static str,
) -> Result<u64, GlobalThreadPlanError> {
    utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or(GlobalThreadPlanError::ArithmeticOverflow { operation })
    })
}

#[derive(Clone, Debug)]
pub struct GlobalThreadWithdrawalPlan {
    pub plan: PskbPlan,
    pub total: u64,
    pub user_receives: u64,
    pub continuation: u64,
    pub is_close: bool,
}
pub struct GlobalThreadWithdrawalRequest<'a> {
    pub thread_utxos: &'a [UtxoEntry],
    pub covenant_script_public_key: &'a [u8],
    pub destination_script_public_key: &'a [u8],
    pub redeem_script: &'a [u8],
    pub covenant_id: &'a [u8; 32],
    pub withdrawal: u64,
    pub fee: u64,
    pub csv_sequence: u64,
    pub policy: &'a GlobalThreadPolicy,
}
pub fn plan_global_thread_withdrawal(
    request: GlobalThreadWithdrawalRequest<'_>,
) -> Result<GlobalThreadWithdrawalPlan, GlobalThreadPlanError> {
    let thread_utxos = request.thread_utxos;
    let total = checked_utxo_total(thread_utxos, "summing thread UTXOs")?;
    let (is_close, continuation, user_receives) =
        withdrawal_amounts(total, request.withdrawal, request.fee)?;
    let inputs = withdrawal_inputs(&request);
    let outputs = withdrawal_outputs(&request, is_close, continuation, user_receives);
    Ok(GlobalThreadWithdrawalPlan {
        plan: withdrawal_plan(&request, inputs, outputs),
        total,
        user_receives,
        continuation,
        is_close,
    })
}
fn withdrawal_amounts(
    total: u64,
    withdrawal: u64,
    fee: u64,
) -> Result<(bool, u64, u64), GlobalThreadPlanError> {
    validate_withdrawal_balances(total, withdrawal, fee)?;
    let is_close = total <= withdrawal;
    let continuation = continuation_amount(total, withdrawal, is_close)?;
    validate_continuation(continuation, is_close)?;
    let user_receives = receive_amount(total, withdrawal, fee, is_close)?;
    Ok((is_close, continuation, user_receives))
}

fn validate_withdrawal_balances(
    total: u64,
    withdrawal: u64,
    fee: u64,
) -> Result<(), GlobalThreadPlanError> {
    if total <= fee {
        return Err(GlobalThreadPlanError::BalanceTooLow { total, fee });
    }
    if withdrawal <= fee {
        return Err(GlobalThreadPlanError::WithdrawalNotAboveFee { withdrawal, fee });
    }
    Ok(())
}
fn continuation_amount(
    total: u64,
    withdrawal: u64,
    is_close: bool,
) -> Result<u64, GlobalThreadPlanError> {
    if is_close {
        return Ok(0);
    }
    total
        .checked_sub(withdrawal)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "subtracting withdrawal from thread balance",
        })
}
fn receive_amount(
    total: u64,
    withdrawal: u64,
    fee: u64,
    is_close: bool,
) -> Result<u64, GlobalThreadPlanError> {
    let source = if is_close { total } else { withdrawal };
    source
        .checked_sub(fee)
        .ok_or(GlobalThreadPlanError::ArithmeticOverflow {
            operation: "subtracting fee from withdrawal value",
        })
}
fn validate_continuation(continuation: u64, is_close: bool) -> Result<(), GlobalThreadPlanError> {
    if !is_close && continuation < MIN_THREAD_CONTINUATION_SOMPI {
        Err(GlobalThreadPlanError::ContinuationTooSmall { continuation })
    } else {
        Ok(())
    }
}

fn withdrawal_inputs(request: &GlobalThreadWithdrawalRequest<'_>) -> Vec<PskbInputPlan> {
    request
        .thread_utxos
        .iter()
        .cloned()
        .map(|utxo| {
            PskbInputPlan::covenant(
                utxo,
                request.covenant_script_public_key,
                request.redeem_script,
                CovenantInputSettings {
                    sequence: request.csv_sequence,
                    sig_op_count: 1,
                    minimum_signatures: 1,
                    proprietaries: Value::Array(Vec::new()),
                    min_time: Value::from(0),
                },
            )
        })
        .collect()
}
fn withdrawal_outputs(
    request: &GlobalThreadWithdrawalRequest<'_>,
    is_close: bool,
    continuation: u64,
    user_receives: u64,
) -> Vec<PskbOutputPlan> {
    let mut outputs = Vec::with_capacity(if is_close { 1 } else { 2 });
    if !is_close {
        outputs.push(
            PskbOutputPlan::plain(continuation, request.covenant_script_public_key)
                .with_binding_field(json!({
                    "authorizingInput": 0,
                    "covenantId": hex::encode(request.covenant_id),
                })),
        );
    }
    outputs.push(
        PskbOutputPlan::plain(user_receives, request.destination_script_public_key)
            .with_binding_field(Value::Null),
    );
    outputs
}
fn withdrawal_plan(
    request: &GlobalThreadWithdrawalRequest<'_>,
    inputs: Vec<PskbInputPlan>,
    outputs: Vec<PskbOutputPlan>,
) -> PskbPlan {
    PskbPlan {
        global: PskbGlobalPlan {
            tx_version: 1,
            fallback_lock_time: request.policy.withdrawal_lock_time.clone(),
            covenant_branch: request.policy.withdrawal_branch.clone(),
            proprietaries: Value::Array(Vec::new()),
            transaction_payload: None,
        },
        inputs,
        outputs,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
mod topup;
#[cfg(any(test, target_arch = "wasm32"))]
pub use topup::{plan_global_thread_topup, GlobalThreadTopupRequest};
