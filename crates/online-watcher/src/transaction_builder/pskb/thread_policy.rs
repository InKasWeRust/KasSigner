use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GlobalThreadFamily {
    Allowance,
    SpendingLimit,
}
/// Contract-family differences for the shared single-thread withdrawal/top-up flow.
#[derive(Clone, Debug)]
pub struct GlobalThreadPolicy {
    pub(super) withdrawal_lock_time: Value,
    pub(super) withdrawal_branch: Option<Value>,
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(super) topup_branch: Option<Value>,
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(super) topup_sequence: u64,
}
impl GlobalThreadPolicy {
    #[must_use]
    pub fn allowance(cltv_lock_time: u64) -> Self {
        Self {
            withdrawal_lock_time: if cltv_lock_time > 0 {
                Value::from(cltv_lock_time)
            } else {
                Value::Null
            },
            withdrawal_branch: Some(Value::from("beneficiary")),
            #[cfg(any(test, target_arch = "wasm32"))]
            topup_branch: Some(Value::from("owner")),
            #[cfg(any(test, target_arch = "wasm32"))]
            topup_sequence: 0,
        }
    }
    #[must_use]
    pub fn spending_limit() -> Self {
        Self {
            withdrawal_lock_time: Value::from(0),
            withdrawal_branch: Some(Value::Null),
            #[cfg(any(test, target_arch = "wasm32"))]
            topup_branch: Some(Value::Null),
            #[cfg(any(test, target_arch = "wasm32"))]
            topup_sequence: 0,
        }
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    #[must_use]
    pub fn spending_limit_topup(csv_sequence: u64) -> Self {
        let mut policy = Self::spending_limit();
        policy.topup_sequence = csv_sequence;
        policy
    }
}

pub(crate) fn withdrawal_policy_for(
    family: GlobalThreadFamily,
    redeem_script: &[u8],
) -> Result<(u64, GlobalThreadPolicy), String> {
    match family {
        GlobalThreadFamily::Allowance => {
            let locktime =
                crate::protocol::script::extract_cltv_locktime(redeem_script)?.unwrap_or(0);
            Ok((locktime, GlobalThreadPolicy::allowance(locktime)))
        }
        GlobalThreadFamily::SpendingLimit => Ok((0, GlobalThreadPolicy::spending_limit())),
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn topup_policy_for(
    family: GlobalThreadFamily,
    redeem_script: &[u8],
) -> Result<(u64, GlobalThreadPolicy), String> {
    match family {
        GlobalThreadFamily::Allowance => Ok((0, GlobalThreadPolicy::allowance(0))),
        GlobalThreadFamily::SpendingLimit => {
            let csv_sequence =
                crate::protocol::script::extract_csv_sequence(redeem_script)?.unwrap_or(0);
            Ok((
                csv_sequence,
                GlobalThreadPolicy::spending_limit_topup(csv_sequence),
            ))
        }
    }
}
