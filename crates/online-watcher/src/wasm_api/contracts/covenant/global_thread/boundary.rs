//! Shared WASM-boundary logging and wire extraction for global-thread operations.

#[cfg(any(test, target_arch = "wasm32"))]
use super::planning::{build_topup, TopupRequest};
use super::planning::{build_withdrawal, GlobalThreadFamily, WithdrawalRequest};

pub(crate) async fn create_withdrawal(
    request: WithdrawalRequest<'_>,
    label: &str,
) -> Result<String, String> {
    let family = request.family;
    let withdrawal = request.withdrawal;
    let fee = request.fee;
    let prepared = build_withdrawal(request)?;
    let timing = match family {
        GlobalThreadFamily::Allowance => format!(
            "csv_seq {}, cltv {}",
            prepared.csv_sequence, prepared.cltv_lock_time,
        ),
        GlobalThreadFamily::SpendingLimit => format!("csv_seq {}", prepared.csv_sequence),
    };
    crate::infrastructure::log_info(format!(
            "[KasSee] {label} withdraw PSKB: {} input(s), total {}, withdraw {}, user_receives {}, continuation {}, fee {}, close={}, {}, cov_id={}, wire {} chars",
            prepared.input_count,
            prepared.total,
            withdrawal,
            prepared.user_receives,
            prepared.continuation,
            fee,
            prepared.is_close,
            timing,
            hex::encode(prepared.covenant_id),
            prepared.wire.len(),
        ));
    Ok(prepared.wire)
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) async fn create_topup(request: TopupRequest<'_>, label: &str) -> Result<String, String> {
    let family = request.family;
    let fee = request.fee;
    let prepared = build_topup(request).await?;
    let timing = match family {
        GlobalThreadFamily::Allowance => String::new(),
        GlobalThreadFamily::SpendingLimit => format!(", csv_seq {}", prepared.csv_sequence),
    };
    crate::infrastructure::log_info(format!(
            "[KasSee] {label} top-up PSKB: {} input(s) (1 thread + {} wallet), thread {}, added {}, continuation {}, fee {}{}, cov_id={}, wire {} chars",
            prepared.input_count,
            prepared.selected_count,
            prepared.thread_amount,
            prepared.wallet_total,
            prepared.continuation,
            fee,
            timing,
            hex::encode(prepared.covenant_id),
            prepared.wire.len(),
        ));
    Ok(prepared.wire)
}
