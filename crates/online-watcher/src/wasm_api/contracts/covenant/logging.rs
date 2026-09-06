use crate::transaction_builder::pskb::PreparedSweep;

fn log_sweep(
    label: &str,
    input_count: usize,
    total: u64,
    send_amount: u64,
    fee: u64,
    wire: &str,
    detail: Option<(&str, u64)>,
) {
    let message = if let Some((detail_name, detail_value)) = detail {
        format!(
            "[KasSee] {label}: {input_count} inputs, total {total}, send {send_amount}, fee {fee}, {detail_name} {detail_value}, wire {} chars",
            wire.len(),
        )
    } else {
        format!(
            "[KasSee] {label}: {input_count} inputs, total {total}, send {send_amount}, fee {fee}, wire {} chars",
            wire.len(),
        )
    };
    crate::infrastructure::log_info(message);
}

pub(super) fn log_prepared_sweep(label: &str, prepared: &PreparedSweep, fee: u64, wire: &str) {
    log_sweep(
        label,
        prepared.utxos.len(),
        prepared.total,
        prepared.send_amount,
        fee,
        wire,
        None,
    );
}

pub(super) fn log_prepared_sweep_with_detail(
    label: &str,
    prepared: &PreparedSweep,
    fee: u64,
    wire: &str,
    detail: (&str, u64),
) {
    log_sweep(
        label,
        prepared.utxos.len(),
        prepared.total,
        prepared.send_amount,
        fee,
        wire,
        Some(detail),
    );
}
