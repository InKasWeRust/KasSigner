use super::{
    fee::DepositFeePolicy,
    model::{CovenantBuildRequest, CovenantDustPolicy, CovenantEncoding, KIP9_MIN_CHANGE_SOMPI},
    selection,
};
use crate::{account::address, network, protocol::pskt};

const MIN_GENESIS_SOMPI: u64 = 10_000_000;

pub(super) struct PreparedRequest {
    covenant_script: Vec<u8>,
    change_script: Vec<u8>,
    payload: Option<Vec<u8>>,
}

pub(crate) struct CovenantPlanInput<'a> {
    pub(crate) send_amount: u64,
    pub(crate) fee: u64,
    pub(crate) dust_policy: CovenantDustPolicy,
    pub(crate) utxo_indices_csv: &'a str,
    pub(crate) encoding: CovenantEncoding<'a>,
    pub(crate) covenant_script: &'a [u8],
    pub(crate) change_script: &'a [u8],
    pub(crate) payload: Option<&'a [u8]>,
}

struct SelectedPlan {
    selected: Vec<crate::UtxoEntry>,
    adjusted_send: u64,
    fee: u64,
}

pub(crate) async fn build(request: CovenantBuildRequest<'_>) -> Result<String, String> {
    build_with_binding(request).await.map(|(wire, _)| wire)
}

/// Build a covenant PSKB and return the genesis covenant ID when the selected
/// encoding carries a bound genesis. This keeps the UI from recomputing the ID
/// from a potentially different UTXO selection.
pub(crate) async fn build_with_binding(
    request: CovenantBuildRequest<'_>,
) -> Result<(String, Option<[u8; 32]>), String> {
    let prepared = prepare_request(&request)?;
    let utxos = network::queries::utxos::fetch_all(request.websocket_url, request.wallet).await?;
    encode_from_utxos_with_binding(
        CovenantPlanInput {
            send_amount: request.send_amount,
            fee: request.fee,
            dust_policy: CovenantDustPolicy::for_type(request.covenant_type),
            utxo_indices_csv: request.utxo_indices_csv,
            encoding: request.encoding,
            covenant_script: &prepared.covenant_script,
            change_script: &prepared.change_script,
            payload: prepared.payload.as_deref(),
        },
        utxos,
    )
}

pub(super) fn prepare_request(
    request: &CovenantBuildRequest<'_>,
) -> Result<PreparedRequest, String> {
    let covenant_script = address::address_to_script_pubkey(request.covenant_address)?;
    let change_script = address::address_to_script_pubkey(request.change_address)?;
    let payload = match request.encoding {
        CovenantEncoding::Payload { payload_hex, .. } => {
            Some(hex::decode(payload_hex).map_err(|error| format!("Bad payload hex: {error}"))?)
        }
        CovenantEncoding::BoundGenesis => None,
    };
    Ok(PreparedRequest {
        covenant_script,
        change_script,
        payload,
    })
}

#[cfg(test)]
pub(crate) fn encode_from_utxos(
    input: CovenantPlanInput<'_>,
    utxos: Vec<crate::UtxoEntry>,
) -> Result<String, String> {
    encode_from_utxos_with_binding(input, utxos).map(|(wire, _)| wire)
}

fn encode_from_utxos_with_binding(
    input: CovenantPlanInput<'_>,
    mut utxos: Vec<crate::UtxoEntry>,
) -> Result<(String, Option<[u8; 32]>), String> {
    crate::transaction_builder::selection::sort_for_display(&mut utxos);
    let plan = select_plan(&input, &utxos)?;
    let binding = genesis_binding(&input, &plan)?;
    let outputs = planned_outputs(&input, &plan, binding)?;
    let wire = encode_plan(&input, &plan, &outputs, binding)?;
    Ok((wire, binding.map(|(_, covenant_id)| covenant_id)))
}

fn select_plan(
    input: &CovenantPlanInput<'_>,
    utxos: &[crate::UtxoEntry],
) -> Result<SelectedPlan, String> {
    let fee_policy = DepositFeePolicy::new(
        input.payload.map_or(0, |payload| payload.len() as u64),
        input.encoding.tag_genesis(),
    );
    let selection::SelectionResult {
        selected,
        total,
        fee,
        target,
        used_manual_selection,
    } = selection::select(
        utxos,
        input.send_amount,
        input.fee,
        input.utxo_indices_csv,
        fee_policy,
    )?;
    let adjusted_send = adjusted_send(input, total, fee, target, used_manual_selection)?;
    Ok(SelectedPlan {
        selected,
        adjusted_send,
        fee,
    })
}

fn adjusted_send(
    input: &CovenantPlanInput<'_>,
    total: u64,
    fee: u64,
    target: u64,
    used_manual_selection: bool,
) -> Result<u64, String> {
    let selected =
        selected_send_amount(input.send_amount, total, fee, target, used_manual_selection)?;
    let adjusted = apply_send_policies(input, selected, total, fee, used_manual_selection)?;
    validate_genesis_minimum(input, adjusted)?;
    Ok(adjusted)
}

fn apply_send_policies(
    input: &CovenantPlanInput<'_>,
    selected: u64,
    total: u64,
    fee: u64,
    used_manual_selection: bool,
) -> Result<u64, String> {
    let adjusted = apply_genesis_send_policy(input, selected, total, fee)?;
    apply_dust_policy(
        input.dust_policy,
        adjusted,
        total,
        fee,
        used_manual_selection,
    )
}

fn selected_send_amount(
    requested: u64,
    total: u64,
    fee: u64,
    target: u64,
    used_manual_selection: bool,
) -> Result<u64, String> {
    if total >= target {
        return Ok(requested);
    }
    if total <= fee || !used_manual_selection {
        return Err(format!("Insufficient funds: {total} < {target}"));
    }
    let adjusted = total
        .checked_sub(fee)
        .ok_or("Covenant send adjustment underflow".to_string())?;
    crate::infrastructure::log_info(format!(
        "[KasSee] Auto-adjusted send: {requested} -> {adjusted} (fee {fee})"
    ));
    Ok(adjusted)
}

fn apply_dust_policy(
    policy: CovenantDustPolicy,
    selected: u64,
    total: u64,
    fee: u64,
    used_manual_selection: bool,
) -> Result<u64, String> {
    if policy != CovenantDustPolicy::FoldSubKip9Change || !used_manual_selection {
        return Ok(selected);
    }
    let change = total
        .checked_sub(selected)
        .and_then(|remaining| remaining.checked_sub(fee))
        .ok_or("Covenant dust-policy arithmetic underflow".to_string())?;
    if change == 0 || change >= KIP9_MIN_CHANGE_SOMPI {
        return Ok(selected);
    }
    total
        .checked_sub(fee)
        .ok_or("Covenant dust-fold arithmetic underflow".to_string())
}

fn apply_genesis_send_policy(
    input: &CovenantPlanInput<'_>,
    selected: u64,
    total: u64,
    fee: u64,
) -> Result<u64, String> {
    if !input.encoding.uses_tagged_genesis_policy() || input.send_amount != 0 || total <= fee {
        return Ok(selected);
    }
    total
        .checked_sub(fee)
        .ok_or("Covenant genesis adjustment underflow".to_string())
}

fn validate_genesis_minimum(input: &CovenantPlanInput<'_>, adjusted: u64) -> Result<(), String> {
    if !input.encoding.uses_tagged_genesis_policy() || adjusted >= MIN_GENESIS_SOMPI {
        return Ok(());
    }
    Err(format!(
        "Genesis funding {} sompi ({:.4} KAS) is too small for a covenant thread. \
         Fund at least 0.1 KAS so the tagged output clears the storage-mass floor.",
        adjusted,
        adjusted as f64 / 1e8
    ))
}

fn genesis_binding(
    input: &CovenantPlanInput<'_>,
    plan: &SelectedPlan,
) -> Result<Option<(u16, [u8; 32])>, String> {
    input
        .encoding
        .tag_genesis()
        .then(|| {
            compute_genesis_binding(
                input.encoding,
                &plan.selected,
                plan.adjusted_send,
                input.covenant_script,
            )
        })
        .transpose()
}

fn planned_outputs(
    input: &CovenantPlanInput<'_>,
    plan: &SelectedPlan,
    binding: Option<(u16, [u8; 32])>,
) -> Result<Vec<pskt::pskb::PskbOutput>, String> {
    let total = crate::transaction_builder::selection::checked_total(&plan.selected)?;
    let change = total
        .checked_sub(plan.adjusted_send)
        .and_then(|remaining| remaining.checked_sub(plan.fee))
        .ok_or("Covenant output arithmetic underflow".to_string())?;
    let mut outputs = vec![pskt::pskb::PskbOutput {
        amount: plan.adjusted_send,
        script: input.covenant_script.to_vec(),
        covenant: binding,
        derivation_hint: None,
        bip32_derivations: None,
    }];
    if change > 0 {
        outputs.push(pskt::pskb::PskbOutput {
            amount: change,
            script: input.change_script.to_vec(),
            covenant: None,
            derivation_hint: None,
            bip32_derivations: None,
        });
    }
    Ok(outputs)
}

fn encode_plan(
    input: &CovenantPlanInput<'_>,
    plan: &SelectedPlan,
    outputs: &[pskt::pskb::PskbOutput],
    binding: Option<(u16, [u8; 32])>,
) -> Result<String, String> {
    match input.encoding {
        CovenantEncoding::Payload { .. } => {
            let payload = input
                .payload
                .ok_or("Covenant payload encoding requires payload bytes".to_string())?;
            let encoded =
                pskt::pskb::encode_covenant_with_payload(&plan.selected, outputs, payload)?;
            crate::infrastructure::log_info(format!(
                "[KasSee] Covenant PSKB (payload): {} chars, {} inputs, {} outputs, payload {} bytes",
                encoded.len(), plan.selected.len(), outputs.len(), payload.len()
            ));
            Ok(encoded)
        }
        CovenantEncoding::BoundGenesis => {
            let covenant_id = binding
                .ok_or("Bound genesis encoding requires a covenant binding".to_string())?
                .1;
            let encoded = pskt::pskb::encode_covenant(&plan.selected, outputs)?;
            crate::infrastructure::log_info(format!(
                "[KasSee] Covenant PSKB: {} chars, {} inputs, {} outputs, cov_id={}",
                encoded.len(),
                plan.selected.len(),
                outputs.len(),
                hex::encode(covenant_id)
            ));
            Ok(encoded)
        }
    }
}

fn compute_genesis_binding(
    encoding: CovenantEncoding<'_>,
    selected: &[crate::UtxoEntry],
    adjusted_send: u64,
    covenant_script: &[u8],
) -> Result<(u16, [u8; 32]), String> {
    let funding = selected.first().ok_or("No UTXOs selected".to_string())?;
    let funding_txid = hex::decode(&funding.tx_id).map_err(|error| match encoding {
        CovenantEncoding::Payload { .. } => format!("Bad funding txid: {error}"),
        CovenantEncoding::BoundGenesis => format!("Bad txid: {error}"),
    })?;
    if funding_txid.len() != 32 {
        return Err(match encoding {
            CovenantEncoding::Payload { .. } => "funding txid not 32 bytes".to_string(),
            CovenantEncoding::BoundGenesis => "txid not 32 bytes".to_string(),
        });
    }

    let mut transaction_id = [0u8; 32];
    transaction_id.copy_from_slice(&funding_txid);
    let covenant_id = crate::contracts::vault::script::compute_covenant_id(
        &transaction_id,
        funding.index,
        &[(0u32, adjusted_send, 0u16, covenant_script)],
    );

    match encoding {
        CovenantEncoding::Payload { .. } => crate::infrastructure::log_info(format!(
            "[KasSee] Tagged genesis: covenant_id (G) = {}",
            hex::encode(covenant_id)
        )),
        CovenantEncoding::BoundGenesis => crate::infrastructure::log_info(format!(
            "[KasSee] Covenant PSKB: computed cov_id={} from utxo {}:{}",
            hex::encode(covenant_id),
            funding.tx_id.get(..16).unwrap_or(&funding.tx_id),
            funding.index
        )),
    }

    Ok((0u16, covenant_id))
}

#[cfg(test)]
mod unit_tests;
