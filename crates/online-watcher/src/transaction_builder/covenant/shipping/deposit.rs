use super::plan;

pub(crate) struct DepositSummary {
    pub(crate) wire: String,
    pub(crate) funding_count: usize,
    pub(crate) covenant_output: u64,
    pub(crate) change: u64,
}

pub(crate) async fn create_remote(
    borrower_wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
    add_amount_sompi: u64,
    fee: u64,
    websocket_url: &str,
) -> Result<DepositSummary, String> {
    let needed = required_funding(add_amount_sompi, fee)?;
    let plan = plan::prepare(
        borrower_wallet_json,
        covenant_address,
        redeem_script_hex,
        needed,
        websocket_url,
    )
    .await?;
    build_deposit(&plan, add_amount_sompi, fee)
}

fn required_funding(add_amount_sompi: u64, fee: u64) -> Result<u64, String> {
    add_amount_sompi
        .checked_add(fee)
        .ok_or_else(|| "Deposit amount plus fee overflows u64".to_string())
}

pub(crate) fn build_deposit(
    plan: &plan::BorrowerPlan,
    add_amount_sompi: u64,
    fee: u64,
) -> Result<DepositSummary, String> {
    let needed = required_funding(add_amount_sompi, fee)?;
    if plan.funding_total < needed {
        return Err("Borrower funding is below the required deposit and fee".to_string());
    }
    let covenant_output = plan
        .covenant
        .amount
        .checked_add(add_amount_sompi)
        .ok_or_else(|| "Covenant output amount overflows u64".to_string())?;
    let change = plan.funding_total - needed;
    let outputs = deposit_outputs(plan, covenant_output, change)?;
    let funding_count = plan.funding.len();
    let input_count = funding_count
        .checked_add(1)
        .ok_or_else(|| "Deposit input count overflows usize".to_string())?;
    let wire = plan::encode_pskb(
        deposit_global(input_count, outputs.len()),
        plan.inputs(),
        serde_json::Value::Array(outputs),
    )?;
    Ok(DepositSummary {
        wire,
        funding_count,
        covenant_output,
        change,
    })
}

fn deposit_outputs(
    plan: &plan::BorrowerPlan,
    covenant_output: u64,
    change: u64,
) -> Result<Vec<serde_json::Value>, String> {
    let mut outputs = vec![serde_json::json!({
        "amount": covenant_output,
        "scriptPublicKey": plan.covenant_spk_hex.as_str(),
        "bip32Derivations": [],
        "proprietaries": []
    })];
    if let Some(change) = core::num::NonZeroU64::new(change) {
        outputs.push(serde_json::json!({
            "amount": change.get(),
            "scriptPublicKey": plan.change_script()?,
            "bip32Derivations": [],
            "proprietaries": []
        }));
    }
    Ok(outputs)
}

fn deposit_global(input_count: usize, output_count: usize) -> serde_json::Value {
    serde_json::json!({
        "txVersion": 0,
        "fallbackLockTime": null,
        "inputsModifiableFlag": false,
        "outputsModifiableFlag": false,
        "inputCount": input_count,
        "outputCount": output_count,
        "bip32Derivations": [],
        "proprietaries": []
    })
}
