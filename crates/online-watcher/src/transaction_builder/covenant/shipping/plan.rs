use crate::{
    account::{address, bip32, utxo::UtxoEntry},
    network,
};

pub(crate) struct BorrowerPlan {
    pub wallet: bip32::WalletData,
    pub covenant: UtxoEntry,
    pub funding: Vec<UtxoEntry>,
    pub funding_total: u64,
    pub covenant_spk_hex: String,
    pub redeem_hex: String,
    pub csv_sequence: u64,
}

impl BorrowerPlan {
    pub(crate) fn covenant_input(&self) -> serde_json::Value {
        serde_json::json!({
            "previousOutpoint": {
                "transactionId": self.covenant.tx_id.as_str(),
                "index": self.covenant.index
            },
            "sequence": self.csv_sequence,
            "sigOpCount": 1,
            "utxoEntry": {
                "amount": self.covenant.amount,
                "scriptPublicKey": self.covenant_spk_hex.as_str(),
                "blockDaaScore": 0,
                "isCoinbase": false
            },
            "redeemScript": self.redeem_hex.as_str(),
            "partialSigs": {},
            "minimumSignatures": 0,
            "bip32Derivations": [],
            "proprietaries": [],
            "finalScriptSig": null,
            "minTime": 0
        })
    }

    pub(crate) fn inputs(&self) -> Vec<serde_json::Value> {
        let mut inputs = Vec::with_capacity(1 + self.funding.len());
        inputs.push(self.covenant_input());
        inputs.extend(self.funding.iter().map(funding_input));
        inputs
    }

    pub(crate) fn change_script(&self) -> Result<String, String> {
        indexed_wallet_script(
            &self.wallet.change_addresses,
            self.wallet.next_change_index,
            "change",
        )
    }

    pub(crate) fn receive_script(&self) -> Result<String, String> {
        indexed_wallet_script(
            &self.wallet.receive_addresses,
            self.wallet.next_receive_index,
            "receive",
        )
    }
}

pub(crate) struct PlanRequest {
    wallet: bip32::WalletData,
    covenant_address: String,
    redeem: Vec<u8>,
}

pub(crate) struct PlanSources {
    pub(crate) covenant: Vec<UtxoEntry>,
    pub(crate) funding: Vec<UtxoEntry>,
}

pub(crate) async fn prepare(
    wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
    funding_needed: u64,
    ws_url: &str,
) -> Result<BorrowerPlan, String> {
    let request = parse_plan_request(wallet_json, covenant_address, redeem_script_hex)?;
    let covenant = fetch_covenant_utxos(ws_url, covenant_address).await?;
    let funding = fetch_wallet_utxos(ws_url, &request.wallet).await?;
    build_borrower_plan(request, PlanSources { covenant, funding }, funding_needed)
}

pub(crate) fn parse_plan_request(
    wallet_json: &str,
    covenant_address: &str,
    redeem_script_hex: &str,
) -> Result<PlanRequest, String> {
    crate::serialization::input::parse_json(wallet_json, "Invalid wallet").and_then(|wallet| {
        hex::decode(redeem_script_hex)
            .map_err(|error| format!("Bad redeem hex: {error}"))
            .map(|redeem| PlanRequest {
                wallet,
                covenant_address: covenant_address.to_string(),
                redeem,
            })
    })
}

pub(crate) async fn fetch_covenant_utxos(
    ws_url: &str,
    covenant_address: &str,
) -> Result<Vec<UtxoEntry>, String> {
    network::queries::utxos::fetch_for_address(ws_url, covenant_address).await
}

pub(crate) async fn fetch_wallet_utxos(
    ws_url: &str,
    wallet: &bip32::WalletData,
) -> Result<Vec<UtxoEntry>, String> {
    network::queries::utxos::fetch_all(ws_url, wallet).await
}

pub(crate) fn build_borrower_plan(
    request: PlanRequest,
    sources: PlanSources,
    funding_needed: u64,
) -> Result<BorrowerPlan, String> {
    build_plan_from_sources(
        request.wallet,
        &request.covenant_address,
        request.redeem,
        sources.covenant,
        sources.funding,
        funding_needed,
    )
}

pub(crate) fn build_plan_from_sources(
    wallet: bip32::WalletData,
    covenant_address: &str,
    redeem: Vec<u8>,
    covenant: Vec<UtxoEntry>,
    funding: Vec<UtxoEntry>,
    funding_needed: u64,
) -> Result<BorrowerPlan, String> {
    let covenant_utxo = largest_covenant_utxo(covenant)?;
    let (funding, funding_total) = select_funding(funding, funding_needed)?;
    let covenant_spk_hex = script_pubkey_hex(covenant_address)?;
    let csv_sequence = crate::protocol::script::extract_csv_sequence(&redeem)?.unwrap_or(0);
    Ok(BorrowerPlan {
        wallet,
        covenant: covenant_utxo,
        funding,
        funding_total,
        covenant_spk_hex,
        redeem_hex: hex::encode(redeem),
        csv_sequence,
    })
}

fn largest_covenant_utxo(utxos: Vec<UtxoEntry>) -> Result<UtxoEntry, String> {
    utxos
        .into_iter()
        .max_by_key(|utxo| utxo.amount)
        .ok_or_else(|| "No UTXOs at covenant address".to_string())
}

fn select_funding(available: Vec<UtxoEntry>, needed: u64) -> Result<(Vec<UtxoEntry>, u64), String> {
    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in available {
        if total >= needed {
            break;
        }
        total = total
            .checked_add(utxo.amount)
            .ok_or_else(|| "Borrower funding total overflows u64".to_string())?;
        selected.push(utxo);
    }
    if total < needed {
        return Err(format!(
            "Borrower needs {needed} sompi but only has {total}"
        ));
    }
    Ok((selected, total))
}

fn script_pubkey_hex(value: &str) -> Result<String, String> {
    let script = address::address_to_script_pubkey(value)?;
    Ok(format!("0000{}", hex::encode(script)))
}

fn indexed_wallet_script(
    addresses: &[String],
    next_index: usize,
    label: &str,
) -> Result<String, String> {
    let last = addresses
        .len()
        .checked_sub(1)
        .ok_or_else(|| format!("Wallet has no {label} addresses"))?;
    script_pubkey_hex(&addresses[next_index.min(last)])
}

fn funding_input(utxo: &UtxoEntry) -> serde_json::Value {
    serde_json::json!({
        "previousOutpoint": {
            "transactionId": utxo.tx_id.as_str(),
            "index": utxo.index
        },
        "sequence": 0,
        "sigOpCount": 1,
        "utxoEntry": {
            "amount": utxo.amount,
            "scriptPublicKey": format!("0000{}", hex::encode(&utxo.script_public_key)),
            "blockDaaScore": 0,
            "isCoinbase": false
        },
        "redeemScript": null,
        "partialSigs": {},
        "minimumSignatures": 1,
        "bip32Derivations": [],
        "proprietaries": [],
        "finalScriptSig": null,
        "minTime": 0
    })
}

pub(crate) fn encode_pskb(
    global: serde_json::Value,
    inputs: Vec<serde_json::Value>,
    outputs: serde_json::Value,
) -> Result<String, String> {
    crate::transaction_builder::pskb::encode_pskt_value(serde_json::json!({
        "global": global,
        "inputs": inputs,
        "outputs": outputs
    }))
}

#[cfg(test)]
mod unit_tests;
