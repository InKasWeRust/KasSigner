//! Merkle whitelist spend transaction planning.

use crate::account::address;

pub(crate) async fn build_remote(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
    proof_json: &str,
    send_amount: u64,
    requested_fee: u64,
    websocket_url: &str,
) -> Result<String, String> {
    let utxos =
        crate::network::queries::utxos::fetch_for_address(websocket_url, covenant_address).await?;
    prepare_merkle_whitelist_spend(MerkleSpendRequest {
        covenant_address,
        destination_address,
        redeem_script_hex,
        proof_json,
        send_amount,
        requested_fee,
        utxos,
    })
}

pub(crate) struct MerkleSpendRequest<'a> {
    pub(crate) covenant_address: &'a str,
    pub(crate) destination_address: &'a str,
    pub(crate) redeem_script_hex: &'a str,
    pub(crate) proof_json: &'a str,
    pub(crate) send_amount: u64,
    pub(crate) requested_fee: u64,
    pub(crate) utxos: Vec<crate::account::utxo::UtxoEntry>,
}

pub(crate) struct PreparedMerkleSpend {
    pub(crate) wire: String,
}

pub(crate) fn prepare_merkle_whitelist_spend(
    mut request: MerkleSpendRequest<'_>,
) -> Result<String, String> {
    let prepared = build_merkle_whitelist_spend(&mut request)?;
    Ok(prepared.wire)
}

pub(crate) fn build_merkle_whitelist_spend(
    request: &mut MerkleSpendRequest<'_>,
) -> Result<PreparedMerkleSpend, String> {
    require_merkle_utxos(&request.utxos).and_then(|()| {
        limit_merkle_utxos(&mut request.utxos);
        parse_merkle_proof(request.proof_json).and_then(|proof| {
            merkle_spend_fee(request.requested_fee, request.utxos.len(), proof.len()).and_then(
                |fee| {
                    merkle_total(&request.utxos).and_then(|total| {
                        validate_merkle_amounts(request.send_amount, fee, total).and_then(
                            |change| {
                                decode_merkle_scripts(
                                    request.covenant_address,
                                    request.destination_address,
                                    request.redeem_script_hex,
                                )
                                .and_then(|scripts| encode_merkle_spend(request, scripts, change))
                            },
                        )
                    })
                },
            )
        })
    })
}

pub(crate) struct MerkleScripts {
    pub(crate) covenant: Vec<u8>,
    pub(crate) destination: Vec<u8>,
    pub(crate) redeem: Vec<u8>,
}

pub(crate) fn require_merkle_utxos(
    utxos: &[crate::account::utxo::UtxoEntry],
) -> Result<(), String> {
    if utxos.is_empty() {
        Err("No UTXOs at covenant address".to_string())
    } else {
        Ok(())
    }
}

pub(crate) fn limit_merkle_utxos(utxos: &mut Vec<crate::account::utxo::UtxoEntry>) {
    const MAX_COVENANT_INPUTS: usize = 4;
    if utxos.len() > MAX_COVENANT_INPUTS {
        crate::transaction_builder::selection::sort_largest_first(utxos);
        utxos.truncate(MAX_COVENANT_INPUTS);
    }
}

pub(crate) fn parse_merkle_proof(value: &str) -> Result<Vec<serde_json::Value>, String> {
    serde_json::from_str(value).map_err(|error| format!("Bad merkle proof JSON: {error}"))
}

pub(crate) fn merkle_total(utxos: &[crate::account::utxo::UtxoEntry]) -> Result<u64, String> {
    utxos.iter().try_fold(0u64, |sum, utxo| {
        sum.checked_add(utxo.amount)
            .ok_or_else(|| "Merkle covenant balance overflow".to_string())
    })
}

fn validate_merkle_amounts(send_amount: u64, fee: u64, total: u64) -> Result<u64, String> {
    require_merkle_send(send_amount).and_then(|()| {
        merkle_required(send_amount, fee)
            .and_then(|required| require_merkle_balance(send_amount, fee, required, total))
    })
}

pub(crate) fn require_merkle_send(send_amount: u64) -> Result<(), String> {
    if send_amount == 0 {
        Err("Send amount must be > 0".to_string())
    } else {
        Ok(())
    }
}

pub(crate) fn merkle_required(send_amount: u64, fee: u64) -> Result<u64, String> {
    send_amount
        .checked_add(fee)
        .ok_or_else(|| "Merkle spend amount overflow".to_string())
}

pub(crate) fn require_merkle_balance(
    send_amount: u64,
    fee: u64,
    required: u64,
    total: u64,
) -> Result<u64, String> {
    if required > total {
        Err(format!(
            "Send {send_amount} + fee {fee} = {required} exceeds balance {total}"
        ))
    } else {
        Ok(total - required)
    }
}

pub(crate) fn decode_merkle_scripts(
    covenant_address: &str,
    destination_address: &str,
    redeem_script_hex: &str,
) -> Result<MerkleScripts, String> {
    address::address_to_script_pubkey(covenant_address).and_then(|covenant| {
        address::address_to_script_pubkey(destination_address).and_then(|destination| {
            hex::decode(redeem_script_hex)
                .map_err(|error| format!("Bad redeem hex: {error}"))
                .map(|redeem| MerkleScripts {
                    covenant,
                    destination,
                    redeem,
                })
        })
    })
}

pub(crate) fn encode_merkle_spend(
    request: &MerkleSpendRequest<'_>,
    scripts: MerkleScripts,
    change: u64,
) -> Result<PreparedMerkleSpend, String> {
    let inputs = merkle_inputs(request, &scripts);
    let outputs = merkle_outputs(
        request.send_amount,
        change,
        &scripts.destination,
        &scripts.covenant,
    );
    let plan = crate::transaction_builder::pskb::PskbPlan {
        global: crate::transaction_builder::pskb::PskbGlobalPlan::standard()
            .with_branch("beneficiary"),
        inputs,
        outputs,
    };
    crate::transaction_builder::pskb::encode_wire(&plan).map(|wire| PreparedMerkleSpend { wire })
}

pub(crate) fn merkle_inputs(
    request: &MerkleSpendRequest<'_>,
    scripts: &MerkleScripts,
) -> Vec<crate::transaction_builder::pskb::PskbInputPlan> {
    let destination_script_hex = format!("0000{}", hex::encode(&scripts.destination));
    request
        .utxos
        .iter()
        .cloned()
        .map(|utxo| {
            crate::transaction_builder::pskb::PskbInputPlan::covenant(
                utxo,
                &scripts.covenant,
                &scripts.redeem,
                crate::transaction_builder::pskb::CovenantInputSettings {
                    sequence: 0,
                    sig_op_count: 1,
                    minimum_signatures: 1,
                    proprietaries: serde_json::json!({
                        "merkleProof": request.proof_json,
                        "merkleDestSpk": destination_script_hex.clone(),
                    }),
                    min_time: serde_json::Value::from(0),
                },
            )
        })
        .collect()
}

pub(crate) fn merkle_outputs(
    send_amount: u64,
    change: u64,
    destination_script: &[u8],
    covenant_script: &[u8],
) -> Vec<crate::transaction_builder::pskb::PskbOutputPlan> {
    let mut outputs = vec![crate::transaction_builder::pskb::PskbOutputPlan::plain(
        send_amount,
        destination_script,
    )];
    if change > 0 {
        outputs.push(crate::transaction_builder::pskb::PskbOutputPlan::plain(
            change,
            covenant_script,
        ));
    }
    outputs
}

pub(crate) fn merkle_spend_fee(
    requested_fee: u64,
    input_count: usize,
    proof_depth: usize,
) -> Result<u64, String> {
    let input_count =
        u64::try_from(input_count).map_err(|_| "Merkle input count overflow".to_string())?;
    let proof_depth =
        u64::try_from(proof_depth).map_err(|_| "Merkle proof depth overflow".to_string())?;
    let per_input_mass = proof_depth
        .checked_mul(40)
        .and_then(|value| value.checked_add(1270))
        .ok_or_else(|| "Merkle mass overflow".to_string())?;
    let compute_mass = input_count
        .checked_mul(per_input_mass)
        .and_then(|value| value.checked_add(769))
        .ok_or_else(|| "Merkle mass overflow".to_string())?;
    let mass_fee = compute_mass
        .checked_mul(115)
        .ok_or_else(|| "Merkle fee overflow".to_string())?;
    Ok(requested_fee.max(mass_fee))
}

#[cfg(test)]
mod unit_tests;
