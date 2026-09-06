use crate::contracts::zk::crowdfund::{decode_hex, versioned_spk};
use crate::{
    account::{address, utxo::UtxoEntry},
    contracts::{
        crowdfund::script::{
            crowdfund_redeem_script, CrowdfundScript, CROWDFUND_MAX_CONTRIBUTORS,
            CROWDFUND_MAX_SWEEP_FEE_SOMPI, CROWDFUND_MAX_TX_INPUTS, CROWDFUND_SIG_OP_COUNT,
        },
        zk::{cost, proof},
    },
    network,
    protocol::{
        script::{p2sh, push_data},
        transaction::consensus::{
            ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding,
        },
    },
    serialization::input::decode_pubkey32,
};
use serde::Deserialize;
use std::collections::BTreeSet;

const MAX_CROWDFUND_VK_BYTES: usize = 16_384;
const MAX_CROWDFUND_PROOF_BYTES: usize = 1_024;
const MAX_CROWDFUND_PUBLIC_INPUT_BYTES: usize = 64;

#[derive(Clone, Deserialize)]
pub(crate) struct ContributionRef {
    pub address: String,
    pub contributor_pubkey_hex: String,
    pub redeem_script_hex: String,
    pub crowdfund_salt_hex: String,
}

pub(crate) struct CrowdfundSweepRequest<'a> {
    pub contributions_json: &'a str,
    pub organizer_address: &'a str,
    pub goal_sompi: u64,
    pub locktime_daa: u64,
    pub verifying_key_hex: &'a str,
    pub proof_hex: &'a str,
    pub public_input_hex: &'a str,
    pub requested_fee: u64,
    pub fetched: Vec<(ContributionRef, Vec<UtxoEntry>)>,
}

pub(crate) async fn inspect_crowdfund_contributions_string(
    contributions_json: &str,
    ws_url: &str,
) -> Result<String, String> {
    let fetched = fetch_contributions_json(contributions_json, ws_url).await?;
    summarize_contributions(fetched)
}

pub(super) fn summarize_contributions(
    fetched: Vec<(ContributionRef, Vec<UtxoEntry>)>,
) -> Result<String, String> {
    let mut totals = Vec::with_capacity(fetched.len());
    let mut grand_total = 0u64;
    let mut input_count = 0usize;
    for (contribution, utxos) in fetched {
        let total = checked_total(&utxos)?;
        grand_total = grand_total
            .checked_add(total)
            .ok_or_else(|| "Crowdfund total overflow".to_string())?;
        input_count = input_count
            .checked_add(utxos.len())
            .ok_or_else(|| "Crowdfund input count overflow".to_string())?;
        totals.push(serde_json::json!({
            "address": contribution.address,
            "amount_sompi": total.to_string(),
            "utxo_count": utxos.len(),
        }));
    }
    serde_json::to_string(&serde_json::json!({
        "contributions": totals,
        "total_sompi": grand_total.to_string(),
        "input_count": input_count,
    }))
    .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_crowdfund_sweep_string(
    contributions_json: &str,
    organizer_address: &str,
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hex: &str,
    proof_hex: &str,
    public_input_hex: &str,
    requested_fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    let fetched = fetch_contributions_json(contributions_json, ws_url).await?;
    submit_crowdfund_sweep(
        CrowdfundSweepRequest {
            contributions_json,
            organizer_address,
            goal_sompi,
            locktime_daa,
            verifying_key_hex,
            proof_hex,
            public_input_hex,
            requested_fee,
            fetched,
        },
        ws_url,
    )
    .await
}

async fn submit_crowdfund_sweep(
    request: CrowdfundSweepRequest<'_>,
    ws_url: &str,
) -> Result<String, String> {
    let transaction = prepare_crowdfund_sweep(request)?;
    network::submission::submit(ws_url, &transaction).await
}

async fn fetch_contributions_json(
    contributions_json: &str,
    ws_url: &str,
) -> Result<Vec<(ContributionRef, Vec<UtxoEntry>)>, String> {
    let contributions = parse_contributions(contributions_json)?;
    fetch_contributions(&contributions, ws_url).await
}

pub(crate) fn prepare_crowdfund_sweep(
    request: CrowdfundSweepRequest<'_>,
) -> Result<ConsensusTransaction, String> {
    let contributions = parse_contributions(request.contributions_json)?;
    if contributions.len() != request.fetched.len() {
        return Err("Crowdfunding contribution set changed during preparation".to_string());
    }
    let material = verified_sweep_material(&request)?;
    let storage_inputs = request
        .fetched
        .iter()
        .flat_map(|(_, utxos)| utxos.iter())
        .map(|utxo| {
            (
                utxo.amount,
                crate::transaction_builder::planning::amounts::utxo_plurality(
                    utxo.script_public_key.len(),
                    utxo.covenant_id.is_some(),
                ),
            )
        })
        .collect::<Vec<_>>();
    let (inputs, actual_total) = build_campaign_inputs(&request, &material)?;
    validate_sweep_totals(
        actual_total,
        request.goal_sompi,
        inputs.len(),
        &material.public_input,
    )?;
    let fee = calculate_fee(request.requested_fee, inputs.len())?;
    let send_amount = actual_total
        .checked_sub(fee)
        .ok_or_else(|| "Crowdfunding balance does not cover its fee".to_string())?;
    let output = ConsensusOutput {
        value: send_amount,
        spk_version: 0,
        spk_script: material.organizer_script,
        covenant: None,
    };
    let storage_outputs = [(
        output.value,
        crate::transaction_builder::planning::amounts::utxo_plurality(
            output.spk_script.len(),
            false,
        ),
    )];
    let storage_mass = crate::transaction_builder::planning::amounts::storage_mass_estimate(
        &storage_inputs,
        &storage_outputs,
    )?;
    Ok(ConsensusTransaction {
        tx_version: 0,
        input_encoding: InputEncoding::Compact,
        inputs,
        outputs: vec![output],
        locktime: 0,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: Vec::new(),
        storage_mass,
    })
}

struct VerifiedSweepMaterial {
    verifying_key: Vec<u8>,
    proof_bytes: Vec<u8>,
    public_input: Vec<u8>,
    organizer_script: Vec<u8>,
    organizer_output_spk: Vec<u8>,
    verifying_key_hash: [u8; 32],
}

fn verified_sweep_material(
    request: &CrowdfundSweepRequest<'_>,
) -> Result<VerifiedSweepMaterial, String> {
    let verifying_key = decode_hex_bounded(
        request.verifying_key_hex,
        "crowdfunding verifying key",
        MAX_CROWDFUND_VK_BYTES,
    )?;
    let proof_bytes = decode_hex_bounded(
        request.proof_hex,
        "crowdfunding proof",
        MAX_CROWDFUND_PROOF_BYTES,
    )?;
    let public_input = decode_hex_bounded(
        request.public_input_hex,
        "crowdfunding public input",
        MAX_CROWDFUND_PUBLIC_INPUT_BYTES,
    )?;
    if !proof::verify_proof(&verifying_key, &proof_bytes, &public_input)? {
        return Err("Crowdfunding proof is invalid".to_string());
    }
    let organizer_script = address::address_to_script_pubkey(request.organizer_address)?;
    let organizer_output_spk = versioned_spk(&organizer_script);
    let verifying_key_hash = p2sh::blake2b_hash(&verifying_key);
    Ok(VerifiedSweepMaterial {
        verifying_key,
        proof_bytes,
        public_input,
        organizer_script,
        organizer_output_spk,
        verifying_key_hash,
    })
}

fn build_campaign_inputs(
    request: &CrowdfundSweepRequest<'_>,
    material: &VerifiedSweepMaterial,
) -> Result<(Vec<ConsensusInput>, u64), String> {
    let mut inputs = Vec::new();
    let mut actual_total = 0u64;
    for (reference, utxos) in &request.fetched {
        let canonical = canonical_redeem(
            reference,
            request.goal_sompi,
            request.locktime_daa,
            &material.verifying_key_hash,
            &material.organizer_output_spk,
        )?;
        validate_canonical_contribution(reference, &canonical)?;
        let expected_spk = address::address_to_script_pubkey(&reference.address)?;
        for utxo in utxos {
            if utxo.script_public_key != expected_spk {
                return Err(
                    "Crowdfunding UTXO script does not match its contribution address".to_string(),
                );
            }
            actual_total = actual_total
                .checked_add(utxo.amount)
                .ok_or_else(|| "Crowdfunding transaction total overflow".to_string())?;
            inputs.push(build_input(
                utxo,
                &material.public_input,
                &material.proof_bytes,
                &material.verifying_key,
                &canonical,
            )?);
        }
    }
    Ok((inputs, actual_total))
}

fn validate_canonical_contribution(
    reference: &ContributionRef,
    canonical: &[u8],
) -> Result<(), String> {
    let expected_address = p2sh::script_to_address(canonical, address_prefix(&reference.address)?)?;
    let canonical_hex = hex::encode(canonical);
    if expected_address != reference.address
        || canonical_hex != reference.redeem_script_hex.to_ascii_lowercase()
    {
        return Err(
            "Crowdfunding contribution does not match the canonical campaign covenant".to_string(),
        );
    }
    Ok(())
}

fn parse_contributions(value: &str) -> Result<Vec<ContributionRef>, String> {
    let contributions: Vec<ContributionRef> = serde_json::from_str(value)
        .map_err(|error| format!("Invalid crowdfunding contribution JSON: {error}"))?;
    if contributions.is_empty() || contributions.len() > CROWDFUND_MAX_CONTRIBUTORS {
        return Err(format!(
            "Crowdfunding requires 1..={CROWDFUND_MAX_CONTRIBUTORS} contribution addresses"
        ));
    }
    let mut unique = BTreeSet::new();
    if contributions
        .iter()
        .any(|entry| !unique.insert(entry.address.clone()))
    {
        return Err("Duplicate crowdfunding contribution address".to_string());
    }
    Ok(contributions)
}

pub(super) async fn fetch_contributions(
    contributions: &[ContributionRef],
    ws_url: &str,
) -> Result<Vec<(ContributionRef, Vec<UtxoEntry>)>, String> {
    let mut fetched = Vec::with_capacity(contributions.len());
    for contribution in contributions {
        let utxos =
            network::queries::utxos::fetch_for_address(ws_url, &contribution.address).await?;
        fetched.push(require_nonempty_contribution(contribution, utxos)?);
    }
    Ok(fetched)
}

fn require_nonempty_contribution(
    contribution: &ContributionRef,
    utxos: Vec<UtxoEntry>,
) -> Result<(ContributionRef, Vec<UtxoEntry>), String> {
    if utxos.is_empty() {
        return Err(format!(
            "No UTXOs at crowdfunding address {}",
            contribution.address
        ));
    }
    Ok((contribution.clone(), utxos))
}

fn canonical_redeem(
    reference: &ContributionRef,
    goal: u64,
    locktime: u64,
    vk_hash: &[u8; 32],
    organizer_spk: &[u8],
) -> Result<Vec<u8>, String> {
    let contributor = decode_pubkey32(&reference.contributor_pubkey_hex)?;
    let salt_bytes = decode_hex(&reference.crowdfund_salt_hex, "crowdfunding salt")?;
    let salt: [u8; 8] = salt_bytes
        .try_into()
        .map_err(|_| "Crowdfunding salt must be 8 bytes".to_string())?;
    crowdfund_redeem_script(CrowdfundScript {
        contributor_pubkey: &contributor,
        goal_sompi: goal,
        locktime_daa: locktime,
        verifying_key_hash: vk_hash,
        organizer_output_spk: organizer_spk,
        salt: &salt,
    })
}

fn build_input(
    utxo: &UtxoEntry,
    public_input: &[u8],
    proof_bytes: &[u8],
    verifying_key: &[u8],
    redeem: &[u8],
) -> Result<ConsensusInput, String> {
    let prev_tx_id: [u8; 32] = hex::decode(&utxo.tx_id)
        .map_err(|error| format!("Invalid crowdfunding UTXO txid: {error}"))?
        .try_into()
        .map_err(|_| "Crowdfunding UTXO txid must be 32 bytes".to_string())?;
    let mut sig_script = Vec::with_capacity(
        public_input.len() + proof_bytes.len() + verifying_key.len() + redeem.len() + 24,
    );
    push_data(&mut sig_script, public_input);
    sig_script.push(crate::protocol::script::opcode::OP_1);
    push_data(&mut sig_script, proof_bytes);
    push_data(&mut sig_script, verifying_key);
    sig_script.push(crate::protocol::script::opcode::OP_0);
    push_data(&mut sig_script, redeem);
    Ok(ConsensusInput {
        prev_tx_id,
        prev_index: utxo.index,
        sig_script,
        sequence: 0,
        sig_op_count: CROWDFUND_SIG_OP_COUNT,
    })
}

fn validate_sweep_totals(
    total: u64,
    goal: u64,
    input_count: usize,
    public_input: &[u8],
) -> Result<(), String> {
    if total < goal {
        return Err("Crowdfunding goal has not been reached".to_string());
    }
    if input_count == 0 || input_count > CROWDFUND_MAX_TX_INPUTS as usize {
        return Err(format!(
            "Crowdfunding sweep supports at most {CROWDFUND_MAX_TX_INPUTS} transaction inputs"
        ));
    }
    if proof::serialize_total(total)? != public_input {
        return Err(
            "Crowdfunding proof public total does not match the actual UTXO total".to_string(),
        );
    }
    Ok(())
}

fn calculate_fee(requested: u64, input_count: usize) -> Result<u64, String> {
    let count = u64::try_from(input_count)
        .map_err(|_| "Crowdfunding input count is too large".to_string())?;
    let floor = cost::groth16_min_fee_sompi(1)
        .checked_mul(count)
        .and_then(|value| value.checked_mul(12))
        .map(|value| value / 10)
        .ok_or_else(|| "Crowdfunding fee estimate overflow".to_string())?;
    let fee = requested.max(floor);
    if fee > CROWDFUND_MAX_SWEEP_FEE_SOMPI {
        return Err(format!(
            "Crowdfunding fee exceeds the on-chain {} sompi safety ceiling",
            CROWDFUND_MAX_SWEEP_FEE_SOMPI
        ));
    }
    Ok(fee)
}

fn checked_total(utxos: &[UtxoEntry]) -> Result<u64, String> {
    utxos.iter().try_fold(0u64, |sum, utxo| {
        sum.checked_add(utxo.amount)
            .ok_or_else(|| "Crowdfunding balance overflow".to_string())
    })
}

fn address_prefix(address: &str) -> Result<&str, String> {
    address
        .split_once(':')
        .map(|(prefix, _)| prefix)
        .ok_or_else(|| "Crowdfunding address is missing a network prefix".to_string())
}

fn decode_hex_bounded(value: &str, field: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if value.len() > max_bytes.saturating_mul(2) {
        return Err(format!("{field} exceeds the supported size limit"));
    }
    decode_hex(value, field)
}

#[cfg(test)]
mod unit_tests;
