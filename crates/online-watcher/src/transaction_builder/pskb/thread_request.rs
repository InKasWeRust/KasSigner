//! Domain preparation for single-thread allowance/spending-limit PSKB requests.
//!
//! Browser adapters provide strings and fetched UTXOs. This module owns decoding,
//! address/script validation, covenant policy selection, monetary planning, and
//! final PSKB wire assembly.

use crate::{
    account::{address, utxo::UtxoEntry},
    protocol::script,
};

use super::{
    encode_wire,
    global_thread::{plan_global_thread_withdrawal, GlobalThreadWithdrawalRequest},
    thread_input::{decode_covenant_id, decode_redeem_script, parse_withdrawal_thread_utxos},
    withdrawal_policy_for, GlobalThreadFamily, GlobalThreadPolicy,
};

#[cfg(any(test, target_arch = "wasm32"))]
use super::{
    global_thread::{plan_global_thread_topup, GlobalThreadTopupRequest},
    thread_input::parse_thread_utxo,
    topup_policy_for,
};

pub(crate) struct WithdrawalBuildRequest<'a> {
    pub family: GlobalThreadFamily,
    pub covenant_address: &'a str,
    pub destination_address: &'a str,
    pub redeem_script_hex: &'a str,
    pub covenant_id_hex: &'a str,
    pub withdrawal: u64,
    pub fee: u64,
    pub selected_utxos_json: &'a str,
}

pub(crate) struct PreparedWithdrawal {
    pub wire: String,
    pub input_count: usize,
    pub total: u64,
    pub user_receives: u64,
    pub continuation: u64,
    pub is_close: bool,
    pub csv_sequence: u64,
    pub cltv_lock_time: u64,
    pub covenant_id: [u8; 32],
}

struct WithdrawalMaterial {
    redeem_script: Vec<u8>,
    csv_sequence: u64,
    cltv_lock_time: u64,
    policy: GlobalThreadPolicy,
    covenant_id: [u8; 32],
    thread_utxos: Vec<UtxoEntry>,
    covenant_script: Vec<u8>,
    destination_script: Vec<u8>,
}

pub(crate) fn build_withdrawal(
    request: WithdrawalBuildRequest<'_>,
) -> Result<PreparedWithdrawal, String> {
    let material = prepare_withdrawal_material(&request)?;
    finalize_withdrawal(request, material)
}

fn prepare_withdrawal_material(
    request: &WithdrawalBuildRequest<'_>,
) -> Result<WithdrawalMaterial, String> {
    let redeem_script = decode_redeem_script(request.redeem_script_hex)?;
    let csv_sequence = script::extract_csv_sequence(&redeem_script)?.unwrap_or(0);
    let (cltv_lock_time, policy) = withdrawal_policy_for(request.family, &redeem_script)?;
    Ok(WithdrawalMaterial {
        covenant_id: decode_covenant_id(request.covenant_id_hex)?,
        thread_utxos: parse_withdrawal_thread_utxos(request.selected_utxos_json)?,
        covenant_script: address::address_to_script_pubkey(request.covenant_address)?,
        destination_script: address::address_to_script_pubkey(request.destination_address)?,
        redeem_script,
        csv_sequence,
        cltv_lock_time,
        policy,
    })
}

fn finalize_withdrawal(
    request: WithdrawalBuildRequest<'_>,
    material: WithdrawalMaterial,
) -> Result<PreparedWithdrawal, String> {
    let planned = plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
        thread_utxos: &material.thread_utxos,
        covenant_script_public_key: &material.covenant_script,
        destination_script_public_key: &material.destination_script,
        redeem_script: &material.redeem_script,
        covenant_id: &material.covenant_id,
        withdrawal: request.withdrawal,
        fee: request.fee,
        csv_sequence: material.csv_sequence,
        policy: &material.policy,
    })
    .map_err(|error| error.to_string())?;
    let input_count = planned.plan.inputs.len();
    let wire = encode_wire(&planned.plan)?;
    Ok(PreparedWithdrawal {
        wire,
        input_count,
        total: planned.total,
        user_receives: planned.user_receives,
        continuation: planned.continuation,
        is_close: planned.is_close,
        csv_sequence: material.csv_sequence,
        cltv_lock_time: material.cltv_lock_time,
        covenant_id: material.covenant_id,
    })
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) struct TopupMaterial {
    redeem_script: Vec<u8>,
    csv_sequence: u64,
    policy: GlobalThreadPolicy,
    covenant_id: [u8; 32],
    thread_utxo: UtxoEntry,
    covenant_script: Vec<u8>,
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn prepare_topup_material(
    family: GlobalThreadFamily,
    covenant_address: &str,
    redeem_script_hex: &str,
    covenant_id_hex: &str,
    thread_utxo_json: &str,
) -> Result<TopupMaterial, String> {
    let redeem_script = decode_redeem_script(redeem_script_hex)?;
    let (csv_sequence, policy) = topup_policy_for(family, &redeem_script)?;
    let covenant_id = decode_covenant_id(covenant_id_hex)?;
    let thread_utxo = parse_thread_utxo(thread_utxo_json)?;
    let covenant_script = address::address_to_script_pubkey(covenant_address)?;
    Ok(TopupMaterial {
        redeem_script,
        csv_sequence,
        policy,
        covenant_id,
        thread_utxo,
        covenant_script,
    })
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) struct PreparedTopup {
    pub wire: String,
    pub input_count: usize,
    pub selected_count: usize,
    pub thread_amount: u64,
    pub wallet_total: u64,
    pub continuation: u64,
    pub csv_sequence: u64,
    pub covenant_id: [u8; 32],
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn build_topup(
    material: TopupMaterial,
    selected: Vec<UtxoEntry>,
    fee: u64,
) -> Result<PreparedTopup, String> {
    let selected_count = selected.len();
    let thread_amount = material.thread_utxo.amount;
    let planned = plan_global_thread_topup(GlobalThreadTopupRequest {
        thread_utxo: material.thread_utxo,
        wallet_utxos: &selected,
        covenant_script_public_key: &material.covenant_script,
        redeem_script: &material.redeem_script,
        covenant_id: &material.covenant_id,
        fee,
        policy: &material.policy,
    })
    .map_err(|error| error.to_string())?;
    let input_count = planned.plan.inputs.len();
    let wire = encode_wire(&planned.plan)?;
    Ok(PreparedTopup {
        wire,
        input_count,
        selected_count,
        thread_amount,
        wallet_total: planned.wallet_total,
        continuation: planned.continuation,
        csv_sequence: material.csv_sequence,
        covenant_id: material.covenant_id,
    })
}
