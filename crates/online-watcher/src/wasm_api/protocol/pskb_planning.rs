//! Thin WASM adapter for browser-neutral PSKB sweep application services.

use wasm_bindgen::prelude::JsValue;

use crate::{
    account::utxo::UtxoEntry,
    transaction_builder::pskb::{
        application as core, encode_prepared_sweep as encode_prepared_sweep_core,
        prepare_selected_sweep as prepare_selected_sweep_core,
        prepare_sweep_from_utxos as prepare_sweep_from_utxos_core, PreparedSweep, PskbGlobalPlan,
        SweepInputPolicy,
    },
};

pub fn prepare_sweep_from_utxos(
    utxos: Vec<UtxoEntry>,
    source_address: &str,
    destination_address: &str,
    fee: u64,
    empty_error: &str,
    low_balance_error: &str,
) -> Result<PreparedSweep, JsValue> {
    prepare_sweep_from_utxos_core(
        utxos,
        source_address,
        destination_address,
        fee,
        empty_error,
        low_balance_error,
    )
    .map_err(|error| wasm_error!(&error))
}

#[cfg(test)]
pub(crate) fn prepare_sweep_from_utxos_string(
    utxos: Vec<UtxoEntry>,
    source_address: &str,
    destination_address: &str,
    fee: u64,
    empty_error: &str,
    low_balance_error: &str,
) -> Result<PreparedSweep, String> {
    prepare_sweep_from_utxos_core(
        utxos,
        source_address,
        destination_address,
        fee,
        empty_error,
        low_balance_error,
    )
}

pub fn encode_prepared_sweep(
    prepared: &PreparedSweep,
    global: PskbGlobalPlan,
    input_policy: &SweepInputPolicy,
) -> Result<String, JsValue> {
    encode_prepared_sweep_core(prepared, global, input_policy).map_err(|error| wasm_error!(&error))
}

pub(crate) use crate::transaction_builder::pskb::application::CovenantSweepRequest;

pub async fn build_covenant_sweep(
    request: CovenantSweepRequest<'_>,
) -> Result<(PreparedSweep, String), JsValue> {
    core::build_covenant_sweep(request)
        .await
        .map_err(|error| wasm_error!(&error))
}

pub fn prepare_selected_sweep(
    utxos_json: &str,
    source_address: &str,
    destination_address: &str,
    fee: u64,
    missing_set_error: &str,
    low_balance_error: &str,
) -> Result<PreparedSweep, JsValue> {
    prepare_selected_sweep_string(
        utxos_json,
        source_address,
        destination_address,
        fee,
        missing_set_error,
        low_balance_error,
    )
    .map_err(|error| wasm_error!(&error))
}

pub(crate) fn prepare_selected_sweep_string(
    utxos_json: &str,
    source_address: &str,
    destination_address: &str,
    fee: u64,
    missing_set_error: &str,
    low_balance_error: &str,
) -> Result<PreparedSweep, String> {
    prepare_selected_sweep_core(
        utxos_json,
        source_address,
        destination_address,
        fee,
        missing_set_error,
        low_balance_error,
    )
}
