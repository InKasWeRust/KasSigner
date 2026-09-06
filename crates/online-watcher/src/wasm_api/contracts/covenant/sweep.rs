//! Thin WASM adapter for browser-neutral covenant sweep planning.

use wasm_bindgen::prelude::JsValue;

pub(crate) use crate::transaction_builder::covenant::sweep::CovenantSweepConfig;
#[cfg(test)]
pub(crate) use crate::transaction_builder::covenant::sweep::SweepSourceKind;
use crate::transaction_builder::{covenant::sweep as core, pskb::PreparedSweep};

#[derive(Clone, Copy)]
pub(crate) struct CovenantSweepSpec<'a> {
    pub(crate) covenant_address: &'a str,
    pub(crate) destination_address: &'a str,
    pub(crate) fee: u64,
    pub(crate) empty_error: &'a str,
    pub(crate) low_balance_error: &'a str,
    pub(crate) config: CovenantSweepConfig<'a>,
    pub(crate) label: &'a str,
    pub(crate) detail: Option<(&'a str, u64)>,
}

impl<'a> CovenantSweepSpec<'a> {
    fn core(self) -> core::CovenantSweepSpec<'a> {
        core::CovenantSweepSpec {
            covenant_address: self.covenant_address,
            destination_address: self.destination_address,
            fee: self.fee,
            empty_error: self.empty_error,
            low_balance_error: self.low_balance_error,
            config: self.config,
        }
    }
}

pub(super) fn decode_redeem_script(redeem_script_hex: &str) -> Result<Vec<u8>, JsValue> {
    core::decode_redeem_script(redeem_script_hex).map_err(|error| wasm_error!(&error))
}

pub(super) fn encode_covenant_sweep(
    prepared: &PreparedSweep,
    config: CovenantSweepConfig<'_>,
) -> Result<String, JsValue> {
    core::encode_covenant_sweep(prepared, config).map_err(|error| wasm_error!(&error))
}

pub(super) fn finalize_covenant_sweep(
    prepared: &PreparedSweep,
    config: CovenantSweepConfig<'_>,
    label: &str,
    fee: u64,
    detail: Option<(&str, u64)>,
) -> Result<String, JsValue> {
    let wire = encode_covenant_sweep(prepared, config)?;
    log_result(label, prepared, fee, &wire, detail);
    Ok(wire)
}

pub(super) async fn prepare_and_finalize_automatic(
    websocket_url: &str,
    spec: CovenantSweepSpec<'_>,
) -> Result<String, JsValue> {
    let label = spec.label;
    let detail = spec.detail;
    let fee = spec.fee;
    let (prepared, wire) = core::build_automatic(websocket_url, spec.core())
        .await
        .map_err(|error| wasm_error!(&error))?;
    log_result(label, &prepared, fee, &wire, detail);
    Ok(wire)
}

pub(super) fn prepare_and_finalize_selected(
    utxos_json: &str,
    spec: CovenantSweepSpec<'_>,
) -> Result<String, JsValue> {
    let label = spec.label;
    let detail = spec.detail;
    let fee = spec.fee;
    let (prepared, wire) =
        core::build_selected(utxos_json, spec.core()).map_err(|error| wasm_error!(&error))?;
    log_result(label, &prepared, fee, &wire, detail);
    Ok(wire)
}

fn log_result(
    label: &str,
    prepared: &PreparedSweep,
    fee: u64,
    wire: &str,
    detail: Option<(&str, u64)>,
) {
    if let Some(detail) = detail {
        super::logging::log_prepared_sweep_with_detail(label, prepared, fee, wire, detail);
    } else {
        super::logging::log_prepared_sweep(label, prepared, fee, wire);
    }
}
