//! Browser-neutral covenant sweep planning.
//!
//! This is the authoritative application layer for one-source covenant sweeps.
//! WASM adapters may choose an exported operation and translate errors, but UTXO
//! acquisition, monetary validation, lock/branch policy and PSKB construction
//! stay here.

use crate::{
    network,
    transaction_builder::pskb::{
        encode_prepared_sweep, prepare_selected_sweep, prepare_sweep_from_utxos, PreparedSweep,
        PskbGlobalPlan, SweepInputPolicy,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SweepSourceKind {
    Automatic,
    Selected,
}

impl SweepSourceKind {
    #[must_use]
    pub(crate) fn choose<'a>(self, automatic: &'a str, selected: &'a str) -> &'a str {
        match self {
            Self::Automatic => automatic,
            Self::Selected => selected,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CovenantSweepConfig<'a> {
    pub(crate) redeem_script: &'a [u8],
    pub(crate) input_sequence: u64,
    pub(crate) lock_time: u64,
    pub(crate) branch: Option<&'a str>,
    pub(crate) minimum_signatures: Option<u8>,
}

#[derive(Clone, Copy)]
pub(crate) struct CovenantSweepSpec<'a> {
    pub(crate) covenant_address: &'a str,
    pub(crate) destination_address: &'a str,
    pub(crate) fee: u64,
    pub(crate) empty_error: &'a str,
    pub(crate) low_balance_error: &'a str,
    pub(crate) config: CovenantSweepConfig<'a>,
}

pub(crate) fn decode_redeem_script(redeem_script_hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(redeem_script_hex).map_err(|error| format!("Bad redeem hex: {error}"))
}

pub(crate) fn encode_covenant_sweep(
    prepared: &PreparedSweep,
    config: CovenantSweepConfig<'_>,
) -> Result<String, String> {
    let mut global = PskbGlobalPlan::standard().with_lock_time(config.lock_time);
    if let Some(branch) = config.branch {
        global = global.with_branch(branch);
    }

    let mut policy = SweepInputPolicy::covenant(
        config.redeem_script,
        config.input_sequence,
        serde_json::json!([]),
    );
    if let Some(minimum_signatures) = config.minimum_signatures {
        policy.minimum_signatures = minimum_signatures;
    }
    encode_prepared_sweep(prepared, global, &policy)
}

pub(crate) async fn prepare_automatic(
    websocket_url: &str,
    spec: CovenantSweepSpec<'_>,
) -> Result<PreparedSweep, String> {
    let utxos =
        network::queries::utxos::fetch_for_address(websocket_url, spec.covenant_address).await?;
    prepare_sweep_from_utxos(
        utxos,
        spec.covenant_address,
        spec.destination_address,
        spec.fee,
        spec.empty_error,
        spec.low_balance_error,
    )
}

pub(crate) fn prepare_selected(
    utxos_json: &str,
    spec: CovenantSweepSpec<'_>,
) -> Result<PreparedSweep, String> {
    prepare_selected_sweep(
        utxos_json,
        spec.covenant_address,
        spec.destination_address,
        spec.fee,
        spec.empty_error,
        spec.low_balance_error,
    )
}

pub(crate) async fn build_automatic(
    websocket_url: &str,
    spec: CovenantSweepSpec<'_>,
) -> Result<(PreparedSweep, String), String> {
    let prepared = prepare_automatic(websocket_url, spec).await?;
    let wire = encode_covenant_sweep(&prepared, spec.config)?;
    Ok((prepared, wire))
}

pub(crate) fn build_selected(
    utxos_json: &str,
    spec: CovenantSweepSpec<'_>,
) -> Result<(PreparedSweep, String), String> {
    let prepared = prepare_selected(utxos_json, spec)?;
    let wire = encode_covenant_sweep(&prepared, spec.config)?;
    Ok((prepared, wire))
}
