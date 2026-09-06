use super::request::{decode_heartbeat_covenant_id, PublishRequest};
use crate::account::{address, utxo::UtxoEntry};
use crate::network;

const ORACLE_PUBLISH_CHANGE_DUST: u64 = 20_000;

pub(crate) struct HeartbeatContext {
    pub(crate) redeem_script: Vec<u8>,
    pub(crate) script_public_key: Vec<u8>,
    pub(crate) utxo: UtxoEntry,
}

pub(crate) struct PublishContext {
    pub(crate) request: PublishRequest,
    pub(crate) next_address: String,
    pub(crate) next_script_public_key: Vec<u8>,
    pub(crate) oracle_script_public_key: Vec<u8>,
    pub(crate) oracle_redeem_script: Vec<u8>,
    pub(crate) oracle_utxo: UtxoEntry,
    pub(crate) fee_utxo: UtxoEntry,
    pub(crate) change: u64,
    pub(crate) emit_change: bool,
    pub(crate) heartbeat: Option<HeartbeatContext>,
}

pub(crate) struct HeartbeatTemplate {
    address: String,
    redeem_script: Vec<u8>,
    script_public_key: Vec<u8>,
}

pub(crate) struct PublishTemplate {
    next_address: String,
    next_script_public_key: Vec<u8>,
    oracle_script_public_key: Vec<u8>,
    oracle_redeem_script: Vec<u8>,
    heartbeat: Option<HeartbeatTemplate>,
}

pub(crate) struct PublishSources {
    pub(crate) oracle_utxos: Vec<UtxoEntry>,
    pub(crate) wallet_utxos: Vec<UtxoEntry>,
    pub(crate) heartbeat_utxos: Vec<UtxoEntry>,
}

pub(crate) async fn prepare(request: PublishRequest) -> Result<PublishContext, String> {
    let template = prepare_template(&request)?;
    prepare_oracle_source(request, template).await
}

fn prepare_template(request: &PublishRequest) -> Result<PublishTemplate, String> {
    derive_template(request)
}

async fn prepare_oracle_source(
    request: PublishRequest,
    template: PublishTemplate,
) -> Result<PublishContext, String> {
    let oracle_utxos = fetch_address_utxos(&request.ws_url, &request.oracle_address).await?;
    prepare_wallet_source(request, template, oracle_utxos).await
}

async fn prepare_wallet_source(
    request: PublishRequest,
    template: PublishTemplate,
    oracle_utxos: Vec<UtxoEntry>,
) -> Result<PublishContext, String> {
    let wallet_utxos = fetch_wallet_utxos(&request.ws_url, &request.wallet).await?;
    prepare_heartbeat_source(request, template, oracle_utxos, wallet_utxos).await
}

async fn prepare_heartbeat_source(
    request: PublishRequest,
    template: PublishTemplate,
    oracle_utxos: Vec<UtxoEntry>,
    wallet_utxos: Vec<UtxoEntry>,
) -> Result<PublishContext, String> {
    let heartbeat_utxos =
        fetch_heartbeat_utxos(&request.ws_url, template.heartbeat.as_ref()).await?;
    finish_prepare(
        request,
        template,
        oracle_utxos,
        wallet_utxos,
        heartbeat_utxos,
    )
}

fn finish_prepare(
    request: PublishRequest,
    template: PublishTemplate,
    oracle_utxos: Vec<UtxoEntry>,
    wallet_utxos: Vec<UtxoEntry>,
    heartbeat_utxos: Vec<UtxoEntry>,
) -> Result<PublishContext, String> {
    prepare_from_sources(
        request,
        template,
        PublishSources {
            oracle_utxos,
            wallet_utxos,
            heartbeat_utxos,
        },
    )
}

pub(crate) async fn fetch_address_utxos(
    websocket_url: &str,
    address: &str,
) -> Result<Vec<UtxoEntry>, String> {
    network::queries::utxos::fetch_for_address(websocket_url, address).await
}

pub(crate) async fn fetch_wallet_utxos(
    websocket_url: &str,
    wallet: &crate::account::bip32::WalletData,
) -> Result<Vec<UtxoEntry>, String> {
    network::queries::utxos::fetch_all(websocket_url, wallet).await
}

pub(crate) async fn fetch_heartbeat_utxos(
    websocket_url: &str,
    heartbeat: Option<&HeartbeatTemplate>,
) -> Result<Vec<UtxoEntry>, String> {
    if let Some(template) = heartbeat {
        fetch_address_utxos(websocket_url, &template.address).await
    } else {
        Ok(Vec::new())
    }
}

pub(crate) fn derive_template(request: &PublishRequest) -> Result<PublishTemplate, String> {
    let prefix = crate::account::address::network_prefix(&request.network);
    let heartbeat_cov_id = decode_heartbeat_covenant_id(&request.heartbeat_cov_id_hex)?;
    let next_redeem = crate::contracts::oracle::script::build_oracle_mb_redeem(
        request.new_price,
        request.new_t,
        &request.image_id,
        &request.control_id,
        &request.set_root,
        request.hashfn,
        &heartbeat_cov_id,
    );
    let next_address = crate::protocol::script::p2sh::script_to_address(&next_redeem, prefix)?;
    let next_script_public_key = address::address_to_script_pubkey(&next_address)?;
    let oracle_script_public_key = address::address_to_script_pubkey(&request.oracle_address)?;
    let oracle_redeem_script = hex::decode(&request.redeem_script_hex)
        .map_err(|error| format!("Bad redeem hex: {error}"))?;
    let heartbeat = derive_heartbeat_template(request, prefix)?;

    Ok(PublishTemplate {
        next_address,
        next_script_public_key,
        oracle_script_public_key,
        oracle_redeem_script,
        heartbeat,
    })
}

fn derive_heartbeat_template(
    request: &PublishRequest,
    prefix: &str,
) -> Result<Option<HeartbeatTemplate>, String> {
    if request.omit_heartbeat {
        return Ok(None);
    }
    let redeem_script = crate::contracts::oracle::script::build_oracle_mb_heartbeat_script();
    let address = crate::protocol::script::p2sh::script_to_address(&redeem_script, prefix)?;
    let script_public_key = address::address_to_script_pubkey(&address)?;
    Ok(Some(HeartbeatTemplate {
        address,
        redeem_script,
        script_public_key,
    }))
}

pub(crate) fn prepare_from_sources(
    request: PublishRequest,
    template: PublishTemplate,
    mut sources: PublishSources,
) -> Result<PublishContext, String> {
    let oracle_utxo = select_oracle_utxo(&request.covenant_id_hex, sources.oracle_utxos)?;
    let fee_utxo = select_fee_utxo(request.fee, &mut sources.wallet_utxos)?;
    let change = fee_utxo.amount - request.fee;
    let heartbeat = select_heartbeat(
        &request.heartbeat_cov_id_hex,
        template.heartbeat,
        sources.heartbeat_utxos,
    )?;

    Ok(PublishContext {
        request,
        next_address: template.next_address,
        next_script_public_key: template.next_script_public_key,
        oracle_script_public_key: template.oracle_script_public_key,
        oracle_redeem_script: template.oracle_redeem_script,
        oracle_utxo,
        fee_utxo,
        change,
        emit_change: change >= ORACLE_PUBLISH_CHANGE_DUST,
        heartbeat,
    })
}

fn select_oracle_utxo(covenant_id: &str, utxos: Vec<UtxoEntry>) -> Result<UtxoEntry, String> {
    select_singleton(
        covenant_id,
        utxos,
        "No oracle UTXO carrying this covenant_id at the address (only untagged/foreign UTXOs found); pass the genesis covenant_id",
        "Multiple UTXOs carry this covenant_id; a strict singleton must have exactly one",
    )
}

fn select_heartbeat(
    covenant_id: &str,
    template: Option<HeartbeatTemplate>,
    utxos: Vec<UtxoEntry>,
) -> Result<Option<HeartbeatContext>, String> {
    let Some(template) = template else {
        return Ok(None);
    };
    let utxo = select_singleton(
        covenant_id,
        utxos,
        "No heartbeat UTXO carrying H at the heartbeat address; run heartbeat genesis + fund (tx_version=1) first",
        "Multiple heartbeat UTXOs carry H; a strict singleton must have exactly one",
    )?;
    Ok(Some(HeartbeatContext {
        redeem_script: template.redeem_script,
        script_public_key: template.script_public_key,
        utxo,
    }))
}

fn select_singleton(
    covenant_id: &str,
    utxos: Vec<UtxoEntry>,
    missing: &str,
    multiple: &str,
) -> Result<UtxoEntry, String> {
    let mut matching = utxos
        .into_iter()
        .filter(|utxo| {
            utxo.covenant_id
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(covenant_id))
        })
        .collect::<Vec<_>>();
    match matching.len() {
        0 => Err(missing.to_string()),
        1 => Ok(matching.remove(0)),
        _ => Err(multiple.to_string()),
    }
}

fn select_fee_utxo(fee: u64, utxos: &mut Vec<UtxoEntry>) -> Result<UtxoEntry, String> {
    utxos.retain(|utxo| utxo.covenant_id.is_none());
    crate::transaction_builder::selection::sort_smallest_first(utxos);
    utxos
        .iter()
        .find(|utxo| utxo.amount >= fee)
        .cloned()
        .ok_or_else(|| {
            format!(
                "No single wallet UTXO covers the publish fee {fee} sompi. Consolidate the fee wallet first (one input only: the 222 KB seal leaves little mass headroom under the 500K cap)."
            )
        })
}

#[cfg(test)]
mod unit_tests;
