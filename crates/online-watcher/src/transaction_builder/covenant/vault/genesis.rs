//! Watch-only KIP-20 genesis planners. No private key is accepted here.

use crate::{
    account::{address::network_prefix, bip32::WalletData},
    serialization::input::{decode_pubkey32, parse_json},
    transaction_builder::covenant::{build_with_binding, CovenantBuildRequest, CovenantEncoding},
};

#[derive(Clone, Copy)]
pub(crate) enum VaultGenesisKind {
    Tagged,
    Split,
}

impl VaultGenesisKind {
    fn redeem_script(self, owner: &[u8; 32]) -> Vec<u8> {
        match self {
            Self::Tagged => crate::contracts::vault::script::build_tagged_vault_script(owner),
            Self::Split => crate::contracts::vault::script::build_split_vault_script(owner),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VaultGenesisMaterial {
    pub redeem_script: Vec<u8>,
    pub covenant_address: String,
}

pub(crate) fn prepare_vault_genesis(
    kind: VaultGenesisKind,
    owner: &[u8; 32],
    network: &str,
) -> Result<VaultGenesisMaterial, String> {
    let redeem_script = kind.redeem_script(owner);
    crate::protocol::script::p2sh::script_to_address(&redeem_script, network_prefix(network)).map(
        |covenant_address| VaultGenesisMaterial {
            redeem_script,
            covenant_address,
        },
    )
}

pub(crate) struct PreparedVaultGenesisRequest {
    pub material: VaultGenesisMaterial,
    pub wallet: WalletData,
    pub change_address: String,
}

pub(crate) fn prepare_vault_genesis_request(
    kind: VaultGenesisKind,
    wallet_json: &str,
    owner_pubkey_hex: &str,
    network: &str,
) -> Result<PreparedVaultGenesisRequest, String> {
    let owner = decode_pubkey32(owner_pubkey_hex)?;
    let material = prepare_vault_genesis(kind, &owner, network)?;
    let wallet: WalletData = parse_json(wallet_json, "Bad wallet JSON")?;
    let change_address = wallet
        .change_addresses
        .first()
        .cloned()
        .ok_or("Watch-only wallet has no change address".to_string())?;
    Ok(PreparedVaultGenesisRequest {
        material,
        wallet,
        change_address,
    })
}

pub(crate) async fn build_vault_genesis_pskb(
    kind: VaultGenesisKind,
    wallet_json: &str,
    owner_pubkey_hex: &str,
    send_amount: u64,
    fee: u64,
    network: &str,
    ws_url: &str,
) -> Result<String, String> {
    let prepared = prepare_vault_genesis_request(kind, wallet_json, owner_pubkey_hex, network)?;
    build_vault_genesis_wire(&prepared, send_amount, fee, ws_url)
        .await
        .and_then(|result| finalize_vault_genesis(&prepared.material, send_amount, result))
}

async fn build_vault_genesis_wire(
    prepared: &PreparedVaultGenesisRequest,
    send_amount: u64,
    fee: u64,
    ws_url: &str,
) -> Result<(String, Option<[u8; 32]>), String> {
    build_with_binding(CovenantBuildRequest {
        wallet: &prepared.wallet,
        covenant_address: &prepared.material.covenant_address,
        covenant_type: "vault",
        send_amount,
        fee,
        change_address: &prepared.change_address,
        utxo_indices_csv: "",
        websocket_url: ws_url,
        encoding: CovenantEncoding::BoundGenesis,
    })
    .await
}

pub(crate) fn finalize_vault_genesis(
    material: &VaultGenesisMaterial,
    send_amount: u64,
    result: (String, Option<[u8; 32]>),
) -> Result<String, String> {
    match result.1 {
        Some(covenant_id) => {
            encode_vault_genesis_response(material, send_amount, &result.0, covenant_id)
        }
        None => Err("Tagged vault genesis did not produce a covenant ID".to_string()),
    }
}

pub(crate) fn encode_vault_genesis_response(
    material: &VaultGenesisMaterial,
    send_amount: u64,
    pskb_hex: &str,
    covenant_id: [u8; 32],
) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({
        "pskb_hex": pskb_hex,
        "covenant_id_hex": hex::encode(covenant_id),
        "covenant_address": material.covenant_address,
        "redeem_script_hex": hex::encode(&material.redeem_script),
        "send_amount": send_amount.to_string(),
    }))
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod unit_tests;
