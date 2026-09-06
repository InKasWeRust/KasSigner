//! Shared preparation for tagged and split vault spends.

use crate::{
    account::{address, utxo::UtxoEntry},
    network,
    serialization::input::decode_pubkey32,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VaultSpendKind {
    Tagged,
    Split,
}

pub(crate) struct VaultSpendMaterial {
    pub redeem_script: Vec<u8>,
    pub split: bool,
}

pub(crate) fn prepare_vault_spend_material(
    kind: VaultSpendKind,
    owner_pubkey_hex: &str,
) -> Result<VaultSpendMaterial, String> {
    let public_key = decode_pubkey32(owner_pubkey_hex)?;
    let redeem_script = match kind {
        VaultSpendKind::Tagged => {
            crate::contracts::vault::script::build_tagged_vault_script(&public_key)
        }
        VaultSpendKind::Split => {
            crate::contracts::vault::script::build_split_vault_script(&public_key)
        }
    };
    Ok(VaultSpendMaterial {
        redeem_script,
        split: matches!(kind, VaultSpendKind::Split),
    })
}

pub(crate) async fn build_vault_spend_pskb(
    kind: VaultSpendKind,
    covenant_address: &str,
    owner_pubkey_hex: &str,
    covenant_id_hex: &str,
    fee: u64,
    network_name: &str,
    websocket_url: &str,
) -> Result<String, String> {
    let material = prepare_vault_spend_material(kind, owner_pubkey_hex)?;
    build_vault_spend_with_material(
        material,
        covenant_address,
        covenant_id_hex,
        fee,
        network_name,
        websocket_url,
    )
    .await
}

async fn build_vault_spend_with_material(
    material: VaultSpendMaterial,
    covenant_address: &str,
    covenant_id_hex: &str,
    fee: u64,
    network_name: &str,
    websocket_url: &str,
) -> Result<String, String> {
    let prepared = prepare(
        covenant_address,
        covenant_id_hex,
        &material.redeem_script,
        fee,
        network_name,
        websocket_url,
    )
    .await?;
    finalize_vault_spend(
        prepared,
        &material.redeem_script,
        material.split,
        covenant_id_hex,
    )
}

pub(crate) struct PreparedVaultSpend {
    pub utxos: Vec<UtxoEntry>,
    pub covenant_id: [u8; 32],
    pub covenant_script_pubkey: Vec<u8>,
    pub spendable: u64,
}

pub(crate) fn decode_covenant_id(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("Bad cov_id hex: {error}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| "covenant_id not 32 bytes".to_string())
}

pub(crate) async fn prepare(
    covenant_address: &str,
    covenant_id_hex: &str,
    redeem_script: &[u8],
    fee: u64,
    network_name: &str,
    websocket_url: &str,
) -> Result<PreparedVaultSpend, String> {
    validate_covenant_address(covenant_address, redeem_script, network_name)?;
    fetch_and_prepare(
        covenant_address,
        covenant_id_hex,
        redeem_script,
        fee,
        network_name,
        websocket_url,
    )
    .await
}

async fn fetch_and_prepare(
    covenant_address: &str,
    covenant_id_hex: &str,
    redeem_script: &[u8],
    fee: u64,
    network_name: &str,
    websocket_url: &str,
) -> Result<PreparedVaultSpend, String> {
    let utxos = network::queries::utxos::fetch_for_address(websocket_url, covenant_address).await?;
    prepare_from_utxos(covenant_id_hex, redeem_script, fee, network_name, utxos)
}

pub(crate) fn validate_covenant_address(
    covenant_address: &str,
    redeem_script: &[u8],
    network_name: &str,
) -> Result<(), String> {
    let derived_address = crate::protocol::script::p2sh::script_to_address(
        redeem_script,
        address::network_prefix(network_name),
    )?;
    if derived_address != covenant_address {
        return Err("Covenant address does not match the supplied redeem script".to_string());
    }
    Ok(())
}

pub(crate) fn prepare_from_utxos(
    covenant_id_hex: &str,
    redeem_script: &[u8],
    fee: u64,
    network_name: &str,
    utxos: Vec<UtxoEntry>,
) -> Result<PreparedVaultSpend, String> {
    if utxos.is_empty() {
        return Err("No UTXOs at covenant address".to_string());
    }
    let derived_address = crate::protocol::script::p2sh::script_to_address(
        redeem_script,
        address::network_prefix(network_name),
    )?;
    let covenant_script_pubkey = address::address_to_script_pubkey(&derived_address)?;
    let covenant_id = decode_covenant_id(covenant_id_hex)?;
    let total = utxos.iter().try_fold(0u64, |sum, utxo| {
        sum.checked_add(utxo.amount)
            .ok_or("Vault balance overflows u64".to_string())
    })?;
    if total <= fee {
        return Err(format!("Balance {total} <= fee {fee}"));
    }
    let spendable = total
        .checked_sub(fee)
        .ok_or("Vault spendable amount underflows fee".to_string())?;
    Ok(PreparedVaultSpend {
        utxos,
        covenant_id,
        covenant_script_pubkey,
        spendable,
    })
}

pub(crate) fn split_vault_amounts(spendable: u64) -> Result<(u64, u64), String> {
    let amount_a = spendable / 2;
    spendable
        .checked_sub(amount_a)
        .map(|amount_b| (amount_a, amount_b))
        .ok_or("Vault split amount underflow".to_string())
}

pub(crate) type EncodedVaultSpend = (String, u64, Option<(u64, u64)>);

pub(crate) fn encode_vault_spend_pskb(
    prepared: PreparedVaultSpend,
    redeem_script: &[u8],
    split: bool,
) -> Result<EncodedVaultSpend, String> {
    use crate::transaction_builder::pskb::{
        encode_wire, CovenantInputSettings, PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan,
    };
    use serde_json::{json, Value};

    if prepared.utxos.len() != 1 {
        return Err(format!(
            "KIP-20 vault continuation requires exactly one covenant UTXO, got {}",
            prepared.utxos.len()
        ));
    }
    let input = PskbInputPlan::covenant(
        prepared.utxos[0].clone(),
        &prepared.covenant_script_pubkey,
        redeem_script,
        CovenantInputSettings {
            sequence: 0,
            sig_op_count: 1,
            minimum_signatures: 1,
            proprietaries: Value::Array(Vec::new()),
            min_time: Value::from(0),
        },
    );
    let binding = json!({
        "authorizingInput": 0,
        "covenantId": hex::encode(prepared.covenant_id),
    });
    let (outputs, split_amounts) = if split {
        let (amount_a, amount_b) = split_vault_amounts(prepared.spendable)?;
        (
            vec![
                PskbOutputPlan::plain(amount_a, &prepared.covenant_script_pubkey)
                    .with_binding_field(binding.clone()),
                PskbOutputPlan::plain(amount_b, &prepared.covenant_script_pubkey)
                    .with_binding_field(binding),
            ],
            Some((amount_a, amount_b)),
        )
    } else {
        (
            vec![
                PskbOutputPlan::plain(prepared.spendable, &prepared.covenant_script_pubkey)
                    .with_binding_field(binding),
            ],
            None,
        )
    };
    let plan = PskbPlan {
        global: PskbGlobalPlan {
            tx_version: 1,
            fallback_lock_time: Value::from(0),
            covenant_branch: None,
            proprietaries: Value::Array(Vec::new()),
            transaction_payload: None,
        },
        inputs: vec![input],
        outputs,
    };
    encode_wire(&plan).map(|wire| (wire, prepared.spendable, split_amounts))
}

pub(crate) fn finalize_vault_spend(
    prepared: PreparedVaultSpend,
    redeem_script: &[u8],
    split: bool,
    covenant_id_hex: &str,
) -> Result<String, String> {
    let encoded = encode_vault_spend_pskb(prepared, redeem_script, split)?;
    encode_vault_spend_response(covenant_id_hex, encoded)
}

pub(crate) fn encode_vault_spend_response(
    covenant_id_hex: &str,
    encoded: EncodedVaultSpend,
) -> Result<String, String> {
    let (pskb_hex, spendable, split_amounts) = encoded;
    let payload = match split_amounts {
        Some((amount_a, amount_b)) => serde_json::json!({
            "pskb_hex": pskb_hex,
            "covenant_id_hex": covenant_id_hex,
            "amount_a": amount_a.to_string(),
            "amount_b": amount_b.to_string(),
        }),
        None => serde_json::json!({
            "pskb_hex": pskb_hex,
            "covenant_id_hex": covenant_id_hex,
            "new_amount": spendable.to_string(),
        }),
    };
    serde_json::to_string(&payload).map_err(|error| error.to_string())
}
