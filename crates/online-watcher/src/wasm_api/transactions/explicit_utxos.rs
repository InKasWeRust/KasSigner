use crate::UtxoEntry;
use wasm_bindgen::prelude::JsValue;

#[derive(serde::Deserialize)]
struct ExplicitUtxo {
    tx_id: String,
    index: u64,
    #[serde(with = "crate::serialization::decimal_u64")]
    amount: u64,
    script_public_key: ExplicitScriptPublicKey,
    #[serde(default, with = "crate::serialization::decimal_u64")]
    block_daa_score: u64,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ExplicitScriptPublicKey {
    Bytes(Vec<u64>),
    Hex(String),
}

impl ExplicitUtxo {
    fn into_entry(self) -> Result<UtxoEntry, String> {
        let transaction_id = hex::decode(&self.tx_id)
            .map_err(|error| format!("Invalid UTXO transaction ID: {error}"))?;
        if transaction_id.len() != 32 {
            return Err("UTXO transaction ID must be 32 bytes".to_string());
        }
        let script_public_key = match self.script_public_key {
            ExplicitScriptPublicKey::Bytes(values) => values
                .into_iter()
                .map(|value| {
                    u8::try_from(value)
                        .map_err(|_| "UTXO script_public_key byte exceeds 255".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
            ExplicitScriptPublicKey::Hex(value) => {
                hex::decode(value).map_err(|error| format!("Invalid UTXO script hex: {error}"))?
            }
        };
        if script_public_key.is_empty() {
            return Err("UTXO script_public_key must not be empty".to_string());
        }
        Ok(UtxoEntry {
            tx_id: self.tx_id,
            index: u32::try_from(self.index).map_err(|_| "UTXO index exceeds u32".to_string())?,
            amount: self.amount,
            script_public_key,
            block_daa_score: self.block_daa_score,
            covenant_id: None,
        })
    }
}

pub(crate) fn parse_explicit_utxos_string(utxos_json: &str) -> Result<Vec<UtxoEntry>, String> {
    serde_json::from_str::<Vec<ExplicitUtxo>>(utxos_json)
        .map_err(|error| format!("Bad UTXOs JSON: {error}"))?
        .into_iter()
        .map(ExplicitUtxo::into_entry)
        .collect()
}

pub(super) fn parse_explicit_utxos(utxos_json: &str) -> Result<Vec<UtxoEntry>, JsValue> {
    parse_explicit_utxos_string(utxos_json).map_err(crate::wasm_api::utilities::common::js_error)
}
