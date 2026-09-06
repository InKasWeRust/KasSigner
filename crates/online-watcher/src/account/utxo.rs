use serde::{Deserialize, Serialize};

/// Spendable transaction output returned by the Kaspa node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_id: String,
    pub index: u32,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub block_daa_score: u64,
    /// On-chain covenant id for covenant-tagged UTXOs.
    #[serde(default)]
    pub covenant_id: Option<String>,
}
