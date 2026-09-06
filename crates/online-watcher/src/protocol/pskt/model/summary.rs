// KasSee Web — PSKT review models
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde::{Deserialize, Serialize};

/// One partial signature present on an input.
#[derive(Clone, Serialize, Deserialize)]
pub struct PartialSigInfo {
    pub pubkey_hex: String,
    /// Position in the redeem script, if the public key matched one.
    pub position: Option<u8>,
}

/// One input, as digestible by the review UI.
#[derive(Clone, Serialize, Deserialize)]
pub struct InputSummary {
    pub prev_tx_id: String,
    pub prev_index: u32,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub amount_sompi: u64,
    pub amount_kas: f64,
    pub script_kind: String,
    pub script_hex: String,
    pub redeem_script_hex: Option<String>,
    pub multisig_m: Option<u8>,
    pub multisig_n: Option<u8>,
    pub sigs_present: u8,
    pub partial_sigs: Vec<PartialSigInfo>,
}

/// One transaction output.
#[derive(Clone, Serialize, Deserialize)]
pub struct OutputSummary {
    #[serde(with = "crate::serialization::decimal_u64")]
    pub amount_sompi: u64,
    pub amount_kas: f64,
    pub script_kind: String,
    pub script_hex: String,
    pub address: Option<String>,
    pub derivation_branch: Option<u8>,
    pub derivation_index: Option<u32>,
}

/// Everything the UI needs to render a PSKT review screen.
#[derive(Clone, Serialize, Deserialize)]
pub struct PsktSummary {
    pub format: String,
    pub tx_version: u16,
    pub input_count: usize,
    pub output_count: usize,
    pub inputs: Vec<InputSummary>,
    pub outputs: Vec<OutputSummary>,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub total_in_sompi: u64,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub total_out_sompi: u64,
    #[serde(with = "crate::serialization::decimal_u64")]
    pub fee_sompi: u64,
    pub finalize_ready: bool,
}
