// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use super::first_schnorr_signature;

pub(crate) fn build_p2pk_sig_script(
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "P2PK input has no signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad sig length"),
        "sig hex",
    )?;

    let mut sig_script = Vec::with_capacity(66);
    sig_script.push(65u8);
    sig_script.extend_from_slice(&sig_bytes);
    Ok(sig_script)
}
