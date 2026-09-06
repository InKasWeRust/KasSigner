// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use crate::protocol::pskt::scripts::{
    first_schnorr_signature, push_data_sigscript, push_redeem_script,
};

pub(crate) fn build_p2sh_state_machine_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "State machine input has no signature".to_string(),
        "State machine sig missing schnorr field".to_string(),
        None,
        "bad state machine sig hex",
    )?;

    let mut ss: Vec<u8> = Vec::with_capacity(sig_bytes.len() + 2 + redeem.len() + 3);

    // Push signature
    push_data_sigscript(&mut ss, &sig_bytes);

    // Push redeem script
    push_redeem_script(&mut ss, redeem)?;

    Ok(ss)
}
