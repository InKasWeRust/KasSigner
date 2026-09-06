// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use crate::protocol::pskt::scripts::{
    first_schnorr_signature, push_data_sigscript, push_redeem_script,
};

struct SignatureErrors {
    missing: &'static str,
    bad_length: &'static str,
    hex_label: &'static str,
}

fn signed_rollup_witness(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    prefix: &[u8],
    suffix: &[u8],
    selectors: &[u8],
    errors: SignatureErrors,
) -> Result<Vec<u8>, String> {
    let (_public_key_hex, signature) = first_schnorr_signature(
        partial_map,
        errors.missing.to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some(errors.bad_length),
        errors.hex_label,
    )?;

    let mut script = Vec::with_capacity(
        redeem.len() + proof.len() + prefix.len() + suffix.len() + signature.len() + 64,
    );
    for item in [proof, prefix, suffix, signature.as_slice()] {
        push_data_sigscript(&mut script, item);
    }
    script.extend_from_slice(selectors);
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}

pub(crate) fn build_p2sh_rollup_advance_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, String> {
    signed_rollup_witness(
        redeem,
        partial_map,
        proof,
        prefix,
        suffix,
        &[0x00],
        SignatureErrors {
            missing: "rollup advance has no owner signature",
            bad_length: "bad owner sig length",
            hex_label: "owner sig hex",
        },
    )
}

pub(crate) fn build_p2sh_rollup_unified_advance_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, String> {
    signed_rollup_witness(
        redeem,
        partial_map,
        proof,
        prefix,
        suffix,
        &[0x51, 0x00],
        SignatureErrors {
            missing: "unified advance has no owner signature",
            bad_length: "bad owner sig length",
            hex_label: "owner sig hex",
        },
    )
}

pub(crate) fn build_p2sh_rollup_forced_exit_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>, String> {
    signed_rollup_witness(
        redeem,
        partial_map,
        proof,
        prefix,
        suffix,
        &[0x00, 0x00],
        SignatureErrors {
            missing: "forced exit has no account-owner signature",
            bad_length: "bad exiter sig length",
            hex_label: "exiter sig hex",
        },
    )
}

pub(crate) fn build_p2sh_rollup_refund_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_public_key_hex, signature) = first_schnorr_signature(
        partial_map,
        "rollup refund has no owner signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad owner sig length"),
        "owner sig hex",
    )?;
    let mut script = Vec::with_capacity(redeem.len() + signature.len() + 32);
    push_data_sigscript(&mut script, &signature);
    script.push(0x51);
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}

pub(crate) fn build_p2sh_deposit_holding_credit_sig_script(
    redeem: &[u8],
    vault_prefix: &[u8],
    vault_suffix: &[u8],
) -> Result<Vec<u8>, String> {
    let mut script =
        Vec::with_capacity(redeem.len() + vault_prefix.len() + vault_suffix.len() + 16);
    push_data_sigscript(&mut script, vault_prefix);
    push_data_sigscript(&mut script, vault_suffix);
    script.push(0x00);
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}
