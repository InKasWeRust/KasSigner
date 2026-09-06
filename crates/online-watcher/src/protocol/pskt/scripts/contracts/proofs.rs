// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use crate::protocol::pskt::scripts::{
    first_schnorr_signature, push_data_sigscript, push_int_sigscript, push_redeem_script,
};

fn build_p2sh_zk_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    public_inputs: &[Vec<u8>],
    vk: &[u8],
    stack_prefix: Option<&[u8]>,
    missing_signature: &str,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        missing_signature.to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad owner sig length"),
        "owner sig hex",
    )?;

    let mut sig_script = Vec::with_capacity(1024);
    if let Some(prefix) = stack_prefix {
        push_data_sigscript(&mut sig_script, prefix);
    }
    for input in public_inputs.iter().rev() {
        push_data_sigscript(&mut sig_script, input);
    }
    push_int_sigscript(&mut sig_script, public_inputs.len() as u64);
    push_data_sigscript(&mut sig_script, proof);
    push_data_sigscript(&mut sig_script, vk);
    push_data_sigscript(&mut sig_script, &sig_bytes);
    sig_script.push(0x00);
    push_redeem_script(&mut sig_script, redeem)?;
    Ok(sig_script)
}

pub(crate) fn build_p2sh_zk_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    public_inputs: &[Vec<u8>],
    vk: &[u8],
) -> Result<Vec<u8>, String> {
    build_p2sh_zk_sig_script(
        redeem,
        partial_map,
        proof,
        public_inputs,
        vk,
        None,
        "ZK claim input has no owner signature",
    )
}

pub(crate) fn build_p2sh_bridge_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof: &[u8],
    public_inputs: &[Vec<u8>],
    vk: &[u8],
    withdrawal_spk: &[u8],
) -> Result<Vec<u8>, String> {
    build_p2sh_zk_sig_script(
        redeem,
        partial_map,
        proof,
        public_inputs,
        vk,
        Some(withdrawal_spk),
        "Bridge claim input has no owner signature",
    )
}

fn decode_risc0_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Vec<u8>, String> {
    let hex_str = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing risc0 field: {name}"))?;
    hex::decode(hex_str).map_err(|error| format!("bad hex for {name}: {error}"))
}

fn build_risc0_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    seal: &[u8],
    fields: &serde_json::Map<String, Value>,
    committed_fields: &[&str],
    missing_signature: &str,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, signature) = first_schnorr_signature(
        partial_map,
        missing_signature.to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad owner sig length"),
        "owner sig hex",
    )?;

    let mut script = Vec::with_capacity(seal.len() + redeem.len() + 1024);
    for field_name in ["claim", "controlIndex", "controlDigests"] {
        push_data_sigscript(&mut script, &decode_risc0_field(fields, field_name)?);
    }
    push_data_sigscript(&mut script, seal);
    for field_name in committed_fields {
        push_data_sigscript(&mut script, &decode_risc0_field(fields, field_name)?);
    }
    push_data_sigscript(&mut script, &signature);
    script.push(0x00); // OP_FALSE selects the claim branch.
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}

pub(crate) fn build_p2sh_risc0_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    seal: &[u8],
    fields: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    build_risc0_claim_sig_script(
        redeem,
        partial_map,
        seal,
        fields,
        &["journal", "imageId", "controlId", "hashfn"],
        "RISC0 claim has no owner signature",
    )
}

pub(crate) fn build_p2sh_merkle_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    proof_json: &str,
    dest_spk: &[u8],
) -> Result<Vec<u8>, String> {
    // Parse proof
    let proof: Vec<serde_json::Value> =
        serde_json::from_str(proof_json).map_err(|e| format!("Bad proof JSON: {}", e))?;

    // Get signature
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Merkle claim has no signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        None,
        "sig hex",
    )?;

    let mut ss: Vec<u8> = Vec::with_capacity(1024);

    // Push dest_spk copy (for output verification at end of script)
    push_data_sigscript(&mut ss, dest_spk);

    // Push proof items in reverse order (deepest level first on stack)
    // so they get consumed top-down during verification
    for item in proof.iter().rev() {
        let sibling_hex = item
            .get("sibling")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "proof item missing sibling".to_string())?;
        let direction =
            item.get("direction")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "proof item missing direction".to_string())? as u8;

        let sibling = hex::decode(sibling_hex).map_err(|e| format!("bad sibling hex: {}", e))?;

        push_data_sigscript(&mut ss, &sibling);
        // Push direction as a minimal integer
        if direction == 0 {
            ss.push(0x00); // OP_FALSE = 0
        } else {
            ss.push(0x51); // OP_TRUE = 1
        }
    }

    // Push dest_spk (the leaf — will be hashed by script)
    push_data_sigscript(&mut ss, dest_spk);

    // Push signature
    push_data_sigscript(&mut ss, &sig_bytes);

    // OP_FALSE to select ELSE branch
    ss.push(0x00);

    // Push redeem script
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}

/// Assemble the RISC0 ZK-bridge withdrawal signature script.
/// The redeem script commits the journal, image ID, control ID, and hash function,
/// so this witness supplies only the claim, control index, control digests, seal,
/// owner signature, ELSE selector, and redeem script.
/// Matches the verified tier-6 layout byte-for-byte.
pub(crate) fn build_p2sh_risc0_bridge_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    seal: &[u8],
    fields: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    build_risc0_claim_sig_script(
        redeem,
        partial_map,
        seal,
        fields,
        &[],
        "RISC0 bridge claim has no owner signature",
    )
}

pub(crate) fn build_p2sh_groth16_bridge_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Groth16 bridge claim has no owner signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad owner sig length"),
        "owner sig hex",
    )?;

    let mut ss: Vec<u8> = Vec::with_capacity(redeem.len() + 128);
    push_data_sigscript(&mut ss, &sig_bytes);
    ss.push(0x00); // OP_FALSE -> ELSE
    push_redeem_script(&mut ss, redeem)?;
    Ok(ss)
}
