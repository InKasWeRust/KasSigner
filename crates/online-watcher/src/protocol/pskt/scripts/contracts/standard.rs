// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use crate::{
    protocol::pskt::scripts::{first_schnorr_signature, push_data_sigscript, push_redeem_script},
    protocol::script::walk::contains_opcode_pair,
};

use crate::protocol::pskt::scripts::common::strip_optional_covenant_salt;

pub(crate) fn compute_genesis_covenant_id(
    prev_tx_id: &[u8; 32],
    prev_index: u32,
    output_index: u32,
    output_value: u64,
    spk_version: u16,
    spk_script: &[u8],
) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"CovenantID")
        .to_state()
        .update(prev_tx_id)
        .update(&prev_index.to_le_bytes())
        .update(&1u64.to_le_bytes())
        .update(&output_index.to_le_bytes())
        .update(&output_value.to_le_bytes())
        .update(&spk_version.to_le_bytes())
        .update(&(spk_script.len() as u64).to_le_bytes())
        .update(spk_script)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

pub(crate) fn build_p2sh_covenant_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    force_time_path: bool,
) -> Result<Vec<u8>, String> {
    let (pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Covenant input has no signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        None,
        "sig hex",
    )?;
    let body = covenant_body(redeem);
    let use_if_branch = signer_uses_if_branch(body, pk_hex);
    let nested = covenant_has_nested_if(body);
    let mut sig_script = Vec::with_capacity(sig_bytes.len() + redeem.len() + 10);
    append_covenant_branch(
        &mut sig_script,
        &sig_bytes,
        use_if_branch,
        nested,
        force_time_path,
    );
    push_redeem_script(&mut sig_script, redeem)?;
    Ok(sig_script)
}

fn covenant_body(redeem: &[u8]) -> &[u8] {
    strip_optional_covenant_salt(redeem)
}

fn signer_uses_if_branch(body: &[u8], pk_hex: &str) -> bool {
    let owner = match (body.first(), body.get(1), body.get(2..34)) {
        (Some(0x63), Some(0x20), Some(owner)) => owner,
        _ => return true,
    };
    let encoded = if pk_hex.len() == 66 {
        &pk_hex[2..]
    } else {
        pk_hex
    };
    hex::decode(encoded).is_ok_and(|signer| signer.as_slice() == owner)
}

fn covenant_has_nested_if(body: &[u8]) -> bool {
    matches!((body.get(34), body.get(35)), (Some(0xad), Some(0x63)))
}

fn append_covenant_branch(
    sig_script: &mut Vec<u8>,
    sig_bytes: &[u8],
    use_if_branch: bool,
    nested: bool,
    force_time_path: bool,
) {
    if use_if_branch && nested {
        sig_script.push(if force_time_path { 0x00 } else { 0x51 });
    }
    sig_script.push(sig_bytes.len() as u8);
    sig_script.extend_from_slice(sig_bytes);
    sig_script.push(if use_if_branch { 0x51 } else { 0x00 });
}

pub(crate) fn build_p2sh_covenant_borrower_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    // Beneficiary/borrower spend: <sig||sighash> [branch_selectors] <redeem_script>
    // Simple 2-branch (vault): <sig> OP_FALSE <redeem>
    // Nested 3-branch (time-locked escrow, inner IF): <sig> OP_TRUE OP_FALSE <redeem>
    // Detect nesting by counting OP_ENDIF (0x68) bytes.

    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Beneficiary input has no signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad sig length"),
        "sig hex",
    )?;

    // Decide whether the spender must supply an INNER branch selector.
    //
    // Some covenants nest a spender-selected inner branch directly inside the
    // outer OP_ELSE (the time-locked escrow: outer ELSE -> inner OP_IF chooses
    // release-vs-refund). Those need <sig> OP_TRUE OP_FALSE <redeem>.
    //
    // Others have an inner OP_IF that is NOT spender-selected: the script itself
    // computes the condition and feeds OP_IF from the stack (e.g. the global
    // allowance, whose inner IF tests OP_COV_OUTPUT_COUNT == 1). Those have two
    // OP_ENDIFs but must NOT receive an inner selector, or the extra byte sits
    // between the signature and CHECKSIGVERIFY and the node rejects it as a
    // "malformed signature".
    //
    // The precise signal is a top-level OP_ELSE (0x67) immediately followed by
    // OP_IF (0x63): an inner branch the spender chooses. Walk opcodes (skipping
    // push data) so a 0x67/0x63 byte inside pushed data is never mistaken for an
    // opcode. Counting OP_ENDIF is too coarse and misclassifies stack-driven
    // inner IFs like the global allowance.
    let nested = contains_opcode_pair(redeem, 0x67, 0x63);

    let mut sig_script: Vec<u8> = Vec::with_capacity(66 + 3 + redeem.len() + 3);

    // Push signature (65 bytes: 64-byte Schnorr + 1-byte sighash)
    sig_script.push(65u8);
    sig_script.extend_from_slice(&sig_bytes);

    if nested {
        // Nested: OP_TRUE (inner IF) then OP_FALSE (outer ELSE)
        sig_script.push(0x51); // OP_TRUE
    }
    // OP_FALSE to select outer ELSE branch
    sig_script.push(0x00);

    // Push redeem script (supports >255 bytes via OP_PUSHDATA2)
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

pub(crate) fn build_p2sh_treasury_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    // Get the single signature
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Treasury input has no signature".to_string(),
        "Treasury sig missing schnorr field".to_string(),
        None,
        "bad treasury sig hex",
    )?;

    let mut sig_script: Vec<u8> = Vec::with_capacity(sig_bytes.len() + 2 + redeem.len() + 2);

    // Push signature (64 bytes sig + 1 byte sighash type = 65)
    sig_script.push(sig_bytes.len() as u8);
    sig_script.extend_from_slice(&sig_bytes);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

pub(crate) fn build_p2sh_token_conservation_sig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    let mut sig_script: Vec<u8> = Vec::with_capacity(redeem.len() + 4);
    push_redeem_script(&mut sig_script, redeem)?;
    Ok(sig_script)
}

pub(crate) fn build_p2sh_covenant_nosig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    // Single OP_FALSE selects the ELSE branch for borrower/no-sig covenants.
    // Nested scripts (escrow) use different builders with explicit branch selectors.
    let false_count = 1;

    let mut sig_script: Vec<u8> = Vec::with_capacity(redeem.len() + 5 + false_count);

    // Push OP_FALSE(s) to select ELSE branch(es)
    sig_script.resize(sig_script.len() + false_count, 0x00u8);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

pub(crate) fn build_p2sh_private_swap_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let (_pk, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Private Swap claim missing completed signature".to_string(),
        "Private Swap signature missing schnorr variant".to_string(),
        Some("Private Swap signature length"),
        "Private Swap signature hex",
    )?;
    let mut script = Vec::with_capacity(sig_bytes.len() + redeem.len() + 6);
    push_data_sigscript(&mut script, &sig_bytes);
    script.push(0x51); // OP_TRUE selects adaptor-claim branch.
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}
