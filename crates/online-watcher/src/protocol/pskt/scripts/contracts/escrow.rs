// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use crate::protocol::pskt::scripts::{first_schnorr_signature, push_data_item, push_redeem_script};

pub(crate) fn build_p2sh_escrow_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    branch: &str,
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Escrow input has no signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad sig length"),
        "sig hex",
    )?;

    let mut ss: Vec<u8> = Vec::with_capacity(66 + 8 + redeem.len() + 4);

    match branch {
        "buyer-release" => {
            // <sig> TRUE <redeem>
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L1 IF)
        }
        "seller-refund" => {
            // <sig> TRUE FALSE <redeem>
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L2 IF)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "arbiter-award-seller" => {
            // Stack needed (bottom to top): L4a_sel, <sig>, L3_sel, L2_sel, L1_sel
            // L4a IF selector goes BELOW sig (survives CHECKSIGVERIFY)
            ss.push(0x51); // TRUE (L4a IF = award bob/seller) - pushed first, deepest
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L3 IF = arbiter path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "arbiter-refund-buyer" => {
            // Stack needed (bottom to top): L4a_sel, <sig>, L3_sel, L2_sel, L1_sel
            ss.push(0x00); // FALSE (L4a ELSE = refund alice/buyer) - pushed first, deepest
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L3 IF = arbiter path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "buyer-dispute" => {
            // Stack needed (bottom to top): <sig>, L4b_sel, L3_sel, L2_sel, L1_sel
            // After 3 IF pops: <sig>, L4b_sel. OP_IF pops L4b. CHECKSIGVERIFY gets sig.
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x51); // TRUE (L4b IF = buyer signs)
            ss.push(0x00); // FALSE (L3 ELSE = dispute path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        "seller-dispute" => {
            // Stack needed (bottom to top): <sig>, L4b_sel, L3_sel, L2_sel, L1_sel
            ss.push(65u8);
            ss.extend_from_slice(&sig_bytes);
            ss.push(0x00); // FALSE (L4b ELSE = seller signs)
            ss.push(0x00); // FALSE (L3 ELSE = dispute path)
            ss.push(0x00); // FALSE (L2 ELSE)
            ss.push(0x00); // FALSE (L1 ELSE)
        }
        _ => {
            return Err(format!("Unknown escrow branch: {}", branch));
        }
    }

    push_redeem_script(&mut ss, redeem)?;

    Ok(ss)
}

pub(crate) fn build_p2sh_ship_escrow_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    branch: &str,
) -> Result<Vec<u8>, String> {
    let sig_bytes = ship_escrow_signature(partial_map, branch)?;
    let mut script = Vec::with_capacity(66 + 4 + redeem.len() + 4);
    append_ship_escrow_branch(&mut script, &sig_bytes, branch)?;
    push_redeem_script(&mut script, redeem)?;
    Ok(script)
}

fn ship_escrow_signature(
    partial_map: &serde_json::Map<String, Value>,
    branch: &str,
) -> Result<Vec<u8>, String> {
    if matches!(branch, "state0-timeout" | "state1-timeout") {
        return Ok(Vec::new());
    }
    first_schnorr_signature(
        partial_map,
        format!("ship-escrow branch '{branch}' requires a signature"),
        "partial sig missing schnorr variant".to_string(),
        Some("bad sig length"),
        "sig hex",
    )
    .map(|(_, signature)| signature)
}

fn append_ship_escrow_branch(
    script: &mut Vec<u8>,
    signature: &[u8],
    branch: &str,
) -> Result<(), String> {
    match branch {
        "pickup" => {
            crate::protocol::pskt::scripts::push_data_sigscript(script, signature);
            script.push(0x51);
        }
        "delivery" => {
            crate::protocol::pskt::scripts::push_data_sigscript(script, signature);
            script.extend_from_slice(&[0x51, 0x51]);
        }
        "state0-arb-refund" => {
            crate::protocol::pskt::scripts::push_data_sigscript(script, signature);
            script.extend_from_slice(&[0x51, 0x00]);
        }
        "state0-timeout" => script.extend_from_slice(&[0x00, 0x00]),
        "state1-arb-award" => {
            crate::protocol::pskt::scripts::push_data_sigscript(script, signature);
            script.extend_from_slice(&[0x51, 0x00, 0x51]);
        }
        "state1-timeout" => script.extend_from_slice(&[0x00, 0x00, 0x51]),
        "state1-arb-refund" => {
            crate::protocol::pskt::scripts::push_data_sigscript(script, signature);
            script.push(0x00);
        }
        _ => return Err(format!("Unknown ship-escrow branch: {branch}")),
    }
    Ok(())
}

pub(crate) fn build_p2sh_preimage_claim_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    preimage: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Preimage claim input has no signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad sig length"),
        "sig hex",
    )?;

    let mut sig_script: Vec<u8> = Vec::with_capacity(66 + preimage.len() + 3 + redeem.len() + 3);

    // Push preimage FIRST (goes deepest on stack — consumed by OP_BLAKE2B after CHECKSIGVERIFY)
    if preimage.len() <= 75 {
        sig_script.push(preimage.len() as u8);
    } else if preimage.len() <= 255 {
        sig_script.push(0x4C);
        sig_script.push(preimage.len() as u8);
    } else {
        return Err("preimage too large".into());
    }
    sig_script.extend_from_slice(preimage);

    // Push signature (65 bytes) — on top of preimage
    sig_script.push(65u8);
    sig_script.extend_from_slice(&sig_bytes);

    // OP_FALSE to select ELSE branch (claim)
    sig_script.push(0x00);

    // Push redeem script
    push_redeem_script(&mut sig_script, redeem)?;

    Ok(sig_script)
}

pub(crate) fn build_p2sh_commit_reveal_split_sig_script(
    redeem: &[u8],
    partial_map: &serde_json::Map<String, Value>,
    part_a: &[u8],
    part_b: &[u8],
) -> Result<Vec<u8>, String> {
    let (_pk_hex, sig_bytes) = first_schnorr_signature(
        partial_map,
        "Commit-reveal split input has no signature".to_string(),
        "partial sig missing schnorr variant".to_string(),
        Some("bad sig length"),
        "sig hex",
    )?;

    let mut ss: Vec<u8> =
        Vec::with_capacity(part_a.len() + part_b.len() + 66 + 3 + redeem.len() + 10);

    // Push part_A FIRST (goes deepest on stack)
    push_data_item(&mut ss, part_a)?;

    // Push part_B (above part_A on stack)
    push_data_item(&mut ss, part_b)?;

    // Push signature (65 bytes) — on top
    ss.push(65u8);
    ss.extend_from_slice(&sig_bytes);

    // OP_FALSE to select ELSE branch
    ss.push(0x00);

    // Push redeem script
    push_redeem_script(&mut ss, redeem)?;

    Ok(ss)
}
