// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

pub(crate) fn build_p2sh_oracle_mb_publish_sig_script(
    redeem: &[u8],
    seal: &[u8],
    fields: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let decode_field = |name: &str| -> Result<Vec<u8>, String> {
        let hex_str = fields
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("missing risc0 field: {}", name))?;
        hex::decode(hex_str).map_err(|e| format!("bad hex for {}: {}", name, e))
    };
    let claim = decode_field("claim")?;
    let control_index = decode_field("controlIndex")?;
    let control_digests = decode_field("controlDigests")?;
    let journal = decode_field("journal")?;
    if journal.len() != 48 {
        return Err(format!(
            "oracle journal must be 48 bytes, got {}",
            journal.len()
        ));
    }
    let mut j = [0u8; 48];
    j.copy_from_slice(&journal);
    Ok(
        crate::contracts::oracle::script::build_oracle_mb_publish_sig_script(
            redeem,
            &claim,
            &control_index,
            &control_digests,
            seal,
            &j,
        ),
    )
}

pub(crate) fn build_p2sh_oracle_mb_passthrough_sig_script(
    redeem: &[u8],
) -> Result<Vec<u8>, String> {
    Ok(crate::contracts::oracle::script::build_oracle_mb_passthrough_sig_script(redeem))
}

pub(crate) fn build_p2sh_oracle_mb_heartbeat_sig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    Ok(crate::contracts::oracle::script::build_oracle_mb_heartbeat_sig_script(redeem))
}

pub(crate) fn build_p2sh_oracle_mb_consumer_sig_script(redeem: &[u8]) -> Result<Vec<u8>, String> {
    Ok(crate::contracts::oracle::script::build_oracle_mb_consumer_sig_script(redeem))
}

fn oracle_v1_role_signature(
    partial_signatures: &serde_json::Map<String, Value>,
    expected_xonly: &[u8; 32],
    role: &str,
) -> Result<Vec<u8>, String> {
    let expected = hex::encode(expected_xonly);
    let mut matches = partial_signatures.iter().filter_map(|(public_key, value)| {
        let bytes = public_key.as_bytes();
        if bytes.len() != 66 {
            return None;
        }
        let prefix = &bytes[..2];
        if !matches!(prefix, b"02" | b"03") {
            return None;
        }
        if !bytes.iter().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let xonly = core::str::from_utf8(&bytes[2..]).ok()?;
        xonly.eq_ignore_ascii_case(&expected).then_some(value)
    });
    let signature_value = matches
        .next()
        .ok_or_else(|| format!("Oracle-v1 {role} transaction signature is missing"))?;
    if matches.next().is_some() {
        return Err(format!(
            "Oracle-v1 {role} transaction signature is ambiguous"
        ));
    }
    let signature_hex = signature_value
        .get("schnorr")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Oracle-v1 {role} partial signature has no schnorr variant"))?;
    if signature_hex.len() != 128 {
        return Err(format!(
            "Oracle-v1 {role} schnorr signature must be 64 bytes"
        ));
    }
    let mut signature = hex::decode(signature_hex)
        .map_err(|error| format!("Bad Oracle-v1 {role} signature hex: {error}"))?;
    signature.push(0x01); // SIGHASH_ALL
    Ok(signature)
}

pub(crate) fn build_p2sh_oracle_v1_claim_sig_script(
    redeem: &[u8],
    partial_signatures: &serde_json::Map<String, Value>,
    oracle_signature: &[u8],
) -> Result<Vec<u8>, String> {
    if oracle_signature.len() != 64 {
        return Err(format!(
            "oracle-v1 signature must be 64 bytes, got {}",
            oracle_signature.len()
        ));
    }
    let (beneficiary_key, _, _) =
        crate::contracts::covenant::script::oracle_v1_attestation_binding(redeem)
            .ok_or_else(|| "Oracle-v1 claim redeem script is not canonical".to_string())?;
    let beneficiary_signature =
        oracle_v1_role_signature(partial_signatures, &beneficiary_key, "beneficiary")?;
    let mut script = Vec::with_capacity(redeem.len() + 140);
    crate::protocol::pskt::scripts::push_data_item(&mut script, oracle_signature)?;
    crate::protocol::pskt::scripts::push_data_item(&mut script, &beneficiary_signature)?;
    script.push(0x00); // outer ELSE = beneficiary claim
    crate::protocol::pskt::scripts::push_redeem_script(&mut script, redeem)?;
    Ok(script)
}
