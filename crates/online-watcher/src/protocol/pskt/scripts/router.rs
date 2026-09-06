// KasSee Web — signature-script routing
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

use super::{
    build_if_else_covenant_script, build_p2pk_sig_script, build_p2sh_multisig_sig_script,
    build_p2sh_oracle_mb_consumer_sig_script, build_p2sh_oracle_mb_heartbeat_sig_script,
    build_p2sh_oracle_mb_passthrough_sig_script, build_p2sh_oracle_mb_publish_sig_script,
    build_p2sh_ship_escrow_sig_script, build_p2sh_single_path_sig_script,
    build_p2sh_state_machine_sig_script, build_p2sh_token_conservation_sig_script,
    build_p2sh_treasury_sig_script, common::strip_optional_covenant_salt,
};

#[derive(Clone, Copy)]
pub(crate) struct ScriptBuildOptions<'a> {
    pub(crate) force_beneficiary: bool,
    pub(crate) force_time_path: bool,
    pub(crate) escrow_branch: &'a Option<String>,
    pub(crate) ship_branch: &'a Option<String>,
}

pub(crate) fn build_signature_script(
    input: &Map<String, Value>,
    script_public_key: &[u8],
    redeem_script: &Option<Vec<u8>>,
    partial_signatures: &Map<String, Value>,
    options: ScriptBuildOptions<'_>,
) -> Result<Vec<u8>, String> {
    if !is_p2sh(script_public_key) {
        return build_p2pk_sig_script(partial_signatures);
    }
    let redeem = redeem_script
        .as_deref()
        .ok_or_else(|| "P2SH input without redeem script cannot be finalized".to_string())?;
    build_p2sh_signature_script(input, redeem, partial_signatures, options)
}

fn build_p2sh_signature_script(
    input: &Map<String, Value>,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
    options: ScriptBuildOptions<'_>,
) -> Result<Vec<u8>, String> {
    let redeem_body = strip_optional_covenant_salt(redeem);
    if let Some(script) = build_keyless_oracle_script(input, redeem)? {
        return Ok(script);
    }
    if redeem_body.first() == Some(&0x63) {
        return build_if_else_covenant_script(
            input,
            redeem,
            redeem_body,
            partial_signatures,
            options.force_beneficiary,
            options.force_time_path,
            options.escrow_branch,
        );
    }
    build_standard_p2sh_script(redeem, redeem_body, partial_signatures, options)
}

fn build_standard_p2sh_script(
    redeem: &[u8],
    redeem_body: &[u8],
    partial_signatures: &Map<String, Value>,
    options: ScriptBuildOptions<'_>,
) -> Result<Vec<u8>, String> {
    if is_treasury_redeem(redeem) {
        return build_p2sh_treasury_sig_script(redeem, partial_signatures);
    }
    if redeem_body.first() == Some(&0xb9) {
        return build_state_machine_script(redeem, partial_signatures, options.ship_branch);
    }
    if is_single_path_redeem(redeem_body) {
        return build_p2sh_single_path_sig_script(redeem, partial_signatures);
    }
    if redeem.first() == Some(&0x00) {
        return build_p2sh_token_conservation_sig_script(redeem);
    }
    build_p2sh_multisig_sig_script(redeem, partial_signatures)
}

fn build_state_machine_script(
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
    ship_branch: &Option<String>,
) -> Result<Vec<u8>, String> {
    if let Some(branch) = ship_branch {
        return build_p2sh_ship_escrow_sig_script(redeem, partial_signatures, branch);
    }
    build_p2sh_state_machine_sig_script(redeem, partial_signatures)
}

fn is_treasury_redeem(redeem: &[u8]) -> bool {
    redeem.len() >= 35 && redeem.first() == Some(&0x20) && redeem.get(33) == Some(&0xad)
}

fn is_single_path_redeem(redeem: &[u8]) -> bool {
    redeem.len() > 34 && redeem.first() == Some(&0x20) && redeem.get(33) == Some(&0xad)
}

fn build_keyless_oracle_script(
    input: &Map<String, Value>,
    redeem: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let proprietary = input.get("proprietaries").and_then(Value::as_object);
    if bool_field(proprietary, "risc0OracleMb") {
        let seal = hex_field(proprietary, "risc0Seal")
            .ok_or_else(|| "oracle MB publish missing risc0Seal".to_string())?;
        let fields = proprietary
            .and_then(|values| values.get("risc0Fields"))
            .and_then(Value::as_object)
            .cloned()
            .ok_or_else(|| "oracle MB publish missing risc0Fields".to_string())?;
        return build_p2sh_oracle_mb_publish_sig_script(redeem, &seal, &fields).map(Some);
    }
    if bool_field(proprietary, "oracleMbHeartbeat") {
        return build_p2sh_oracle_mb_heartbeat_sig_script(redeem).map(Some);
    }
    if bool_field(proprietary, "oracleMbPassthrough") {
        return build_p2sh_oracle_mb_passthrough_sig_script(redeem).map(Some);
    }
    if bool_field(proprietary, "oracleMbConsumer") {
        return build_p2sh_oracle_mb_consumer_sig_script(redeem).map(Some);
    }
    Ok(None)
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87
}

fn bool_field(proprietary: Option<&Map<String, Value>>, key: &str) -> bool {
    proprietary
        .and_then(|values| values.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn hex_field(proprietary: Option<&Map<String, Value>>, key: &str) -> Option<Vec<u8>> {
    proprietary
        .and_then(|values| values.get(key))
        .and_then(Value::as_str)
        .and_then(|value| hex::decode(value).ok())
}
