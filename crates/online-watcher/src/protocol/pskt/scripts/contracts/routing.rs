// KasSee Web — IF/ELSE covenant witness routing
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

use super::{
    build_p2sh_bridge_claim_sig_script, build_p2sh_commit_reveal_split_sig_script,
    build_p2sh_covenant_borrower_sig_script, build_p2sh_covenant_nosig_script,
    build_p2sh_covenant_sig_script, build_p2sh_deposit_holding_credit_sig_script,
    build_p2sh_escrow_sig_script, build_p2sh_groth16_bridge_claim_sig_script,
    build_p2sh_merkle_claim_sig_script, build_p2sh_oracle_mb_consumer_sig_script,
    build_p2sh_oracle_mb_heartbeat_sig_script, build_p2sh_oracle_mb_passthrough_sig_script,
    build_p2sh_oracle_mb_publish_sig_script, build_p2sh_oracle_v1_claim_sig_script,
    build_p2sh_preimage_claim_sig_script, build_p2sh_private_swap_claim_sig_script,
    build_p2sh_risc0_bridge_claim_sig_script, build_p2sh_risc0_claim_sig_script,
    build_p2sh_rollup_advance_sig_script, build_p2sh_rollup_forced_exit_sig_script,
    build_p2sh_rollup_refund_sig_script, build_p2sh_rollup_unified_advance_sig_script,
    build_p2sh_zk_claim_sig_script, CovenantContext, SignerBranch,
};

type RollupParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

pub(crate) fn build_if_else_covenant_script(
    input: &Map<String, Value>,
    redeem: &[u8],
    redeem_body: &[u8],
    partial_signatures: &Map<String, Value>,
    force_beneficiary: bool,
    force_time_path: bool,
    escrow_branch: &Option<String>,
) -> Result<Vec<u8>, String> {
    let signer = SignerBranch::detect(redeem_body, partial_signatures, force_beneficiary);
    let context = CovenantContext::parse(input);

    if let Some(script) =
        route_operational_branches(&context, redeem, partial_signatures, escrow_branch)?
    {
        return Ok(script);
    }
    if let Some(script) = route_proof_branches(&context, redeem, partial_signatures)? {
        return Ok(script);
    }

    if signer.is_owner || (!signer.is_beneficiary && !partial_signatures.is_empty()) {
        build_p2sh_covenant_sig_script(redeem, partial_signatures, force_time_path)
    } else if signer.is_beneficiary {
        build_p2sh_covenant_borrower_sig_script(redeem, partial_signatures)
    } else {
        build_p2sh_covenant_nosig_script(redeem)
    }
}

fn route_operational_branches(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
    escrow_branch: &Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(script) =
        route_basic_operational(context, redeem, partial_signatures, escrow_branch)?
    {
        return Ok(Some(script));
    }
    if let Some(script) = route_rollup_operational(context, redeem, partial_signatures)? {
        return Ok(Some(script));
    }
    route_oracle_operational(context, redeem, partial_signatures)
}

fn route_basic_operational(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
    escrow_branch: &Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    if context.rollup.deposit_holding_credit {
        let prefix = required(
            &context.rollup.prefix,
            "deposit-holding credit missing rollupPrefix",
        )?;
        let suffix = required(
            &context.rollup.suffix,
            "deposit-holding credit missing rollupSuffix",
        )?;
        return build_p2sh_deposit_holding_credit_sig_script(redeem, prefix, suffix).map(Some);
    }
    if context.signatures.minimum_signatures == 0 {
        return build_p2sh_covenant_nosig_script(redeem).map(Some);
    }
    if let Some(branch) = escrow_branch {
        return build_p2sh_escrow_sig_script(redeem, partial_signatures, branch).map(Some);
    }
    Ok(None)
}

fn route_rollup_operational(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    if context.rollup.state_advance {
        return build_rollup_advance(context, redeem, partial_signatures, "rollup advance")
            .map(Some);
    }
    if context.rollup.deposit_advance {
        return build_rollup_advance(context, redeem, partial_signatures, "deposit advance")
            .map(Some);
    }
    if context.rollup.unified_advance {
        let (proof, prefix, suffix) = rollup_parts(context, "unified advance")?;
        return build_p2sh_rollup_unified_advance_sig_script(
            redeem,
            partial_signatures,
            proof,
            prefix,
            suffix,
        )
        .map(Some);
    }
    if context.rollup.forced_exit {
        let (proof, prefix, suffix) = rollup_parts(context, "forced exit")?;
        return build_p2sh_rollup_forced_exit_sig_script(
            redeem,
            partial_signatures,
            proof,
            prefix,
            suffix,
        )
        .map(Some);
    }
    if context.rollup.state_refund {
        return build_p2sh_rollup_refund_sig_script(redeem, partial_signatures).map(Some);
    }
    if context.rollup.deposit_holding_refund {
        return build_p2sh_rollup_refund_sig_script(redeem, partial_signatures).map(Some);
    }
    if context.proofs.groth16_bridge {
        return build_p2sh_groth16_bridge_claim_sig_script(redeem, partial_signatures).map(Some);
    }
    Ok(None)
}

fn route_oracle_operational(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    if context.oracle.v1.claim {
        let signature = context
            .oracle
            .v1
            .signature
            .as_deref()
            .ok_or_else(|| "Oracle-v1 claim missing oracleV1Signature".to_string())?;
        return build_p2sh_oracle_v1_claim_sig_script(redeem, partial_signatures, signature)
            .map(Some);
    }
    if context.oracle.model_b.heartbeat {
        return build_p2sh_oracle_mb_heartbeat_sig_script(redeem).map(Some);
    }
    if context.oracle.model_b.passthrough {
        return build_p2sh_oracle_mb_passthrough_sig_script(redeem).map(Some);
    }
    if context.oracle.model_b.consumer {
        return build_p2sh_oracle_mb_consumer_sig_script(redeem).map(Some);
    }
    Ok(None)
}

fn route_proof_branches(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(script) = route_zk_proof(context, redeem, partial_signatures)? {
        return Ok(Some(script));
    }
    if let Some(script) = route_risc0_proof(context, redeem, partial_signatures)? {
        return Ok(Some(script));
    }
    route_auxiliary_proof(context, redeem, partial_signatures)
}

fn route_zk_proof(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    let Some(proof) = context.proofs.zk_proof.as_ref() else {
        return Ok(None);
    };
    let Some(inputs) = context.proofs.zk_public_inputs.as_ref() else {
        return Ok(None);
    };
    let Some(key) = context.proofs.zk_verification_key.as_ref() else {
        return Ok(None);
    };
    if let Some(withdrawal_script) = context.bridge.withdrawal_script.as_ref() {
        return build_p2sh_bridge_claim_sig_script(
            redeem,
            partial_signatures,
            proof,
            inputs,
            key,
            withdrawal_script,
        )
        .map(Some);
    }
    build_p2sh_zk_claim_sig_script(redeem, partial_signatures, proof, inputs, key).map(Some)
}

fn route_risc0_proof(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    let Some(seal) = context.proofs.risc0_seal.as_ref() else {
        return Ok(None);
    };
    let Some(fields) = context.proofs.risc0_fields.as_ref() else {
        return Ok(None);
    };
    if context.proofs.risc0_bridge {
        return build_p2sh_risc0_bridge_claim_sig_script(redeem, partial_signatures, seal, fields)
            .map(Some);
    }
    if context.oracle.model_b.risc0 {
        return build_p2sh_oracle_mb_publish_sig_script(redeem, seal, fields).map(Some);
    }
    build_p2sh_risc0_claim_sig_script(redeem, partial_signatures, seal, fields).map(Some)
}

fn route_auxiliary_proof(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    if context.private_swap.claim {
        return build_p2sh_private_swap_claim_sig_script(redeem, partial_signatures).map(Some);
    }
    if let (Some(part_a), Some(part_b)) = (
        context.commit_reveal.part_a.as_ref(),
        context.commit_reveal.part_b.as_ref(),
    ) {
        return build_p2sh_commit_reveal_split_sig_script(
            redeem,
            partial_signatures,
            part_a,
            part_b,
        )
        .map(Some);
    }
    if let Some(preimage) = context.commit_reveal.preimage.as_ref() {
        return build_p2sh_preimage_claim_sig_script(redeem, partial_signatures, preimage)
            .map(Some);
    }
    route_merkle_proof(context, redeem, partial_signatures)
}

fn route_merkle_proof(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Option<Vec<u8>>, String> {
    let (Some(proof), Some(destination_script)) = (
        context.merkle.proof.as_ref(),
        context.merkle.destination_script.as_ref(),
    ) else {
        return Ok(None);
    };
    build_p2sh_merkle_claim_sig_script(redeem, partial_signatures, proof, destination_script)
        .map(Some)
}

fn build_rollup_advance(
    context: &CovenantContext,
    redeem: &[u8],
    partial_signatures: &Map<String, Value>,
    label: &str,
) -> Result<Vec<u8>, String> {
    let (proof, prefix, suffix) = rollup_parts(context, label)?;
    build_p2sh_rollup_advance_sig_script(redeem, partial_signatures, proof, prefix, suffix)
}

fn rollup_parts<'a>(context: &'a CovenantContext, label: &str) -> Result<RollupParts<'a>, String> {
    let proof = required(
        &context.rollup.proof,
        &format!("{} missing rollupProof", label),
    )?;
    let prefix = required(
        &context.rollup.prefix,
        &format!("{} missing rollupPrefix", label),
    )?;
    let suffix = required(
        &context.rollup.suffix,
        &format!("{} missing rollupSuffix", label),
    )?;
    Ok((proof, prefix, suffix))
}

fn required<'a>(value: &'a Option<Vec<u8>>, message: &str) -> Result<&'a [u8], String> {
    value.as_deref().ok_or_else(|| message.to_string())
}
