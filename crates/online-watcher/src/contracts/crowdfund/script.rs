//! Hardened ZK crowdfunding covenant.
//!
//! Contributor path: ordinary wallet signature after CLTV timeout.
//! Sweep path: Groth16 proof plus transaction-introspection constraints. The proof
//! remains campaign-specific, while fund safety does not trust browser witness
//! amounts: the script independently requires every input to carry the same
//! campaign fingerprint, sums the real transaction inputs, requires the campaign
//! goal, pins the sole output script, and caps the transaction fee.

use crate::protocol::script::{opcode::*, push_data, push_int, push_pubkey};

pub const CROWDFUND_MAX_CONTRIBUTORS: usize = 8;
pub const CROWDFUND_MAX_TX_INPUTS: u64 = 16;
pub const CROWDFUND_MAX_SWEEP_FEE_SOMPI: u64 = 500_000_000; // 5 KAS safety ceiling.
pub const CROWDFUND_SIG_OP_COUNT: u8 = crate::contracts::zk::cost::GROTH16_SIG_OP_COUNT;
const CAMPAIGN_TAIL_LEN: u64 = 35;
const CAMPAIGN_ID_START_FROM_END: u64 = 34;
const CAMPAIGN_ID_END_FROM_END: u64 = 2;

pub struct CrowdfundScript<'a> {
    pub contributor_pubkey: &'a [u8; 32],
    pub goal_sompi: u64,
    pub locktime_daa: u64,
    pub verifying_key_hash: &'a [u8; 32],
    /// OP_TX_OUTPUT_SPK representation: two-byte SPK version followed by script bytes.
    pub organizer_output_spk: &'a [u8],
    pub salt: &'a [u8; 8],
}

#[must_use]
pub fn crowdfund_campaign_id(
    goal_sompi: u64,
    locktime_daa: u64,
    verifying_key_hash: &[u8; 32],
    organizer_output_spk: &[u8],
) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(b"KasSignerCrowdfundV2")
        .to_state();
    state.update(verifying_key_hash);
    state.update(&goal_sompi.to_le_bytes());
    state.update(&locktime_daa.to_le_bytes());
    state.update(&(organizer_output_spk.len() as u64).to_le_bytes());
    state.update(organizer_output_spk);
    let digest = state.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

pub fn crowdfund_redeem_script(config: CrowdfundScript<'_>) -> Result<Vec<u8>, String> {
    validate_config(&config)?;
    let campaign_id = crowdfund_campaign_id(
        config.goal_sompi,
        config.locktime_daa,
        config.verifying_key_hash,
        config.organizer_output_spk,
    );
    let mut script = Vec::with_capacity(640);
    push_data(&mut script, config.salt);
    script.push(OP_DROP);

    // Contributor refund after timeout. Putting the refund key first in the IF body
    // intentionally preserves the generic signer branch detector used by PSKB refunds.
    script.push(OP_IF);
    push_pubkey(&mut script, config.contributor_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_int(&mut script, config.locktime_daa);
    script.push(OP_CHECKLOCKTIMEVERIFY);

    // Organizer sweep. No wallet/raw-hash signature exists on this branch.
    script.push(OP_ELSE);
    append_proof_verification(&mut script, config.verifying_key_hash);
    append_campaign_isolation(&mut script, &campaign_id);
    append_real_input_total(&mut script);
    append_sweep_constraints(&mut script, config.goal_sompi, config.organizer_output_spk);
    script.push(OP_ENDIF);

    // Fixed tail used by every crowdfunding input to prove campaign membership to
    // every other crowdfunding input in the same sweep. Because this is at a fixed
    // offset from the end of the revealed redeem script, the check is independent
    // of contributor key/salt and script-number encoding lengths.
    push_data(&mut script, &campaign_id);
    script.push(OP_DROP);
    script.push(OP_1);
    Ok(script)
}

fn validate_config(config: &CrowdfundScript<'_>) -> Result<(), String> {
    if config.goal_sompi == 0 {
        return Err("Crowdfunding goal must be greater than zero".to_string());
    }
    if config.locktime_daa == 0 {
        return Err("Crowdfunding refund timeout must be greater than zero".to_string());
    }
    if config.organizer_output_spk.len() < 3 || config.organizer_output_spk.len() > 260 {
        return Err("Crowdfunding organizer output script length is unsupported".to_string());
    }
    if config.salt.iter().all(|byte| *byte == 0) {
        return Err("Crowdfunding salt must not be all zero".to_string());
    }
    Ok(())
}

fn append_proof_verification(script: &mut Vec<u8>, verifying_key_hash: &[u8; 32]) {
    // Entry stack: public_input | OP_1 | proof | verifying_key.
    script.push(OP_DUP);
    script.push(OP_BLAKE2B);
    push_data(script, verifying_key_hash);
    script.push(OP_EQUALVERIFY);
    push_data(script, &[crate::contracts::zk::cost::GROTH16_TAG]);
    script.push(OP_ZK_PRECOMPILE);
    script.push(OP_VERIFY);
}

fn append_campaign_isolation(script: &mut Vec<u8>, campaign_id: &[u8; 32]) {
    // Every input in a crowdfunding sweep must reveal a redeem script whose fixed
    // tail carries this exact campaign fingerprint. A transaction cannot therefore
    // use genuine contribution UTXOs from campaign B to satisfy campaign A's goal:
    // B's own covenant performs the reciprocal check and rejects A's fingerprint.
    // Ordinary attacker-owned inputs can only add the attacker's own value, which is
    // equivalent to self-contributing and cannot redirect any other campaign's funds.
    for index in 0..CROWDFUND_MAX_TX_INPUTS {
        script.push(OP_TX_INPUT_COUNT);
        push_int(script, index + 1);
        script.push(OP_GREATERTHANOREQUAL);
        script.push(OP_IF);

        push_int(script, index); // substring input index
        push_int(script, index);
        script.push(OP_TX_INPUT_SCRIPT_SIG_LEN);
        script.push(OP_DUP);
        push_int(script, CAMPAIGN_TAIL_LEN);
        script.push(OP_GREATERTHANOREQUAL);
        script.push(OP_VERIFY);
        script.push(OP_DUP);
        push_int(script, CAMPAIGN_ID_START_FROM_END);
        script.push(OP_SUB); // start = sig_len - 34
        script.push(OP_SWAP);
        push_int(script, CAMPAIGN_ID_END_FROM_END);
        script.push(OP_SUB); // end = sig_len - 2
        script.push(OP_TX_INPUT_SCRIPT_SIG_SUBSTR);
        push_data(script, campaign_id);
        script.push(OP_EQUALVERIFY);
        script.push(OP_ENDIF);
    }
}

fn append_real_input_total(script: &mut Vec<u8>) {
    // Fail closed outside the bounded introspection range.
    script.push(OP_TX_INPUT_COUNT);
    push_int(script, 1);
    script.push(OP_GREATERTHANOREQUAL);
    script.push(OP_VERIFY);
    script.push(OP_TX_INPUT_COUNT);
    push_int(script, CROWDFUND_MAX_TX_INPUTS);
    script.push(OP_LESSTHANOREQUAL);
    script.push(OP_VERIFY);

    // Sum every real transaction input. Each amount fetch is guarded by the actual
    // input count so no out-of-range introspection opcode is evaluated.
    push_int(script, 0);
    for index in 0..CROWDFUND_MAX_TX_INPUTS {
        script.push(OP_TX_INPUT_COUNT);
        push_int(script, index + 1);
        script.push(OP_GREATERTHANOREQUAL);
        script.push(OP_IF);
        push_int(script, index);
        script.push(OP_TX_INPUT_AMOUNT);
        script.push(OP_ADD);
        script.push(OP_ENDIF);
    }
}

fn append_sweep_constraints(script: &mut Vec<u8>, goal_sompi: u64, organizer_spk: &[u8]) {
    // total >= goal
    script.push(OP_DUP);
    push_int(script, goal_sompi);
    script.push(OP_GREATERTHANOREQUAL);
    script.push(OP_VERIFY);

    // Exactly one fixed organizer output. This prevents proof possession from being
    // turned into an arbitrary destination authorization.
    script.push(OP_TX_OUTPUT_COUNT);
    push_int(script, 1);
    script.push(OP_NUMEQUALVERIFY);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_SPK);
    push_data(script, organizer_spk);
    script.push(OP_EQUALVERIFY);

    // The sole output cannot exceed the inputs, and at most 5 KAS can disappear as
    // fee even if a malicious host supplies an absurd transaction fee.
    script.push(OP_DUP);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_AMOUNT);
    script.push(OP_GREATERTHANOREQUAL);
    script.push(OP_VERIFY);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_AMOUNT);
    script.push(OP_SUB);
    push_int(script, CROWDFUND_MAX_SWEEP_FEE_SOMPI);
    script.push(OP_LESSTHANOREQUAL);
    script.push(OP_VERIFY);
}
