//! Private Swap v2 covenant: adaptor-signature claim + timed owner refund.
//!
//! The claim branch uses ordinary OP_CHECKSIG over the Kaspa transaction
//! sighash. The adaptor construction exists only off-chain, so no preimage or
//! shared hash appears on-chain. The claim transaction is constrained to one
//! input, one fixed destination output, and a bounded fee as defense in depth.

use super::covenant_ops::*;
use super::{push_data, push_int, push_pubkey};

pub const PRIVATE_SWAP_MAX_FEE_SOMPI: u64 = 500_000_000; // 5 KAS hard ceiling.

pub fn build_private_swap_script(
    owner_pubkey: &[u8; 32],
    claimer_pubkey: &[u8; 32],
    claimer_output_spk: &[u8],
    refund_locktime_daa: u64,
    salt: &[u8; 16],
) -> Result<Vec<u8>, String> {
    if refund_locktime_daa == 0 {
        return Err("Private Swap refund timeout must be nonzero".into());
    }
    if salt.iter().all(|byte| *byte == 0) {
        return Err("Private Swap salt must be nonzero".into());
    }
    if claimer_output_spk.len() < 3 || claimer_output_spk.len() > 73 {
        return Err("Private Swap destination script length is unsupported".into());
    }
    if owner_pubkey == claimer_pubkey {
        return Err("Private Swap owner and claimer keys must differ".into());
    }

    let mut destination_spk = Vec::with_capacity(2 + claimer_output_spk.len());
    destination_spk.extend_from_slice(&[0x00, 0x00]);
    destination_spk.extend_from_slice(claimer_output_spk);
    let mut script = Vec::with_capacity(242 + claimer_output_spk.len());
    push_data(&mut script, salt);
    script.push(OP_DROP);

    // Adaptor claim. The final on-chain object is an ordinary transaction
    // Schnorr signature under the isolated per-swap claimer key.
    script.push(OP_IF);
    push_pubkey(&mut script, claimer_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    script.push(OP_TX_INPUT_COUNT);
    push_int(&mut script, 1);
    script.push(OP_NUMEQUALVERIFY);
    script.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut script, 1);
    script.push(OP_NUMEQUALVERIFY);
    push_int(&mut script, 0);
    script.push(OP_TX_OUTPUT_SPK);
    push_data(&mut script, &destination_spk);
    script.push(OP_EQUALVERIFY);
    append_claim_fee_bound(&mut script);
    script.push(OP_1);

    // Funding owner recovers after timeout using the ordinary wallet key.
    script.push(OP_ELSE);
    push_pubkey(&mut script, owner_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_int(&mut script, refund_locktime_daa);
    script.push(OP_CHECKLOCKTIMEVERIFY);
    script.push(OP_1);
    script.push(OP_ENDIF);
    Ok(script)
}

fn append_claim_fee_bound(script: &mut Vec<u8>) {
    push_int(script, 0);
    script.push(OP_TX_INPUT_AMOUNT);
    script.push(OP_DUP);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_AMOUNT);
    script.push(OP_GREATERTHANOREQUAL);
    script.push(OP_VERIFY);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_AMOUNT);
    script.push(OP_SUB);
    push_int(script, PRIVATE_SWAP_MAX_FEE_SOMPI);
    script.push(OP_LESSTHANOREQUAL);
    script.push(OP_VERIFY);
}

#[cfg(test)]
mod unit_tests;
