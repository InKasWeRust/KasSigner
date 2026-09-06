use super::{push_int, push_pubkey};
/// Build a Piggy Bank covenant redeem script.
///
/// Two optional break conditions for the owner: savings goal and/or deadline.
/// - threshold_sompi > 0: owner can break if the swept output[0].amount >= threshold
/// - deadline_daa > 0: owner can break if DAA score >= deadline
/// - Both set: owner can break if EITHER condition is met
/// - Neither set: owner can break anytime (simple additive)
///
/// Every script is prefixed with `<8-byte salt> OP_DROP` so identical params
/// produce a unique P2SH each time; the salt is dropped at execution and does
/// not affect spending.
///
/// With conditions:
///   <salt> DROP IF <pk> CHECKSIGVERIFY IF <amount_check> ELSE <time_check> ENDIF
///   ELSE <deposit_check> ENDIF
///
/// Without conditions:
///   <salt> DROP IF <pk> CHECKSIG ELSE <deposit_check> ENDIF
///
/// Owner sig_script (with conditions):
///   Amount path: <sig> OP_TRUE OP_TRUE  (inner IF, outer IF)
///   Time path:   <sig> OP_FALSE OP_TRUE (inner ELSE, outer IF)
/// Owner sig_script (no conditions):
///   <sig> OP_TRUE
pub fn build_piggy_bank_script(
    owner_pubkey: &[u8; 32],
    threshold_sompi: u64,
    deadline_daa: u64,
    salt: &[u8; 8],
) -> Vec<u8> {
    use super::covenant_ops::*;
    let has_conditions = threshold_sompi > 0 || deadline_daa > 0;
    let mut s = Vec::with_capacity(128);

    // Salt: unique nonce so identical params produce a different P2SH each time.
    s.push(0x08);
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);

    if has_conditions {
        s.push(OP_CHECKSIGVERIFY);
        // Inner IF: amount path
        s.push(OP_IF);
        if threshold_sompi > 0 {
            // Check output[0].amount >= threshold (use OP_0 to always check output index 0,
            // so all inputs in a multi-input sweep verify the same total output)
            s.push(0x00);
            s.push(OP_TX_OUTPUT_AMOUNT);
            push_int(&mut s, threshold_sompi);
            s.push(OP_GREATERTHANOREQUAL);
        } else {
            // No goal set: keep this amount path UNUSABLE. A bare OP_TRUE here is
            // an unconditional break, which defeats a deadline-only piggy. OP_FALSE
            // forces the spender onto the real (time) branch.
            s.push(0x00); // OP_FALSE
        }
        // Inner ELSE: time path
        s.push(OP_ELSE);
        if deadline_daa > 0 {
            push_int(&mut s, deadline_daa);
            s.push(OP_CHECKLOCKTIMEVERIFY);
            s.push(0x51); // OP_TRUE
        } else {
            // No deadline set: keep this time path UNUSABLE. A bare OP_TRUE here is
            // an unconditional break, which defeats a goal-only piggy. OP_FALSE
            // forces the spender onto the real (amount) branch.
            s.push(0x00); // OP_FALSE
        }
        s.push(OP_ENDIF);
    } else {
        // No conditions, owner can break anytime
        s.push(OP_CHECKSIG);
    }

    // Deposit path
    s.push(OP_ELSE);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_OUTPUT_AMOUNT);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);
    s.push(OP_GREATERTHANOREQUAL);

    s.push(OP_ENDIF);
    s
}

/// Build a time-locked SAVINGS covenant redeem script.
///
/// Unlike the time-locked vault, there is NO owner-spend-anytime branch.
/// Funds are frozen for EVERYONE (including the depositor) until
/// `locktime_daa`. After that score, EITHER of two independent wallets
/// can sweep the funds anywhere with a single signature. This is 1-of-2,
/// NOT multisig: one signature, from whichever wallet you still hold.
/// The second wallet is a key-loss recovery path; set it equal to the
/// first if you do not want a recovery key.
///
/// Deposits are ordinary sends to the P2SH address from any wallet, so
/// the vault holds one UTXO per deposit and the claim sweeps them all.
/// (Optional single-UTXO consolidation + covenant_id tagging is a later
/// layer that needs an output >= sum-of-inputs check; not in this script.)
///
/// The time gate sits INSIDE each branch (not before the OP_IF), so the
/// redeem layout mirrors the time-locked vault exactly:
///   OP_IF  <pk32> ...  OP_ELSE  <pk32> ...  OP_ENDIF
/// That lets the existing finalizer auto-detect the signer's branch by
/// matching its x-only pubkey at redeem[2..34]: wallet1 -> OP_IF (OP_TRUE
/// selector), wallet2 -> OP_ELSE (OP_FALSE selector). No finalizer or
/// firmware change is needed, and putting CLTV in both branches means
/// neither wallet can extract before the date.
///
/// Script:
///   OP_IF
///       <wallet1_pubkey> OP_CHECKSIGVERIFY
///       <locktime_daa>   OP_CHECKLOCKTIMEVERIFY
///       OP_TRUE
///   OP_ELSE
///       <wallet2_pubkey> OP_CHECKSIGVERIFY
///       <locktime_daa>   OP_CHECKLOCKTIMEVERIFY
///       OP_TRUE
///   OP_ENDIF
///
/// CHECKSIGVERIFY consumes the signature (stack clean), CLTV pops its
/// argument (Kaspa semantics, stack clean), OP_TRUE leaves the single
/// truthy final item. The claim TX must set locktime >= locktime_daa.
///
/// Sig_scripts (claim only, valid after the date):
///   wallet1: <sig> OP_TRUE  <redeem>   (OP_IF branch)
///   wallet2: <sig> OP_FALSE <redeem>   (OP_ELSE branch)
pub fn build_timelocked_savings_script(
    wallet1_pubkey: &[u8; 32],
    wallet2_pubkey: &[u8; 32],
    locktime_daa: u64,
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut s = Vec::with_capacity(128);

    // wallet1 path (OP_IF), time-gated.
    s.push(OP_IF);
    push_pubkey(&mut s, wallet1_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_1); // OP_TRUE

    // wallet2 recovery path (OP_ELSE), same time gate.
    s.push(OP_ELSE);
    push_pubkey(&mut s, wallet2_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_1); // OP_TRUE

    s.push(OP_ENDIF);

    s
}
