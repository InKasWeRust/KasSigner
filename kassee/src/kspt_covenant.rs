// KasSee Web — KIP-10 covenant script builders (moved out of kspt.rs).
// Re-exported by kspt via `pub use covenant_builders::*`, so `kspt::build_*`
// resolve unchanged for covenant_api. License: GPL-3.0.

//! KIP-10 covenant redeem-script builders (piggy-bank, escrow, spending-limit,
//! allowance, timelocked savings/escrow, DMS, treasury, atomic-swap, oracle,
//! payjoin). Re-exported by the parent `kspt` module.

use super::{covenant_ops, push_data, push_int, push_pubkey};

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
    use covenant_ops::*;
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

/// Build a 2-of-3 escrow covenant redeem script with arbiter.
///
/// Three parties: Alice (buyer), Bob (seller), Arbiter.
/// Five paths:
///   1. Alice releases to Bob (deal done)
///   2. Bob refunds to Alice (cancel)
///   3. Arbiter awards to Bob (dispute, Bob wins)
///   4. Arbiter refunds to Alice (dispute, Alice wins)
///   5. Dispute signal: buyer or seller sends funds back to same address
///      (heartbeat-style, signals arbitration needed)
///
/// Script:
///   IF
///     <alice_pk> CHECKSIGVERIFY 0 TX_OUTPUT_SPK <bob_spk> EQUALVERIFY TRUE
///   ELSE IF
///     <bob_pk> CHECKSIGVERIFY 0 TX_OUTPUT_SPK <alice_spk> EQUALVERIFY TRUE
///   ELSE IF
///     <arbiter_pk> CHECKSIGVERIFY
///     IF  0 TX_OUTPUT_SPK <bob_spk> EQUALVERIFY TRUE
///     ELSE 0 TX_OUTPUT_SPK <alice_spk> EQUALVERIFY TRUE
///     ENDIF
///   ELSE
///     IF <alice_pk> CHECKSIG
///     ELSE <bob_pk> CHECKSIG
///     ENDIF
///     TX_INPUT_INDEX TX_INPUT_SPK 0 TX_OUTPUT_SPK EQUALVERIFY TRUE
///   ENDIF ENDIF ENDIF
///
/// Sig scripts:
///   Alice releases:          <sig> TRUE
///   Bob refunds:             <sig> TRUE FALSE
///   Arbiter awards Bob:      <sig> TRUE TRUE FALSE FALSE
///   Arbiter refunds Alice:   <sig> FALSE TRUE FALSE FALSE
///   Buyer disputes:          <sig> TRUE FALSE FALSE FALSE
///   Seller disputes:         <sig> FALSE FALSE FALSE FALSE
///
/// The script starts with <salt> OP_DROP to make each escrow unique
/// even with the same participants.
pub fn build_escrow_script(
    alice_pubkey: &[u8; 32],
    bob_pubkey: &[u8; 32],
    arbiter_pubkey: &[u8; 32],
    alice_spk: &[u8],
    bob_spk: &[u8],
    salt: &[u8; 8],
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(524);

    // Salt: unique nonce so same participants produce different P2SH each time
    s.push(0x08); // push 8 bytes
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    // OP_TX_OUTPUT_SPK pushes the full ScriptPublicKey including the
    // 2-byte LE version prefix. Prepend version 0x0000 to the raw
    // script bytes so the OP_EQUAL comparison matches.
    let mut bob_spk_full = Vec::with_capacity(2 + bob_spk.len());
    bob_spk_full.extend_from_slice(&[0x00, 0x00]);
    bob_spk_full.extend_from_slice(bob_spk);

    let mut alice_spk_full = Vec::with_capacity(2 + alice_spk.len());
    alice_spk_full.extend_from_slice(&[0x00, 0x00]);
    alice_spk_full.extend_from_slice(alice_spk);

    // Path 1: Alice releases to Bob (buyer confirms delivery)
    s.push(OP_IF);
    push_pubkey(&mut s, alice_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &bob_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ELSE);

    // Path 2: Bob refunds to Alice (seller cancels)
    s.push(OP_IF);
    push_pubkey(&mut s, bob_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ELSE);

    // Path 3+4: Arbiter decides direction
    s.push(OP_IF);
    push_pubkey(&mut s, arbiter_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Inner IF: arbiter awards Bob
    s.push(OP_IF);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &bob_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    // Inner ELSE: arbiter refunds Alice
    s.push(OP_ELSE);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ENDIF); // arbiter direction

    s.push(OP_ELSE);

    // Path 5: Dispute signal (heartbeat back to self)
    // Either buyer or seller signs, output must go back to same P2SH
    s.push(OP_IF);
    push_pubkey(&mut s, alice_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_ELSE);
    push_pubkey(&mut s, bob_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_ENDIF); // buyer/seller selector

    // Enforce output[0] == own input SPK (send back to same address)
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ENDIF); // arbiter/dispute
    s.push(OP_ENDIF); // bob/rest
    s.push(OP_ENDIF); // alice/rest
    s
}

/// GLOBAL spending limit (covenant_id single-thread).
///
/// Unlike the per-UTXO `build_spending_limit_script`, the whole balance is held
/// in ONE covenant_id-tagged UTXO (the thread). Every spend must continue that
/// thread as exactly ONE tagged output back to this same covenant address, so
/// the cap applies to the entire balance, not per UTXO. Adding funds is just a
/// consolidation into the single thread; an untagged deposit can never be spent
/// through this script (it reads as ZERO_HASH and the count check fails), so it
/// cannot bypass the cap.
///
/// Decoded logic (matches the proven engine test global_spending_limit_script_enforced):
///   <salt> DROP
///   <owner_pk> CHECKSIGVERIFY
///   <cooldown> CHECKSEQUENCEVERIFY
///   TX_INPUT_INDEX INPUT_COVENANT_ID DUP COV_OUTPUT_COUNT DUP 1 EQUAL
///   IF      // a continuation exists (withdraw or top-up)
///     DROP 0 COV_OUTPUT_IDX                       // the single tagged output's index
///     DUP TX_OUTPUT_SPK TX_INPUT_INDEX TX_INPUT_SPK EQUALVERIFY   // it must sit at THIS address
///     TX_OUTPUT_AMOUNT TX_INPUT_INDEX TX_INPUT_AMOUNT <max> SUB GREATERTHANOREQUAL VERIFY
///   ELSE    // no continuation
///     0 EQUALVERIFY DROP                          // exactly 0 tagged outputs (no split)
///     TX_INPUT_INDEX TX_INPUT_AMOUNT <max> LESSTHANOREQUAL VERIFY  // close only if balance <= cap
///   ENDIF
///   OP_1
///
/// sig_op_count: 1 (CHECKSIGVERIFY)
pub fn build_global_spending_limit_script(
    owner_pubkey: &[u8; 32],
    max_withdraw_sompi: u64,
    cooldown_daa: u64,
    salt: &[u8; 8],
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(160);

    // Salt: unique nonce so identical params produce a different P2SH each time.
    s.push(0x08);
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    // Owner must sign every spend.
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Cooldown between spends (CSV relative timelock).
    push_int(&mut s, cooldown_daa);
    s.push(OP_CHECKSEQUENCEVERIFY);

    // --- Global single-thread spending limit (proven on engine) ---

    // [id]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_INPUT_COVENANT_ID);
    // [id, count]
    s.push(OP_DUP);
    s.push(OP_COV_OUTPUT_COUNT);
    // [id, count, (count == 1)]
    s.push(OP_DUP);
    push_int(&mut s, 1);
    s.push(OP_EQUAL);

    s.push(OP_IF);
    // Continuation exists (withdraw or top-up).
    s.push(OP_DROP); // [id]
    push_int(&mut s, 0);
    s.push(OP_COV_OUTPUT_IDX); // [contIdx]  index of the single tagged output
                               // Continuation must sit at THIS covenant address: output[contIdx].spk == input.spk
    s.push(OP_DUP);
    s.push(OP_TX_OUTPUT_SPK); // [contIdx, contSpk]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK); // [contIdx, contSpk, inSpk]
    s.push(OP_EQUALVERIFY); // [contIdx]
                            // Continuation amount >= input amount - max
    s.push(OP_TX_OUTPUT_AMOUNT); // [contAmount]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT); // [contAmount, inAmount]
    push_int(&mut s, max_withdraw_sompi);
    s.push(OP_SUB); // [contAmount, inAmount - max]
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    s.push(OP_ELSE);
    // No continuation: allow closing only if the whole balance fits under the cap,
    // and require exactly 0 tagged outputs (so a split cannot sneak through here).
    push_int(&mut s, 0);
    s.push(OP_EQUALVERIFY); // count == 0  -> [id]
    s.push(OP_DROP); // []
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT); // [inAmount]
    push_int(&mut s, max_withdraw_sompi);
    s.push(OP_LESSTHANOREQUAL);
    s.push(OP_VERIFY);

    s.push(OP_ENDIF);

    // Leave TRUE on the stack.
    s.push(OP_1);

    s
}

/// Build a GLOBAL single-thread ALLOWANCE covenant redeem script.
///
/// Like the global spending-limit, this binds a `covenant_id` so the per-spend
/// cap applies to the WHOLE thread balance held in one tagged UTXO rather than
/// per individual UTXO, and cannot be bypassed by splitting funds. The
/// difference from the global spending-limit: the capped continuation path is
/// signed by the BENEFICIARY, not the owner, with an optional vesting start
/// date (CLTV) and a cooldown (CSV) between withdrawals. The OWNER keeps a free
/// top-level path so they can reclaim or close the thread and are never locked
/// out.
///
/// The top-level shape mirrors the per-UTXO allowance (OP_IF owner / OP_ELSE
/// beneficiary) so the existing finalizer branch selectors work unchanged:
/// "owner" takes the IF (OP_TRUE selector), "beneficiary" takes the ELSE
/// (OP_FALSE selector). The beneficiary ELSE branch carries the global
/// single-thread covenant_id enforcement copied verbatim from
/// `build_global_spending_limit_script`.
///
/// Script:
///   <salt> OP_DROP
///   OP_IF
///       <owner_pubkey> OP_CHECKSIG                  -- owner: free reclaim/close
///   OP_ELSE
///       <beneficiary_pubkey> OP_CHECKSIGVERIFY
///       [<start_daa> OP_CHECKLOCKTIMEVERIFY]        -- optional vesting start
///       [<cooldown_daa> OP_CHECKSEQUENCEVERIFY]     -- cooldown between withdrawals
///       OP_TXINPUTINDEX OP_INPUTCOVENANTID
///       OP_DUP OP_COVOUTPUTCOUNT
///       OP_DUP 1 OP_EQUAL
///       OP_IF                                       -- continuation (capped withdraw)
///           OP_DROP 0 OP_COVOUTPUTIDX
///           OP_DUP OP_TXOUTPUTSPK
///           OP_TXINPUTINDEX OP_TXINPUTSPK OP_EQUALVERIFY
///           OP_TXOUTPUTAMOUNT
///           OP_TXINPUTINDEX OP_TXINPUTAMOUNT <max_withdraw> OP_SUB
///           OP_GREATERTHANOREQUAL OP_VERIFY
///       OP_ELSE                                     -- close (no continuation)
///           0 OP_EQUALVERIFY OP_DROP
///           OP_TXINPUTINDEX OP_TXINPUTAMOUNT <max_withdraw> OP_LESSTHANOREQUAL OP_VERIFY
///       OP_ENDIF
///       OP_1
///   OP_ENDIF
pub fn build_global_allowance_script(
    owner_pubkey: &[u8; 32],
    beneficiary_pubkey: &[u8; 32],
    max_withdraw_sompi: u64,
    cooldown_daa: u64,
    start_daa: u64,
    salt: &[u8; 8],
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(208);

    // Salt: unique nonce so identical params produce a different P2SH (and thus
    // a distinct covenant_id) each setup. Sits before the branch, so it runs on
    // both paths; the push+DROP is stack-neutral and harmless on either.
    s.push(0x08);
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    // Owner free path (reclaim / close). Leaves the CHECKSIG bool.
    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIG);

    // Beneficiary capped path.
    s.push(OP_ELSE);
    push_pubkey(&mut s, beneficiary_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Optional vesting start: no beneficiary withdrawal before start_daa.
    // CLTV pops its value (Kaspa semantics, stack clean).
    if start_daa > 0 {
        push_int(&mut s, start_daa);
        s.push(OP_CHECKLOCKTIMEVERIFY);
    }

    // Cooldown between beneficiary withdrawals (relative timelock).
    // CSV pops its value (Kaspa semantics, stack clean).
    if cooldown_daa > 0 {
        push_int(&mut s, cooldown_daa);
        s.push(OP_CHECKSEQUENCEVERIFY);
    }

    // --- Global single-thread enforcement (mirrors global spending-limit) ---

    // [id]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_INPUT_COVENANT_ID);
    // [id, count]
    s.push(OP_DUP);
    s.push(OP_COV_OUTPUT_COUNT);
    // [id, count, (count == 1)]
    s.push(OP_DUP);
    push_int(&mut s, 1);
    s.push(OP_EQUAL);

    s.push(OP_IF);
    // Continuation exists (capped withdrawal).
    s.push(OP_DROP); // [id]
    push_int(&mut s, 0);
    s.push(OP_COV_OUTPUT_IDX); // [contIdx]  index of the single tagged output
                               // Continuation must sit at THIS covenant address: output[contIdx].spk == input.spk
    s.push(OP_DUP);
    s.push(OP_TX_OUTPUT_SPK); // [contIdx, contSpk]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK); // [contIdx, contSpk, inSpk]
    s.push(OP_EQUALVERIFY); // [contIdx]
                            // Continuation amount >= input amount - max
    s.push(OP_TX_OUTPUT_AMOUNT); // [contAmount]
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT); // [contAmount, inAmount]
    push_int(&mut s, max_withdraw_sompi);
    s.push(OP_SUB); // [contAmount, inAmount - max]
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    s.push(OP_ELSE);
    // No continuation: closing the thread is allowed only if the whole balance
    // fits under the cap, and exactly 0 tagged outputs (so a split cannot sneak
    // through here).
    push_int(&mut s, 0);
    s.push(OP_EQUALVERIFY); // count == 0  -> [id]
    s.push(OP_DROP); // []
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT); // [inAmount]
    push_int(&mut s, max_withdraw_sompi);
    s.push(OP_LESSTHANOREQUAL);
    s.push(OP_VERIFY);

    s.push(OP_ENDIF);

    // Leave TRUE on the stack for the beneficiary branch.
    s.push(OP_1);

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
    use covenant_ops::*;
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

/// Build a time-locked escrow covenant redeem script.
///
/// Two-party escrow with automatic refund after timeout.
/// - Alice signs → funds go to Bob (destination enforced via OUTPUT_SPK)
/// - Bob signs → funds go to Alice (destination enforced)
/// - After locktime passes → funds refund to Alice (no signature needed,
///   destination enforced, TX locktime must be >= threshold)
///
/// Script:
///   OP_IF
///       <alice_pk> OP_CHECKSIGVERIFY
///       0 OP_TX_OUTPUT_SPK <bob_spk_full> OP_EQUAL
///   OP_ELSE
///       OP_IF
///           <bob_pk> OP_CHECKSIGVERIFY
///           0 OP_TX_OUTPUT_SPK <alice_spk_full> OP_EQUAL
///       OP_ELSE
///           <locktime_daa> OP_CHECKLOCKTIMEVERIFY
///           0 OP_TX_OUTPUT_SPK <alice_spk_full> OP_EQUAL
///       OP_ENDIF
///   OP_ENDIF
///
/// Sig_scripts:
///   Alice releases: <sig> OP_TRUE        (outer IF)
///   Bob releases:   <sig> OP_TRUE OP_FALSE (outer ELSE → inner IF)
///   Timeout refund: OP_FALSE OP_FALSE    (outer ELSE → inner ELSE)
pub fn build_timelocked_escrow_script(
    alice_pubkey: &[u8; 32],
    bob_pubkey: &[u8; 32],
    alice_spk: &[u8],
    bob_spk: &[u8],
    locktime_daa: u64,
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(256);

    // Prepend 2-byte BE version prefix (0x0000) for OUTPUT_SPK comparison
    let mut bob_spk_full = Vec::with_capacity(2 + bob_spk.len());
    bob_spk_full.extend_from_slice(&[0x00, 0x00]);
    bob_spk_full.extend_from_slice(bob_spk);

    let mut alice_spk_full = Vec::with_capacity(2 + alice_spk.len());
    alice_spk_full.extend_from_slice(&[0x00, 0x00]);
    alice_spk_full.extend_from_slice(alice_spk);

    // Outer IF: Alice signs → Bob receives
    s.push(OP_IF);
    push_pubkey(&mut s, alice_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &bob_spk_full);
    s.push(OP_EQUAL);

    // Outer ELSE
    s.push(OP_ELSE);

    // Inner IF: Bob signs → Alice receives
    s.push(OP_IF);
    push_pubkey(&mut s, bob_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUAL);

    // Inner ELSE: Timeout → refund to Alice
    s.push(OP_ELSE);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUAL);

    s.push(OP_ENDIF); // inner
    s.push(OP_ENDIF); // outer
    s
}

/// Build a true dead man's switch script using CSV (relative timelock).
///
/// Owner can spend anytime (heartbeat: send back to same address to reset timer).
/// Heir can only spend if the UTXO has been untouched for `inactivity_daa` DAA units.
///
/// Script:
///   OP_IF
///       <owner_pk> OP_CHECKSIG
///   OP_ELSE
///       <inactivity_daa> OP_CHECKSEQUENCEVERIFY
///       <heir_pk> OP_CHECKSIG
///   OP_ENDIF
pub fn build_dms_csv_script(
    owner_pubkey: &[u8; 32],
    heir_pubkey: &[u8; 32],
    inactivity_daa: u64,
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(80);

    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIG);

    s.push(OP_ELSE);
    // Relative time-lock: UTXO must be at least inactivity_daa old
    push_int(&mut s, inactivity_daa);
    s.push(OP_CHECKSEQUENCEVERIFY);
    // Heir must also sign
    push_pubkey(&mut s, heir_pubkey);
    s.push(OP_CHECKSIG);

    s.push(OP_ENDIF);
    s
}

/// Build an allowance covenant redeem script.
///
/// Spending limit + relative time-lock (CSV). After each withdrawal,
/// a minimum number of blocks (encoded in input sequence) must pass
/// before the next withdrawal.
///
/// Script:
///   OP_IF
///       <owner_pubkey> OP_CHECKSIG
///   OP_ELSE
///       -- Output[0] goes back to same covenant address
///       OP_TXINPUTINDEX OP_TXINPUTSPK
///       0 OP_TXOUTPUTSPK OP_EQUALVERIFY
///       -- Output[0] amount >= input amount - max_withdraw
///       0 OP_TXOUTPUTAMOUNT
///       OP_TXINPUTINDEX OP_TXINPUTAMOUNT <max_withdraw> OP_SUB
///       OP_GREATERTHANOREQUAL OP_VERIFY
///       -- Enforce minimum time between withdrawals
///       <min_sequence> OP_CHECKSEQUENCEVERIFY
///       -- Exactly 2 outputs
///       OP_TXOUTPUTCOUNT 2 OP_EQUAL
///   OP_ENDIF
pub fn build_allowance_script(
    owner_pubkey: &[u8; 32],
    beneficiary_pubkey: &[u8; 32],
    max_withdraw_sompi: u64,
    min_sequence: u64,
    start_daa: u64,
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(128);

    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIG);

    s.push(OP_ELSE);

    // Beneficiary must sign
    push_pubkey(&mut s, beneficiary_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Optional start date: CLTV absolute locktime
    if start_daa > 0 {
        push_int(&mut s, start_daa);
        s.push(OP_CHECKLOCKTIMEVERIFY);
    }

    // Output[0] goes back to same covenant address
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);

    // Output[0] amount >= input amount - max_withdraw
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_AMOUNT);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);
    push_int(&mut s, max_withdraw_sompi);
    s.push(OP_SUB);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    // Relative time-lock: input sequence must be >= min_sequence
    // CSV pops the value (Kaspa semantics, same as CLTV)
    if min_sequence > 0 {
        push_int(&mut s, min_sequence);
        s.push(OP_CHECKSEQUENCEVERIFY);
    }

    // Exactly 2 outputs
    s.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut s, 2);
    s.push(OP_EQUAL);

    s.push(OP_ENDIF);
    s
}

/// Build a treasury (approved destinations) covenant redeem script.
///
/// Owner can spend, but ONLY to one of N whitelisted destination SPKs
/// baked into the script. No free spending — output[0] must match
/// a pre-approved address.
///
/// Design: owner signs (CHECKSIGVERIFY), then output[0] SPK is compared
/// against each approved destination using EQUAL. For multiple destinations,
/// duplicates are checked with NIP (OP_TUCK/OP_OVER) and OR'd together.
///
/// Script (1 destination):
///   <owner_pubkey> OP_CHECKSIGVERIFY
///   0 OP_TX_OUTPUT_SPK <dest1_spk_full> OP_EQUAL
///
/// Script (2 destinations):
///   <owner_pubkey> OP_CHECKSIGVERIFY
///   0 OP_TX_OUTPUT_SPK
///   OP_DUP <dest1_spk_full> OP_EQUAL
///   OP_SWAP <dest2_spk_full> OP_EQUAL
///   OP_OR
///
/// Script (3 destinations):
///   <owner_pubkey> OP_CHECKSIGVERIFY
///   0 OP_TX_OUTPUT_SPK
///   OP_DUP <dest1_spk_full> OP_EQUAL
///   OP_SWAP OP_DUP <dest2_spk_full> OP_EQUAL OP_ROT OP_OR
///   OP_SWAP <dest3_spk_full> OP_EQUAL OP_OR
///
/// Sig_script: <sig> <redeem_script>
/// No branch selector needed — no IF/ELSE in the script.
pub fn build_treasury_script(owner_pubkey: &[u8; 32], approved_spks: &[Vec<u8>]) -> Vec<u8> {
    use covenant_ops::*;
    const OP_DUP: u8 = 0x76;
    const OP_SWAP: u8 = 0x7c;
    const OP_BOOLOR: u8 = 0x9b;

    assert!(
        !approved_spks.is_empty() && approved_spks.len() <= 4,
        "Treasury supports 1–4 approved destinations"
    );

    let mut s = Vec::with_capacity(256);

    // Owner must always sign
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Push output[0] SPK for comparison
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);

    if approved_spks.len() == 1 {
        // Single destination — just EQUAL
        let mut spk_full = Vec::with_capacity(2 + approved_spks[0].len());
        spk_full.extend_from_slice(&[0x00, 0x00]); // version BE prefix
        spk_full.extend_from_slice(&approved_spks[0]);
        push_data(&mut s, &spk_full);
        s.push(OP_EQUAL);
    } else {
        // Multiple destinations: DUP + EQUAL + SWAP + EQUAL + OR chain
        for (i, spk) in approved_spks.iter().enumerate() {
            let mut spk_full = Vec::with_capacity(2 + spk.len());
            spk_full.extend_from_slice(&[0x00, 0x00]);
            spk_full.extend_from_slice(spk);

            if i == 0 {
                // First: DUP <dest> EQUAL → stack: [spk, bool]
                s.push(OP_DUP);
                push_data(&mut s, &spk_full);
                s.push(OP_EQUAL);
            } else if i == approved_spks.len() - 1 {
                // Last: SWAP <dest> EQUAL OR → stack: [bool]
                s.push(OP_SWAP);
                push_data(&mut s, &spk_full);
                s.push(OP_EQUAL);
                s.push(OP_BOOLOR);
            } else {
                // Middle: SWAP DUP <dest> EQUAL ROT OR
                // stack before: [spk, accumulated_bool]
                // SWAP → [accumulated_bool, spk]
                // DUP → [accumulated_bool, spk, spk]
                // <dest> EQUAL → [accumulated_bool, spk, bool]
                // ROT → [spk, bool, accumulated_bool]
                // OR → [spk, new_accumulated_bool]
                s.push(OP_SWAP);
                s.push(OP_DUP);
                push_data(&mut s, &spk_full);
                s.push(OP_EQUAL);
                s.push(0x7b); // OP_ROT
                s.push(OP_BOOLOR);
            }
        }
    }

    s
}

/// Build a hash-locked atomic swap (HTLC) covenant redeem script (Blake2b).
/// For cross-chain (SHA256) variant, use `build_atomic_swap_script_with_algo`.
// Kept: atomic-swap covenant builder, not yet wired to UI.
#[allow(dead_code)]
pub fn build_atomic_swap_script(
    owner_pubkey: &[u8; 32],
    counterparty_pubkey: &[u8; 32],
    expected_hash: &[u8; 32],
    locktime_daa: u64,
) -> Vec<u8> {
    build_atomic_swap_script_with_algo(
        owner_pubkey,
        counterparty_pubkey,
        expected_hash,
        locktime_daa,
        "blake2b",
    )
}

/// Build a hash-locked atomic swap (HTLC) covenant redeem script.
///
/// Two branches:
///   1. Refund: owner reclaims after locktime expires (IF branch).
///   2. Claim: counterparty reveals preimage whose hash matches (ELSE branch).
///
/// `hash_algo`: "blake2b" (0xAA, Kaspa-native) or "sha256" (0xA8, Bitcoin-compatible cross-chain)
///
/// Sig_scripts:
///   Refund: <sig> OP_TRUE <redeem>
///   Claim:  <preimage> <sig> OP_FALSE <redeem>
pub fn build_atomic_swap_script_with_algo(
    owner_pubkey: &[u8; 32],
    counterparty_pubkey: &[u8; 32],
    expected_hash: &[u8; 32],
    locktime_daa: u64,
    hash_algo: &str,
) -> Vec<u8> {
    use covenant_ops::*;
    let hash_opcode = match hash_algo {
        "sha256" => OP_SHA256,
        _ => OP_BLAKE2B,
    };
    let mut s = Vec::with_capacity(160);

    // Refund path: owner reclaims after timeout (IF — standard owner branch)
    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(0x51); // OP_TRUE

    // Claim path: counterparty provides preimage (ELSE)
    s.push(OP_ELSE);
    push_pubkey(&mut s, counterparty_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(hash_opcode);
    push_data(&mut s, expected_hash);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ENDIF);
    s
}

/// Build an oracle-gated covenant redeem script (OpCheckSigFromStack — 0xd7).
///
/// Two branches:
///   1. Owner refund: owner reclaims after locktime (IF branch).
///   2. Oracle claim: beneficiary claims only when oracle attests (ELSE branch).
///
/// The oracle signs an ARBITRARY 32-byte message hash off-chain (Schnorr).
/// OpCheckSigFromStack verifies the oracle's signature on-chain against
/// that message hash — NOT against the TX sighash. This enables
/// insurance payouts, sports bets, price triggers, escrow arbitration,
/// and any conditional release gated on external oracle attestation.
///
/// Script:
///   OP_IF
///       <owner_pubkey> OP_CHECKSIGVERIFY
///       <locktime> OP_CHECKLOCKTIMEVERIFY
///       OP_TRUE
///   OP_ELSE
///       <beneficiary_pubkey> OP_CHECKSIGVERIFY
///       <oracle_pubkey> OP_CHECKSIGFROMSTACK
///       OP_VERIFY
///       OP_TRUE
///   OP_ENDIF
///
/// Sig_script for owner refund:
///   <sig> OP_TRUE <redeem>
///
/// Sig_script for oracle claim:
///   <oracle_signature> <message_hash> <beneficiary_sig> OP_FALSE <redeem>
///
/// Stack flow for oracle claim:
///   1. OP_FALSE → selects ELSE branch
///   2. <bene_sig> on stack → CHECKSIGVERIFY validates against TX sighash
///   3. Stack now: [oracle_sig, msg_hash]
///   4. <oracle_pubkey> pushed by script → CHECKSIGFROMSTACK pops
///      [oracle_sig, msg_hash, oracle_pubkey] and verifies Schnorr sig
///   5. OP_VERIFY ensures result is true
///   6. OP_TRUE → clean stack exit
pub fn build_oracle_covenant_script(
    owner_pubkey: &[u8; 32],
    beneficiary_pubkey: &[u8; 32],
    oracle_pubkey: &[u8; 32],
    locktime_daa: u64,
    salt: &[u8; 8],
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(200);

    // Salt: unique nonce so identical params (owner, bene, oracle, locktime)
    // produce a different P2SH each time. It is pushed then OP_DROPped, so it is
    // logic-neutral; it only shifts the covenant body +10 bytes
    // (0x08 <8 salt> OP_DROP). Every parse site already strips it: the firmware
    // covenant signer (opcode-aware walk), build_consensus_input, the owner-spend
    // sig_script builder, and extract_cltv_locktime. The claim/heartbeat builders
    // push the full redeem, so the P2SH hash still matches.
    s.push(0x08);
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    // Path 1: Owner refund after timeout (IF)
    //   Sig_script: <sig> OP_TRUE <redeem>
    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ELSE);

    // Path 2: Beneficiary claim with oracle attestation (ELSE IF)
    //   Sig_script: <oracle_sig> <msg_hash> <bene_sig> OP_TRUE OP_FALSE <redeem>
    s.push(OP_IF);
    push_pubkey(&mut s, beneficiary_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_pubkey(&mut s, oracle_pubkey);
    s.push(OP_CHECKSIGFROMSTACK);
    s.push(OP_VERIFY);
    s.push(0x51); // OP_TRUE

    // Path 3: Oracle heartbeat beacon (ELSE ELSE)
    //   Oracle signs, funds go back to same P2SH. Attestation in TX payload.
    //   Sig_script: <sig> OP_FALSE OP_FALSE <redeem>
    s.push(OP_ELSE);
    push_pubkey(&mut s, oracle_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ENDIF); // inner IF/ELSE
    s.push(OP_ENDIF); // outer IF/ELSE
    s
}

/// Build a PayJoin covenant redeem script.
///
/// Enforces that the spending TX has mixed inputs — the spender MUST
/// include at least one of their own UTXOs alongside the covenant UTXO.
/// This breaks chain analysis by making it impossible to distinguish
/// which inputs belong to which outputs.
///
/// Two branches:
///   1. Owner refund: owner reclaims after locktime (IF branch).
///   2. PayJoin spend: beneficiary claims, but ONLY in a TX with:
///      - At least `min_inputs` inputs (default 2)
///      - At least `min_outputs` outputs (default 2)
///      - Input[0] and Input[1] from different addresses (enforced via OpTxInputSpk)
///
/// Script:
///   OP_IF
///       <owner_pubkey> OP_CHECKSIGVERIFY
///       <locktime> OP_CHECKLOCKTIMEVERIFY
///       OP_TRUE
///   OP_ELSE
///       <beneficiary_pubkey> OP_CHECKSIGVERIFY
///       OP_TXINPUTCOUNT <min_inputs> OP_GREATERTHANOREQUAL OP_VERIFY
///       OP_TXOUTPUTCOUNT <min_outputs> OP_GREATERTHANOREQUAL OP_VERIFY
///       0 OP_TXINPUTSPK 1 OP_TXINPUTSPK OP_EQUAL OP_NOT OP_VERIFY
///       OP_TRUE
///   OP_ENDIF
///
/// Privacy yield: on-chain the TX looks like a normal multi-input spend.
/// The covenant creator guarantees that their funds can only be spent
/// in a PayJoin-style TX, forcing input mixing.
pub fn build_payjoin_covenant_script(
    owner_pubkey: &[u8; 32],
    beneficiary_pubkey: &[u8; 32],
    locktime_daa: u64,
    min_inputs: u64,
    min_outputs: u64,
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(120);

    // Owner refund path (IF)
    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_1); // OP_TRUE

    // PayJoin beneficiary claim (ELSE)
    s.push(OP_ELSE);

    // Beneficiary must sign
    push_pubkey(&mut s, beneficiary_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // At least min_inputs inputs
    s.push(OP_TX_INPUT_COUNT);
    push_int(&mut s, min_inputs);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    // At least min_outputs outputs
    s.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut s, min_outputs);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    // Input[0] and Input[1] must be from different addresses
    push_int(&mut s, 0); // push index 0
    s.push(OP_TX_INPUT_SPK);
    push_int(&mut s, 1); // push index 1
    s.push(OP_TX_INPUT_SPK);
    s.push(OP_EQUAL);
    s.push(OP_NOT);
    s.push(OP_VERIFY);

    s.push(OP_1); // OP_TRUE
    s.push(OP_ENDIF);
    s
}
