use super::{push_int, push_pubkey};
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
    use super::covenant_ops::*;
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

    super::global_thread::append_global_thread_enforcement(&mut s, max_withdraw_sompi);

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
    use super::covenant_ops::*;
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
