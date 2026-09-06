use super::{push_int, push_pubkey};
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
    use super::covenant_ops::*;
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

    super::global_thread::append_global_thread_enforcement(&mut s, max_withdraw_sompi);

    s
}
